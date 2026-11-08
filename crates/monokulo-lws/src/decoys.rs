//! Ring members for `/get_random_outs`, picked as wallet2's `gamma_picker`
//! picks them (monero-lws's `gamma_picker` is the same), then fetched from
//! the node and kept only if the node says they are unlocked, as monero-lws's
//! `pick_random_outputs` does.
//!
//! The picker: an age `x = exp(Γ(19.28, 1/1.61))` seconds; past the default
//! unlock time (10 blocks, 1,200 s) it is moved back by that much, otherwise
//! it is drawn uniformly from the recent spend window (15 blocks, 1,800 s).
//! It becomes a count of outputs back from the newest spendable one at the
//! average output time of the last year of blocks; the block holding that
//! output is found in the cumulative distribution, and an output is drawn
//! uniformly from the block.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use rand_distr::{Distribution as _, Gamma};

use crate::daemon::{Daemon, Distribution};
use crate::error::{Error, Result};
use crate::scanner::SPENDABLE_AGE;

const GAMMA_SHAPE: f64 = 19.28;
const GAMMA_SCALE: f64 = 1.0 / 1.61;
/// `DIFFICULTY_TARGET_V2`.
const BLOCK_TIME: u64 = 120;
const BLOCKS_IN_A_YEAR: usize = (86_400 * 365 / BLOCK_TIME) as usize;
/// wallet2's `DEFAULT_UNLOCK_TIME`: `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE`
/// blocks.
const DEFAULT_UNLOCK_TIME: f64 = (SPENDABLE_AGE * BLOCK_TIME) as f64;
/// wallet2's `RECENT_SPEND_WINDOW`.
const RECENT_SPEND_WINDOW: u64 = 15 * BLOCK_TIME;
/// Draws one pick may take before giving up (monero-lws's `gamma_picker`).
const PICK_TRIES: usize = 100;
/// Rounds of picking and asking the node before a request fails
/// (monero-lws's `pick_random_outputs`).
const MAX_ROUNDS: usize = 64;
/// How long a fetched distribution serves at most.
const FRESH_FOR: Duration = Duration::from_secs(120);
/// How long it serves at least, even once the chain has moved past it
/// (monero-lws keeps it 5 s).
const FRESH_AT_LEAST: Duration = Duration::from_secs(5);
/// Outputs asked of the node in one `get_outs` (a restricted node takes up
/// to 5,000).
const OUTS_PER_REQUEST: usize = 1_000;

/// The distribution, fetched again when the chain has grown past it (or
/// after two minutes), and shared, not copied, between requests (on mainnet
/// it is millions of entries).
pub struct Picker {
    distribution: tokio::sync::Mutex<Option<(Instant, Arc<Distribution>)>>,
}

#[derive(Clone, Debug)]
pub struct Member {
    pub global_index: u64,
    pub public_key: [u8; 32],
    pub commitment: [u8; 32],
}

impl Picker {
    pub fn new() -> Picker {
        Picker {
            distribution: tokio::sync::Mutex::new(None),
        }
    }

    /// The node's distribution; a cached one while it is fresh, which is
    /// while it reaches `chain_height` (the scanner's last word; 0 for
    /// unknown) and is under two minutes old, and always for 5 s.
    async fn distribution(&self, daemon: &Daemon, chain_height: u64) -> Result<Arc<Distribution>> {
        let mut cached = self.distribution.lock().await;
        if let Some((at, d)) = cached.as_ref() {
            let top = d.start_height + d.cumulative.len() as u64;
            let current = chain_height == 0 || top >= chain_height;
            if at.elapsed() < FRESH_AT_LEAST || (current && at.elapsed() < FRESH_FOR) {
                return Ok(d.clone());
            }
        }
        let d = Arc::new(daemon.output_distribution().await?);
        *cached = Some((Instant::now(), d.clone()));
        Ok(d)
    }

    /// `rings` rings of `count` distinct unlocked RingCT outputs each, sorted
    /// by global index, as monero-lws's `pick_random_outputs` makes them:
    /// each round picks what every ring still lacks, asks the node once (in
    /// chunks of 1,000) for all of them, and drops what is locked; after 64
    /// rounds with a ring still short, the request fails. A chain with fewer
    /// spendable outputs than `count` gets no rings at all (monero-lws drops
    /// such rings from its answer); one with exactly `count` gets all of them.
    pub async fn rings(
        &self,
        daemon: &Daemon,
        count: usize,
        rings: usize,
        chain_height: u64,
    ) -> Result<Vec<Vec<Member>>> {
        let d = self.distribution(daemon, chain_height).await?;
        let Some(picker) = GammaPicker::new(&d.cumulative) else {
            return Err(Error::Busy("the chain is too short to pick ring members from"));
        };
        let spendable = picker.spendable();
        if spendable < count as u64 {
            return Ok(vec![]);
        }
        let mut out: Vec<Vec<Member>> = vec![vec![]; rings];
        let mut tried: Vec<HashSet<u64>> = vec![HashSet::new(); rings];
        for _ in 0..MAX_ROUNDS {
            if out.iter().all(|members| members.len() >= count) {
                break;
            }
            let asked: Vec<(usize, u64)> = {
                // The thread's generator doesn't cross an await.
                let mut rng = rand::thread_rng();
                let mut asked = vec![];
                for (ring, members) in out.iter().enumerate() {
                    if spendable == count as u64 {
                        // monero-lws's `pick_all`: every spendable output.
                        asked.extend((0..spendable).filter(|i| tried[ring].insert(*i)).map(|i| (ring, i)));
                        continue;
                    }
                    for _ in 0..count.saturating_sub(members.len()) {
                        let i = picker
                            .pick(&mut rng)
                            .ok_or(Error::Busy("could not pick ring members; try again"))?;
                        // A repeat (in this ring, or one already refused as
                        // locked) is dropped, and drawn again next round.
                        if tried[ring].insert(i) {
                            asked.push((ring, i));
                        }
                    }
                }
                asked
            };
            for chunk in asked.chunks(OUTS_PER_REQUEST) {
                let indexes: Vec<u64> = chunk.iter().map(|(_, i)| *i).collect();
                let outs = daemon.outs(&indexes).await?;
                for (&(ring, index), o) in chunk.iter().zip(outs) {
                    if out[ring].len() >= count || !o.unlocked {
                        continue;
                    }
                    let (Some(key), Some(commitment)) = (crate::daemon::hex32(&o.key), crate::daemon::hex32(&o.mask))
                    else {
                        return Err(Error::Daemon("get_outs: a key that isn't hex".into()));
                    };
                    out[ring].push(Member {
                        global_index: index,
                        public_key: key,
                        commitment,
                    });
                }
            }
        }
        if out.iter().any(|members| members.len() < count) {
            return Err(Error::Busy("not enough unlocked ring members; try again"));
        }
        for members in &mut out {
            members.sort_by_key(|m| m.global_index);
        }
        Ok(out)
    }
}

/// wallet2's `gamma_picker` over a cumulative RingCT output distribution
/// (one entry per block: the outputs up to the end of that block).
struct GammaPicker<'a> {
    offsets: &'a [u64],
    /// The blocks a pick may land in: all but the last
    /// `CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE - 1`.
    end: usize,
    /// The outputs spendable now: the cumulative count at `end - 1`.
    num_rct_outputs: u64,
    /// Seconds between outputs over the last year of blocks.
    average_output_time: f64,
    gamma: Gamma<f64>,
}

impl<'a> GammaPicker<'a> {
    /// `None` where wallet2 throws: fewer blocks than the spendable age, no
    /// spendable output, or no output in the last year.
    fn new(offsets: &'a [u64]) -> Option<GammaPicker<'a>> {
        let age = (SPENDABLE_AGE as usize).max(1);
        if offsets.len() < age {
            return None;
        }
        let blocks_to_consider = offsets.len().min(BLOCKS_IN_A_YEAR);
        let initial = if blocks_to_consider < offsets.len() {
            offsets[offsets.len() - blocks_to_consider - 1]
        } else {
            0
        };
        let outputs_to_consider = offsets[offsets.len() - 1].checked_sub(initial)?;
        let end = offsets.len() - (age - 1);
        let num_rct_outputs = offsets[end - 1];
        if num_rct_outputs == 0 || outputs_to_consider == 0 {
            return None;
        }
        Some(GammaPicker {
            offsets,
            end,
            num_rct_outputs,
            average_output_time: BLOCK_TIME as f64 * blocks_to_consider as f64 / outputs_to_consider as f64,
            gamma: Gamma::new(GAMMA_SHAPE, GAMMA_SCALE).ok()?,
        })
    }

    fn spendable(&self) -> u64 {
        self.num_rct_outputs
    }

    /// One global index, or `None` after 100 draws that each fell off the
    /// chain or into an empty block (monero-lws gives up there too).
    fn pick(&self, rng: &mut impl Rng) -> Option<u64> {
        (0..PICK_TRIES).find_map(|_| {
            let x = self.gamma.sample(rng).exp();
            self.at_age(x, rng)
        })
    }

    /// wallet2's `gamma_picker::pick` once the gamma has drawn `x` seconds.
    fn at_age(&self, x: f64, rng: &mut impl Rng) -> Option<u64> {
        let x = if x > DEFAULT_UNLOCK_TIME {
            // Ages count from the newest spendable output, not the tip.
            x - DEFAULT_UNLOCK_TIME
        } else {
            // Too young to spend: somewhere in the recent spend window.
            rng.gen_range(0..RECENT_SPEND_WINDOW) as f64
        };
        let back = (x / self.average_output_time) as u64;
        if back >= self.num_rct_outputs {
            return None;
        }
        let output_index = self.num_rct_outputs - 1 - back;
        // `std::lower_bound`, as wallet2: the first block whose cumulative
        // count is not below the index.
        let block = self.offsets[..self.end].partition_point(|c| *c < output_index);
        if block == self.end {
            return None;
        }
        let first_rct = if block == 0 { 0 } else { self.offsets[block - 1] };
        let n_rct = self.offsets[block] - first_rct;
        if n_rct == 0 {
            return None;
        }
        Some(first_rct + rng.gen_range(0..n_rct))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// `blocks` blocks of `per_block` outputs each, cumulative.
    fn steady(blocks: u64, per_block: u64) -> Vec<u64> {
        (1..=blocks).map(|b| b * per_block).collect()
    }

    #[test]
    fn the_shape_is_wallet2s() {
        // Two years of blocks, ten outputs each: the average output time is
        // over the last year, 12 s.
        let offsets = steady(2 * BLOCKS_IN_A_YEAR as u64, 10);
        let p = GammaPicker::new(&offsets).unwrap();
        assert!((p.average_output_time - 12.0).abs() < 1e-9);
        // Spendable: everything but the last nine blocks.
        assert_eq!(p.spendable(), offsets[offsets.len() - 10]);
        assert_eq!(p.end, offsets.len() - 9);
        // A young chain: the average is over all of it, the blocks not yet
        // spendable included.
        let young = steady(100, 4);
        let p = GammaPicker::new(&young).unwrap();
        assert!((p.average_output_time - 30.0).abs() < 1e-9);
        assert_eq!(p.spendable(), 91 * 4);
        assert!(
            GammaPicker::new(&steady(9, 4)).is_none(),
            "shorter than the spendable age"
        );
        assert!(GammaPicker::new(&[0; 20]).is_none(), "no outputs");
    }

    #[test]
    fn an_age_maps_to_an_output_as_in_wallet2() {
        // Ten outputs a block: one every 12 s.
        let offsets = steady(1_000, 10);
        let p = GammaPicker::new(&offsets).unwrap();
        let newest = p.spendable() - 1;
        assert_eq!(newest, 9_909);
        let mut rng = StdRng::seed_from_u64(1);
        // 1,200 s past the unlock time: 100 outputs back, so 9,809, in the
        // block of outputs 9,800 to 9,809.
        let i = p.at_age(DEFAULT_UNLOCK_TIME + 1_200.0, &mut rng).unwrap();
        assert!((9_800..9_810).contains(&i), "{i}");
        // Exactly on a block boundary, wallet2's lower_bound takes the
        // earlier block: 9,800 is the cumulative count of the block before.
        let back = newest - 9_800;
        let i = p
            .at_age(DEFAULT_UNLOCK_TIME + back as f64 * 12.0 + 1.0, &mut rng)
            .unwrap();
        assert!((9_790..9_800).contains(&i), "{i}");
        // Younger than the unlock time: in the recent window, 1,800 s, so
        // at most 150 outputs back (and the rest of that block).
        for _ in 0..1_000 {
            let i = p.at_age(600.0, &mut rng).unwrap();
            assert!((9_750..=newest).contains(&i), "{i}");
        }
        // Older than the chain: no pick.
        assert!(p.at_age(DEFAULT_UNLOCK_TIME + 1e9, &mut rng).is_none());
    }

    #[test]
    fn picks_stay_spendable_and_follow_the_gamma() {
        let offsets = steady(100_000, 10);
        let p = GammaPicker::new(&offsets).unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let n = 20_000;
        let picks: Vec<u64> = (0..n).map(|_| p.pick(&mut rng).unwrap()).collect();
        assert!(
            picks.iter().all(|i| *i < p.spendable()),
            "never in the last nine blocks"
        );
        // The gamma's median is about 11.77, so the median age is about
        // e^11.77 s less the unlock time: some 128,000 s, or 10,650 outputs
        // at 12 s.
        let mut back: Vec<u64> = picks.iter().map(|i| p.spendable() - 1 - i).collect();
        back.sort_unstable();
        let median = back[n / 2] as f64;
        assert!((8_000.0..14_000.0).contains(&median), "{median}");
        // A few percent land in the most recent 150 outputs: the draws under
        // the unlock time (the recent window) and those just past it.
        let recent = back.iter().filter(|b| **b < 150).count() as f64 / n as f64;
        assert!((0.02..0.12).contains(&recent), "{recent}");
    }
}
