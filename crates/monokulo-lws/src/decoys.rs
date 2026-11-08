//! Ring members for `/get_random_outs`: picked from the RingCT output
//! distribution the way wallet2 does (a gamma over output age), then
//! fetched from the daemon and kept only if unlocked.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use rand_distr::{Distribution as _, Gamma};

use crate::daemon::{Daemon, Distribution};
use crate::error::{Error, Result};
use crate::scanner::SPENDABLE_AGE;

const GAMMA_SHAPE: f64 = 19.28;
const GAMMA_RATE: f64 = 1.61;
const BLOCK_TIME: f64 = 120.0;
const BLOCKS_IN_A_YEAR: usize = 86_400 * 365 / 120;
/// How long a fetched distribution serves before being asked for again.
const FRESH_FOR: Duration = Duration::from_secs(120);
/// Rounds of picking and asking the daemon before giving up on a ring.
const MAX_ROUNDS: usize = 8;

/// The distribution, fetched at most every two minutes and shared, not
/// copied, between requests (on mainnet it is millions of entries).
pub struct Picker {
    distribution: tokio::sync::Mutex<Option<(Instant, Arc<Distribution>)>>,
}

#[derive(Clone, Debug)]
pub struct Member {
    pub global_index: u64,
    pub public_key: [u8; 32],
    pub commitment: [u8; 32],
}

/// Outputs asked of the node in one `get_outs` (a restricted node takes up
/// to 5,000).
const OUTS_PER_REQUEST: usize = 1_000;

impl Picker {
    pub fn new() -> Picker {
        Picker {
            distribution: tokio::sync::Mutex::new(None),
        }
    }

    async fn distribution(&self, daemon: &Daemon) -> Result<Arc<Distribution>> {
        let mut cached = self.distribution.lock().await;
        if let Some((at, d)) = cached.as_ref()
            && at.elapsed() <= FRESH_FOR
        {
            return Ok(d.clone());
        }
        let d = daemon.output_distribution().await?;
        if d.cumulative.len() < SPENDABLE_AGE as usize + 2 {
            return Err(Error::Daemon("the output distribution is too short".into()));
        }
        let d = Arc::new(d);
        *cached = Some((Instant::now(), d.clone()));
        Ok(d)
    }

    /// `rings` rings of `count` unlocked RingCT outputs each, every ring
    /// drawn afresh. A ring short of members means the chain hasn't enough.
    /// Each round asks the node once for every ring still short, so a
    /// request costs a few `get_outs` however many rings it wants.
    pub async fn rings(&self, daemon: &Daemon, count: usize, rings: usize) -> Result<Vec<Vec<Member>>> {
        let d = self.distribution(daemon).await?;
        let mut out: Vec<Vec<Member>> = vec![vec![]; rings];
        let mut tried: Vec<HashSet<u64>> = vec![HashSet::new(); rings];
        for _ in 0..MAX_ROUNDS {
            let asked: Vec<(usize, u64)> = {
                // The thread's generator doesn't cross an await.
                let mut rng = rand::thread_rng();
                let mut asked = vec![];
                for (ring, members) in out.iter().enumerate() {
                    if members.len() >= count {
                        continue;
                    }
                    let wanted = (count - members.len()) * 2 + 4;
                    let mut picked = 0;
                    for _ in 0..wanted * 4 {
                        if picked >= wanted {
                            break;
                        }
                        if let Some(i) = pick(&d, &mut rng)
                            && tried[ring].insert(i)
                        {
                            asked.push((ring, i));
                            picked += 1;
                        }
                    }
                }
                asked
            };
            if asked.is_empty() {
                break;
            }
            for chunk in asked.chunks(OUTS_PER_REQUEST) {
                let indexes: Vec<u64> = chunk.iter().map(|(_, i)| *i).collect();
                let outs = daemon.outs(&indexes).await?;
                for (&(ring, index), o) in chunk.iter().zip(outs) {
                    if out[ring].len() >= count || !o.unlocked {
                        continue;
                    }
                    let (Some(key), Some(commitment)) = (crate::daemon::hex32(&o.key), crate::daemon::hex32(&o.mask))
                    else {
                        continue;
                    };
                    out[ring].push(Member {
                        global_index: index,
                        public_key: key,
                        commitment,
                    });
                }
            }
        }
        Ok(out)
    }
}

/// One global index, gamma-distributed over output age as wallet2's
/// `gamma_picker`, or `None` for a draw that fell off the chain.
fn pick(d: &Distribution, rng: &mut impl Rng) -> Option<u64> {
    let cumulative = &d.cumulative;
    // Outputs younger than the spendable age can't be ring members.
    let usable_blocks = cumulative.len() - SPENDABLE_AGE as usize;
    let num_outputs = cumulative[usable_blocks - 1];
    if num_outputs == 0 {
        return None;
    }
    let year = usable_blocks.min(BLOCKS_IN_A_YEAR);
    let outputs_in_year = num_outputs - cumulative[usable_blocks - year];
    let average_output_time = BLOCK_TIME * year as f64 / (outputs_in_year.max(1) as f64);

    let gamma = Gamma::new(GAMMA_SHAPE, 1.0 / GAMMA_RATE).ok()?;
    let x = gamma.sample(rng).exp();
    let output_age = (x / average_output_time) as u64;
    if output_age >= num_outputs {
        return None;
    }
    let n = num_outputs - 1 - output_age;
    // The block holding output n, then a uniform draw within it.
    let block = cumulative[..usable_blocks].partition_point(|c| *c <= n);
    let (lo, hi) = (if block == 0 { 0 } else { cumulative[block - 1] }, cumulative[block]);
    if hi <= lo {
        return None;
    }
    Some(rng.gen_range(lo..hi))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_stay_on_the_chain_and_lean_recent() {
        // A thousand blocks of ten outputs each.
        let cumulative: Vec<u64> = (1..=100_000u64).map(|b| b * 10).collect();
        let d = Distribution {
            start_height: 0,
            cumulative,
        };
        let mut rng = rand::thread_rng();
        let mut picks = vec![];
        for _ in 0..2000 {
            if let Some(i) = pick(&d, &mut rng) {
                assert!(i < 10 * (100_000 - SPENDABLE_AGE));
                picks.push(i);
            }
        }
        assert!(picks.len() > 1500);
        let recent = picks.iter().filter(|i| **i > 10 * 90_000).count();
        assert!(recent > picks.len() / 2, "{recent} of {}", picks.len());
    }
}
