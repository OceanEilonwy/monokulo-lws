//! Ring members for `/get_random_outs`: picked from the RingCT output
//! distribution the way wallet2 does (a gamma over output age), then
//! fetched from the daemon and kept only if unlocked.

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

pub struct Picker {
    distribution: Option<(Instant, Distribution)>,
}

#[derive(Clone, Debug)]
pub struct Member {
    pub global_index: u64,
    pub public_key: [u8; 32],
    pub commitment: [u8; 32],
}

impl Picker {
    pub fn new() -> Picker {
        Picker { distribution: None }
    }

    async fn distribution(&mut self, daemon: &Daemon) -> Result<&Distribution> {
        let stale = self
            .distribution
            .as_ref()
            .map(|(at, _)| at.elapsed() > FRESH_FOR)
            .unwrap_or(true);
        if stale {
            let d = daemon.output_distribution().await?;
            if d.cumulative.len() < SPENDABLE_AGE as usize + 2 {
                return Err(Error::Daemon("the output distribution is too short".into()));
            }
            self.distribution = Some((Instant::now(), d));
        }
        Ok(&self.distribution.as_ref().expect("just set").1)
    }

    /// `rings` rings of `count` unlocked RingCT outputs each, every ring
    /// drawn afresh. A ring short of members means the chain hasn't enough.
    pub async fn rings(&mut self, daemon: &Daemon, count: usize, rings: usize) -> Result<Vec<Vec<Member>>> {
        let d = self.distribution(daemon).await?.clone();
        let mut out = Vec::with_capacity(rings);
        for _ in 0..rings {
            out.push(ring(&d, daemon, count).await?);
        }
        Ok(out)
    }
}

async fn ring(d: &Distribution, daemon: &Daemon, count: usize) -> Result<Vec<Member>> {
    let mut members: Vec<Member> = vec![];
    let mut tried = std::collections::HashSet::new();
    for _ in 0..MAX_ROUNDS {
        if members.len() >= count {
            break;
        }
        let wanted = (count - members.len()) * 2 + 4;
        let picks: Vec<u64> = {
            // The thread's generator doesn't cross an await.
            let mut rng = rand::thread_rng();
            let mut picks = vec![];
            for _ in 0..wanted * 4 {
                if picks.len() >= wanted {
                    break;
                }
                if let Some(i) = pick(d, &mut rng)
                    && tried.insert(i)
                {
                    picks.push(i);
                }
            }
            picks
        };
        if picks.is_empty() {
            break;
        }
        let outs = daemon.outs(&picks).await?;
        for (index, out) in picks.iter().zip(outs) {
            if !out.unlocked {
                continue;
            }
            let (Some(key), Some(commitment)) = (crate::daemon::hex32(&out.key), crate::daemon::hex32(&out.mask))
            else {
                continue;
            };
            members.push(Member {
                global_index: *index,
                public_key: key,
                commitment,
            });
            if members.len() >= count {
                break;
            }
        }
    }
    Ok(members)
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
