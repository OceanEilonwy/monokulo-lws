//! Which lane scans which account (docs/scanning.md, "Lanes"): the live lane
//! follows the tip with every caught-up account; catch-up lanes bring
//! accounts with history up to it, each with a keyring of its own, and merge
//! into the live lane when they reach it. This is only the bookkeeping, kept
//! apart from fetching and scanning so its rules can be tested on their own.

use std::collections::BTreeSet;

/// Whether a queued account joins a running catch-up lane whose cursor is
/// below its start, or always waits for a lane of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Join {
    Follow,
    Wait,
}

/// A catch-up lane as the live lane sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lane {
    pub id: u64,
    pub accounts: BTreeSet<i64>,
    /// The next block it scans: the lowest height of its accounts.
    pub cursor: u64,
    /// It has reached the live lane's cursor, and waits for the live lane to
    /// take its accounts in.
    pub ready: bool,
}

#[derive(Debug, Default)]
pub struct Plan {
    /// The live lane's cursor: the next block it scans. `None` until the live
    /// lane's first step sets it.
    pub live: Option<u64>,
    pub lanes: Vec<Lane>,
    next_id: u64,
}

impl Plan {
    /// The lane `account` is in, if a catch-up lane has it.
    pub fn owner(&self, account: i64) -> Option<u64> {
        self.lanes.iter().find(|l| l.accounts.contains(&account)).map(|l| l.id)
    }

    pub fn lane(&self, id: u64) -> Option<&Lane> {
        self.lanes.iter().find(|l| l.id == id)
    }

    /// Finds lanes for accounts behind the live cursor that no lane has yet,
    /// given as (account, scan height). Lowest first, accounts at one height
    /// together: each opens a lane while fewer than `most` run; otherwise,
    /// with `Follow`, it joins the running lane whose cursor is nearest below
    /// its height (it rides along unscanned until the cursor passes it);
    /// otherwise it waits for the next call. Returns the lanes opened.
    pub fn place(&mut self, behind: &[(i64, u64)], most: usize, join: Join) -> Vec<u64> {
        let mut behind: Vec<(i64, u64)> = behind
            .iter()
            .copied()
            .filter(|(a, _)| self.owner(*a).is_none())
            .collect();
        behind.sort_by_key(|&(a, h)| (h, a));
        let mut opened = vec![];
        let mut at = 0;
        while at < behind.len() {
            let height = behind[at].1;
            let group: BTreeSet<i64> = behind[at..]
                .iter()
                .take_while(|(_, h)| *h == height)
                .map(|(a, _)| *a)
                .collect();
            at += group.len();
            if self.lanes.len() < most {
                self.next_id += 1;
                self.lanes.push(Lane {
                    id: self.next_id,
                    accounts: group,
                    cursor: height,
                    ready: false,
                });
                opened.push(self.next_id);
            } else if join == Join::Follow
                && let Some(lane) = self
                    .lanes
                    .iter_mut()
                    .filter(|l| !l.ready && l.cursor <= height)
                    .max_by_key(|l| l.cursor)
            {
                lane.accounts.extend(group);
            }
        }
        opened
    }

    /// A lane's cursor, as it starts a step. True if it has reached the live
    /// cursor, so is ready to merge and should fetch nothing more.
    pub fn reached(&mut self, id: u64, cursor: u64) -> bool {
        let live = self.live.unwrap_or(u64::MAX);
        let Some(lane) = self.lanes.iter_mut().find(|l| l.id == id) else {
            return false;
        };
        lane.cursor = cursor;
        lane.ready = cursor >= live;
        lane.ready
    }

    /// Takes in every ready lane whose cursor is the live cursor: the lanes
    /// end, and their accounts are the live lane's. Called by the live lane
    /// as it starts a step, before it chooses its accounts.
    pub fn merge_ready(&mut self) -> Vec<i64> {
        let live = self.live.unwrap_or(u64::MAX);
        let mut merged = vec![];
        self.lanes.retain(|lane| {
            let merge = lane.ready && lane.cursor >= live;
            if merge {
                merged.extend(lane.accounts.iter().copied());
            }
            !merge
        });
        merged
    }

    /// The live lane moved to `live` (on, or back for a reorg): a lane ready
    /// at the old cursor has more to catch up, and goes on.
    pub fn advance(&mut self, live: u64) {
        self.live = Some(live);
        for lane in &mut self.lanes {
            if lane.cursor < live {
                lane.ready = false;
            }
        }
    }

    /// Drops accounts no longer scanned (hidden, or gone), and lanes left empty.
    pub fn keep_only(&mut self, active: &BTreeSet<i64>) {
        for lane in &mut self.lanes {
            lane.accounts.retain(|a| active.contains(a));
        }
        self.lanes.retain(|l| !l.accounts.is_empty());
    }

    /// Ends a lane, its accounts back in the queue.
    pub fn end(&mut self, id: u64) {
        self.lanes.retain(|l| l.id != id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(live: u64) -> Plan {
        Plan {
            live: Some(live),
            ..Plan::default()
        }
    }

    #[test]
    fn accounts_behind_open_lanes_while_there_is_room() {
        let mut p = plan(1000);
        let opened = p.place(&[(1, 100), (2, 500), (3, 100)], 2, Join::Follow);
        assert_eq!(opened, vec![1, 2]);
        assert_eq!(
            p.lane(1).unwrap().accounts,
            BTreeSet::from([1, 3]),
            "one height, one lane"
        );
        assert_eq!(p.lane(1).unwrap().cursor, 100);
        assert_eq!(p.lane(2).unwrap().accounts, BTreeSet::from([2]));
        assert_eq!(p.owner(3), Some(1));
        assert_eq!(
            p.place(&[(1, 100)], 2, Join::Follow),
            Vec::<u64>::new(),
            "already in a lane"
        );
    }

    #[test]
    fn with_follow_a_late_account_joins_the_lane_nearest_below() {
        let mut p = plan(1000);
        p.place(&[(1, 100), (2, 400)], 2, Join::Follow);
        assert!(
            p.place(&[(3, 450), (4, 300), (5, 50)], 2, Join::Follow).is_empty(),
            "no room for a new lane"
        );
        assert_eq!(p.owner(3), Some(2), "450 rides with the lane at 400");
        assert_eq!(p.owner(4), Some(1), "300 rides with the lane at 100");
        assert_eq!(p.owner(5), None, "below every cursor: it waits");
    }

    #[test]
    fn with_wait_a_late_account_waits_for_a_lane() {
        let mut p = plan(1000);
        p.place(&[(1, 100)], 1, Join::Wait);
        assert!(p.place(&[(2, 500)], 1, Join::Wait).is_empty());
        assert_eq!(p.owner(2), None);
        p.end(1);
        assert_eq!(p.place(&[(2, 500)], 1, Join::Wait), vec![2]);
    }

    #[test]
    fn a_lane_merges_when_it_reaches_the_live_cursor() {
        let mut p = plan(1000);
        p.place(&[(1, 100), (2, 100)], 1, Join::Follow);
        assert!(!p.reached(1, 900));
        assert!(p.merge_ready().is_empty(), "not there yet");
        assert!(p.reached(1, 1000));
        assert_eq!(p.merge_ready(), vec![1, 2]);
        assert!(p.lanes.is_empty());
        assert_eq!(p.owner(1), None, "the live lane's now");
    }

    #[test]
    fn a_lane_that_was_ready_chases_a_live_lane_that_moved_on() {
        let mut p = plan(1000);
        p.place(&[(1, 100)], 1, Join::Follow);
        assert!(p.reached(1, 1000));
        // The live lane's step was under way: it ends at 1003 before merging.
        p.advance(1003);
        assert!(!p.lane(1).unwrap().ready);
        assert!(p.merge_ready().is_empty(), "three blocks short");
        assert!(p.reached(1, 1003));
        assert_eq!(p.merge_ready(), vec![1]);
    }

    #[test]
    fn a_reorg_below_a_ready_lane_keeps_it_ready() {
        let mut p = plan(1000);
        p.place(&[(1, 100)], 1, Join::Follow);
        assert!(p.reached(1, 1000));
        p.advance(990);
        assert!(
            p.lane(1).unwrap().ready,
            "its accounts were rewound too; the next step says"
        );
        assert!(p.reached(1, 990));
        assert_eq!(p.merge_ready(), vec![1]);
    }

    #[test]
    fn hidden_accounts_leave_their_lanes() {
        let mut p = plan(1000);
        p.place(&[(1, 100), (2, 200)], 2, Join::Follow);
        p.keep_only(&BTreeSet::from([2]));
        assert_eq!(p.lanes.len(), 1);
        assert_eq!(p.owner(2), Some(2));
    }
}
