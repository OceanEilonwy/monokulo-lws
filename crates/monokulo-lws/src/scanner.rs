//! The scan loop: blocks from the daemon, outputs and candidate spends
//! written per block; reorgs noticed by hash and unwound; the mempool looked
//! at once caught up.
//!
//! A keyring of every account (`monokulo-8ar`) has the GPU work out 8aR for
//! every transaction key with every account's view key in one pass, and says
//! which transactions may pay which account. Only those go to monero-oxide's
//! `Scanner`, for that account alone, in a stand-in block holding just that
//! transaction. Without a usable GPU, or for a batch too small to be worth
//! one, every block is scanned once per account with the `Scanner`, as
//! monero-lws does.
//!
//! Accounts are scanned in lanes (`lanes.rs`, docs/scanning.md): the live
//! lane follows the tip with every caught-up account, and catch-up lanes
//! bring accounts with history up to it, each with its own keyring and GPU
//! arena, merging into the live lane when they reach it. With no catch-up
//! lanes, one loop starts each step at the lowest height any account stands
//! at, as the first version did.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use curve25519_dalek::scalar::Scalar as DScalar;
use lws_api::SubaddrRanges;
use monero_wallet::{
    Scanner as OxideScanner, WalletOutput,
    address::{Network, SubaddressIndex},
    block::Block,
    extra::{Extra, PaymentId},
    interface::ScannableBlock,
    primitives::keccak256,
    transaction::{Input, Pruned, Timelock, Transaction, TransactionPrefix},
};
use monokulo_8ar::{AccountId, Arena, Hit, Keyring};
use tokio::sync::{Notify, Semaphore};

use crate::crypto;
use crate::daemon::{Daemon, Fetched};
use crate::db::{Account, Db, NewOutput, NewTx, OutputRow, ScanWriter, Status};
use crate::error::{Error, Result};
use crate::lanes::{Join, Plan};

/// Blocks the live lane asks for in one request.
const BATCH: u64 = 100;
/// Block hashes kept behind the tip, to find where a reorg forked.
const KEEP_HASHES: u64 = 200;
/// Outputs are unspendable for this many blocks; new ones can't be ring
/// members either.
pub const SPENDABLE_AGE: u64 = 10;
/// A mined reward waits longer.
pub const COINBASE_AGE: u64 = 60;
/// The fewest derivations (keys × accounts) worth a GPU batch: below about
/// this a batch's fixed cost (3.7 ms on an RX 6800 XT, 46 mJ on a phone's GPU)
/// is more than the `Scanner` takes. Fob's threshold for one account.
const MIN_ITEMS: usize = 512;

/// What the REST side reads about the scanner.
#[derive(Clone, Debug, Default)]
pub struct ScanStatus {
    /// The daemon's chain height, as last heard.
    pub chain_height: u64,
    /// The next block the live lane (or the single loop) will take.
    pub scanner_height: u64,
    pub last_error: Option<String>,
    pub last_step: Option<Instant>,
    /// The catch-up lanes running.
    pub lanes: Vec<LaneStatus>,
}

/// A catch-up lane, for `/daemon_status`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct LaneStatus {
    pub id: u64,
    pub cursor: u64,
    pub accounts: usize,
}

/// An output received by a transaction still in the pool.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct PoolReceipt {
    pub tx_hash: [u8; 32],
    pub tx_prefix_hash: [u8; 32],
    pub tx_pub_key: [u8; 32],
    pub out_index: u16,
    pub amount: u64,
    pub public_key: [u8; 32],
    pub mask: Option<[u8; 32]>,
    pub unlock_time: u64,
    pub mixin: u32,
    pub fee: u64,
    pub payment_id: Option<Vec<u8>>,
    pub maj: u32,
    pub min: u32,
    pub seen: u64,
}

#[derive(Default)]
pub struct Mempool {
    /// Pool transactions already looked at, so each is scanned once.
    seen: HashSet<[u8; 32]>,
    /// What each account received, by account id.
    received: HashMap<i64, Vec<PoolReceipt>>,
}

impl Mempool {
    pub fn for_account(&self, account: i64) -> Vec<PoolReceipt> {
        self.received.get(&account).cloned().unwrap_or_default()
    }

    fn retain(&mut self, still_in_pool: &HashSet<[u8; 32]>) {
        self.seen.retain(|h| still_in_pool.contains(h));
        for list in self.received.values_mut() {
            list.retain(|r| still_in_pool.contains(&r.tx_hash));
        }
        self.received.retain(|_, l| !l.is_empty());
    }
}

/// How accounts with history are caught up (docs/scanning.md, "Lanes").
#[derive(Clone, Debug)]
pub struct LaneConfig {
    /// Catch-up lanes that may run at once; 0 is the single loop.
    pub lanes: usize,
    pub join: Join,
    /// Blocks a catch-up lane asks for at a time.
    pub blocks: u64,
    /// Catch-up requests in flight at once.
    pub in_flight: usize,
    /// GPU arenas: the live lane's, then the catch-up lanes', shared round-robin.
    pub arenas: usize,
}

/// Settings the loop takes.
#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub network: Network,
    /// Minors `0..lookahead` of major 0 are watched for every account.
    pub lookahead: u32,
    pub interval: Duration,
    pub lanes: LaneConfig,
}

/// A lane's keyring of its accounts, and their `Scanner`s, made as hits need
/// them: kept until an account or a subaddress range changes.
pub struct Ring {
    key: Vec<(i64, Vec<SubaddrRanges>)>,
    keyring: Keyring,
    /// Each keyring account's account id, and its id in the keyring.
    ids: Vec<i64>,
    #[cfg_attr(not(test), allow(dead_code))]
    in_keyring: Vec<AccountId>,
    scanners: HashMap<i64, OxideScanner>,
}

/// The subaddresses watched for an account besides its primary address: the
/// lookahead minors of major 0, and every registered range.
fn watched(lookahead: u32, ranges: &[SubaddrRanges]) -> Vec<SubaddressIndex> {
    let mut seen = HashSet::new();
    let mut out = vec![];
    let lookahead = (1..lookahead).map(|minor| (0, minor));
    let registered = ranges.iter().flat_map(|r| r.value.iter().flat_map(move |[lo, hi]| (*lo..=*hi).map(move |minor| (r.key, minor))));
    for (major, minor) in lookahead.chain(registered) {
        if (major, minor) == (0, 0) || !seen.insert((major, minor)) {
            continue;
        }
        if let Some(index) = SubaddressIndex::new(major, minor) {
            out.push(index);
        }
    }
    out
}

impl Ring {
    /// A keyring of `accounts` (sorted by id), each with its subaddress ranges.
    fn build(accounts: &[(&Account, Vec<SubaddrRanges>)], lookahead: u32, arena: &Arena) -> Result<Ring> {
        let mut keyring = Keyring::with_arena(arena.clone());
        let mut ids = Vec::with_capacity(accounts.len());
        let mut in_keyring = Vec::with_capacity(accounts.len());
        for (account, ranges) in accounts {
            let pair = crypto::view_pair(&account.spend_pub, &account.view_key)?;
            let id = keyring.add(&pair, &zeroize::Zeroizing::new(account.view_key));
            for index in watched(lookahead, ranges) {
                keyring.watch(id, &pair, index);
            }
            ids.push(account.id);
            in_keyring.push(id);
        }
        Ok(Ring { key: accounts.iter().map(|(a, r)| (a.id, r.clone())).collect(), keyring, ids, in_keyring, scanners: HashMap::new() })
    }

    /// The ring in `slot` if it's for `accounts`, else a new one there.
    fn get<'a>(slot: &'a mut Option<Ring>, w: &ScanWriter, accounts: &[Account], lookahead: u32, arena: &Arena) -> Result<&'a mut Ring> {
        let mut sorted: Vec<&Account> = accounts.iter().collect();
        sorted.sort_by_key(|a| a.id);
        let with_ranges = sorted.into_iter().map(|a| Ok((a, w.subaddrs(a.id)?))).collect::<Result<Vec<_>>>()?;
        let same = slot.as_ref().is_some_and(|r| r.key.len() == with_ranges.len() && r.key.iter().zip(&with_ranges).all(|(k, (a, ranges))| k.0 == a.id && &k.1 == ranges));
        if !same {
            *slot = Some(Ring::build(&with_ranges, lookahead, arena)?);
        }
        Ok(slot.as_mut().expect("just made"))
    }

    fn account(&self, hit: &Hit) -> i64 {
        self.ids[hit.account.index()]
    }

    /// `account`'s `Scanner`, made the first time it's needed.
    fn scanner(&mut self, account: &Account, lookahead: u32) -> Result<&mut OxideScanner> {
        if !self.scanners.contains_key(&account.id) {
            let ranges = self.key.iter().find(|(id, _)| *id == account.id).map(|(_, r)| r.clone()).unwrap_or_default();
            let mut scanner = OxideScanner::new(crypto::view_pair(&account.spend_pub, &account.view_key)?);
            for index in watched(lookahead, &ranges) {
                scanner.register_subaddress(index);
            }
            self.scanners.insert(account.id, scanner);
        }
        Ok(self.scanners.get_mut(&account.id).expect("just made"))
    }
}

/// What a step scans: the blocks, and each transaction's first RingCT output
/// index (miner first) for stand-in blocks.
pub struct Batch {
    pub blocks: Vec<ScannableBlock>,
    pub first_indexes: Vec<Vec<Option<u64>>>,
}

impl Batch {
    pub fn new(fetched: Vec<Fetched>) -> Batch {
        let (blocks, first_indexes) = fetched.into_iter().map(|f| (f.block, f.first_indexes)).unzip();
        Batch { blocks, first_indexes }
    }
}

/// A block holding only transaction `tx` of `block` (0 its miner transaction,
/// 1 on its others), whose outputs the `Scanner` then numbers as the chain
/// does: the stand-in starts at that transaction's own first RingCT index. A
/// transaction other than the miner's gets a miner transaction with no
/// outputs, which adds nothing to the count.
pub fn stand_in(block: &ScannableBlock, first_indexes: &[Option<u64>], tx: usize) -> Option<ScannableBlock> {
    let header = block.block.header.clone();
    if tx == 0 {
        let only = Block::new(header, block.block.miner_transaction().clone(), vec![])?;
        return Some(ScannableBlock { block: only, transactions: vec![], output_index_for_first_ringct_output: *first_indexes.first()? });
    }
    let hash = *block.block.transactions.get(tx - 1)?;
    let prefix = TransactionPrefix { additional_timelock: Timelock::None, inputs: vec![Input::Gen(block.block.number())], outputs: vec![], extra: vec![] };
    let only = Block::new(header, Transaction::V2 { prefix, proofs: None }, vec![hash])?;
    Some(ScannableBlock { block: only, transactions: vec![block.transactions.get(tx - 1)?.clone()], output_index_for_first_ringct_output: *first_indexes.get(tx)? })
}

/// Every lane account's RingCT outputs by global index, for candidate spends:
/// one lookup per ring member, whoever's it is.
#[derive(Default)]
pub struct SpendMap(HashMap<u64, Vec<(i64, OutputRow)>>);

impl SpendMap {
    fn of(w: &ScanWriter, accounts: &[Account]) -> Result<SpendMap> {
        let mut map = SpendMap::default();
        for account in accounts {
            for (_, row) in w.owned_indexes(account.id)? {
                map.add(account.id, row);
            }
        }
        Ok(map)
    }

    fn add(&mut self, account: i64, row: OutputRow) {
        self.0.entry(row.global_index).or_default().push((account, row));
    }

    fn get(&self, global_index: u64) -> &[(i64, OutputRow)] {
        self.0.get(&global_index).map_or(&[], Vec::as_slice)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What a catch-up lane task holds besides the scanner.
struct LaneTask {
    id: u64,
    ring: Option<Ring>,
    arena: Arena,
}

pub struct Scanner {
    pub db: Arc<Db>,
    pub daemon: Daemon,
    pub config: ScanConfig,
    pub status: RwLock<ScanStatus>,
    pub mempool: Mutex<Mempool>,
    /// Woken by the REST side when an account is added or asked to rescan,
    /// and by a catch-up lane ready to merge.
    pub wake: Notify,
    last_block: Mutex<Option<Block>>,
    plan: Mutex<Plan>,
    /// Woken when the live lane moves, for lanes waiting to merge.
    moved: Notify,
    arenas: Vec<Arena>,
    catch_up: Semaphore,
    live_ring: Mutex<Option<Ring>>,
}

impl Scanner {
    pub fn new(db: Arc<Db>, daemon: Daemon, config: ScanConfig) -> Arc<Scanner> {
        let arenas = (0..config.lanes.arenas.max(1)).map(|_| Arena::new()).collect();
        Arc::new(Scanner {
            db,
            daemon,
            catch_up: Semaphore::new(config.lanes.in_flight.max(1)),
            config,
            status: RwLock::new(ScanStatus::default()),
            mempool: Mutex::new(Mempool::default()),
            wake: Notify::new(),
            last_block: Mutex::new(None),
            plan: Mutex::new(Plan::default()),
            moved: Notify::new(),
            arenas,
            live_ring: Mutex::new(None),
        })
    }

    pub fn status(&self) -> ScanStatus {
        self.status.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_status(&self, f: impl FnOnce(&mut ScanStatus)) {
        let mut s = self.status.write().unwrap_or_else(|e| e.into_inner());
        f(&mut s);
    }

    fn plan(&self) -> std::sync::MutexGuard<'_, Plan> {
        self.plan.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn show_lanes(&self) {
        let lanes = self.plan().lanes.iter().map(|l| LaneStatus { id: l.id, cursor: l.cursor, accounts: l.accounts.len() }).collect();
        self.set_status(|s| s.lanes = lanes);
    }

    /// A lane's arena: the live lane has the first, catch-up lanes share the rest.
    fn arena(&self, lane: u64) -> Arena {
        match self.arenas.len() {
            1 => self.arenas[0].clone(),
            n => self.arenas[1 + (lane as usize % (n - 1))].clone(),
        }
    }

    /// Runs until the task is dropped.
    pub async fn run(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(2);
        loop {
            match self.step().await {
                Ok(true) => {
                    backoff = Duration::from_secs(2);
                    continue;
                }
                Ok(false) => {
                    backoff = Duration::from_secs(2);
                    tokio::select! {
                        _ = tokio::time::sleep(self.config.interval) => {}
                        _ = self.wake.notified() => {}
                    }
                }
                Err(e) => {
                    tracing::warn!("scan: {e}");
                    self.set_status(|s| s.last_error = Some(e.to_string()));
                    tokio::select! {
                        _ = tokio::time::sleep(backoff) => {}
                        _ = self.wake.notified() => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    }

    /// One round of the live lane (or the single loop): a batch of blocks for
    /// its accounts, or a look at the pool when caught up. `Ok(true)` means
    /// there is more to do now.
    pub async fn step(self: &Arc<Self>) -> Result<bool> {
        let info = self.daemon.info().await?;
        let chain_height = info.height;
        self.set_status(|s| {
            s.chain_height = chain_height;
            s.last_error = None;
            s.last_step = Some(Instant::now());
        });
        let active = self.db.accounts(Some(Status::Active))?;
        let (accounts, start) = if self.config.lanes.lanes == 0 {
            let start = active.iter().map(|a| a.scan_height).min().unwrap_or(chain_height).max(1);
            (active, start)
        } else {
            self.live_accounts(active, chain_height)
        };
        self.set_status(|s| s.scanner_height = start);
        if accounts.is_empty() {
            return Ok(false);
        }
        if start >= chain_height {
            self.scan_pool(&accounts).await?;
            return Ok(false);
        }

        let count = BATCH.min(chain_height - start);
        let fetched = self.daemon.blocks(start, count).await?;
        if fetched.is_empty() {
            return Err(Error::Daemon("the node sent no blocks".into()));
        }
        if fetched[0].block.block.number() as u64 != start {
            return Err(Error::Daemon("the node sent blocks from the wrong height".into()));
        }

        // A reorg shows as the first block not following the one we kept.
        if let Some(kept) = self.db.block_hash(start - 1)? {
            if kept != fetched[0].block.block.header.previous {
                let fork = self.find_fork().await?;
                tracing::info!("reorg: rewinding to {fork}");
                self.db.rewind(fork)?;
                self.mempool.lock().unwrap_or_else(|e| e.into_inner()).seen.clear();
                if self.plan().live.is_some() {
                    self.plan().advance(fork);
                    self.moved.notify_waiters();
                }
                return Ok(true);
            }
        }

        let batch = Batch::new(fetched);
        let fetched = batch.blocks.len() as u64;
        let last = batch.blocks.last().map(|b| b.block.clone());
        let mut ring = self.live_ring.lock().unwrap_or_else(|e| e.into_inner()).take();
        let result = tokio::task::block_in_place(|| self.scan_batch(&mut ring, &self.arenas[0], &accounts, &batch, start, true));
        *self.live_ring.lock().unwrap_or_else(|e| e.into_inner()) = ring;
        result?;
        *self.last_block.lock().unwrap_or_else(|e| e.into_inner()) = last;
        let next = start + fetched;
        if self.config.lanes.lanes > 0 {
            self.plan().advance(next);
            self.moved.notify_waiters();
        }
        self.set_status(|s| s.scanner_height = next);
        // A line every thousand blocks, and one on catching up.
        if next % 1000 < fetched || next >= chain_height {
            tracing::info!("scanned to {next} of {chain_height} for {} accounts", accounts.len());
        }
        Ok(next < chain_height)
    }

    /// The live lane's accounts and where it starts: merges lanes that have
    /// caught up, and finds lanes for accounts behind (starting their tasks).
    fn live_accounts(self: &Arc<Self>, active: Vec<Account>, chain_height: u64) -> (Vec<Account>, u64) {
        let opened = {
            let mut plan = self.plan();
            let live = *plan.live.get_or_insert_with(|| active.iter().map(|a| a.scan_height).max().unwrap_or(chain_height).clamp(1, chain_height.max(1)));
            let merged = plan.merge_ready();
            if !merged.is_empty() {
                tracing::info!("{} accounts caught up: into the live lane at {live}", merged.len());
            }
            plan.keep_only(&active.iter().map(|a| a.id).collect::<BTreeSet<_>>());
            let behind: Vec<(i64, u64)> = active.iter().filter(|a| a.scan_height < live && plan.owner(a.id).is_none()).map(|a| (a.id, a.scan_height)).collect();
            let opened = plan.place(&behind, self.config.lanes.lanes, self.config.lanes.join);
            let mine: Vec<Account> = active.into_iter().filter(|a| a.scan_height >= live && plan.owner(a.id).is_none()).collect();
            // With no account of its own, the live lane only keeps up with the
            // tip, for the lanes to merge at.
            if mine.is_empty() && live < chain_height {
                plan.advance(chain_height);
                self.moved.notify_waiters();
            }
            let start = plan.live.unwrap_or(live);
            (opened, mine, start)
        };
        let (opened, mine, start) = opened;
        for id in opened {
            tracing::info!("catch-up lane {id} from {}", self.plan().lane(id).map_or(0, |l| l.cursor));
            let scanner = self.clone();
            let task = LaneTask { id, ring: None, arena: self.arena(id) };
            tokio::spawn(scanner.run_lane(task));
        }
        self.show_lanes();
        (mine, start)
    }

    /// A catch-up lane: fetches from its cursor up to the live lane's, then
    /// waits for the live lane to take its accounts in.
    async fn run_lane(self: Arc<Self>, mut task: LaneTask) {
        let mut backoff = Duration::from_secs(2);
        loop {
            match self.lane_step(&mut task).await {
                Ok(LaneStep::More) => backoff = Duration::from_secs(2),
                Ok(LaneStep::Wait) => {
                    tokio::select! {
                        _ = tokio::time::sleep(self.config.interval) => {}
                        _ = self.moved.notified() => {}
                    }
                }
                Ok(LaneStep::Done) => {
                    self.show_lanes();
                    return;
                }
                Err(e) => {
                    tracing::warn!("catch-up lane {}: {e}", task.id);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    }

    async fn lane_step(&self, task: &mut LaneTask) -> Result<LaneStep> {
        let Some(lane) = self.plan().lane(task.id).cloned() else { return Ok(LaneStep::Done) };
        let accounts: Vec<Account> = self.db.accounts(Some(Status::Active))?.into_iter().filter(|a| lane.accounts.contains(&a.id)).collect();
        if accounts.is_empty() {
            self.plan().end(task.id);
            return Ok(LaneStep::Done);
        }
        let cursor = accounts.iter().map(|a| a.scan_height).min().unwrap_or(0).max(1);
        let (ready, live) = {
            let mut plan = self.plan();
            (plan.reached(task.id, cursor), plan.live.unwrap_or(cursor))
        };
        self.show_lanes();
        if ready {
            self.wake.notify_one();
            return Ok(LaneStep::Wait);
        }
        let count = self.config.lanes.blocks.max(1).min(live - cursor);
        let fetched = {
            let _permit = self.catch_up.acquire().await.map_err(|e| Error::Internal(e.to_string()))?;
            self.daemon.blocks(cursor, count).await?
        };
        if fetched.first().map(|f| f.block.block.number() as u64) != Some(cursor) {
            return Err(Error::Daemon("the node sent blocks from the wrong height".into()));
        }
        let batch = Batch::new(fetched);
        tokio::task::block_in_place(|| self.scan_batch(&mut task.ring, &task.arena, &accounts, &batch, cursor, false))?;
        Ok(LaneStep::More)
    }

    /// Scans `batch` (from height `start`) for `accounts`, each only in the
    /// blocks at or above its scan height, writing outputs, spends and scan
    /// heights, and the block hashes for the live lane.
    fn scan_batch(&self, slot: &mut Option<Ring>, arena: &Arena, accounts: &[Account], batch: &Batch, start: u64, live: bool) -> Result<()> {
        let ring = self.db.write(|tx| Ring::get(slot, &ScanWriter::new(tx), accounts, self.config.lookahead, arena).map(|_| ()));
        ring?;
        let ring = slot.as_mut().expect("just made");
        let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
        let hits = ring.keyring.flag_many(&batch.blocks, threads, MIN_ITEMS.div_ceil(accounts.len().max(1)));
        self.db.write(|tx| record_batch(&ScanWriter::new(tx), ring, self.config.lookahead, accounts, batch, start, hits.as_deref(), live))
    }

    /// The highest kept block the daemon still has; its successor is where
    /// to scan again from.
    async fn find_fork(&self) -> Result<u64> {
        for (height, hash) in self.db.recent_blocks()? {
            if self.daemon.block_hash(height).await? == hash {
                return Ok(height + 1);
            }
        }
        // Nothing kept matches: start over from the lowest kept height.
        let lowest = self.db.recent_blocks()?.last().map(|(h, _)| *h).unwrap_or(0);
        Ok(lowest)
    }

    /// Scans pool transactions not yet seen, in a stand-in block made of
    /// the last block scanned, and forgets ones that left the pool. The live
    /// keyring says which accounts may be paid; only those are scanned.
    async fn scan_pool(&self, accounts: &[Account]) -> Result<()> {
        let hashes = self.daemon.pool_hashes().await?;
        let in_pool: HashSet<[u8; 32]> = hashes.iter().copied().collect();
        let new: Vec<[u8; 32]> = {
            let mut pool = self.mempool.lock().unwrap_or_else(|e| e.into_inner());
            pool.retain(&in_pool);
            hashes.into_iter().filter(|h| !pool.seen.contains(h)).collect()
        };
        if new.is_empty() {
            return Ok(());
        }
        let Some(stand_in) = self.last_block.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
            return Ok(());
        };
        let txs = self.daemon.transactions(&new).await?;
        let hashes: Vec<[u8; 32]> = txs.iter().map(|(h, _)| *h).collect();
        let transactions: Vec<Transaction<Pruned>> = txs.into_iter().map(|(_, t)| t).collect();
        let Some(block) = Block::new(stand_in.header.clone(), stand_in.miner_transaction().clone(), hashes.clone()) else {
            return Ok(());
        };
        let block = ScannableBlock { block, transactions, output_index_for_first_ringct_output: Some(0) };
        let now = crate::db::now();
        let mut found: HashMap<i64, Vec<PoolReceipt>> = HashMap::new();
        let mut slot = self.live_ring.lock().unwrap_or_else(|e| e.into_inner()).take();
        let result = tokio::task::block_in_place(|| {
            self.db.write(|tx| Ring::get(&mut slot, &ScanWriter::new(tx), accounts, self.config.lookahead, &self.arenas[0]).map(|_| ()))?;
            let ring = slot.as_mut().expect("just made");
            let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
            // The accounts that may be paid, or every account unfiltered.
            let paid: Vec<&Account> = match ring.keyring.flag_many(std::slice::from_ref(&block), threads, MIN_ITEMS.div_ceil(accounts.len().max(1))) {
                Some(hits) => {
                    let ids: BTreeSet<i64> = hits.iter().map(|h| ring.account(h)).collect();
                    accounts.iter().filter(|a| ids.contains(&a.id)).collect()
                }
                None => accounts.iter().collect(),
            };
            for account in paid {
                let scanner = ring.scanner(account, self.config.lookahead)?;
                let outputs = scanner.scan(block.clone()).map_err(|e| Error::Internal(format!("scan: {e}")))?.ignore_additional_timelock();
                for output in outputs {
                    let tx_hash = output.transaction();
                    let Some(i) = hashes.iter().position(|h| *h == tx_hash) else { continue };
                    let tx = &block.transactions[i];
                    let meta = TxMeta::of(tx, &output, &account.view_key);
                    found.entry(account.id).or_default().push(PoolReceipt {
                        tx_hash,
                        tx_prefix_hash: meta.prefix_hash,
                        tx_pub_key: meta.derived_key,
                        out_index: output.index_in_transaction() as u16,
                        amount: output.commitment().amount,
                        public_key: output.key().compress().to_bytes(),
                        mask: Some(output.commitment().mask.into()).map(|m: DScalar| *m.as_bytes()),
                        unlock_time: meta.unlock_time,
                        mixin: meta.mixin,
                        fee: meta.fee,
                        payment_id: meta.payment_id.clone(),
                        maj: output.subaddress().map(|s| s.account()).unwrap_or(0),
                        min: output.subaddress().map(|s| s.address()).unwrap_or(0),
                        seen: now,
                    });
                }
            }
            Ok::<_, Error>(())
        });
        *self.live_ring.lock().unwrap_or_else(|e| e.into_inner()) = slot;
        result?;
        let mut pool = self.mempool.lock().unwrap_or_else(|e| e.into_inner());
        for h in new {
            pool.seen.insert(h);
        }
        for (account, receipts) in found {
            pool.received.entry(account).or_default().extend(receipts);
        }
        Ok(())
    }
}

/// What a catch-up lane's step came to.
enum LaneStep {
    More,
    /// At the live lane's cursor, waiting to merge.
    Wait,
    /// Merged, or emptied.
    Done,
}

/// Writes what `batch` holds for `accounts`: with `hits`, each hit's
/// transaction scanned for its account alone in a stand-in block (or the
/// whole block, for a block the prefilter can't vouch for); without, every
/// block for every account. Then candidate spends, scan heights and, for the
/// live lane, block hashes.
#[allow(clippy::too_many_arguments)]
pub fn record_batch(w: &ScanWriter, ring: &mut Ring, lookahead: u32, accounts: &[Account], batch: &Batch, start: u64, hits: Option<&[Hit]>, live: bool) -> Result<()> {
    let by_id: HashMap<i64, &Account> = accounts.iter().map(|a| (a.id, a)).collect();
    let mut spends = SpendMap::of(w, accounts)?;
    let mut by_block: Vec<Vec<Hit>> = vec![vec![]; batch.blocks.len()];
    for hit in hits.unwrap_or_default() {
        if let Some(list) = by_block.get_mut(hit.block) {
            list.push(*hit);
        }
    }
    for (i, block) in batch.blocks.iter().enumerate() {
        let height = start + i as u64;
        if hits.is_some() {
            let mut list = std::mem::take(&mut by_block[i]);
            // Transactions in block order, as the first output with a key counts.
            list.sort_by_key(|h| (h.tx, h.account));
            for hit in list {
                let Some(account) = by_id.get(&ring.account(&hit)).copied() else { continue };
                if account.scan_height > height {
                    continue;
                }
                let target = if hit.tx == Hit::WHOLE_BLOCK { Some(block.clone()) } else { stand_in(block, &batch.first_indexes[i], hit.tx) };
                let Some(target) = target else { continue };
                scan_for(w, ring, lookahead, account, target, block, height, &mut spends)?;
            }
        } else {
            for account in accounts {
                if account.scan_height <= height {
                    scan_for(w, ring, lookahead, account, block.clone(), block, height, &mut spends)?;
                }
            }
        }
        record_spends(w, &by_id, block, height, &spends)?;
        if live {
            w.set_block(height, &block.block.hash(), KEEP_HASHES)?;
        }
    }
    let next = start + batch.blocks.len() as u64;
    for account in accounts {
        if account.scan_height < next {
            w.set_scan_height(account.id, next)?;
        }
    }
    Ok(())
}

/// `target` (`block`, or a stand-in for part of it) scanned for `account`,
/// and what it receives written.
#[allow(clippy::too_many_arguments)]
fn scan_for(w: &ScanWriter, ring: &mut Ring, lookahead: u32, account: &Account, target: ScannableBlock, block: &ScannableBlock, height: u64, spends: &mut SpendMap) -> Result<()> {
    let outputs = ring.scanner(account, lookahead)?.scan(target).map_err(|e| Error::Internal(format!("scan: {e}")))?.ignore_additional_timelock();
    record_received(w, account, outputs, block, height, spends)
}

/// What a transaction row needs, worked out once per transaction.
struct TxMeta {
    prefix_hash: [u8; 32],
    unlock_time: u64,
    coinbase: bool,
    mixin: u32,
    fee: u64,
    payment_id: Option<Vec<u8>>,
    main_key: [u8; 32],
    /// The key the output in hand was derived from.
    derived_key: [u8; 32],
}

impl TxMeta {
    fn of(tx: &Transaction<Pruned>, output: &WalletOutput, view_key: &[u8; 32]) -> TxMeta {
        let prefix = tx.prefix();
        let (main_key, additional) = extra_keys(&prefix.extra);
        let index = output.index_in_transaction();
        let sub = output.subaddress().map(|s| (s.account(), s.address())).unwrap_or((0, 0));
        let key_offset: DScalar = output.key_offset().into();
        let extra_key = additional.get(index as usize);
        let derived_key = crypto::derived_by(view_key, index, &key_offset, sub, &main_key, extra_key);
        TxMeta {
            prefix_hash: prefix_hash(tx),
            unlock_time: unlock_time(prefix.additional_timelock),
            coinbase: is_coinbase(tx),
            mixin: mixin(tx),
            fee: fee(tx),
            payment_id: output.payment_id().map(|id| match id {
                PaymentId::Encrypted(short) => short.to_vec(),
                PaymentId::Unencrypted(long) => long.to_vec(),
            }),
            main_key,
            derived_key,
        }
    }

    fn new_tx<'a>(&'a self, hash: [u8; 32], height: u64, timestamp: u64) -> NewTx<'a> {
        NewTx {
            hash,
            prefix_hash: self.prefix_hash,
            height,
            timestamp,
            unlock_time: self.unlock_time,
            coinbase: self.coinbase,
            mixin: self.mixin,
            fee: self.fee,
            payment_id: self.payment_id.as_deref(),
            tx_pub_key: self.main_key,
        }
    }
}


/// Writes the outputs `account` received in `block` at `height`, and adds the
/// RingCT ones to `spends`, so a spend later in the batch is seen.
fn record_received(w: &ScanWriter, account: &Account, outputs: Vec<WalletOutput>, block: &ScannableBlock, height: u64, spends: &mut SpendMap) -> Result<()> {
    let timestamp = block.block.header.timestamp;
    let miner_hash = block.block.miner_transaction().hash();
    let miner: Transaction<Pruned> = block.block.miner_transaction().clone().into();
    let tx_of = |hash: [u8; 32]| -> Option<&Transaction<Pruned>> {
        if hash == miner_hash {
            return Some(&miner);
        }
        block.block.transactions.iter().position(|h| *h == hash).map(|i| &block.transactions[i])
    };
    for output in outputs {
        let tx_hash = output.transaction();
        let Some(tx) = tx_of(tx_hash) else { continue };
        let meta = TxMeta::of(tx, &output, &account.view_key);
        let tx_id = w.tx_row(account.id, &meta.new_tx(tx_hash, height, timestamp))?;
        let mask: DScalar = output.commitment().mask.into();
        let rct = !matches!(tx, Transaction::V1 { .. });
        let new = NewOutput {
            out_index: output.index_in_transaction() as u16,
            global_index: output.index_on_blockchain(),
            amount: output.commitment().amount,
            public_key: output.key().compress().to_bytes(),
            tx_pub_key: meta.derived_key,
            mask: rct.then(|| *mask.as_bytes()),
            height,
            maj: output.subaddress().map(|s| s.account()).unwrap_or(0),
            min: output.subaddress().map(|s| s.address()).unwrap_or(0),
        };
        if let Some(id) = w.add_output(account.id, tx_id, &new)? {
            if rct {
                spends.add(
                    account.id,
                    OutputRow {
                        id,
                        tx: tx_id,
                        out_index: new.out_index,
                        global_index: new.global_index,
                        amount: new.amount,
                        public_key: new.public_key,
                        tx_pub_key: new.tx_pub_key,
                        mask: new.mask,
                        height,
                        maj: new.maj,
                        min: new.min,
                    },
                );
            }
        }
    }
    Ok(())
}

/// Possibly spent: an input whose ring holds an output of one of `accounts`
/// (each only from its scan height on), looked up once per ring member.
fn record_spends(w: &ScanWriter, accounts: &HashMap<i64, &Account>, block: &ScannableBlock, height: u64, spends: &SpendMap) -> Result<()> {
    if spends.is_empty() {
        return Ok(());
    }
    let timestamp = block.block.header.timestamp;
    for (i, tx) in block.transactions.iter().enumerate() {
        let hash = block.block.transactions[i];
        let ring_size = mixin(tx) + 1;
        for input in &tx.prefix().inputs {
            let Input::ToKey { amount, key_offsets, key_image } = input else { continue };
            if amount.unwrap_or(0) != 0 {
                continue; // Pre-RingCT amounts aren't tracked.
            }
            let mut absolute = 0u64;
            for offset in key_offsets {
                absolute = absolute.saturating_add(*offset);
                for (account, ours) in spends.get(absolute) {
                    if accounts.get(account).is_none_or(|a| a.scan_height > height) {
                        continue;
                    }
                    let meta = TxMeta::spend_only(tx);
                    let tx_id = w.tx_row(*account, &meta.new_tx(hash, height, timestamp))?;
                    w.add_spend(*account, tx_id, ours.id, ours.amount, &key_image.to_bytes(), ring_size - 1, height)?;
                }
            }
        }
    }
    Ok(())
}

impl TxMeta {
    /// For a transaction we only (maybe) spent in: no output of ours to
    /// derive from.
    fn spend_only(tx: &Transaction<Pruned>) -> TxMeta {
        let prefix = tx.prefix();
        let (main_key, _) = extra_keys(&prefix.extra);
        TxMeta {
            prefix_hash: prefix_hash(tx),
            unlock_time: unlock_time(prefix.additional_timelock),
            coinbase: is_coinbase(tx),
            mixin: mixin(tx),
            fee: fee(tx),
            payment_id: None,
            main_key,
            derived_key: main_key,
        }
    }
}

fn extra_keys(extra: &[u8]) -> ([u8; 32], Vec<[u8; 32]>) {
    let Ok(extra) = Extra::read(&mut &extra[..]) else { return ([0; 32], vec![]) };
    match extra.keys() {
        Some((keys, additional)) => (
            keys.first().map(|k| k.compress().to_bytes()).unwrap_or([0; 32]),
            additional.unwrap_or_default().into_iter().map(|k| k.compress().to_bytes()).collect(),
        ),
        None => ([0; 32], vec![]),
    }
}

fn unlock_time(timelock: Timelock) -> u64 {
    match timelock {
        Timelock::None => 0,
        Timelock::Block(b) => b as u64,
        Timelock::Time(t) => t,
    }
}

fn is_coinbase(tx: &Transaction<Pruned>) -> bool {
    matches!(tx.prefix().inputs.first(), Some(Input::Gen(_)))
}

fn mixin(tx: &Transaction<Pruned>) -> u32 {
    tx.prefix()
        .inputs
        .iter()
        .find_map(|i| match i {
            Input::ToKey { key_offsets, .. } => Some(key_offsets.len().saturating_sub(1) as u32),
            Input::Gen(_) => None,
        })
        .unwrap_or(0)
}

fn fee(tx: &Transaction<Pruned>) -> u64 {
    match tx {
        Transaction::V2 { proofs: Some(p), .. } => p.base.fee,
        _ => 0,
    }
}

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Keccak of the prefix as serialised: version, timelock, inputs,
/// outputs, extra. (monero-oxide keeps its own prefix hash private.)
pub fn prefix_hash(tx: &Transaction<Pruned>) -> [u8; 32] {
    let prefix = tx.prefix();
    let mut buf = Vec::with_capacity(512);
    varint(u64::from(tx.version()), &mut buf);
    prefix.additional_timelock.write(&mut buf).expect("vec");
    varint(prefix.inputs.len() as u64, &mut buf);
    for input in &prefix.inputs {
        input.write(&mut buf).expect("vec");
    }
    varint(prefix.outputs.len() as u64, &mut buf);
    for output in &prefix.outputs {
        output.write(&mut buf).expect("vec");
    }
    varint(prefix.extra.len() as u64, &mut buf);
    buf.extend(&prefix.extra);
    keccak256(buf)
}

/// Whether an output can be spent (or used as a decoy) at `chain_height`.
pub fn unlocked(height: u64, coinbase: bool, unlock_time: u64, chain_height: u64, now: u64) -> bool {
    let age = if coinbase { COINBASE_AGE } else { SPENDABLE_AGE };
    if height + age > chain_height {
        return false;
    }
    if unlock_time == 0 {
        return true;
    }
    const BLOCK_OR_TIME: u64 = 500_000_000;
    if unlock_time < BLOCK_OR_TIME { unlock_time <= chain_height } else { unlock_time <= now }
}

/// Feeds a fixture written by monokulo-8ar's `prototypes/scan-bench` (each
/// transaction key with its outputs' indexes, view tags and keys, from 2,000
/// mainnet blocks) through the scanner as a catch-up lane would, 100 blocks a
/// step, for each count of accounts: the fixture's own view key and random
/// others. The blocks are rebuilt from the fixture, one transaction per key
/// and no inputs, so this measures the prefilter and the writing, not
/// fetching. Prints blocks a second.
pub fn replay(fixture: &std::path::Path, counts: &[usize], lookahead: u32, step: usize) -> anyhow::Result<()> {
    use rand::RngCore;
    use std::io::Read;

    let mut f = std::io::BufReader::new(std::fs::File::open(fixture)?);
    let mut word = [0u8; 8];
    f.read_exact(&mut word)?;
    let block_count = u64::from_le_bytes(word) as usize;
    f.read_exact(&mut word)?;
    let key_count = u64::from_le_bytes(word) as usize;
    let mut keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let mut r = [0u8; 32];
        f.read_exact(&mut r)?;
        let mut n = [0u8; 4];
        f.read_exact(&mut n)?;
        let mut outs = vec![];
        for _ in 0..u32::from_le_bytes(n) {
            let mut out = [0u8; 37];
            f.read_exact(&mut out)?;
            outs.push((u32::from_le_bytes(out[..4].try_into().expect("4 bytes")), out[4], <[u8; 32]>::try_from(&out[5..]).expect("32 bytes")));
        }
        keys.push((r, outs));
    }

    // One transaction per key, the keys shared out over the blocks in order.
    let mut blocks = vec![];
    let mut first_indexes = vec![];
    let mut next_index = 1_000_000u64;
    let block_count = block_count.max(1);
    for number in 0..block_count {
        let part = &keys[number * key_count / block_count..(number + 1) * key_count / block_count];
        let number = 3_797_000 + number;
        let miner = Transaction::V2 { prefix: TransactionPrefix { additional_timelock: Timelock::None, inputs: vec![Input::Gen(number)], outputs: vec![], extra: vec![] }, proofs: None };
        let mut firsts = vec![None];
        let mut txs = vec![];
        let mut hashes = vec![];
        for (i, (r, outs)) in part.iter().enumerate() {
            let len = outs.iter().map(|(index, _, _)| *index as usize + 1).max().unwrap_or(0);
            // Outputs another key of the transaction pays are the identity here,
            // which is skipped, as the fixture says nothing of them.
            let mut outputs: Vec<monero_wallet::transaction::Output> =
                (0..len).map(|_| monero_wallet::transaction::Output { amount: None, key: monero_wallet::ed25519::CompressedPoint::IDENTITY, view_tag: None }).collect();
            for (index, tag, key) in outs {
                outputs[*index as usize] = monero_wallet::transaction::Output { amount: None, key: monero_wallet::ed25519::CompressedPoint::from(*key), view_tag: Some(*tag) };
            }
            let mut extra = vec![1];
            extra.extend_from_slice(r);
            firsts.push((len > 0).then_some(next_index));
            next_index += len as u64;
            txs.push(Transaction::<Pruned>::V2 { prefix: TransactionPrefix { additional_timelock: Timelock::None, inputs: vec![], outputs, extra }, proofs: None });
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&(number as u64).to_le_bytes());
            hash[8..16].copy_from_slice(&(i as u64).to_le_bytes());
            hashes.push(hash);
        }
        let header = monero_wallet::block::BlockHeader { hardfork_version: 16, hardfork_signal: 16, timestamp: 1_700_000_000, previous: [0; 32], nonce: 0 };
        let first = firsts.iter().flatten().next().copied();
        blocks.push(ScannableBlock { block: Block::new(header, miner, hashes).expect("a miner transaction"), transactions: txs, output_index_for_first_ringct_output: first });
        first_indexes.push(firsts);
    }
    println!("{} blocks, {key_count} keys, from {}", blocks.len(), fixture.display());

    monokulo_8ar::warm_up();
    monokulo_8ar::settle(Duration::from_secs(120));
    println!("engine: {:?}", monokulo_8ar::engine());
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let fixture_view = {
        use monero_wallet::primitives::keccak256;
        DScalar::from_bytes_mod_order(keccak256(b"scan-bench view key"))
    };
    for &count in counts {
        let dir = std::env::temp_dir().join(format!("monokulo-lws-replay-{}-{count}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let db = Db::open(&dir.join("replay.sqlite"))?;
        let mut rng = rand::rngs::OsRng;
        let mut accounts = vec![];
        for i in 0..count {
            let view = if i == 0 {
                fixture_view
            } else {
                let mut wide = [0u8; 64];
                rng.fill_bytes(&mut wide);
                DScalar::from_bytes_mod_order_wide(&wide)
            };
            let mut wide = [0u8; 64];
            rng.fill_bytes(&mut wide);
            let spend = &DScalar::from_bytes_mod_order_wide(&wide) * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
            let view_pub = (&view * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE).compress().to_bytes();
            accounts.push(db.add_account(
                &crate::db::NewAccount { address: format!("replay-{i}"), view_key: view.to_bytes(), spend_pub: spend.compress().to_bytes(), view_pub, start_height: 3_797_000, generated_locally: false },
                Status::Active,
            )?);
        }
        let arena = Arena::new();
        let mut slot = None;
        let built = Instant::now();
        db.write(|tx| Ring::get(&mut slot, &ScanWriter::new(tx), &accounts, lookahead, &arena).map(|_| ()))?;
        let built = built.elapsed().as_secs_f64();
        let ring = slot.as_mut().expect("just made");
        let started = Instant::now();
        let (mut filtered, mut unfiltered, mut hits) = (0, 0, 0);
        let mut flagging = 0.0;
        for (at, part) in blocks.chunks(step).enumerate() {
            let start = 3_797_000 + (at * step) as u64;
            let batch = Batch { blocks: part.to_vec(), first_indexes: first_indexes[at * step..at * step + part.len()].to_vec() };
            let t = Instant::now();
            let found = ring.keyring.flag_many(&batch.blocks, threads, MIN_ITEMS.div_ceil(count.max(1)));
            flagging += t.elapsed().as_secs_f64();
            match &found {
                Some(h) => {
                    filtered += 1;
                    hits += h.len();
                }
                None => unfiltered += 1,
            }
            // Accounts move on a step at a time, as in a lane.
            for account in &mut accounts {
                account.scan_height = start;
            }
            db.write(|tx| record_batch(&ScanWriter::new(tx), ring, lookahead, &accounts, &batch, start, found.as_deref(), false))?;
        }
        let seconds = started.elapsed().as_secs_f64();
        println!(
            "{count:>5} accounts: {:.0} blocks/s ({:.0} account-blocks/s), {seconds:.2} s ({flagging:.2} s flagging); keyring built in {built:.2} s; {filtered} steps on the GPU, {unfiltered} with monero-oxide, {hits} hits",
            blocks.len() as f64 / seconds,
            (blocks.len() * count) as f64 / seconds,
        );
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
    monokulo_8ar::settle(Duration::from_secs(60));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_rules() {
        assert!(unlocked(100, false, 0, 110, 0));
        assert!(!unlocked(100, false, 0, 109, 0));
        assert!(!unlocked(100, true, 0, 150, 0));
        assert!(unlocked(100, true, 0, 160, 0));
        assert!(!unlocked(100, false, 200, 150, 0));
        assert!(unlocked(100, false, 200, 200, 0));
        assert!(!unlocked(100, false, 1_700_000_000, 150, 1_699_999_999));
        assert!(unlocked(100, false, 1_700_000_000, 150, 1_700_000_000));
    }

    #[test]
    fn varints() {
        let mut v = vec![];
        varint(0, &mut v);
        varint(127, &mut v);
        varint(128, &mut v);
        varint(300, &mut v);
        assert_eq!(v, vec![0, 127, 0x80, 0x01, 0xac, 0x02]);
    }

    // Blocks made to pay a wallet, as monokulo-8ar's tests make them: each held to
    // what monero-oxide's `Scanner` finds in the whole block.

    use curve25519_dalek::{EdwardsPoint, constants::ED25519_BASEPOINT_TABLE};
    use monero_wallet::{
        block::BlockHeader,
        ed25519::CompressedPoint,
        transaction::Output,
    };

    use crate::db::NewAccount;

    struct Keys {
        view: DScalar,
        spend: EdwardsPoint,
    }

    fn keys() -> Keys {
        Keys { view: DScalar::from_bytes_mod_order([9; 32]), spend: &DScalar::from(7u64) * ED25519_BASEPOINT_TABLE }
    }

    /// Output `index` of the transaction with key `r`, paying `keys`.
    fn paying(keys: &Keys, r: &DScalar, index: u64) -> Output {
        let derivation = (keys.view * (r * ED25519_BASEPOINT_TABLE)).mul_by_cofactor().compress().to_bytes();
        let mut tagged = b"view_tag".to_vec();
        tagged.extend_from_slice(&derivation);
        varint(index, &mut tagged);
        let mut shared = derivation.to_vec();
        varint(index, &mut shared);
        let shared = DScalar::from_bytes_mod_order(keccak256(&shared));
        let key = &shared * ED25519_BASEPOINT_TABLE + keys.spend;
        Output { amount: Some(1_000), key: CompressedPoint::from(key.compress().to_bytes()), view_tag: Some(keccak256(&tagged)[0]) }
    }

    fn stranger(seed: u64) -> Output {
        let key = &DScalar::from(seed * 7919 + 13) * ED25519_BASEPOINT_TABLE;
        Output { amount: Some(1_000), key: CompressedPoint::from(key.compress().to_bytes()), view_tag: Some(seed as u8) }
    }

    fn prefix(outputs: Vec<Output>, r: &DScalar, inputs: Vec<Input>) -> TransactionPrefix {
        let mut extra = vec![1];
        extra.extend_from_slice(&(r * ED25519_BASEPOINT_TABLE).compress().to_bytes());
        TransactionPrefix { additional_timelock: Timelock::None, inputs, outputs, extra }
    }

    /// Block `number`: a miner transaction of two outputs, then one of three and
    /// one of two, the second output of the last paying `keys` (or the miner's
    /// first, with `miner_pays`; or nothing, with `spends`, the last spending
    /// from a ring of those offsets instead), and output indexes from 1000.
    fn block(keys: &Keys, number: usize, miner_pays: bool, spends: Option<Vec<u64>>) -> (ScannableBlock, Vec<Option<u64>>) {
        let r = |n: u64| DScalar::from(1000 + n + number as u64 * 10);
        let miner_outputs = if miner_pays { vec![paying(keys, &r(0), 0), stranger(1)] } else { vec![stranger(1), stranger(2)] };
        let miner = Transaction::V2 { prefix: prefix(miner_outputs, &r(0), vec![Input::Gen(number)]), proofs: None };
        let pays_here = !miner_pays && spends.is_none();
        let ring = spends.map(|offsets| vec![Input::ToKey { amount: None, key_offsets: offsets, key_image: CompressedPoint::from([5; 32]) }]).unwrap_or_default();
        let txs: Vec<Transaction<Pruned>> = vec![
            Transaction::V2 { prefix: prefix(vec![stranger(3), stranger(4), stranger(5)], &r(1), vec![]), proofs: None },
            Transaction::V2 { prefix: prefix(vec![stranger(6), if pays_here { paying(keys, &r(2), 1) } else { stranger(7) }], &r(2), ring), proofs: None },
        ];
        let header = BlockHeader { hardfork_version: 16, hardfork_signal: 16, timestamp: 1_700_000_000, previous: [0; 32], nonce: 0 };
        let block = Block::new(header, miner, vec![[1; 32], [2; 32]]).unwrap();
        (ScannableBlock { block, transactions: txs, output_index_for_first_ringct_output: Some(1000) }, vec![Some(1000), Some(1002), Some(1005)])
    }

    fn found(keys: &Keys, block: ScannableBlock) -> Vec<(u64, [u8; 32])> {
        let pair = crypto::view_pair(&keys.spend.compress().to_bytes(), &keys.view.to_bytes()).unwrap();
        let mut scanner = OxideScanner::new(pair);
        scanner.scan(block).unwrap().ignore_additional_timelock().iter().map(|o| (o.index_on_blockchain(), o.transaction())).collect()
    }

    #[test]
    fn a_stand_in_keeps_the_chains_output_indexes() {
        let keys = keys();
        let (whole, firsts) = block(&keys, 50, false, None);
        let expected = found(&keys, whole.clone());
        assert_eq!(expected, vec![(1006, [2; 32])], "the whole block: the 2nd output of the 3rd transaction");
        assert_eq!(found(&keys, stand_in(&whole, &firsts, 2).unwrap()), expected, "the stand-in, the same");
        assert!(found(&keys, stand_in(&whole, &firsts, 1).unwrap()).is_empty(), "another transaction, nothing");
        assert_eq!(stand_in(&whole, &firsts, 2).unwrap().block.number(), 50);

        let (whole, firsts) = block(&keys, 51, true, None);
        let expected = found(&keys, whole.clone());
        assert_eq!(expected.len(), 1);
        assert_eq!(expected[0].0, 1000, "the miner's first output");
        assert_eq!(found(&keys, stand_in(&whole, &firsts, 0).unwrap()), expected, "the miner's stand-in, the same");
        assert!(stand_in(&whole, &firsts, 3).is_none(), "no such transaction");
    }

    #[test]
    fn spends_are_looked_up_once_whoever_owns_the_output() {
        let mut map = SpendMap::default();
        let row = |global_index: u64| OutputRow { id: global_index as i64, tx: 1, out_index: 0, global_index, amount: 5, public_key: [0; 32], tx_pub_key: [0; 32], mask: Some([0; 32]), height: 1, maj: 0, min: 0 };
        map.add(1, row(10));
        map.add(2, row(11));
        map.add(3, row(10));
        assert_eq!(map.get(10).iter().map(|(a, _)| *a).collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(map.get(11).len(), 1);
        assert!(map.get(12).is_empty());
    }

    fn account(db: &Db, keys: &Keys, address: &str, start: u64) -> Account {
        let spend_pub = keys.spend.compress().to_bytes();
        let view_pub = (&keys.view * ED25519_BASEPOINT_TABLE).compress().to_bytes();
        db.add_account(&NewAccount { address: address.into(), view_key: keys.view.to_bytes(), spend_pub, view_pub, start_height: start, generated_locally: false }, Status::Active).unwrap()
    }

    /// Two blocks, the first paying `keys` and the second spending it in a ring,
    /// written with the hits given (or unfiltered), for an account at 100 and one
    /// with the same keys at 200, which must see neither.
    fn record(hits: Option<&dyn Fn(&Ring) -> Vec<Hit>>) -> (Db, Account, Account) {
        let keys = keys();
        let db = Db::in_memory();
        let (a, b) = (account(&db, &keys, "A", 100), account(&db, &keys, "B", 200));
        let (pays, firsts_pays) = block(&keys, 100, false, None);
        let (spends, firsts_spends) = block(&keys, 101, false, Some(vec![1000, 6]));
        let batch = Batch { blocks: vec![pays, spends], first_indexes: vec![firsts_pays, firsts_spends] };
        let accounts = vec![a.clone(), b.clone()];
        let mut slot = None;
        db.write(|tx| {
            let w = ScanWriter::new(tx);
            let ring = Ring::get(&mut slot, &w, &accounts, 1, &Arena::new())?;
            let hits = hits.map(|f| f(ring));
            record_batch(&w, ring, 1, &accounts, &batch, 100, hits.as_deref(), true)
        })
        .unwrap();
        (db, a, b)
    }

    fn check_recorded(db: &Db, a: &Account, b: &Account) {
        let outputs = db.outputs(a.id).unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].global_index, 1006);
        assert_eq!(outputs[0].height, 100);
        let spends = db.spends(a.id).unwrap();
        assert_eq!(spends.len(), 1, "the ring at 101 holds 1006");
        assert!(db.outputs(b.id).unwrap().is_empty() && db.spends(b.id).unwrap().is_empty(), "B starts at 200");
        assert_eq!(db.account("A").unwrap().unwrap().scan_height, 102);
        assert_eq!(db.account("B").unwrap().unwrap().scan_height, 200);
        assert!(db.block_hash(101).unwrap().is_some(), "the live lane keeps hashes");
    }

    #[test]
    fn hits_are_scanned_alone_and_spends_found_through_one_map() {
        // The prefilter's answer, faked: A's and B's hit in block 0's third
        // transaction, and a stray hit for A in a transaction that pays nobody.
        let hits = |ring: &Ring| vec![Hit { account: ring.in_keyring[0], block: 0, tx: 2 }, Hit { account: ring.in_keyring[1], block: 0, tx: 2 }, Hit { account: ring.in_keyring[0], block: 1, tx: 1 }];
        let (db, a, b) = record(Some(&hits));
        check_recorded(&db, &a, &b);
    }

    #[test]
    fn unfiltered_every_block_is_scanned_for_every_account() {
        let (db, a, b) = record(None);
        check_recorded(&db, &a, &b);
    }

    #[test]
    fn no_hits_no_outputs_but_scan_heights_move_on() {
        let (db, a, _) = record(Some(&|_: &Ring| vec![]));
        assert!(db.outputs(a.id).unwrap().is_empty());
        assert_eq!(db.account("A").unwrap().unwrap().scan_height, 102);
    }

    #[test]
    fn a_block_to_read_whole_is_read_whole() {
        let hits = |ring: &Ring| vec![Hit { account: ring.in_keyring[0], block: 0, tx: Hit::WHOLE_BLOCK }];
        let (db, a, _) = record(Some(&hits));
        assert_eq!(db.outputs(a.id).unwrap().len(), 1);
    }

    #[test]
    fn the_watched_subaddresses_are_the_lookahead_and_the_ranges() {
        let ranges = vec![SubaddrRanges { key: 0, value: vec![[0, 3]] }, SubaddrRanges { key: 2, value: vec![[5, 6]] }];
        let got: Vec<(u32, u32)> = watched(3, &ranges).iter().map(|i| (i.account(), i.address())).collect();
        assert_eq!(got, vec![(0, 1), (0, 2), (0, 3), (2, 5), (2, 6)]);
    }

    /// The keyring on the GPU finds the paying transaction, and the scan from
    /// its hits writes what the unfiltered scan writes.
    #[test]
    #[ignore = "needs a GPU; run with --ignored"]
    fn the_gpu_finds_the_paying_transaction() {
        monokulo_8ar::warm_up();
        assert!(monokulo_8ar::settle(Duration::from_secs(120)) && monokulo_8ar::gpu_ready(), "the GPU started");
        let keys = keys();
        let db = Db::in_memory();
        let (a, b) = (account(&db, &keys, "A", 100), account(&db, &keys, "B", 200));
        let (pays, _) = block(&keys, 100, false, None);
        let (spends, _) = block(&keys, 101, false, Some(vec![1000, 6]));
        let accounts = vec![a, b];
        let mut slot = None;
        db.write(|tx| Ring::get(&mut slot, &ScanWriter::new(tx), &accounts, 1, &Arena::new()).map(|_| ())).unwrap();
        let ring = slot.as_mut().unwrap();
        let hits = ring.keyring.flag_many(&[pays, spends], 4, 0).expect("the GPU filtered");
        assert_eq!(hits, vec![Hit { account: ring.in_keyring[0], block: 0, tx: 2 }, Hit { account: ring.in_keyring[1], block: 0, tx: 2 }]);
        let gpu = |ring: &Ring| ring.keyring.flag_many(&[block(&keys, 100, false, None).0, block(&keys, 101, false, Some(vec![1000, 6])).0], 4, 0).expect("the GPU filtered");
        let (db, a, b) = record(Some(&gpu));
        check_recorded(&db, &a, &b);
    }
}
