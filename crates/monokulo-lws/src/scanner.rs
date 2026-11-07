//! The scan loop: blocks from the daemon, each scanned once per active
//! account with monero-oxide's scanner, outputs and candidate spends written
//! per block; reorgs noticed by hash and unwound; the mempool looked at once
//! caught up.
//!
//! Every account is scanned with its own view key, so a block costs one
//! scan per account (as monero-lws does). Accounts behind the rest (new,
//! or rescanning) are caught up by the same loop: a step starts at the
//! lowest height any active account stands at, and scans a block only for
//! the accounts that haven't passed it.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use curve25519_dalek::scalar::Scalar as DScalar;
use monero_wallet::{
    Scanner as OxideScanner, WalletOutput,
    address::{Network, SubaddressIndex},
    block::Block,
    extra::{Extra, PaymentId},
    interface::ScannableBlock,
    primitives::keccak256,
    transaction::{Input, Pruned, Timelock, Transaction},
};
use tokio::sync::Notify;

use crate::crypto;
use crate::daemon::Daemon;
use crate::db::{Account, Db, NewOutput, NewTx, OutputRow, ScanWriter, Status};
use crate::error::{Error, Result};

/// Blocks asked for in one request.
const BATCH: u64 = 100;
/// Block hashes kept behind the tip, to find where a reorg forked.
const KEEP_HASHES: u64 = 200;
/// Outputs are unspendable for this many blocks; new ones can't be ring
/// members either.
pub const SPENDABLE_AGE: u64 = 10;
/// A mined reward waits longer.
pub const COINBASE_AGE: u64 = 60;

/// What the REST side reads about the scanner.
#[derive(Clone, Debug, Default)]
pub struct ScanStatus {
    /// The daemon's chain height, as last heard.
    pub chain_height: u64,
    /// The next block the scanner will take.
    pub scanner_height: u64,
    pub last_error: Option<String>,
    pub last_step: Option<Instant>,
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

/// Settings the loop takes.
#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub network: Network,
    /// Minors `0..lookahead` of major 0 are watched for every account.
    pub lookahead: u32,
    pub interval: Duration,
}

pub struct Scanner {
    pub db: Arc<Db>,
    pub daemon: Daemon,
    pub config: ScanConfig,
    pub status: RwLock<ScanStatus>,
    pub mempool: Mutex<Mempool>,
    /// Woken by the REST side when an account is added or asked to rescan.
    pub wake: Notify,
    last_block: Mutex<Option<Block>>,
}

impl Scanner {
    pub fn new(db: Arc<Db>, daemon: Daemon, config: ScanConfig) -> Arc<Scanner> {
        Arc::new(Scanner {
            db,
            daemon,
            config,
            status: RwLock::new(ScanStatus::default()),
            mempool: Mutex::new(Mempool::default()),
            wake: Notify::new(),
            last_block: Mutex::new(None),
        })
    }

    pub fn status(&self) -> ScanStatus {
        self.status.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_status(&self, f: impl FnOnce(&mut ScanStatus)) {
        let mut s = self.status.write().unwrap_or_else(|e| e.into_inner());
        f(&mut s);
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

    /// One round: a batch of blocks for whoever needs them, or a look at
    /// the pool when caught up. `Ok(true)` means there is more to do now.
    pub async fn step(&self) -> Result<bool> {
        let info = self.daemon.info().await?;
        let chain_height = info.height;
        self.set_status(|s| {
            s.chain_height = chain_height;
            s.last_error = None;
            s.last_step = Some(Instant::now());
        });
        let accounts = self.db.accounts(Some(Status::Active))?;
        if accounts.is_empty() {
            self.set_status(|s| s.scanner_height = chain_height);
            return Ok(false);
        }
        let start = accounts.iter().map(|a| a.scan_height).min().unwrap_or(chain_height).max(1);
        self.set_status(|s| s.scanner_height = start);
        if start >= chain_height {
            self.scan_pool(&accounts).await?;
            return Ok(false);
        }

        let count = BATCH.min(chain_height - start);
        let blocks = self.daemon.blocks(start, count).await?;
        if blocks.is_empty() {
            return Err(Error::Daemon("the node sent no blocks".into()));
        }
        if blocks[0].block.number() as u64 != start {
            return Err(Error::Daemon("the node sent blocks from the wrong height".into()));
        }

        // A reorg shows as the first block not following the one we kept.
        if let Some(kept) = self.db.block_hash(start - 1)? {
            if kept != blocks[0].block.header.previous {
                let fork = self.find_fork().await?;
                tracing::info!("reorg: rewinding to {fork}");
                self.db.rewind(fork)?;
                self.mempool.lock().unwrap_or_else(|e| e.into_inner()).seen.clear();
                return Ok(true);
            }
        }

        let mut scanners: Vec<(Account, OxideScanner, HashMap<u64, OutputRow>)> = Vec::with_capacity(accounts.len());
        let fetched = blocks.len() as u64;
        self.db.write(|tx| {
            let w = ScanWriter::new(tx);
            for account in &accounts {
                if account.scan_height >= start + fetched {
                    continue;
                }
                let scanner = self.scanner_for(&w, account)?;
                let owned = w.owned_indexes(account.id)?;
                scanners.push((account.clone(), scanner, owned));
            }
            let mut height = start;
            for block in &blocks {
                let hash = block.block.hash();
                for (account, scanner, owned) in scanners.iter_mut() {
                    if account.scan_height > height {
                        continue;
                    }
                    scan_block(&w, account, scanner, owned, block, height)?;
                    w.set_scan_height(account.id, height + 1)?;
                }
                w.set_block(height, &hash, KEEP_HASHES)?;
                height += 1;
            }
            Ok(())
        })?;
        if let Some(last) = blocks.last() {
            *self.last_block.lock().unwrap_or_else(|e| e.into_inner()) = Some(last.block.clone());
        }
        let next = start + fetched;
        self.set_status(|s| s.scanner_height = next);
        // A line every thousand blocks, and one on catching up.
        if next % 1000 < fetched || next >= chain_height {
            tracing::info!("scanned to {next} of {chain_height} for {} accounts", scanners.len());
        }
        Ok(next < chain_height)
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

    fn scanner_for(&self, w: &ScanWriter, account: &Account) -> Result<OxideScanner> {
        let pair = crypto::view_pair(&account.spend_pub, &account.view_key)?;
        let mut scanner = OxideScanner::new(pair);
        let mut seen = HashSet::new();
        for minor in 1..self.config.lookahead {
            if let Some(index) = SubaddressIndex::new(0, minor) {
                seen.insert((0, minor));
                scanner.register_subaddress(index);
            }
        }
        for ranges in w.subaddrs(account.id)? {
            for [lo, hi] in ranges.value {
                for minor in lo..=hi {
                    if (ranges.key, minor) == (0, 0) || !seen.insert((ranges.key, minor)) {
                        continue;
                    }
                    if let Some(index) = SubaddressIndex::new(ranges.key, minor) {
                        scanner.register_subaddress(index);
                    }
                }
            }
        }
        Ok(scanner)
    }

    /// Scans pool transactions not yet seen, in a stand-in block made of
    /// the last block scanned, and forgets ones that left the pool.
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
        self.db.write(|tx| {
            let w = ScanWriter::new(tx);
            for account in accounts {
                let mut scanner = self.scanner_for(&w, account)?;
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
            Ok(())
        })?;
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

fn scan_block(
    w: &ScanWriter,
    account: &Account,
    scanner: &mut OxideScanner,
    owned: &mut HashMap<u64, OutputRow>,
    block: &ScannableBlock,
    height: u64,
) -> Result<()> {
    let timestamp = block.block.header.timestamp;
    let miner_hash = block.block.miner_transaction().hash();
    let miner: Transaction<Pruned> = block.block.miner_transaction().clone().into();
    let tx_of = |hash: [u8; 32]| -> Option<&Transaction<Pruned>> {
        if hash == miner_hash {
            return Some(&miner);
        }
        block.block.transactions.iter().position(|h| *h == hash).map(|i| &block.transactions[i])
    };

    // Received.
    let outputs = scanner.scan(block.clone()).map_err(|e| Error::Internal(format!("scan: {e}")))?.ignore_additional_timelock();
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
                owned.insert(
                    new.global_index,
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

    // Possibly spent: an input whose ring holds one of ours.
    if owned.is_empty() {
        return Ok(());
    }
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
                let Some(ours) = owned.get(&absolute) else { continue };
                let meta = TxMeta::spend_only(tx);
                let tx_id = w.tx_row(account.id, &meta.new_tx(hash, height, timestamp))?;
                w.add_spend(account.id, tx_id, ours.id, ours.amount, &key_image.to_bytes(), ring_size - 1, height)?;
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
}
