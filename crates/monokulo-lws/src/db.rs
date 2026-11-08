//! The server's store: one SQLite file, WAL mode, one writer.
//!
//! What is kept, per account: the view key and public keys, where scanning
//! stands, every output received, every candidate spend (an input whose ring
//! holds one of the account's outputs), the transactions those came in, and
//! the subaddress ranges to watch. Globally: recent block hashes (to notice a
//! reorg), pending account and import requests, and admin keys.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::error::{Error, Result, bad};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    view_key BLOB NOT NULL,
    spend_pub BLOB NOT NULL,
    view_pub BLOB NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    start_height INTEGER NOT NULL,
    scan_height INTEGER NOT NULL,
    created INTEGER NOT NULL,
    access_time INTEGER NOT NULL,
    generated_locally INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS subaddrs (
    account INTEGER NOT NULL REFERENCES accounts(id),
    maj INTEGER NOT NULL,
    min_lo INTEGER NOT NULL,
    min_hi INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS subaddrs_account ON subaddrs(account, maj);
CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, hash BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS txs (
    id INTEGER PRIMARY KEY,
    account INTEGER NOT NULL REFERENCES accounts(id),
    hash BLOB NOT NULL,
    prefix_hash BLOB NOT NULL,
    height INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    unlock_time INTEGER NOT NULL,
    coinbase INTEGER NOT NULL,
    mixin INTEGER NOT NULL,
    fee INTEGER NOT NULL,
    payment_id BLOB,
    tx_pub_key BLOB NOT NULL,
    total_received INTEGER NOT NULL DEFAULT 0,
    total_sent INTEGER NOT NULL DEFAULT 0,
    UNIQUE(account, hash)
);
CREATE INDEX IF NOT EXISTS txs_height ON txs(height);
CREATE TABLE IF NOT EXISTS outputs (
    id INTEGER PRIMARY KEY,
    account INTEGER NOT NULL REFERENCES accounts(id),
    tx INTEGER NOT NULL REFERENCES txs(id),
    out_index INTEGER NOT NULL,
    global_index INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    tx_pub_key BLOB NOT NULL,
    mask BLOB,
    height INTEGER NOT NULL,
    maj INTEGER NOT NULL,
    min INTEGER NOT NULL,
    commitment BLOB,
    UNIQUE(account, public_key)
);
CREATE INDEX IF NOT EXISTS outputs_account ON outputs(account, global_index);
CREATE INDEX IF NOT EXISTS outputs_height ON outputs(height);
CREATE TABLE IF NOT EXISTS spends (
    id INTEGER PRIMARY KEY,
    account INTEGER NOT NULL REFERENCES accounts(id),
    tx INTEGER NOT NULL REFERENCES txs(id),
    output INTEGER NOT NULL REFERENCES outputs(id),
    key_image BLOB NOT NULL,
    mixin INTEGER NOT NULL,
    height INTEGER NOT NULL,
    UNIQUE(account, tx, key_image)
);
CREATE INDEX IF NOT EXISTS spends_height ON spends(height);
CREATE TABLE IF NOT EXISTS requests (
    kind TEXT NOT NULL,
    address TEXT NOT NULL,
    view_key BLOB NOT NULL,
    spend_pub BLOB NOT NULL,
    view_pub BLOB NOT NULL,
    start_height INTEGER NOT NULL,
    generated_locally INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL,
    PRIMARY KEY(kind, address)
);
CREATE TABLE IF NOT EXISTS admin_keys (key BLOB PRIMARY KEY, created INTEGER NOT NULL);
"#;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Scanned and served.
    Active,
    /// Served from what was scanned, no longer scanned.
    Inactive,
    /// Neither: the way to delete.
    Hidden,
}

impl Status {
    pub fn parse(s: &str) -> Option<Status> {
        Some(match s {
            "active" => Status::Active,
            "inactive" => Status::Inactive,
            "hidden" => Status::Hidden,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Active => "active",
            Status::Inactive => "inactive",
            Status::Hidden => "hidden",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Account {
    pub id: i64,
    pub address: String,
    pub view_key: [u8; 32],
    pub spend_pub: [u8; 32],
    pub view_pub: [u8; 32],
    pub status: Status,
    pub start_height: u64,
    pub scan_height: u64,
    pub access_time: u64,
    pub generated_locally: bool,
}

/// A new account or a pending request, before it has a row.
#[derive(Clone, Debug)]
pub struct NewAccount {
    pub address: String,
    pub view_key: [u8; 32],
    pub spend_pub: [u8; 32],
    pub view_pub: [u8; 32],
    pub start_height: u64,
    pub generated_locally: bool,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct TxRow {
    pub id: i64,
    pub hash: [u8; 32],
    pub prefix_hash: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub unlock_time: u64,
    pub coinbase: bool,
    pub mixin: u32,
    pub fee: u64,
    pub payment_id: Option<Vec<u8>>,
    pub tx_pub_key: [u8; 32],
    pub total_received: u64,
    pub total_sent: u64,
}

#[derive(Clone, Debug)]
pub struct OutputRow {
    pub id: i64,
    pub tx: i64,
    pub out_index: u16,
    pub global_index: u64,
    pub amount: u64,
    pub public_key: [u8; 32],
    /// The transaction public key this output was derived from (the
    /// additional one for a subaddress, when the sender used one).
    pub tx_pub_key: [u8; 32],
    /// The unencrypted RingCT mask; `None` for a pre-RingCT output.
    pub mask: Option<[u8; 32]>,
    pub height: u64,
    pub maj: u32,
    pub min: u32,
    /// The Pedersen commitment the chain holds for the output (the RingCT
    /// base's `outPk`; `G + amount·H` for a miner output); `None` for a
    /// pre-RingCT output.
    pub commitment: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct SpendRow {
    pub tx: i64,
    pub output: i64,
    pub key_image: [u8; 32],
    pub mixin: u32,
    pub height: u64,
}

/// What a new transaction row carries. `total_received`/`total_sent` grow
/// as outputs and spends are added to it.
pub struct NewTx<'a> {
    pub hash: [u8; 32],
    pub prefix_hash: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub unlock_time: u64,
    pub coinbase: bool,
    pub mixin: u32,
    pub fee: u64,
    pub payment_id: Option<&'a [u8]>,
    pub tx_pub_key: [u8; 32],
}

pub struct NewOutput {
    pub out_index: u16,
    pub global_index: u64,
    pub amount: u64,
    pub public_key: [u8; 32],
    pub tx_pub_key: [u8; 32],
    pub mask: Option<[u8; 32]>,
    pub height: u64,
    pub maj: u32,
    pub min: u32,
    pub commitment: Option<[u8; 32]>,
}

pub struct Db {
    conn: Mutex<Connection>,
}

fn blob32(v: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    v.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn account_row(r: &rusqlite::Row) -> rusqlite::Result<Account> {
    Ok(Account {
        id: r.get(0)?,
        address: r.get(1)?,
        view_key: blob32(r.get(2)?)?,
        spend_pub: blob32(r.get(3)?)?,
        view_pub: blob32(r.get(4)?)?,
        status: Status::parse(&r.get::<_, String>(5)?).unwrap_or(Status::Hidden),
        start_height: r.get::<_, i64>(6)? as u64,
        scan_height: r.get::<_, i64>(7)? as u64,
        access_time: r.get::<_, i64>(8)? as u64,
        generated_locally: r.get::<_, i64>(9)? != 0,
    })
}

const ACCOUNT_COLS: &str =
    "id, address, view_key, spend_pub, view_pub, status, start_height, scan_height, access_time, generated_locally";

/// Brings a database made by an earlier version up to `SCHEMA`.
///
/// `outputs.commitment` (the output's on-chain Pedersen commitment) came
/// after the first release. Rows written before it are filled from their
/// stored mask and amount: the scanner only ever kept an output whose
/// `mask·G + amount·H` equalled the transaction's `outPk` (a miner output's
/// is `G + amount·H`, which is what the chain's output set holds for it), so
/// the commitment worked out again is the on-chain one, without a rescan.
fn migrate(conn: &mut Connection) -> Result<()> {
    let has_commitment = conn
        .prepare("SELECT 1 FROM pragma_table_info('outputs') WHERE name = 'commitment'")?
        .exists([])?;
    let tx = conn.transaction()?;
    if !has_commitment {
        tx.execute("ALTER TABLE outputs ADD COLUMN commitment BLOB", [])?;
    }
    let missing: Vec<(i64, Vec<u8>, i64)> = tx
        .prepare("SELECT id, mask, amount FROM outputs WHERE commitment IS NULL AND mask IS NOT NULL")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (id, mask, amount) in missing {
        let mask = blob32(mask)?;
        let commitment = crate::crypto::commit(&mask, amount as u64);
        tx.execute(
            "UPDATE outputs SET commitment = ?1 WHERE id = ?2",
            params![commitment.as_slice(), id],
        )?;
    }
    tx.commit()?;
    Ok(())
}

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        let mut conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(SCHEMA)?;
        migrate(&mut conn)?;
        Ok(Db { conn: Mutex::new(conn) })
    }

    #[cfg(test)]
    pub fn in_memory() -> Db {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        migrate(&mut conn).unwrap();
        Db { conn: Mutex::new(conn) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run `f` inside one write transaction.
    pub fn write<T>(&self, f: impl FnOnce(&Transaction) -> Result<T>) -> Result<T> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    pub fn read<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = self.lock();
        f(&conn)
    }

    // ---- accounts ----

    pub fn account(&self, address: &str) -> Result<Option<Account>> {
        self.read(|c| {
            Ok(c.query_row(
                &format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE address = ?1"),
                [address],
                account_row,
            )
            .optional()?)
        })
    }

    pub fn accounts(&self, status: Option<Status>) -> Result<Vec<Account>> {
        self.read(|c| {
            let sql = match status {
                Some(s) => format!(
                    "SELECT {ACCOUNT_COLS} FROM accounts WHERE status = '{}' ORDER BY id",
                    s.as_str()
                ),
                None => format!("SELECT {ACCOUNT_COLS} FROM accounts ORDER BY id"),
            };
            let mut st = c.prepare(&sql)?;
            let rows = st.query_map([], account_row)?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Adds an account; `Err(Conflict)` if the address is already here.
    pub fn add_account(&self, new: &NewAccount, status: Status) -> Result<Account> {
        self.write(|tx| {
            let n = now();
            let changed = tx.execute(
                "INSERT OR IGNORE INTO accounts (address, view_key, spend_pub, view_pub, status, start_height, scan_height, created, access_time, generated_locally) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?7, ?8)",
                params![
                    new.address,
                    new.view_key.as_slice(),
                    new.spend_pub.as_slice(),
                    new.view_pub.as_slice(),
                    status.as_str(),
                    new.start_height as i64,
                    n as i64,
                    new.generated_locally as i64
                ],
            )?;
            if changed == 0 {
                return Err(Error::Conflict("account exists".into()));
            }
            tx.query_row(&format!("SELECT {ACCOUNT_COLS} FROM accounts WHERE address = ?1"), [&new.address], account_row)
                .map_err(Error::from)
        })
    }

    pub fn set_status(&self, addresses: &[String], status: Status) -> Result<Vec<String>> {
        self.write(|tx| {
            let mut done = vec![];
            for a in addresses {
                if tx.execute(
                    "UPDATE accounts SET status = ?1 WHERE address = ?2",
                    params![status.as_str(), a],
                )? > 0
                {
                    done.push(a.clone());
                }
            }
            Ok(done)
        })
    }

    pub fn touch(&self, id: i64) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "UPDATE accounts SET access_time = ?1 WHERE id = ?2",
                params![now() as i64, id],
            )?;
            Ok(())
        })
    }

    /// Scan these accounts again from `height`: their rows from there on go.
    pub fn rescan(&self, addresses: &[String], height: u64) -> Result<Vec<String>> {
        self.write(|tx| {
            let mut done = vec![];
            for a in addresses {
                let id: Option<i64> = tx
                    .query_row("SELECT id FROM accounts WHERE address = ?1", [a], |r| r.get(0))
                    .optional()?;
                let Some(id) = id else { continue };
                delete_account_from(tx, id, height)?;
                tx.execute(
                    "UPDATE accounts SET scan_height = MIN(scan_height, ?1) WHERE id = ?2",
                    params![height as i64, id],
                )?;
                done.push(a.clone());
            }
            Ok(done)
        })
    }

    // ---- requests ----

    pub fn add_request(&self, kind: &str, new: &NewAccount) -> Result<bool> {
        self.write(|tx| {
            let changed = tx.execute(
                "INSERT OR IGNORE INTO requests (kind, address, view_key, spend_pub, view_pub, start_height, generated_locally, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    kind,
                    new.address,
                    new.view_key.as_slice(),
                    new.spend_pub.as_slice(),
                    new.view_pub.as_slice(),
                    new.start_height as i64,
                    new.generated_locally as i64,
                    now() as i64
                ],
            )?;
            Ok(changed > 0)
        })
    }

    pub fn requests(&self) -> Result<Vec<(String, NewAccount)>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT kind, address, view_key, spend_pub, view_pub, start_height, generated_locally FROM requests ORDER BY created",
            )?;
            let rows = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        NewAccount {
                            address: r.get(1)?,
                            view_key: blob32(r.get(2)?)?,
                            spend_pub: blob32(r.get(3)?)?,
                            view_pub: blob32(r.get(4)?)?,
                            start_height: r.get::<_, i64>(5)? as u64,
                            generated_locally: r.get::<_, i64>(6)? != 0,
                        },
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// Removes the named requests of a kind, returning what they were.
    pub fn take_requests(&self, kind: &str, addresses: &[String]) -> Result<Vec<NewAccount>> {
        let all = self.requests()?;
        let mut taken = vec![];
        self.write(|tx| {
            for (k, new) in all {
                if k == kind && addresses.contains(&new.address) {
                    tx.execute(
                        "DELETE FROM requests WHERE kind = ?1 AND address = ?2",
                        params![kind, new.address],
                    )?;
                    taken.push(new);
                }
            }
            Ok(())
        })?;
        Ok(taken)
    }

    // ---- subaddresses ----

    pub fn subaddrs(&self, account: i64) -> Result<Vec<lws_api::SubaddrRanges>> {
        self.read(|c| subaddrs_in(c, account))
    }

    /// Adds ranges, merging with what is there; returns only what was new,
    /// as ranges, and refuses to pass `max` minors in all.
    pub fn upsert_subaddrs(
        &self,
        account: i64,
        wanted: &[lws_api::SubaddrRanges],
        max: u64,
    ) -> Result<Vec<lws_api::SubaddrRanges>> {
        self.write(|tx| {
            let existing = subaddrs_in(tx, account)?;
            let mut by_major: HashMap<u32, Vec<[u32; 2]>> = existing.into_iter().map(|r| (r.key, r.value)).collect();
            let mut added = vec![];
            for want in wanted {
                let have = by_major.entry(want.key).or_default();
                let mut new_here = vec![];
                for &[lo, hi] in &want.value {
                    if lo > hi {
                        return Err(bad("a subaddress range runs backwards"));
                    }
                    // Only the minors not already covered are new.
                    let mut cursor = lo;
                    let mut covered: Vec<[u32; 2]> = have.clone();
                    covered.sort();
                    for [clo, chi] in covered {
                        if chi < cursor {
                            continue;
                        }
                        if clo > hi {
                            break;
                        }
                        if clo > cursor {
                            new_here.push([cursor, clo - 1]);
                        }
                        cursor = cursor.max(chi.saturating_add(1));
                        if cursor > hi {
                            break;
                        }
                    }
                    if cursor <= hi {
                        new_here.push([cursor, hi]);
                    }
                    have.push([lo, hi]);
                }
                *have = merge(std::mem::take(have));
                if !new_here.is_empty() {
                    added.push(lws_api::SubaddrRanges {
                        key: want.key,
                        value: merge(new_here),
                    });
                }
            }
            let total: u64 = by_major.values().flatten().map(|[lo, hi]| u64::from(hi - lo) + 1).sum();
            if total > max {
                return Err(Error::Conflict(format!(
                    "subaddress limit of {max} would be passed ({total})"
                )));
            }
            tx.execute("DELETE FROM subaddrs WHERE account = ?1", [account])?;
            let mut majors: Vec<_> = by_major.into_iter().collect();
            majors.sort_by_key(|(m, _)| *m);
            for (maj, ranges) in majors {
                for [lo, hi] in ranges {
                    tx.execute(
                        "INSERT INTO subaddrs (account, maj, min_lo, min_hi) VALUES (?1, ?2, ?3, ?4)",
                        params![account, maj, lo, hi],
                    )?;
                }
            }
            added.sort_by_key(|r| r.key);
            Ok(added)
        })
    }

    // ---- blocks ----

    pub fn block_hash(&self, height: u64) -> Result<Option<[u8; 32]>> {
        self.read(|c| {
            Ok(
                c.query_row("SELECT hash FROM blocks WHERE height = ?1", [height as i64], |r| {
                    r.get::<_, Vec<u8>>(0)
                })
                .optional()?
                .map(blob32)
                .transpose()?,
            )
        })
    }

    pub fn recent_blocks(&self) -> Result<Vec<(u64, [u8; 32])>> {
        self.read(|c| {
            let mut st = c.prepare("SELECT height, hash FROM blocks ORDER BY height DESC")?;
            let rows = st
                .query_map([], |r| Ok((r.get::<_, i64>(0)? as u64, blob32(r.get(1)?)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    /// The scanner's own height: the block after the last one it finished.
    #[cfg(test)]
    pub fn scanner_height(&self) -> Result<Option<u64>> {
        self.read(|c| {
            Ok(
                c.query_row("SELECT value FROM meta WHERE key = 'scanner_height'", [], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?
                .and_then(|s| s.parse().ok()),
            )
        })
    }

    /// Forget everything from `height` on: a reorg went deeper than it.
    pub fn rewind(&self, height: u64) -> Result<()> {
        self.write(|tx| {
            let h = height as i64;
            tx.execute("DELETE FROM spends WHERE height >= ?1", [h])?;
            tx.execute("DELETE FROM outputs WHERE height >= ?1", [h])?;
            tx.execute("DELETE FROM txs WHERE height >= ?1", [h])?;
            tx.execute("DELETE FROM blocks WHERE height >= ?1", [h])?;
            tx.execute("UPDATE accounts SET scan_height = MIN(scan_height, ?1)", [h])?;
            tx.execute("UPDATE txs SET total_received = (SELECT COALESCE(SUM(amount), 0) FROM outputs WHERE outputs.tx = txs.id)", [])?;
            tx.execute(
                "UPDATE txs SET total_sent = (SELECT COALESCE(SUM(o.amount), 0) FROM spends s JOIN outputs o ON o.id = s.output WHERE s.tx = txs.id)",
                [],
            )?;
            tx.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('scanner_height', ?1)", [height.to_string()])?;
            Ok(())
        })
    }

    // ---- what an account holds ----

    pub fn txs(&self, account: i64) -> Result<Vec<TxRow>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT id, hash, prefix_hash, height, timestamp, unlock_time, coinbase, mixin, fee, payment_id, tx_pub_key, total_received, total_sent FROM txs WHERE account = ?1 ORDER BY height, id",
            )?;
            let rows = st
                .query_map([account], |r| {
                    Ok(TxRow {
                        id: r.get(0)?,
                        hash: blob32(r.get(1)?)?,
                        prefix_hash: blob32(r.get(2)?)?,
                        height: r.get::<_, i64>(3)? as u64,
                        timestamp: r.get::<_, i64>(4)? as u64,
                        unlock_time: r.get::<_, i64>(5)? as u64,
                        coinbase: r.get::<_, i64>(6)? != 0,
                        mixin: r.get::<_, i64>(7)? as u32,
                        fee: r.get::<_, i64>(8)? as u64,
                        payment_id: r.get(9)?,
                        tx_pub_key: blob32(r.get(10)?)?,
                        total_received: r.get::<_, i64>(11)? as u64,
                        total_sent: r.get::<_, i64>(12)? as u64,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    pub fn outputs(&self, account: i64) -> Result<Vec<OutputRow>> {
        self.read(|c| outputs_in(c, account))
    }

    pub fn spends(&self, account: i64) -> Result<Vec<SpendRow>> {
        self.read(|c| {
            let mut st = c.prepare(
                "SELECT tx, output, key_image, mixin, height FROM spends WHERE account = ?1 ORDER BY height, id",
            )?;
            let rows = st
                .query_map([account], |r| {
                    Ok(SpendRow {
                        tx: r.get(0)?,
                        output: r.get(1)?,
                        key_image: blob32(r.get(2)?)?,
                        mixin: r.get::<_, i64>(3)? as u32,
                        height: r.get::<_, i64>(4)? as u64,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    // ---- admin ----

    pub fn add_admin_key(&self, key: &[u8; 32]) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO admin_keys (key, created) VALUES (?1, ?2)",
                params![key.as_slice(), now() as i64],
            )?;
            Ok(())
        })
    }

    pub fn admin_keys(&self) -> Result<Vec<[u8; 32]>> {
        self.read(|c| {
            let mut st = c.prepare("SELECT key FROM admin_keys")?;
            let rows = st
                .query_map([], |r| blob32(r.get(0)?))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }
}

fn merge(mut ranges: Vec<[u32; 2]>) -> Vec<[u32; 2]> {
    ranges.sort();
    let mut out: Vec<[u32; 2]> = vec![];
    for [lo, hi] in ranges {
        match out.last_mut() {
            Some(last) if lo <= last[1].saturating_add(1) => last[1] = last[1].max(hi),
            _ => out.push([lo, hi]),
        }
    }
    out
}

fn subaddrs_in(c: &Connection, account: i64) -> Result<Vec<lws_api::SubaddrRanges>> {
    let mut st = c.prepare("SELECT maj, min_lo, min_hi FROM subaddrs WHERE account = ?1 ORDER BY maj, min_lo")?;
    let mut out: Vec<lws_api::SubaddrRanges> = vec![];
    for row in st.query_map([account], |r| {
        Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?, r.get::<_, u32>(2)?))
    })? {
        let (maj, lo, hi) = row?;
        match out.last_mut() {
            Some(last) if last.key == maj => last.value.push([lo, hi]),
            _ => out.push(lws_api::SubaddrRanges {
                key: maj,
                value: vec![[lo, hi]],
            }),
        }
    }
    Ok(out)
}

fn outputs_in(c: &Connection, account: i64) -> Result<Vec<OutputRow>> {
    let mut st = c.prepare(
        "SELECT id, tx, out_index, global_index, amount, public_key, tx_pub_key, mask, height, maj, min, commitment FROM outputs WHERE account = ?1 ORDER BY height, id",
    )?;
    let rows = st
        .query_map([account], |r| {
            Ok(OutputRow {
                id: r.get(0)?,
                tx: r.get(1)?,
                out_index: r.get::<_, i64>(2)? as u16,
                global_index: r.get::<_, i64>(3)? as u64,
                amount: r.get::<_, i64>(4)? as u64,
                public_key: blob32(r.get(5)?)?,
                tx_pub_key: blob32(r.get(6)?)?,
                mask: r.get::<_, Option<Vec<u8>>>(7)?.map(blob32).transpose()?,
                height: r.get::<_, i64>(8)? as u64,
                maj: r.get(9)?,
                min: r.get(10)?,
                commitment: r.get::<_, Option<Vec<u8>>>(11)?.map(blob32).transpose()?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn delete_account_from(tx: &Transaction, account: i64, height: u64) -> Result<()> {
    let h = height as i64;
    tx.execute(
        "DELETE FROM spends WHERE account = ?1 AND height >= ?2",
        params![account, h],
    )?;
    tx.execute(
        "DELETE FROM outputs WHERE account = ?1 AND height >= ?2",
        params![account, h],
    )?;
    tx.execute(
        "DELETE FROM txs WHERE account = ?1 AND height >= ?2",
        params![account, h],
    )?;
    Ok(())
}

/// Writes the scanner makes, inside one transaction per batch of blocks.
pub struct ScanWriter<'a> {
    tx: &'a Transaction<'a>,
}

impl<'a> ScanWriter<'a> {
    pub fn new(tx: &'a Transaction<'a>) -> Self {
        ScanWriter { tx }
    }

    pub fn set_block(&self, height: u64, hash: &[u8; 32], keep: u64) -> Result<()> {
        self.tx.execute(
            "INSERT OR REPLACE INTO blocks (height, hash) VALUES (?1, ?2)",
            params![height as i64, hash.as_slice()],
        )?;
        self.tx.execute(
            "DELETE FROM blocks WHERE height < ?1",
            [height.saturating_sub(keep) as i64],
        )?;
        self.tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('scanner_height', ?1)",
            [(height + 1).to_string()],
        )?;
        Ok(())
    }

    /// Where `account` stands now, and whether it is still scanned: what a
    /// batch checks before writing, as the account may have been rescanned,
    /// rewound or hidden while the batch was fetched.
    pub fn standing(&self, account: i64) -> Result<Option<(u64, Status)>> {
        Ok(self
            .tx
            .query_row(
                "SELECT scan_height, status FROM accounts WHERE id = ?1",
                [account],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(h, s)| (h, Status::parse(&s).unwrap_or(Status::Hidden))))
    }

    pub fn set_scan_height(&self, account: i64, height: u64) -> Result<()> {
        self.tx.execute(
            "UPDATE accounts SET scan_height = ?1 WHERE id = ?2",
            params![height as i64, account],
        )?;
        Ok(())
    }

    /// The transaction's row id, made if it wasn't there.
    pub fn tx_row(&self, account: i64, new: &NewTx) -> Result<i64> {
        self.tx.execute(
            "INSERT OR IGNORE INTO txs (account, hash, prefix_hash, height, timestamp, unlock_time, coinbase, mixin, fee, payment_id, tx_pub_key) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                account,
                new.hash.as_slice(),
                new.prefix_hash.as_slice(),
                new.height as i64,
                new.timestamp as i64,
                new.unlock_time as i64,
                new.coinbase as i64,
                new.mixin,
                new.fee as i64,
                new.payment_id,
                new.tx_pub_key.as_slice()
            ],
        )?;
        let id = self.tx.query_row(
            "SELECT id FROM txs WHERE account = ?1 AND hash = ?2",
            params![account, new.hash.as_slice()],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    /// Adds an output and gives its row id; `None` if one with that key was
    /// already here (the burning bug: only the first counts).
    pub fn add_output(&self, account: i64, tx: i64, o: &NewOutput) -> Result<Option<i64>> {
        let changed = self.tx.execute(
            "INSERT OR IGNORE INTO outputs (account, tx, out_index, global_index, amount, public_key, tx_pub_key, mask, height, maj, min, commitment) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                account,
                tx,
                o.out_index,
                o.global_index as i64,
                o.amount as i64,
                o.public_key.as_slice(),
                o.tx_pub_key.as_slice(),
                o.mask.as_ref().map(|m| m.as_slice()),
                o.height as i64,
                o.maj,
                o.min,
                o.commitment.as_ref().map(|c| c.as_slice())
            ],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        self.tx.execute(
            "UPDATE txs SET total_received = total_received + ?1 WHERE id = ?2",
            params![o.amount as i64, tx],
        )?;
        Ok(Some(self.tx.last_insert_rowid()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_spend(
        &self,
        account: i64,
        tx: i64,
        output: i64,
        amount: u64,
        key_image: &[u8; 32],
        mixin: u32,
        height: u64,
    ) -> Result<()> {
        let changed = self.tx.execute(
            "INSERT OR IGNORE INTO spends (account, tx, output, key_image, mixin, height) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![account, tx, output, key_image.as_slice(), mixin, height as i64],
        )?;
        if changed > 0 {
            self.tx.execute(
                "UPDATE txs SET total_sent = total_sent + ?1 WHERE id = ?2",
                params![amount as i64, tx],
            )?;
        }
        Ok(())
    }

    /// Owned outputs by global index, for matching rings against.
    pub fn owned_indexes(&self, account: i64) -> Result<HashMap<u64, OutputRow>> {
        Ok(outputs_in(self.tx, account)?
            .into_iter()
            .filter(|o| o.mask.is_some())
            .map(|o| (o.global_index, o))
            .collect())
    }

    pub fn subaddrs(&self, account: i64) -> Result<Vec<lws_api::SubaddrRanges>> {
        subaddrs_in(self.tx, account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acct(db: &Db) -> Account {
        db.add_account(
            &NewAccount {
                address: "A".into(),
                view_key: [1; 32],
                spend_pub: [2; 32],
                view_pub: [3; 32],
                start_height: 10,
                generated_locally: false,
            },
            Status::Active,
        )
        .unwrap()
    }

    #[test]
    fn accounts_round_trip() {
        let db = Db::in_memory();
        let a = acct(&db);
        assert_eq!(a.scan_height, 10);
        assert!(
            db.add_account(
                &NewAccount {
                    address: "A".into(),
                    view_key: [1; 32],
                    spend_pub: [2; 32],
                    view_pub: [3; 32],
                    start_height: 0,
                    generated_locally: false
                },
                Status::Active
            )
            .is_err()
        );
        assert_eq!(
            db.set_status(&["A".into(), "B".into()], Status::Hidden).unwrap(),
            vec!["A".to_string()]
        );
        assert_eq!(db.account("A").unwrap().unwrap().status, Status::Hidden);
        assert!(db.accounts(Some(Status::Active)).unwrap().is_empty());
    }

    #[test]
    fn subaddress_ranges_merge_and_report_only_new() {
        let db = Db::in_memory();
        let a = acct(&db);
        let new = db
            .upsert_subaddrs(
                a.id,
                &[lws_api::SubaddrRanges {
                    key: 0,
                    value: vec![[1, 10]],
                }],
                1000,
            )
            .unwrap();
        assert_eq!(
            new,
            vec![lws_api::SubaddrRanges {
                key: 0,
                value: vec![[1, 10]]
            }]
        );
        let new = db
            .upsert_subaddrs(
                a.id,
                &[lws_api::SubaddrRanges {
                    key: 0,
                    value: vec![[5, 15], [20, 20]],
                }],
                1000,
            )
            .unwrap();
        assert_eq!(
            new,
            vec![lws_api::SubaddrRanges {
                key: 0,
                value: vec![[11, 15], [20, 20]]
            }]
        );
        let all = db.subaddrs(a.id).unwrap();
        assert_eq!(
            all,
            vec![lws_api::SubaddrRanges {
                key: 0,
                value: vec![[1, 15], [20, 20]]
            }]
        );
        assert!(
            db.upsert_subaddrs(
                a.id,
                &[lws_api::SubaddrRanges {
                    key: 1,
                    value: vec![[0, 100]]
                }],
                50
            )
            .is_err()
        );
        let none = db
            .upsert_subaddrs(
                a.id,
                &[lws_api::SubaddrRanges {
                    key: 0,
                    value: vec![[2, 3]],
                }],
                1000,
            )
            .unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn scan_writes_and_rewind() {
        let db = Db::in_memory();
        let a = acct(&db);
        db.write(|tx| {
            let w = ScanWriter::new(tx);
            let t = w.tx_row(
                a.id,
                &NewTx {
                    hash: [9; 32],
                    prefix_hash: [8; 32],
                    height: 12,
                    timestamp: 5,
                    unlock_time: 0,
                    coinbase: false,
                    mixin: 15,
                    fee: 3,
                    payment_id: None,
                    tx_pub_key: [7; 32],
                },
            )?;
            assert!(
                w.add_output(
                    a.id,
                    t,
                    &NewOutput {
                        out_index: 0,
                        global_index: 100,
                        amount: 50,
                        public_key: [4; 32],
                        tx_pub_key: [7; 32],
                        mask: Some([5; 32]),
                        height: 12,
                        maj: 0,
                        min: 0,
                        commitment: None
                    }
                )?
                .is_some()
            );
            assert!(
                w.add_output(
                    a.id,
                    t,
                    &NewOutput {
                        out_index: 1,
                        global_index: 101,
                        amount: 50,
                        public_key: [4; 32],
                        tx_pub_key: [7; 32],
                        mask: Some([5; 32]),
                        height: 12,
                        maj: 0,
                        min: 0,
                        commitment: None
                    }
                )?
                .is_none()
            );
            let t2 = w.tx_row(
                a.id,
                &NewTx {
                    hash: [10; 32],
                    prefix_hash: [8; 32],
                    height: 14,
                    timestamp: 6,
                    unlock_time: 0,
                    coinbase: false,
                    mixin: 15,
                    fee: 3,
                    payment_id: None,
                    tx_pub_key: [7; 32],
                },
            )?;
            let owned = w.owned_indexes(a.id)?;
            let o = &owned[&100];
            w.add_spend(a.id, t2, o.id, o.amount, &[6; 32], 15, 14)?;
            w.set_block(14, &[1; 32], 100)?;
            w.set_scan_height(a.id, 15)?;
            Ok(())
        })
        .unwrap();
        let txs = db.txs(a.id).unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].total_received, 50);
        assert_eq!(txs[1].total_sent, 50);
        assert_eq!(db.spends(a.id).unwrap().len(), 1);
        assert_eq!(db.scanner_height().unwrap(), Some(15));
        db.rewind(13).unwrap();
        assert_eq!(db.txs(a.id).unwrap().len(), 1);
        assert!(db.spends(a.id).unwrap().is_empty());
        assert_eq!(db.account("A").unwrap().unwrap().scan_height, 13);
        assert_eq!(db.scanner_height().unwrap(), Some(13));
        db.rescan(&["A".into()], 0).unwrap();
        assert!(db.outputs(a.id).unwrap().is_empty());
        assert_eq!(db.account("A").unwrap().unwrap().scan_height, 0);
    }

    #[test]
    fn an_old_database_gains_commitments_from_its_masks() {
        // The outputs table as the first release made it: no commitment.
        let old = SCHEMA.replace("    commitment BLOB,\n", "");
        assert!(!old.contains("commitment"));
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(&old).unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (id, address, view_key, spend_pub, view_pub, start_height, scan_height, created, access_time) VALUES (1, 'A', x'00', x'00', x'00', 0, 0, 0, 0);
             INSERT INTO txs (id, account, hash, prefix_hash, height, timestamp, unlock_time, coinbase, mixin, fee, tx_pub_key) VALUES (1, 1, x'01', x'01', 5, 0, 0, 0, 15, 0, x'01');",
        )
        .unwrap();
        let mask = [7u8; 32];
        conn.execute(
            "INSERT INTO outputs (account, tx, out_index, global_index, amount, public_key, tx_pub_key, mask, height, maj, min) VALUES (1, 1, 0, 9, 1234, randomblob(32), zeroblob(32), ?1, 5, 0, 0)",
            [mask.as_slice()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO outputs (account, tx, out_index, global_index, amount, public_key, tx_pub_key, mask, height, maj, min) VALUES (1, 1, 1, 10, 99, randomblob(32), zeroblob(32), NULL, 5, 0, 0)",
            [],
        )
        .unwrap();
        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        let outputs = outputs_in(&conn, 1).unwrap();
        assert_eq!(outputs[0].commitment, Some(crate::crypto::commit(&mask, 1234)));
        assert_eq!(outputs[1].commitment, None, "a pre-RingCT output has none");
    }
}
