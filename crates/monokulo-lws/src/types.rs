//! The server's own value types: row ids, and how each is stored.
//!
//! Each is its own type so that passing one where another belongs (an
//! output's row id where a transaction's goes) doesn't compile. Each that is
//! stored implements rusqlite's `ToSql`/`FromSql` with checked conversions:
//! SQLite's INTEGER is an i64, so a value past `i64::MAX` is refused on
//! write (rather than stored negative) and a negative one refused on read
//! (rather than read back as a huge u64).
//!
//! These stay in the server: the wire types (`lws_api`) carry plain numbers
//! and hex, and rusqlite's traits can only be implemented here.

use std::fmt;

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

/// `v` as an SQLite INTEGER: an error past `i64::MAX`.
fn u64_to_sql(v: u64) -> rusqlite::Result<ToSqlOutput<'static>> {
    i64::try_from(v)
        .map(ToSqlOutput::from)
        .map_err(|_| rusqlite::Error::ToSqlConversionFailure(format!("{v} is past what SQLite stores").into()))
}

/// An SQLite INTEGER as a u64: an error if it is negative.
fn u64_from_sql(v: ValueRef<'_>) -> FromSqlResult<u64> {
    let i = v.as_i64()?;
    u64::try_from(i).map_err(|_| FromSqlError::OutOfRange(i))
}

/// A u64 column with no type of its own (a timestamp, a count): the checked
/// conversions, for a value that is only ever read or written whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlU64(pub u64);

impl ToSql for SqlU64 {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        u64_to_sql(self.0)
    }
}

impl FromSql for SqlU64 {
    fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
        u64_from_sql(v).map(SqlU64)
    }
}

/// A u64 newtype stored as an SQLite INTEGER, checked both ways.
macro_rules! sql_u64 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        #[allow(dead_code)] // Not every type uses every accessor.
        impl $name {
            pub const fn new(v: u64) -> Self {
                $name(v)
            }

            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                u64_to_sql(self.0)
            }
        }

        impl FromSql for $name {
            fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
                u64_from_sql(v).map($name)
            }
        }
    };
}

/// A row id, which SQLite gives as an i64: a negative one (which SQLite
/// never assigns here) is an error, as on read.
macro_rules! row_id {
    ($(#[$doc:meta])* $name:ident) => {
        sql_u64!($(#[$doc])* $name);

        #[allow(dead_code)] // Not every type uses every accessor.
        impl $name {
            /// The id SQLite gave a row (`last_insert_rowid`).
            pub fn from_rowid(id: i64) -> rusqlite::Result<Self> {
                u64::try_from(id)
                    .map($name)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, id))
            }
        }
    };
}

row_id!(
    /// An account's row id.
    AccountId
);
row_id!(
    /// A transaction row's id (one row per account and transaction). Served
    /// as a transaction's `id`.
    TxId
);
row_id!(
    /// An output row's id.
    OutputId
);

/// A block height: the number of blocks below it, so the genesis block is
/// at 0 and a chain of `n` blocks has its top at `n - 1`.
///
/// There is no `+` or `-`: a step past either end is spelled out at the
/// call site, as `checked_*` (the caller says what an overflow means) or
/// `saturating_*` (the end is where it stops).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Height(u64);

impl Height {
    pub const ZERO: Height = Height(0);
    pub const MAX: Height = Height(u64::MAX);
    /// The highest height the database stores (SQLite's INTEGER is an i64).
    pub const MAX_STORED: Height = Height(i64::MAX.unsigned_abs());

    pub const fn new(v: u64) -> Height {
        Height(v)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// The height after this one, stopping at `u64::MAX` (which no chain
    /// reaches, and which the database refuses).
    pub const fn next(self) -> Height {
        Height(self.0.saturating_add(1))
    }

    /// The height before this one; `None` below the genesis block.
    pub fn prev(self) -> Option<Height> {
        self.checked_sub(1)
    }

    pub fn checked_add(self, blocks: u64) -> Option<Height> {
        self.0.checked_add(blocks).map(Height)
    }

    pub const fn saturating_add(self, blocks: u64) -> Height {
        Height(self.0.saturating_add(blocks))
    }

    pub fn checked_sub(self, blocks: u64) -> Option<Height> {
        self.0.checked_sub(blocks).map(Height)
    }

    pub const fn saturating_sub(self, blocks: u64) -> Height {
        Height(self.0.saturating_sub(blocks))
    }

    /// Blocks from `earlier` up to this height; `None` if `earlier` is above it.
    pub fn since(self, earlier: Height) -> Option<u64> {
        self.0.checked_sub(earlier.0)
    }

    /// The height `i` blocks on, for the `i`th block of a batch from here;
    /// `None` past `u64::MAX`.
    pub fn offset(self, i: usize) -> Option<Height> {
        u64::try_from(i).ok().and_then(|i| self.checked_add(i))
    }
}

impl fmt::Display for Height {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl ToSql for Height {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        u64_to_sql(self.0)
    }
}

impl FromSql for Height {
    fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
        u64_from_sql(v).map(Height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE t (v);").unwrap();
        c
    }

    /// Past `i64::MAX` is refused on write, nothing stored; up to it is
    /// stored and read back whole.
    #[test]
    fn writes_past_i64_are_refused() {
        let c = conn();
        for v in [i64::MAX.unsigned_abs() + 1, u64::MAX] {
            assert!(c.execute("INSERT INTO t VALUES (?1)", [SqlU64(v)]).is_err(), "{v}");
            assert!(c.execute("INSERT INTO t VALUES (?1)", [TxId::new(v)]).is_err(), "{v}");
        }
        let n: i64 = c.query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
        let max = i64::MAX.unsigned_abs();
        c.execute("INSERT INTO t VALUES (?1)", [AccountId::new(max)]).unwrap();
        let back: AccountId = c.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(back.get(), max);
    }

    /// A negative value is refused on read, not read as a huge u64.
    #[test]
    fn negative_reads_are_refused() {
        let c = conn();
        c.execute("INSERT INTO t VALUES (-1)", []).unwrap();
        assert!(c.query_row("SELECT v FROM t", [], |r| r.get::<_, SqlU64>(0)).is_err());
        assert!(c.query_row("SELECT v FROM t", [], |r| r.get::<_, OutputId>(0)).is_err());
        assert!(OutputId::from_rowid(-1).is_err());
        assert_eq!(OutputId::from_rowid(7).unwrap(), OutputId::new(7));
        assert!(c.query_row("SELECT v FROM t", [], |r| r.get::<_, Height>(0)).is_err());
    }

    /// Heights past the database's range are refused on write; the steps
    /// past either end are explicit.
    #[test]
    fn heights_store_checked_and_step_explicitly() {
        let c = conn();
        assert!(
            c.execute("INSERT INTO t VALUES (?1)", [Height::MAX_STORED.next()])
                .is_err()
        );
        assert!(c.execute("INSERT INTO t VALUES (?1)", [Height::MAX]).is_err());
        c.execute("INSERT INTO t VALUES (?1)", [Height::MAX_STORED]).unwrap();
        let back: Height = c.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(back, Height::MAX_STORED);

        assert_eq!(Height::ZERO.prev(), None);
        assert_eq!(Height::ZERO.checked_sub(1), None);
        assert_eq!(Height::ZERO.saturating_sub(10), Height::ZERO);
        assert_eq!(Height::new(5).saturating_sub(10), Height::ZERO);
        assert_eq!(Height::new(5).prev(), Some(Height::new(4)));
        assert_eq!(Height::MAX.next(), Height::MAX);
        assert_eq!(Height::MAX.checked_add(1), None);
        assert_eq!(Height::MAX.offset(1), None);
        assert_eq!(Height::new(10).offset(3), Some(Height::new(13)));
        assert_eq!(Height::new(10).since(Height::new(4)), Some(6));
        assert_eq!(Height::new(4).since(Height::new(10)), None);
    }
}
