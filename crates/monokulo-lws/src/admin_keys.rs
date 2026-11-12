//! Admin API keys: 32 random bytes handed to the operator once, stored only
//! as `SHA3-256("monokulo-lws admin key v1" ‖ key)`. Someone who reads the
//! database learns no key that opens the admin API. A fast hash is enough:
//! the key is random and 256 bits long, so there is nothing to guess.
//!
//! The `admin_keys` table is the one the database always had; a database
//! from before hashing has its plain keys hashed in place by [`migrate`],
//! which `open_db` runs once when the database is opened, and `meta`
//! remembers that it was done. The functions here don't run it again, so an
//! admin request makes no write transaction.

use rusqlite::{OptionalExtension, params};
use sha3::{Digest, Sha3_256};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::db::{Db, now};
use crate::error::Result;

const DOMAIN: &[u8] = b"monokulo-lws admin key v1";
const HASHED: &str = "admin_keys_hashed";

pub fn hash(key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN);
    h.update(key);
    h.finalize().into()
}

/// Hashes keys stored in the clear by an older version, once. Run when the
/// database is opened, before anything else here.
pub fn migrate(db: &Db) -> Result<()> {
    db.write(|tx| {
        let done: Option<String> = tx
            .query_row("SELECT value FROM meta WHERE key = ?1", [HASHED], |r| r.get(0))
            .optional()?;
        if done.is_some() {
            return Ok(());
        }
        let plain: Vec<(Vec<u8>, i64)> = tx
            .prepare("SELECT key, created FROM admin_keys")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        tx.execute("DELETE FROM admin_keys", [])?;
        for (key, created) in plain {
            let key = Zeroizing::new(key);
            let Ok(key) = <[u8; 32]>::try_from(key.as_slice()) else {
                continue;
            };
            tx.execute(
                "INSERT OR IGNORE INTO admin_keys (key, created) VALUES (?1, ?2)",
                params![hash(&key).as_slice(), created],
            )?;
        }
        tx.execute("INSERT INTO meta (key, value) VALUES (?1, '1')", [HASHED])?;
        Ok(())
    })
}

/// A new key: stored hashed, returned once for the operator.
pub fn create(db: &Db) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key.as_mut());
    let hashed = hash(&key);
    db.write(|tx| {
        tx.execute(
            "INSERT OR IGNORE INTO admin_keys (key, created) VALUES (?1, ?2)",
            params![hashed.as_slice(), now() as i64],
        )?;
        Ok(())
    })?;
    Ok(key)
}

/// How many keys there are.
pub fn count(db: &Db) -> Result<u64> {
    db.read(|c| Ok(c.query_row("SELECT COUNT(*) FROM admin_keys", [], |r| r.get::<_, i64>(0))? as u64))
}

/// Whether `presented` is one of the keys. The presented key is hashed and
/// compared with every stored hash in constant time, all of them each time,
/// so the time taken says nothing of which (or whether one) matched.
pub fn verify(db: &Db, presented: &[u8; 32]) -> Result<bool> {
    let stored: Vec<Vec<u8>> = db.read(|c| {
        Ok(c.prepare("SELECT key FROM admin_keys")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    })?;
    Ok(matches(&stored, &hash(presented)))
}

fn matches(stored: &[Vec<u8>], wanted: &[u8; 32]) -> bool {
    let mut ok = Choice::from(0);
    for s in stored {
        // A wrong-length row compares unequal (ct_eq on slices checks length).
        ok |= s.as_slice().ct_eq(wanted.as_slice());
    }
    ok.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_stored_hashed_and_verify() {
        let db = Db::in_memory();
        assert_eq!(count(&db).unwrap(), 0);
        let key = create(&db).unwrap();
        assert_eq!(count(&db).unwrap(), 1);
        let stored: Vec<Vec<u8>> = db
            .read(|c| {
                Ok(c.prepare("SELECT key FROM admin_keys")?
                    .query_map([], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?)
            })
            .unwrap();
        assert_eq!(stored, vec![hash(&key).to_vec()]);
        assert_ne!(stored[0], key.to_vec(), "the key itself is not in the database");
        assert!(verify(&db, &key).unwrap());
        let mut wrong = *key;
        wrong[31] ^= 1;
        assert!(!verify(&db, &wrong).unwrap());
        // The hash itself is not a key.
        assert!(!verify(&db, &hash(&key)).unwrap());
    }

    #[test]
    fn plain_keys_from_before_are_hashed_in_place() {
        let db = Db::in_memory();
        let old = [9u8; 32];
        db.write(|tx| {
            tx.execute(
                "INSERT INTO admin_keys (key, created) VALUES (?1, 5)",
                params![old.as_slice()],
            )?;
            Ok(())
        })
        .unwrap();
        // What open_db does once.
        migrate(&db).unwrap();
        assert!(verify(&db, &old).unwrap(), "the old key still opens the admin API");
        let stored: Vec<u8> = db
            .read(|c| Ok(c.query_row("SELECT key FROM admin_keys", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(stored, hash(&old).to_vec());
        // Running again doesn't hash the hash.
        migrate(&db).unwrap();
        assert!(verify(&db, &old).unwrap());
    }

    #[test]
    fn verify_and_count_write_nothing() {
        let db = Db::in_memory();
        let key = create(&db).unwrap();
        // Without the migration's mark, a verify that migrated would add it.
        assert!(verify(&db, &key).unwrap());
        assert_eq!(count(&db).unwrap(), 1);
        let marked: bool = db
            .read(|c| Ok(c.prepare("SELECT 1 FROM meta WHERE key = ?1")?.exists([HASHED])?))
            .unwrap();
        assert!(!marked, "verify or count ran the migration");
    }

    #[test]
    fn the_comparison_looks_at_every_key() {
        let a = hash(&[1; 32]);
        let b = hash(&[2; 32]);
        let stored = vec![vec![0u8; 5], a.to_vec(), b.to_vec()];
        assert!(matches(&stored, &a));
        assert!(matches(&stored, &b));
        assert!(!matches(&stored, &hash(&[3; 32])));
        assert!(!matches(&[], &a));
    }
}
