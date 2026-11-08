//! The database file at rest: created readable by its owner only, and a
//! warning when its directory or an existing file lets others in.
//!
//! The view keys in it are stored in the clear, as monero-lws stores them:
//! the scanner needs them every block. What protects them is the file's
//! permissions and the disk's encryption (see docs/security.md).

use std::path::Path;

/// Before SQLite opens `path`: make the file (0600) if it isn't there,
/// tighten it and its `-wal`/`-shm` companions if they're open to others,
/// and warn about a directory others can write to. SQLite gives the
/// companions the main file's mode when it makes them.
#[cfg(unix)]
pub fn prepare_db_file(path: &Path) -> std::io::Result<()> {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    if let Ok(meta) = fs::metadata(&dir) {
        let mode = meta.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            tracing::warn!(
                "the database's directory {} can be written by other users (mode {:o}): they could replace the \
                 database; make it 0700 or 0750",
                dir.display(),
                mode & 0o7777
            );
        } else if mode & 0o007 != 0 {
            tracing::info!(
                "the database's directory {} is open to every user (mode {:o}); 0700 or 0750 is better",
                dir.display(),
                mode & 0o7777
            );
        }
    }

    if !path.exists() {
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let file = Path::new(&name);
        let Ok(meta) = fs::metadata(file) else { continue };
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                "{} was readable by other users (mode {:o}); setting it to 0600",
                file.display(),
                mode & 0o777
            );
            fs::set_permissions(file, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn prepare_db_file(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// A warning when a TLS private key file is readable by others.
#[cfg(unix)]
pub fn check_key_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                "the TLS key {} is readable by other users (mode {:o}); 0600 is better",
                path.display(),
                mode & 0o777
            );
        }
    }
}

#[cfg(not(unix))]
pub fn check_key_file(_path: &Path) {}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("monokulo-lws-at-rest-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[test]
    fn a_new_database_is_owner_only() {
        let dir = scratch("new");
        let path = dir.join("lws.sqlite");
        prepare_db_file(&path).unwrap();
        let db = crate::db::Db::open(&path).unwrap();
        db.write(|tx| {
            tx.execute("INSERT INTO meta (key, value) VALUES ('t', 'x')", [])?;
            Ok(())
        })
        .unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let p = format!("{}{suffix}", path.display());
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{p}");
        }
        drop(db);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_open_database_is_tightened() {
        let dir = scratch("open");
        let path = dir.join("lws.sqlite");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        prepare_db_file(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
