//! The database file at rest: created readable by its owner only, and
//! refused when its directory or an existing file lets other users in.
//!
//! The view keys in it are stored in the clear, as monero-lws stores them:
//! the scanner needs them every block. What protects them is the file's
//! permissions and the disk's encryption (see docs/security.md).

use std::path::Path;

/// Before SQLite opens `path`: refuse a directory every user can write to
/// (sticky, like /tmp, or not: another user could make the database or its
/// `-wal`/`-shm` companions before SQLite does), and existing files that
/// are symbolic links, not plain files, or owned by a third user; make the
/// file (0600) if it isn't there, tighten it and its companions if they're
/// open to others, and warn about a directory its group can write to.
/// SQLite gives the companions the main file's mode when it makes them.
#[cfg(unix)]
pub fn prepare_db_file(path: &Path) -> std::io::Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let dir_meta = fs::metadata(&dir)?;
    let mode = dir_meta.permissions().mode();
    if mode & 0o002 != 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "the database's directory {} can be written by every user (mode {:o}): another user could put \
                 their own database, or its -wal or -shm file, there first; use a directory of its own, 0700",
                dir.display(),
                mode & 0o7777
            ),
        ));
    }
    if mode & 0o020 != 0 && mode & 0o1000 == 0 {
        tracing::warn!(
            "the database's directory {} can be written by its group (mode {:o}): they could replace the \
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

    // This process's uid, found only when a file isn't the directory
    // owner's (the usual case is the server's own folder and files).
    let mut my_uid = None;
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let file = Path::new(&name);
        let meta = match fs::symlink_metadata(file) {
            Ok(meta) => meta,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if meta.file_type().is_symlink() {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("{} is a symbolic link: name the database file itself", file.display()),
            ));
        }
        if !meta.is_file() {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("{} is not a plain file", file.display()),
            ));
        }
        if meta.uid() != dir_meta.uid() {
            let me = match my_uid {
                Some(uid) => uid,
                None => *my_uid.insert(current_uid(&dir)?),
            };
            if !owner_trusted(meta.uid(), me, dir_meta.uid()) {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "{} is owned by another user (uid {}), neither this one (uid {me}) nor the directory's \
                         owner (uid {}): not using it",
                        file.display(),
                        meta.uid(),
                        dir_meta.uid()
                    ),
                ));
            }
        }
    }

    if fs::symlink_metadata(path).is_err() {
        // create_new refuses whatever is there by then, a link included.
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let file = Path::new(&name);
        let Ok(meta) = fs::symlink_metadata(file) else { continue };
        if !meta.is_file() {
            continue;
        }
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

/// Whether a database file owned by `owner` may be used by this process
/// (`me`) in a directory owned by `dir_owner`: its own, or the directory
/// owner's (who could replace any file there anyway; root running an
/// admin command on the server's database, say). A third user's file is
/// one they planted.
#[cfg(unix)]
fn owner_trusted(owner: u32, me: u32, dir_owner: u32) -> bool {
    owner == me || owner == dir_owner
}

/// This process's effective uid, without a libc call: the owner of a file
/// it makes, briefly, in `dir` (which it must be able to write to anyway,
/// for SQLite's -wal and -shm files).
#[cfg(unix)]
fn current_uid(dir: &Path) -> std::io::Result<u32> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNT: AtomicU64 = AtomicU64::new(0);
    let probe = dir.join(format!(
        ".monokulo-lws-uid-{}-{}",
        std::process::id(),
        COUNT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)?;
    let uid = file.metadata().map(|m| m.uid());
    drop(file);
    let _ = std::fs::remove_file(&probe);
    uid
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

    #[test]
    fn a_directory_every_user_can_write_is_refused_sticky_or_not() {
        for mode in [0o777, 0o1777, 0o703] {
            let dir = scratch(&format!("world-{mode:o}"));
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let path = dir.join("lws.sqlite");
            let err = prepare_db_file(&path).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{mode:o}");
            assert!(err.to_string().contains("every user"), "{err}");
            assert!(!path.exists(), "nothing made in a refused directory ({mode:o})");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn a_directory_others_can_only_read_is_used() {
        let dir = scratch("readable");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        prepare_db_file(&dir.join("lws.sqlite")).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn database_files_that_are_links_are_refused() {
        for suffix in ["", "-wal", "-shm"] {
            let dir = scratch(&format!("link{suffix}"));
            let path = dir.join("lws.sqlite");
            let target = dir.join("elsewhere");
            std::fs::write(&target, b"").unwrap();
            std::os::unix::fs::symlink(&target, format!("{}{suffix}", path.display())).unwrap();
            let err = prepare_db_file(&path).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{suffix}");
            assert!(err.to_string().contains("symbolic link"), "{err}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
        // A dangling link too: it would make the file wherever it points.
        let dir = scratch("dangling");
        let path = dir.join("lws.sqlite");
        std::os::unix::fs::symlink(dir.join("nowhere"), &path).unwrap();
        assert!(prepare_db_file(&path).is_err());
        assert!(!dir.join("nowhere").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_database_path_that_is_a_directory_is_refused() {
        let dir = scratch("notfile");
        let path = dir.join("lws.sqlite");
        std::fs::create_dir(format!("{}-wal", path.display())).unwrap();
        assert!(
            prepare_db_file(&path)
                .unwrap_err()
                .to_string()
                .contains("not a plain file")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_this_users_or_the_directory_owners_files_are_used() {
        // (Files owned by another uid can't be made without root, so the
        // rule is tested on its own.)
        assert!(owner_trusted(1000, 1000, 1000));
        assert!(owner_trusted(1000, 1000, 0), "its own file in another's directory");
        assert!(
            owner_trusted(101, 0, 101),
            "root on the server's database, in the server's folder"
        );
        assert!(!owner_trusted(1001, 1000, 1000), "a file another user planted");
        assert!(!owner_trusted(1001, 0, 101));
    }

    #[test]
    fn the_uid_probe_finds_this_process_and_leaves_nothing() {
        let dir = scratch("uid");
        let mine = dir.join("mine");
        std::fs::write(&mine, b"").unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(current_uid(&dir).unwrap(), std::fs::metadata(&mine).unwrap().uid());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
