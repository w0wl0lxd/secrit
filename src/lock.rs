//! The per-store write lock (PLAN section 8.1, step 4).
//!
//! The lock file is keyed by the store file's parent directory (device and
//! inode) and a hash of the file name. It is not keyed by the store file's
//! inode: every write renames a new inode over the file, so an inode key
//! would let two writers hold "the" lock at once.

use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{FlockOperation, Mode, OFlags, flock, openat};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

const POLL: Duration = Duration::from_millis(25);

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("XDG_RUNTIME_DIR is not set to an absolute path; secrit does not fall back to /tmp")]
    NoRuntimeDir,
    #[error("refusing lock directory {}: {reason}", path.display())]
    UnsafeDir { path: PathBuf, reason: &'static str },
    #[error("lock {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("timed out after {secs}s waiting for lock {}", path.display())]
    Timeout { path: PathBuf, secs: u64 },
    #[error("interrupted by a signal while waiting for the lock; nothing was written")]
    Interrupted,
}

/// A held lock. Dropping it closes the file, which releases the `flock`.
#[derive(Debug)]
pub struct StoreLock {
    _file: File,
}

/// Lower-case hex of `bytes`.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// The lock file path for `basename` in the directory `(dir_dev, dir_ino)`.
#[must_use]
pub fn lock_path(runtime_dir: &Path, dir_dev: u64, dir_ino: u64, basename: &OsStr) -> PathBuf {
    let digest = Sha256::digest(basename.as_bytes());
    let short = hex(&digest[..8]);
    runtime_dir
        .join("secrit")
        .join(format!("{dir_dev:x}-{dir_ino:x}-{short}.lock"))
}

/// Take an exclusive lock on `path`, waiting at most `timeout`.
pub fn acquire(path: &Path, timeout: Duration) -> Result<StoreLock, LockError> {
    let dir = path.parent().ok_or(LockError::NoRuntimeDir)?;
    ensure_private_dir(dir)?;
    let io = |e: std::io::Error| LockError::Io {
        path: path.to_path_buf(),
        source: e,
    };
    let fd = openat(
        rustix::fs::CWD,
        path,
        OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|e| io(e.into()))?;
    let deadline = Instant::now() + timeout;
    loop {
        match flock(&fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {
                return Ok(StoreLock {
                    _file: File::from(fd),
                });
            }
            Err(Errno::WOULDBLOCK | Errno::INTR) => {
                if crate::signals::pending() {
                    return Err(LockError::Interrupted);
                }
                if Instant::now() >= deadline {
                    return Err(LockError::Timeout {
                        path: path.to_path_buf(),
                        secs: timeout.as_secs(),
                    });
                }
                std::thread::sleep(POLL);
            }
            Err(e) => return Err(io(e.into())),
        }
    }
}

fn ensure_private_dir(dir: &Path) -> Result<(), LockError> {
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(LockError::Io {
                path: dir.to_path_buf(),
                source: e,
            });
        }
    }
    let meta = std::fs::symlink_metadata(dir).map_err(|e| LockError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    let bad = |reason| LockError::UnsafeDir {
        path: dir.to_path_buf(),
        reason,
    };
    if !meta.is_dir() {
        return Err(bad("not a directory (or a symlink)"));
    }
    if meta.uid() != rustix::process::getuid().as_raw() {
        return Err(bad("owned by another user"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(bad("readable or writable by group or others"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lock_path_is_stable_and_distinct() {
        let r = Path::new("/run/user/1000");
        let a = lock_path(r, 1, 2, OsStr::new("a.yaml"));
        assert_eq!(a, lock_path(r, 1, 2, OsStr::new("a.yaml")));
        assert_ne!(a, lock_path(r, 1, 2, OsStr::new("b.yaml")));
        assert_ne!(a, lock_path(r, 1, 3, OsStr::new("a.yaml")));
        assert!(a.starts_with("/run/user/1000/secrit"));
    }

    #[test]
    fn second_lock_times_out_until_first_drops() {
        let rt = tempfile::tempdir().unwrap();
        let p = lock_path(rt.path(), 1, 2, OsStr::new("s.yaml"));
        let first = acquire(&p, Duration::from_secs(1)).unwrap();
        let err = acquire(&p, Duration::from_millis(100)).unwrap_err();
        assert!(matches!(err, LockError::Timeout { .. }));
        drop(first);
        assert!(acquire(&p, Duration::from_millis(100)).is_ok());
        let mode = std::fs::metadata(p.parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn refuses_a_shared_lock_dir() {
        let rt = tempfile::tempdir().unwrap();
        let dir = rt.path().join("secrit");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = lock_path(rt.path(), 1, 2, OsStr::new("s.yaml"));
        assert!(matches!(
            acquire(&p, Duration::from_millis(10)),
            Err(LockError::UnsafeDir { .. })
        ));
    }
}
