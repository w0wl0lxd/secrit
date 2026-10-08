//! The write protocol for one store file (PLAN section 8.1; v0.2 plan 5.5).
//!
//! secrit never edits a store file in place. [`FileStore::write`] edits a
//! copy next to it under a lock, has the [`FileEdit`] validate the copy, and
//! renames it over the original. [`FileStore::create_new`] puts a new file
//! in place with `RENAME_NOREPLACE`, and [`FileStore::backup`] keeps a 0600
//! copy of the old file outside the store's repository. The format and the
//! tool belong to the [`FileEdit`]; this module knows neither.
//!
//! Every fsync goes through [`sync`], [`sync_path`] or
//! [`create_new_noreplace`], and every no-replace rename through
//! [`rename_noreplace`], so the macOS port (S17) changes only this file.

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::fs::{
    AtFlags, Dev, FileType, Mode, OFlags, RawMode, RenameFlags, fchmod, fstat, fsync, openat,
    renameat, renameat_with, unlinkat,
};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use super::{BackendError, MAX_RETRIES, WriteReport};
use crate::lock::{self, LockError};
use crate::signals;
use crate::testhook;

const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Backups kept for each store file; older ones are deleted.
const MAX_BACKUPS: usize = 10;
/// The mark in every temp copy name, after the store file name.
const TEMP_MARK: &str = ".secrit-";

/// One edit of a store file through [`FileStore::write`]. The store calls
/// the steps in this order on each try, and stops at the first error.
pub trait FileEdit {
    /// The parsed file.
    type Doc;
    /// The extension of the temp copy, without the dot. A tool that picks
    /// the format from the file name reads the copy as the store's format.
    fn temp_ext(&self) -> &'static str;
    /// Parse the original and check the edit against it, before any tool
    /// runs. `true` when the edit changes an entry that exists, so the old
    /// file gets a backup.
    fn precheck(&self, original: &[u8]) -> Result<(Self::Doc, bool), BackendError>;
    /// Run the tool on the temp copy at `tmp`.
    fn apply(&self, tmp: &Path) -> Result<(), BackendError>;
    /// Parse the copy that the tool wrote.
    fn parse(&self, copy: &[u8], path: &Path) -> Result<Self::Doc, BackendError>;
    /// Compare the copy with the original (PLAN 8.1, step 9).
    fn validate(&self, original: &Self::Doc, copy: &Self::Doc) -> Result<(), BackendError>;
    /// Read the new value back from the copy bytes.
    fn readback(&self, copy: &[u8]) -> Result<(), BackendError>;
}

/// One store file: where it is, where its lock and backups go.
#[derive(Debug)]
pub struct FileStore {
    file: PathBuf,
    dir: PathBuf,
    base: OsString,
    runtime_dir: Option<PathBuf>,
    backup_dir: Option<PathBuf>,
    lock_timeout: Duration,
}

/// The store file as one read saw it.
pub struct Snapshot {
    dev: Dev,
    ino: u64,
    size: u64,
    /// Seconds and nanoseconds. `i128` holds the nanoseconds of every
    /// platform (`u64` on Linux, `i64` on macOS).
    mtime: (i64, i128),
    mode: RawMode,
    hash: [u8; 32],
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl Snapshot {
    /// The same file, content, mtime and mode (PLAN 8.1, steps 5 and 11). A
    /// chmod between the snapshot and the rename would otherwise be lost by
    /// the `fchmod` of the copy (R12).
    fn same_as(&self, other: &Snapshot) -> bool {
        (
            self.dev, self.ino, self.size, self.mtime, self.mode, self.hash,
        ) == (
            other.dev,
            other.ino,
            other.size,
            other.mtime,
            other.mode,
            other.hash,
        )
    }
}

/// A backup file, kept open so a failed rename can remove it again.
#[derive(Debug)]
pub struct Backup {
    dir: OwnedFd,
    name: OsString,
    pub path: PathBuf,
}

impl Backup {
    /// Remove the backup again, best effort: the write that needed it failed.
    pub fn discard(&self) {
        let _ = unlinkat(&self.dir, &self.name, AtFlags::empty());
    }

    /// Delete the oldest backups of this store file, so that the newest
    /// [`MAX_BACKUPS`] remain. Best effort: a failed prune leaves extra
    /// backups, never a broken write.
    pub fn prune(&self) {
        let Some(dir) = self.path.parent() else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let names = entries
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.file_name())
            .collect();
        for name in backups_to_prune(names, MAX_BACKUPS) {
            let _ = unlinkat(&self.dir, &name, AtFlags::empty());
        }
    }
}

impl FileStore {
    /// `backup_root` holds one backup directory per store file; `None`
    /// fails every write that needs a backup.
    pub fn new(
        file: PathBuf,
        runtime_dir: Option<PathBuf>,
        backup_root: Option<&Path>,
        lock_timeout: Duration,
    ) -> Result<Self, BackendError> {
        let (Some(dir), Some(base)) = (file.parent(), file.file_name()) else {
            return Err(BackendError::Unsafe {
                path: file,
                reason: "the store path has no directory or file name".into(),
            });
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            base: base.to_os_string(),
            backup_dir: backup_root.map(|r| r.join(backup_key(&file, base))),
            file,
            runtime_dir,
            lock_timeout,
        })
    }

    pub fn file(&self) -> &Path {
        &self.file
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// This store file's backup directory.
    pub fn backup_dir(&self) -> Option<&Path> {
        self.backup_dir.as_deref()
    }

    /// The prefix of every temp copy name of this file.
    pub fn temp_prefix(&self) -> OsString {
        let mut p = OsString::from(".");
        p.push(&self.base);
        p.push(TEMP_MARK);
        p
    }

    /// The store directory checks of the write path (section 8.1, step 2).
    pub fn check_dir(&self) -> Result<(), BackendError> {
        let dir = self.open_dir()?;
        self.check_dir_fd(&dir).map(|_| ())
    }

    /// Read the store file. `strict` adds the write-path checks of the file
    /// (owner, mode, one link).
    pub fn read(&self, strict: bool) -> Result<Snapshot, BackendError> {
        let dir = self.open_dir()?;
        self.snapshot(&dir, strict)
    }

    /// Create the store file, which must not exist (PLAN section 4.6,
    /// step 4). `make` runs after the directory checks and gives the
    /// checked bytes. secrit writes them to a temp file, fsyncs it and
    /// renames it with `RENAME_NOREPLACE`, so an existing file is never
    /// replaced.
    pub fn create_new<B: AsRef<[u8]>>(
        &self,
        temp_ext: &str,
        make: impl FnOnce() -> Result<B, BackendError>,
    ) -> Result<(), BackendError> {
        let _critical = signals::Critical::enter();
        let dir = self.open_dir()?;
        self.check_dir_fd(&dir)?;
        let bytes = make()?;
        let tmp = TempCopy::create(&dir, &self.dir, &self.base, temp_ext, bytes.as_ref())?;
        let (fd, _) = read_entry(&dir, &tmp.name, &tmp.path, true)?;
        sync(&fd).map_err(|e| io_err("fsync the new store file", &tmp.path, e))?;
        if signals::pending() {
            return Err(BackendError::Interrupted);
        }
        rename_noreplace(&dir, &tmp.name, &dir, &self.base).map_err(|e| match e {
            Errno::EXIST => BackendError::Unsafe {
                path: self.file.clone(),
                reason: "it appeared while secrit created it; nothing was replaced".into(),
            },
            e => io_err("rename the new store file into place", &self.file, e),
        })?;
        tmp.disarm();
        sync(&dir).map_err(|e| io_err("fsync the store directory", &self.dir, e))
    }

    /// Run `edit` under the lock (PLAN 8.1). A change of the file under the
    /// edit starts it over, at most [`MAX_RETRIES`] times.
    pub fn write<E: FileEdit>(&self, edit: &E) -> Result<WriteReport, BackendError> {
        let runtime = self.runtime_dir.as_deref().ok_or(LockError::NoRuntimeDir)?;
        let dir = self.open_dir()?;
        let dst = self.check_dir_fd(&dir)?;
        let lock_path = lock::lock_path(runtime, dst.st_dev, dst.st_ino, &self.base);
        signals::defer().map_err(|e| BackendError::Io {
            step: "install signal handlers",
            path: self.file.clone(),
            source: e,
        })?;
        // Until the rename (or the cleanup) is done, a signal only sets the
        // flag that the lock wait, the tool wait and the protocol poll.
        let _critical = signals::Critical::enter();
        let _lock = lock::acquire(&lock_path, self.lock_timeout)?;
        testhook::hook("after-lock");
        // The first try, then at most MAX_RETRIES more (PLAN 8.1, step 11).
        for _ in 0..=MAX_RETRIES {
            if let Some(report) = self.attempt(&dir, edit)? {
                return Ok(report);
            }
        }
        Err(BackendError::Changed(self.file.clone()))
    }

    /// One pass of the write protocol. `Ok(None)` means the original changed
    /// under us and the caller should retry.
    fn attempt<E: FileEdit>(
        &self,
        dir: &OwnedFd,
        edit: &E,
    ) -> Result<Option<WriteReport>, BackendError> {
        // Steps 2 and 3 again, on the locked file: the directory may have
        // changed owner or mode while secrit waited for the lock (step 4).
        self.check_dir_fd(dir)?;
        let snap = self.snapshot(dir, true)?;
        let (doc, existed) = edit.precheck(&snap.bytes)?;

        let tmp = TempCopy::create(dir, &self.dir, &self.base, edit.temp_ext(), &snap.bytes)?;
        testhook::hook("after-copy");
        edit.apply(&tmp.path)?;
        // The hook name predates other tools than sops; tests use it.
        testhook::hook("after-sops");

        let (copy_fd, copy_bytes) = read_entry(dir, &tmp.name, &tmp.path, true)?;
        let copy = edit.parse(&copy_bytes, &tmp.path)?;
        edit.validate(&doc, &copy)?;
        edit.readback(&copy_bytes)?;
        sync(&copy_fd).map_err(|e| io_err("fsync the temp copy", &tmp.path, e))?;
        fchmod(&copy_fd, Mode::from_raw_mode(snap.mode))
            .map_err(|e| io_err("chmod the temp copy", &tmp.path, e))?;

        if !self.snapshot(dir, true)?.same_as(&snap) {
            return Ok(None);
        }
        testhook::hook("before-rename");
        if signals::pending() {
            return Err(BackendError::Interrupted);
        }
        let backup = if existed {
            Some(self.backup(&snap.bytes)?)
        } else {
            None
        };
        if let Err(e) = renameat(dir, &tmp.name, dir, &self.base) {
            if let Some(b) = &backup {
                b.discard();
            }
            return Err(io_err("rename the temp copy over", &self.file, e));
        }
        tmp.disarm();
        sync(dir).map_err(|e| io_err("fsync the store directory", &self.dir, e))?;
        let backup = backup.map(|b| {
            b.prune();
            b.path
        });
        Ok(Some(WriteReport { backup }))
    }

    /// Write a copy of the old file to the private backup directory,
    /// outside the store's repository (SEC-2).
    pub fn backup(&self, bytes: &[u8]) -> Result<Backup, BackendError> {
        let dir_path = self.backup_dir.as_ref().ok_or(BackendError::NoBackupDir)?;
        let dir = open_private_dir(dir_path)?;
        let stamp = utc_stamp(SystemTime::now());
        for i in 0..100 {
            let mut name = self.base.clone();
            name.push(format!(".{stamp}"));
            if i > 0 {
                name.push(format!("-{i:02}"));
            }
            let path = dir_path.join(&name);
            match create_exclusive(&dir, &name) {
                Ok(fd) => {
                    let mut f = File::from(fd);
                    let written = f.write_all(bytes).and_then(|()| f.sync_all());
                    let backup = Backup { dir, name, path };
                    if let Err(e) = written {
                        backup.discard();
                        return Err(BackendError::Io {
                            step: "write the backup",
                            path: backup.path,
                            source: e,
                        });
                    }
                    sync(&backup.dir)
                        .map_err(|e| io_err("fsync the backup directory", dir_path, e))?;
                    return Ok(backup);
                }
                Err(Errno::EXIST) => {}
                Err(e) => return Err(io_err("create the backup", &path, e)),
            }
        }
        Err(BackendError::Io {
            step: "create the backup",
            path: dir_path.clone(),
            source: io::Error::other("could not find a free backup file name"),
        })
    }

    fn open_dir(&self) -> Result<OwnedFd, BackendError> {
        openat(
            rustix::fs::CWD,
            &self.dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            Errno::LOOP | Errno::NOTDIR => BackendError::Unsafe {
                path: self.dir.clone(),
                reason: "the store directory is a symlink or not a directory".into(),
            },
            e => io_err("open the store directory", &self.dir, e),
        })
    }

    fn check_dir_fd(&self, dir: &OwnedFd) -> Result<rustix::fs::Stat, BackendError> {
        let st = fstat(dir).map_err(|e| io_err("stat the store directory", &self.dir, e))?;
        let unsafe_ = |reason: &str| BackendError::Unsafe {
            path: self.dir.clone(),
            reason: reason.into(),
        };
        if st.st_uid != rustix::process::getuid().as_raw() {
            return Err(unsafe_("the store directory is owned by another user"));
        }
        // A group member could rename or unlink the store file or the temp
        // copy in a group-writable directory, unless it is sticky (SEC-4).
        if st.st_mode & 0o022 != 0 && st.st_mode & 0o1000 == 0 {
            return Err(unsafe_(
                "the store directory is writable by group or others",
            ));
        }
        Ok(st)
    }

    /// Read the store file through `dir`. `strict` adds the write-path checks.
    fn snapshot(&self, dir: &OwnedFd, strict: bool) -> Result<Snapshot, BackendError> {
        let (fd, bytes) = read_entry(dir, &self.base, &self.file, strict).map_err(|e| match e {
            BackendError::Io {
                step: "open",
                source,
                ..
            } if source.kind() == io::ErrorKind::NotFound => {
                BackendError::NoStoreFile(self.file.clone())
            }
            e => e,
        })?;
        let st = fstat(&fd).map_err(|e| io_err("stat the store file", &self.file, e))?;
        Ok(Snapshot {
            dev: st.st_dev,
            ino: st.st_ino,
            size: u64::try_from(st.st_size).unwrap_or(0),
            mtime: (st.st_mtime, i128::from(st.st_mtime_nsec)),
            mode: st.st_mode & 0o7777,
            hash: Sha256::digest(&bytes).into(),
            bytes,
        })
    }
}

/// fsync `fd`.
pub fn sync(fd: impl AsFd) -> Result<(), Errno> {
    fsync(fd)
}

/// Open `path` (a file or a directory) and fsync it. std's `sync_all` is
/// `F_FULLFSYNC` on Apple already.
pub fn sync_path(path: &Path) -> io::Result<()> {
    File::open(path).and_then(|f| f.sync_all())
}

/// Rename `old` in `old_dir` to `new` in `new_dir`, and fail with
/// `EEXIST` when `new` exists.
pub fn rename_noreplace<P: rustix::path::Arg, Q: rustix::path::Arg>(
    old_dir: impl AsFd,
    old: P,
    new_dir: impl AsFd,
    new: Q,
) -> Result<(), Errno> {
    renameat_with(old_dir, old, new_dir, new, RenameFlags::NOREPLACE)
}

/// Create `path` with `O_EXCL` and `O_NOFOLLOW`, write `bytes` and fsync.
/// A failed write removes the file again.
pub fn create_new_noreplace(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let _critical = signals::Critical::enter();
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// The per-store backup directory name: a hash of the store path, so two
/// stores with the same file name do not share it, plus the file name.
fn backup_key(file: &Path, base: &OsStr) -> OsString {
    let digest = Sha256::digest(file.as_os_str().as_bytes());
    let mut key = OsString::from(format!("{}-", lock::hex(&digest[..4])));
    key.push(base);
    key
}

/// Create `path` (mode 0700) if needed and open it. It must be a directory
/// that only this user can read or write.
fn open_private_dir(path: &Path) -> Result<OwnedFd, BackendError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| BackendError::Io {
            step: "create the backup directory",
            path: path.to_path_buf(),
            source: e,
        })?;
    let unsafe_ = |reason: &str| BackendError::Unsafe {
        path: path.to_path_buf(),
        reason: reason.into(),
    };
    let dir = openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::NOTDIR => unsafe_("the backup directory is a symlink"),
        e => io_err("open the backup directory", path, e),
    })?;
    let st = fstat(&dir).map_err(|e| io_err("stat the backup directory", path, e))?;
    if st.st_uid != rustix::process::getuid().as_raw() || st.st_mode & 0o077 != 0 {
        return Err(unsafe_(
            "the backup directory must be owned by you with mode 0700",
        ));
    }
    Ok(dir)
}

/// The backups to delete so that the newest `keep` remain. Names sort by
/// time: `<base>.<UTC stamp>[-NN]`.
fn backups_to_prune(mut names: Vec<OsString>, keep: usize) -> Vec<OsString> {
    names.sort();
    let excess = names.len().saturating_sub(keep);
    names.truncate(excess);
    names
}

fn io_err(step: &'static str, path: &Path, e: Errno) -> BackendError {
    BackendError::Io {
        step,
        path: path.to_path_buf(),
        source: e.into(),
    }
}

fn create_exclusive(dir: &OwnedFd, name: &OsStr) -> Result<OwnedFd, Errno> {
    openat(
        dir,
        name,
        OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )
}

/// Open `name` in `dir` without following a symlink and read it whole.
fn read_entry(
    dir: &OwnedFd,
    name: &OsStr,
    path: &Path,
    strict: bool,
) -> Result<(OwnedFd, Vec<u8>), BackendError> {
    let unsafe_ = |reason: &str| BackendError::Unsafe {
        path: path.to_path_buf(),
        reason: reason.into(),
    };
    let fd = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP => unsafe_("it is a symlink"),
        e => io_err("open", path, e),
    })?;
    let st = fstat(&fd).map_err(|e| io_err("stat", path, e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(unsafe_("not a regular file"));
    }
    if strict {
        if st.st_uid != rustix::process::getuid().as_raw() {
            return Err(unsafe_("owned by another user"));
        }
        if st.st_mode & 0o022 != 0 {
            return Err(unsafe_("writable by group or others"));
        }
        if st.st_nlink != 1 {
            return Err(unsafe_("it has more than one hard link"));
        }
    }
    let mut bytes = Vec::new();
    let mut f = File::from(fd);
    (&mut f)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| BackendError::Io {
            step: "read",
            path: path.to_path_buf(),
            source: e,
        })?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(unsafe_("larger than 16 MiB"));
    }
    Ok((OwnedFd::from(f), bytes))
}

/// A temp copy name of `file` with a fixed random part, to ask git whether
/// it ignores temp copies (PLAN 8.1, step 6).
pub fn temp_sample(file: &Path, ext: &str) -> PathBuf {
    file.with_file_name(temp_name(
        file.file_name().unwrap_or_default(),
        "0000000000000000",
        ext,
    ))
}

/// `.<base>.secrit-<random>.<ext>`: hidden, next to the store file, and
/// with the store's extension.
fn temp_name(base: &OsStr, random: &str, ext: &str) -> OsString {
    let mut raw = b".".to_vec();
    raw.extend_from_slice(base.as_bytes());
    raw.extend_from_slice(format!("{TEMP_MARK}{random}.{ext}").as_bytes());
    OsString::from_vec(raw)
}

/// A ciphertext copy next to the store file. Dropping it unlinks it unless
/// it was renamed into place.
struct TempCopy {
    dir: OwnedFd,
    name: OsString,
    path: PathBuf,
    armed: bool,
}

impl TempCopy {
    fn create(
        dir: &OwnedFd,
        dir_path: &Path,
        base: &OsStr,
        ext: &str,
        bytes: &[u8],
    ) -> Result<Self, BackendError> {
        let dup = dir.try_clone().map_err(|e| BackendError::Io {
            step: "duplicate the directory handle",
            path: dir_path.to_path_buf(),
            source: e,
        })?;
        for _ in 0..8 {
            let mut rnd = [0u8; 8];
            getrandom::fill(&mut rnd).map_err(|_| BackendError::Io {
                step: "name the temp copy",
                path: dir_path.to_path_buf(),
                source: io::Error::other("no randomness for the temp name"),
            })?;
            let name = temp_name(base, &lock::hex(&rnd), ext);
            let path = dir_path.join(&name);
            match create_exclusive(dir, &name) {
                Ok(fd) => {
                    let copy = Self {
                        dir: dup,
                        name,
                        path,
                        armed: true,
                    };
                    let mut f = File::from(fd);
                    f.write_all(bytes).map_err(|e| BackendError::Io {
                        step: "write the temp copy",
                        path: copy.path.clone(),
                        source: e,
                    })?;
                    return Ok(copy);
                }
                Err(Errno::EXIST) => {}
                Err(e) => return Err(io_err("create the temp copy", &path, e)),
            }
        }
        Err(BackendError::Io {
            step: "create the temp copy",
            path: dir_path.to_path_buf(),
            source: io::Error::other("could not find a free temp file name"),
        })
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for TempCopy {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlinkat(&self.dir, &self.name, AtFlags::empty());
        }
    }
}

fn utc_stamp(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (y, m, d) = civil_from_days(i64::try_from(secs / 86_400).unwrap_or(0));
    let rem = secs % 86_400;
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (H. Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_stamp_known_dates() {
        assert_eq!(utc_stamp(UNIX_EPOCH), "19700101T000000Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400 + 3_723);
        assert_eq!(utc_stamp(leap), "20000229T010203Z");
        let d = UNIX_EPOCH + Duration::from_secs(1_791_331_199);
        assert_eq!(utc_stamp(d), "20261006T235959Z");
    }

    #[test]
    fn backups_keep_the_newest() {
        let names: Vec<OsString> = [
            "m.yaml.20261006T120000Z",
            "m.yaml.20261006T120000Z-01",
            "m.yaml.20251231T235959Z",
            "m.yaml.20261007T000000Z",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        assert_eq!(
            backups_to_prune(names.clone(), 2),
            [
                OsString::from("m.yaml.20251231T235959Z"),
                OsString::from("m.yaml.20261006T120000Z"),
            ]
        );
        assert!(backups_to_prune(names, MAX_BACKUPS).is_empty());
    }

    #[test]
    fn backup_dirs_differ_per_store_path() {
        let a = backup_key(Path::new("/a/s/main.yaml"), OsStr::new("main.yaml"));
        let b = backup_key(Path::new("/b/s/main.yaml"), OsStr::new("main.yaml"));
        assert_ne!(a, b);
        assert!(a.to_string_lossy().ends_with("-main.yaml"));
        assert_eq!(a.len(), 8 + 1 + "main.yaml".len());
    }

    #[test]
    fn same_as_compares_the_mode_and_mtime() {
        let snap = |mode, mtime| Snapshot {
            dev: 1,
            ino: 2,
            size: 3,
            mtime,
            mode,
            hash: [0; 32],
            bytes: Vec::new(),
        };
        assert!(snap(0o600, (5, 6)).same_as(&snap(0o600, (5, 6))));
        assert!(!snap(0o600, (5, 6)).same_as(&snap(0o640, (5, 6))));
        assert!(!snap(0o600, (5, 6)).same_as(&snap(0o600, (5, 7))));
    }

    /// The temp copy and the git sample share one name shape, so the
    /// `.gitignore` probe asks about the names that writes use.
    #[test]
    fn temp_names_have_the_v01_shape() {
        let store = FileStore::new("/s/main.yaml".into(), None, None, Duration::ZERO).unwrap();
        assert_eq!(
            temp_sample(store.file(), "yaml"),
            Path::new("/s/.main.yaml.secrit-0000000000000000.yaml")
        );
        assert_eq!(store.temp_prefix(), ".main.yaml.secrit-");
        assert_eq!(
            temp_name(OsStr::new("m.yaml"), "00aa", "yaml"),
            ".m.yaml.secrit-00aa.yaml"
        );
    }
}
