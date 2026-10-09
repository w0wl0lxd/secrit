//! The pass layout backend (v0.2 plan 6.4).
//!
//! One gpg file per name: `<dir>/<prefix>/<name>.gpg`, encrypted to the
//! keys of the nearest `.gpg-id`. secrit runs gpg itself, never `pass` or
//! `gopass`, and never commits. A write encrypts the value plus one `\n`
//! to a temp copy, checks the copy's recipient packets without decrypting
//! it, and renames it into place through [`FileStore`]. `gpg.rs` runs gpg,
//! and `doctor.rs` gives the `doctor` rows of a pass store.
//!
//! Names have one segment until S5. `list` already reports nested entries
//! (`a/b`) that pass or gopass wrote.

mod doctor;
mod gpg;

use std::collections::BTreeSet;
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, fstat, openat, statat, unlinkat};
use rustix::io::Errno;
use zeroize::{Zeroize, Zeroizing};

use self::gpg::{Gpg, Recipient};
use super::atomic::{self, FileEdit, FileStore};
use super::{Backend, BackendError, DoctorCtx, Location, PutMode, Target, WriteReport};
use crate::config::{BackendKind, Env, PassStore, PassValue, Pinentry};
use crate::lock::{self, LockError};
use crate::name::Name;
use crate::report::Report;
use crate::secret::SecretValue;
use crate::{agent, paths, signals, testhook};

/// The extension of an entry and of its temp copy.
const EXT: &str = "gpg";
const GPG_ID: &str = ".gpg-id";
const GPG_ID_SIG: &str = ".gpg-id.sig";
const MAX_GPG_ID_BYTES: u64 = 64 * 1024;
/// The deepest subdirectory that `list` walks into.
const MAX_DEPTH: usize = 8;
const FIRST_LINE_RULE: &str =
    "the store sets value = \"first-line\", so the value must be one line with no newline";

#[derive(Debug)]
pub struct PassBackend {
    /// The password-store directory: the root `.gpg-id` lives here.
    root: PathBuf,
    /// `root` plus the prefix: the entries of this store.
    entries: PathBuf,
    location: Location,
    gpg: Gpg,
    value: PassValue,
    pinentry: Pinentry,
    runtime_dir: Option<PathBuf>,
    backup_root: Option<PathBuf>,
    lock_timeout: Duration,
}

/// The recipient packets of an entry.
#[derive(Debug, Default)]
struct Packets {
    ids: BTreeSet<String>,
    symkey: bool,
}

impl PassBackend {
    /// `env` supplies `GNUPGHOME`, `HOME`, `XDG_STATE_HOME` and
    /// `XDG_RUNTIME_DIR`.
    pub fn new(
        store: &PassStore,
        gpg: PathBuf,
        lock_timeout: Duration,
        env: &Env,
    ) -> Result<Self, BackendError> {
        let abs = |k: &str| env(k).map(PathBuf::from).filter(|p| p.is_absolute());
        let gnupg_home = store
            .gnupg_home
            .clone()
            .or_else(|| abs("GNUPGHOME"))
            .or_else(|| abs("HOME").map(|h| h.join(".gnupg")))
            .ok_or(BackendError::NoGnupgHome)?;
        let entries = store.entries_dir();
        Ok(Self {
            root: store.dir.clone(),
            location: Location::Dir(entries.clone()),
            entries,
            gpg: Gpg::new(gpg, gnupg_home),
            value: store.value,
            pinentry: store.pinentry,
            runtime_dir: paths::runtime_dir(env),
            backup_root: paths::backup_dir(env),
            lock_timeout,
        })
    }

    pub fn entries(&self) -> &Path {
        &self.entries
    }

    /// The version that `gpg --version` reports.
    pub fn gpg_version(&self) -> Result<(u64, u64, u64), BackendError> {
        self.gpg.version(&self.target(None))
    }

    /// The checks of `secrit init`: the directory, the `.gpg-id` of the
    /// entries, and its recipients. Returns each `.gpg-id` line with the
    /// fingerprint that it resolves to.
    pub fn check_setup(&self) -> Result<(PathBuf, Vec<(String, String)>), BackendError> {
        self.check_root()?;
        let gpg_id = self.gpg_id(&self.entries)?;
        let lines = read_gpg_id(&gpg_id)?;
        let mut found = Vec::new();
        for line in lines {
            let r = self.resolve_line(&gpg_id, &line, &self.target(None))?;
            found.push((line, r.fpr));
        }
        Ok((gpg_id, found))
    }

    fn target(&self, name: Option<&Name>) -> Target {
        Target {
            location: self.location.clone(),
            name: name.cloned(),
        }
    }

    fn entry_path(&self, name: &Name) -> PathBuf {
        self.entries.join(format!("{}.{EXT}", name.as_str()))
    }

    fn file_store(&self, name: &Name) -> Result<FileStore, BackendError> {
        FileStore::new(
            self.entry_path(name),
            self.runtime_dir.clone(),
            self.backup_root.as_deref(),
            self.lock_timeout,
        )
    }

    fn missing(&self, name: &Name) -> BackendError {
        BackendError::Missing {
            name: name.clone(),
            location: self.location.clone(),
        }
    }

    fn check_root(&self) -> Result<(), BackendError> {
        match std::fs::metadata(&self.root) {
            Ok(m) if m.is_dir() => Ok(()),
            Ok(_) => Err(BackendError::Unsafe {
                path: self.root.clone(),
                reason: "the store directory is not a directory".into(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(BackendError::NoStoreDir(self.root.clone()))
            }
            Err(e) => Err(BackendError::Io {
                step: "stat the store directory",
                path: self.root.clone(),
                source: e,
            }),
        }
    }

    /// Whether the entry of `name` exists, without following a symlink.
    fn entry_exists(&self, name: &Name) -> Result<bool, BackendError> {
        let path = self.entry_path(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(BackendError::Io {
                step: "stat",
                path,
                source: e,
            }),
        }
    }

    /// The nearest `.gpg-id` from `dir` up to the store directory, as pass
    /// finds it. `dir` need not exist yet.
    fn gpg_id(&self, dir: &Path) -> Result<PathBuf, BackendError> {
        dir.ancestors()
            .take_while(|a| a.starts_with(&self.root))
            .map(|a| a.join(GPG_ID))
            .find(|p| std::fs::symlink_metadata(p).is_ok())
            .ok_or_else(|| BackendError::NoGpgId(dir.to_path_buf()))
    }

    /// pass signing (`.gpg-id.sig`) refuses every write: secrit cannot
    /// check the signature yet.
    fn refuse_signed(gpg_id: &Path) -> Result<(), BackendError> {
        let sig = gpg_id.with_file_name(GPG_ID_SIG);
        if std::fs::symlink_metadata(&sig).is_ok() {
            return Err(BackendError::Unsafe {
                path: sig,
                reason: "pass signs the .gpg-id of this store, and secrit cannot check the signature yet, so it refuses every write (reads still work)".into(),
            });
        }
        Ok(())
    }

    /// The signature check for the entry of `name`, when it has a
    /// `.gpg-id`.
    fn refuse_signed_entry(&self, name: &Name) -> Result<(), BackendError> {
        match self.gpg_id(&self.entry_dir(name)) {
            Ok(p) => Self::refuse_signed(&p),
            Err(_) => Ok(()),
        }
    }

    fn entry_dir(&self, name: &Name) -> PathBuf {
        self.entry_path(name)
            .parent()
            .map_or_else(|| self.entries.clone(), Path::to_path_buf)
    }

    fn resolve_line(
        &self,
        gpg_id: &Path,
        line: &str,
        target: &Target,
    ) -> Result<Recipient, BackendError> {
        self.gpg
            .resolve(line, target)?
            .map_err(|why| BackendError::Recipient {
                path: gpg_id.to_path_buf(),
                entry: line.to_owned(),
                reason: why.reason(),
            })
    }

    /// The keys that the entry of `name` is encrypted to. Runs before the
    /// value is read, and decrypts nothing.
    fn recipients(&self, name: &Name) -> Result<Vec<Recipient>, BackendError> {
        self.check_root()?;
        let gpg_id = self.gpg_id(&self.entry_dir(name))?;
        Self::refuse_signed(&gpg_id)?;
        let target = self.target(Some(name));
        let mut keys: Vec<Recipient> = Vec::new();
        for line in read_gpg_id(&gpg_id)? {
            let r = self.resolve_line(&gpg_id, &line, &target)?;
            if !keys.iter().any(|k| k.fpr == r.fpr) {
                keys.push(r);
            }
        }
        Ok(keys)
    }

    /// The packet check of an entry copy (T35): every packet names an
    /// encryption key of a `.gpg-id` key, every `.gpg-id` key has a packet,
    /// and no passphrase opens it.
    fn check_packets(
        &self,
        name: &Name,
        packets: &Packets,
        recipients: &[Recipient],
    ) -> Result<(), BackendError> {
        let fail = |reason: String| BackendError::Validation {
            target: self.target(Some(name)),
            reason,
        };
        if packets.symkey {
            return Err(fail("the copy can also be opened with a passphrase".into()));
        }
        if packets.ids.is_empty() {
            return Err(fail("the copy names no recipient key".into()));
        }
        let named: BTreeSet<&String> = recipients.iter().flat_map(|r| &r.enc_ids).collect();
        let extra: Vec<&str> = packets
            .ids
            .iter()
            .filter(|id| !named.contains(id))
            .map(String::as_str)
            .collect();
        if !extra.is_empty() {
            return Err(fail(format!(
                "the copy is encrypted to key IDs that .gpg-id does not name: {}",
                extra.join(", ")
            )));
        }
        if let Some(r) = recipients
            .iter()
            .find(|r| r.enc_ids.is_disjoint(&packets.ids))
        {
            return Err(fail(format!(
                "the copy is not encrypted to the .gpg-id key {}",
                r.fpr
            )));
        }
        Ok(())
    }

    fn packets(&self, bytes: &[u8], name: &Name) -> Result<Packets, BackendError> {
        let (ids, symkey) = self.gpg.packets(bytes, &self.target(Some(name)))?;
        Ok(Packets { ids, symkey })
    }

    /// The new entry bytes for `plaintext`, checked.
    fn encrypt(
        &self,
        name: &Name,
        plaintext: &[u8],
        value: &[u8],
        recipients: &[Recipient],
    ) -> Result<Vec<u8>, BackendError> {
        let mut out = self
            .gpg
            .encrypt(plaintext, recipients, value, &self.target(Some(name)))?;
        let bytes = std::mem::take(&mut *out);
        let packets = self.packets(&bytes, name)?;
        self.check_packets(name, &packets, recipients)?;
        Ok(bytes)
    }

    /// `mkdir -p` with mode 0700 for the directory of a new entry, inside
    /// a store directory that exists.
    fn make_entry_dir(&self, name: &Name) -> Result<(), BackendError> {
        let dir = self.entry_dir(name);
        if dir.is_dir() {
            return Ok(());
        }
        let _critical = signals::Critical::enter();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| BackendError::Io {
                step: "create the directory",
                path: dir,
                source: e,
            })
    }

    /// Whether `get` lets gpg-agent start a pinentry: only when the store
    /// asks for it, no agent is detected and `/dev/tty` opens.
    fn agent_pinentry(&self) -> bool {
        self.pinentry == Pinentry::Agent && agent::detect().is_none()
    }

    fn remove_locked(&self, name: &Name) -> Result<WriteReport, BackendError> {
        let store = self.file_store(name)?;
        let file = store.file().to_path_buf();
        let base = file.file_name().unwrap_or_default().to_os_string();
        let runtime = self.runtime_dir.as_deref().ok_or(LockError::NoRuntimeDir)?;
        store.check_dir()?;
        let dir = open_dir(store.dir())?;
        let st = fstat(&dir).map_err(|e| io_err("stat the store directory", store.dir(), e))?;
        let lock_path = lock::lock_path(runtime, st.st_dev, st.st_ino, &base);
        signals::defer().map_err(|e| BackendError::Io {
            step: "install signal handlers",
            path: file.clone(),
            source: e,
        })?;
        let _critical = signals::Critical::enter();
        let _lock = lock::acquire(&lock_path, self.lock_timeout)?;
        testhook::hook("after-lock");
        store.check_dir()?;
        let snap = store.read(true).map_err(|e| match e {
            BackendError::NoStoreFile(_) => self.missing(name),
            e => e,
        })?;
        let backup = store.backup(&snap.bytes)?;
        if signals::pending() {
            backup.discard();
            return Err(BackendError::Interrupted);
        }
        if let Err(e) = unlinkat(&dir, &base, AtFlags::empty()) {
            backup.discard();
            return Err(io_err("remove", &file, e));
        }
        atomic::sync(&dir).map_err(|e| io_err("fsync the store directory", store.dir(), e))?;
        backup.prune();
        Ok(WriteReport {
            backup: Some(backup.path),
        })
    }
}

impl Backend for PassBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Pass
    }

    fn location(&self) -> &Location {
        &self.location
    }

    fn list(&self) -> Result<Vec<String>, BackendError> {
        self.check_root()?;
        let dir = match open_dir(&self.entries) {
            Ok(d) => d,
            Err(BackendError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };
        let mut names = Vec::new();
        walk(&dir, &self.entries, "", 0, &mut names)?;
        names.sort();
        Ok(names)
    }

    fn exists(&self, name: &Name) -> Result<bool, BackendError> {
        self.check_root()?;
        self.entry_exists(name)
    }

    fn check_put(&self, name: &Name, mode: PutMode) -> Result<(), BackendError> {
        self.recipients(name)?;
        if mode == PutMode::CreateOnly && self.entry_exists(name)? {
            return Err(BackendError::Exists {
                name: name.clone(),
                location: self.location.clone(),
            });
        }
        Ok(())
    }

    fn check_remove(&self, name: &Name) -> Result<(), BackendError> {
        self.check_root()?;
        self.refuse_signed_entry(name)?;
        if self.entry_exists(name)? {
            Ok(())
        } else {
            Err(self.missing(name))
        }
    }

    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError> {
        self.check_root()?;
        let pinentry = self.agent_pinentry();
        names
            .iter()
            .map(|n| {
                let snap = self.file_store(n)?.read(false).map_err(|e| match e {
                    BackendError::NoStoreFile(_) => self.missing(n),
                    e => e,
                })?;
                let mut plain = self
                    .gpg
                    .decrypt(&snap.bytes, pinentry, &self.target(Some(n)))?;
                let value = pass_value(std::mem::take(&mut *plain), self.value);
                Ok((n.clone(), SecretValue::new(value)))
            })
            .collect()
    }

    fn put(
        &self,
        name: &Name,
        value: &SecretValue,
        mode: PutMode,
    ) -> Result<WriteReport, BackendError> {
        let bytes = value.expose();
        if self.value == PassValue::FirstLine && bytes.contains(&b'\n') {
            return Err(BackendError::ValueRefused {
                name: name.clone(),
                location: self.location.clone(),
                reason: FIRST_LINE_RULE,
            });
        }
        let recipients = self.recipients(name)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(bytes.len() + 1));
        plaintext.extend_from_slice(bytes);
        plaintext.push(b'\n');
        let exists = self.entry_exists(name)?;
        if exists && mode == PutMode::CreateOnly {
            return Err(BackendError::Exists {
                name: name.clone(),
                location: self.location.clone(),
            });
        }
        let store = self.file_store(name)?;
        if exists {
            return store.write(&PassEdit {
                backend: self,
                name,
                plaintext: &plaintext,
                value: bytes,
                recipients: &recipients,
            });
        }
        self.make_entry_dir(name)?;
        store.create_new(EXT, || self.encrypt(name, &plaintext, bytes, &recipients))?;
        Ok(WriteReport::default())
    }

    fn remove(&self, name: &Name) -> Result<WriteReport, BackendError> {
        self.check_root()?;
        self.refuse_signed_entry(name)?;
        self.remove_locked(name)
    }

    fn doctor(&self, report: &mut Report, ctx: &DoctorCtx<'_>) {
        doctor::rows(report, self, ctx);
    }

    fn commit_hint(&self, name: &Name) -> Option<PathBuf> {
        Some(self.entry_path(name))
    }
}

/// One `store --replace` of a pass entry through [`FileStore::write`].
struct PassEdit<'a> {
    backend: &'a PassBackend,
    name: &'a Name,
    plaintext: &'a [u8],
    value: &'a [u8],
    recipients: &'a [Recipient],
}

impl FileEdit for PassEdit<'_> {
    type Doc = Packets;

    fn temp_ext(&self) -> &'static str {
        EXT
    }

    /// The old entry is replaced whole, so its packets do not matter.
    fn precheck(&self, _original: &[u8]) -> Result<(Packets, bool), BackendError> {
        Ok((Packets::default(), true))
    }

    fn apply(&self, tmp: &Path) -> Result<(), BackendError> {
        let mut out = self.backend.gpg.encrypt(
            self.plaintext,
            self.recipients,
            self.value,
            &self.backend.target(Some(self.name)),
        )?;
        let written = OpenOptions::new()
            .write(true)
            .truncate(true)
            .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits().cast_signed())
            .open(tmp)
            .and_then(|mut f| f.write_all(&out));
        out.zeroize();
        written.map_err(|e| BackendError::Io {
            step: "write the temp copy",
            path: tmp.to_path_buf(),
            source: e,
        })
    }

    fn parse(&self, copy: &[u8], _path: &Path) -> Result<Packets, BackendError> {
        self.backend.packets(copy, self.name)
    }

    fn validate(&self, _original: &Packets, copy: &Packets) -> Result<(), BackendError> {
        self.backend.check_packets(self.name, copy, self.recipients)
    }

    /// A read back would need the secret key and maybe its passphrase; the
    /// packet check stands in for it.
    fn readback(&self, _copy: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }
}

/// The value of a decrypted entry: the whole file minus one trailing
/// newline, or the bytes before the first newline. The cut-off bytes are
/// zeroized.
fn pass_value(mut bytes: Vec<u8>, rule: PassValue) -> Vec<u8> {
    let cut = match rule {
        PassValue::Whole => bytes.len() - usize::from(bytes.last() == Some(&b'\n')),
        PassValue::FirstLine => bytes
            .iter()
            .position(|b| *b == b'\n')
            .unwrap_or(bytes.len()),
    };
    bytes[cut..].zeroize();
    bytes.truncate(cut);
    bytes
}

/// The `.gpg-id` lines: `#` starts a comment, and blank lines are skipped.
/// The file must be a regular file that only its owner (this user) can
/// write, because it picks who can read every new entry.
fn read_gpg_id(path: &Path) -> Result<Vec<String>, BackendError> {
    let unsafe_ = |reason: &str| BackendError::Unsafe {
        path: path.to_path_buf(),
        reason: reason.into(),
    };
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(
            (OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK)
                .bits()
                .cast_signed(),
        )
        .open(path)
        .map_err(|e| match Errno::from_io_error(&e) {
            Some(Errno::LOOP) => unsafe_("it is a symlink"),
            _ => BackendError::Io {
                step: "open",
                path: path.to_path_buf(),
                source: e,
            },
        })?;
    let m = f.metadata().map_err(|e| BackendError::Io {
        step: "stat",
        path: path.to_path_buf(),
        source: e,
    })?;
    if !m.is_file() {
        return Err(unsafe_("not a regular file"));
    }
    if m.uid() != rustix::process::getuid().as_raw() {
        return Err(unsafe_("owned by another user"));
    }
    if m.mode() & 0o022 != 0 {
        return Err(unsafe_("writable by group or others"));
    }
    let mut text = String::new();
    f.take(MAX_GPG_ID_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| BackendError::Io {
            step: "read",
            path: path.to_path_buf(),
            source: e,
        })?;
    if text.len() as u64 > MAX_GPG_ID_BYTES {
        return Err(unsafe_("larger than 64 KiB"));
    }
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect();
    if lines.is_empty() {
        return Err(BackendError::Parse {
            location: Location::File(path.to_path_buf()),
            format: ".gpg-id file",
            what: "it names no key".into(),
        });
    }
    Ok(lines)
}

fn io_err(step: &'static str, path: &Path, e: Errno) -> BackendError {
    BackendError::Io {
        step,
        path: path.to_path_buf(),
        source: e.into(),
    }
}

fn open_dir(path: &Path) -> Result<OwnedFd, BackendError> {
    openat(
        rustix::fs::CWD,
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::NOTDIR => BackendError::Unsafe {
            path: path.to_path_buf(),
            reason: "the store directory is a symlink or not a directory".into(),
        },
        e => io_err("open the store directory", path, e),
    })
}

/// Collect the entry names under `dir` (at `path`), with `prefix` before
/// each. Hidden names and symlinks are skipped, and nothing is followed or
/// decrypted.
fn walk(
    dir: &OwnedFd,
    path: &Path,
    prefix: &str,
    depth: usize,
    names: &mut Vec<String>,
) -> Result<(), BackendError> {
    let entries = Dir::read_from(dir).map_err(|e| io_err("read the directory", path, e))?;
    let mut subdirs: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| io_err("read the directory", path, e))?;
        let Some(name) = visible_name(entry.file_name()) else {
            continue;
        };
        let kind = match entry.file_type() {
            FileType::Unknown => statat(dir, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map(|st| FileType::from_raw_mode(st.st_mode))
                .map_err(|e| io_err("stat", &path.join(&name), e))?,
            k => k,
        };
        match kind {
            FileType::Directory => subdirs.push(name),
            FileType::RegularFile => {
                if let Some(stem) = name.strip_suffix(".gpg").filter(|s| !s.is_empty()) {
                    names.push(format!("{prefix}{stem}"));
                }
            }
            _ => {}
        }
    }
    if depth + 1 >= MAX_DEPTH {
        return Ok(());
    }
    for sub in subdirs {
        let sub_path = path.join(&sub);
        let fd = match openat(
            dir,
            sub.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            // Replaced by a symlink or removed since the read: skip it.
            Err(Errno::LOOP | Errno::NOTDIR | Errno::NOENT) => continue,
            Err(e) => return Err(io_err("open the directory", &sub_path, e)),
        };
        walk(&fd, &sub_path, &format!("{prefix}{sub}/"), depth + 1, names)?;
    }
    Ok(())
}

/// The UTF-8 name of a directory entry, or `None` for `.`, `..`, a hidden
/// name or a name that is not UTF-8.
fn visible_name(raw: &CStr) -> Option<String> {
    let name = raw.to_str().ok()?;
    (!name.starts_with('.')).then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_value_rule_cuts_one_newline_or_the_first_line() {
        let cases: [(&[u8], PassValue, &[u8]); 7] = [
            (b"pw\n", PassValue::Whole, b"pw"),
            (b"pw", PassValue::Whole, b"pw"),
            (b"pw\n\n", PassValue::Whole, b"pw\n"),
            (b"pw\nlogin: a\n", PassValue::Whole, b"pw\nlogin: a"),
            (b"pw\nlogin: a\n", PassValue::FirstLine, b"pw"),
            (b"pw", PassValue::FirstLine, b"pw"),
            (b"", PassValue::Whole, b""),
        ];
        for (input, rule, want) in cases {
            assert_eq!(pass_value(input.to_vec(), rule), want, "{input:?}");
        }
    }

    #[test]
    fn gpg_id_lines_skip_comments_and_blanks() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(GPG_ID);
        std::fs::write(&p, "# team\n\n a@x.test \nB0B # bob\n#\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_gpg_id(&p).unwrap(), ["a@x.test", "B0B"]);

        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o620)).unwrap();
        let e = read_gpg_id(&p).unwrap_err();
        assert!(matches!(e, BackendError::Unsafe { .. }), "{e}");

        std::fs::write(&p, "# only a comment\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            read_gpg_id(&p)
                .unwrap_err()
                .to_string()
                .contains("names no key")
        );
    }

    fn backend(root: &Path, prefix: Option<&str>) -> PassBackend {
        let store = PassStore {
            dir: root.to_path_buf(),
            prefix: prefix.map(str::to_owned),
            gnupg_home: Some(root.join("gnupg")),
            value: PassValue::Whole,
            pinentry: Pinentry::Error,
        };
        PassBackend::new(&store, "/nonexistent/gpg".into(), Duration::ZERO, &|_| None).unwrap()
    }

    /// `list` walks the entries with no gpg run (the gpg path does not
    /// exist), skips hidden names, symlinks and other files, and treats a
    /// missing prefix directory as empty.
    #[test]
    fn list_walks_entries_without_gpg() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        std::fs::create_dir_all(root.join("x/y")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        for f in [
            "one.gpg",
            "x/three.gpg",
            "x/y/four.gpg",
            ".hidden.gpg",
            ".git/c.gpg",
            "note.txt",
            ".gpg",
        ] {
            std::fs::write(root.join(f), b"").unwrap();
        }
        std::os::unix::fs::symlink(root.join("one.gpg"), root.join("link.gpg")).unwrap();
        std::os::unix::fs::symlink(root.join("x"), root.join("linkdir")).unwrap();
        let b = backend(root, None);
        assert_eq!(b.list().unwrap(), ["one", "x/three", "x/y/four"]);
        assert_eq!(
            backend(root, Some("x")).list().unwrap(),
            ["three", "y/four"]
        );
        assert!(backend(root, Some("none")).list().unwrap().is_empty());
        let e = backend(&root.join("gone"), None).list().unwrap_err();
        assert!(matches!(e, BackendError::NoStoreDir(_)), "{e}");
    }

    /// The nearest `.gpg-id` wins, and the search stops at the store
    /// directory.
    #[test]
    fn the_nearest_gpg_id_names_the_recipients() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("store");
        std::fs::create_dir_all(root.join("team/sub")).unwrap();
        std::fs::write(d.path().join(GPG_ID), "outside\n").unwrap();
        let b = backend(&root, Some("team/sub"));
        let e = b.gpg_id(b.entries()).unwrap_err();
        assert!(e.to_string().contains("pass init"), "{e}");
        std::fs::write(root.join(GPG_ID), "root\n").unwrap();
        assert_eq!(b.gpg_id(b.entries()).unwrap(), root.join(GPG_ID));
        std::fs::write(root.join("team").join(GPG_ID), "team\n").unwrap();
        assert_eq!(
            b.gpg_id(b.entries()).unwrap(),
            root.join("team").join(GPG_ID)
        );
        std::fs::write(root.join("team").join(GPG_ID_SIG), "sig\n").unwrap();
        let e = PassBackend::refuse_signed(&root.join("team").join(GPG_ID)).unwrap_err();
        assert!(e.to_string().contains(".gpg-id.sig"), "{e}");
        assert!(PassBackend::refuse_signed(&root.join(GPG_ID)).is_ok());
    }

    #[test]
    fn the_first_line_rule_refuses_a_newline_before_gpg_runs() {
        let d = tempfile::tempdir().unwrap();
        let mut b = backend(d.path(), None);
        b.value = PassValue::FirstLine;
        let n = Name::parse("n").unwrap();
        let e = b
            .put(&n, &SecretValue::new(b"a\nb".to_vec()), PutMode::CreateOnly)
            .unwrap_err();
        assert_eq!(e.exit(), crate::error::Exit::Refused);
        assert!(e.to_string().contains("first-line"), "{e}");
    }

    #[test]
    fn gnupg_home_falls_back_to_the_environment() {
        let store = PassStore {
            dir: "/d".into(),
            prefix: None,
            gnupg_home: None,
            value: PassValue::Whole,
            pinentry: Pinentry::Error,
        };
        let open = |vars: &'static [(&'static str, &'static str)]| {
            PassBackend::new(&store, "/g".into(), Duration::ZERO, &move |k| {
                vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.into())
            })
        };
        let b = open(&[("GNUPGHOME", "/g/home"), ("HOME", "/h")]).unwrap();
        assert_eq!(b.gpg.gnupg_home(), Path::new("/g/home"));
        let b = open(&[("GNUPGHOME", "rel"), ("HOME", "/h")]).unwrap();
        assert_eq!(b.gpg.gnupg_home(), Path::new("/h/.gnupg"));
        assert!(matches!(open(&[]), Err(BackendError::NoGnupgHome)));
    }
}
