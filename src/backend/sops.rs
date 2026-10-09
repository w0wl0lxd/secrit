//! The sops backend (PLAN sections 6.2, 8.1 and 8.2).
//!
//! secrit runs the `sops` binary by absolute path with a cleared environment
//! and always passes `--config`. It never edits the store file in place: it
//! edits a ciphertext copy under a lock, validates the copy, and renames it
//! over the original.
//!
//! Every sops run is bounded (R1). sops runs in its own process group, so a
//! Ctrl-C to secrit's group does not reach it mid-write. secrit polls the
//! child: a deferred signal, a stop (sops read the terminal from a background
//! group, for example a passphrase prompt) or [`child::TIMEOUT`] kills the
//! whole sops group, and the temp copy is removed. `setsid` would give sops
//! no terminal at all, but `CommandExt::setsid` is unstable and the crate
//! forbids `unsafe`, so the stop is detected instead.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::fs::{
    AtFlags, Dev, FileType, Mode, OFlags, RawMode, RenameFlags, fchmod, fstat, fsync, openat,
    renameat, renameat_with, unlinkat,
};
use rustix::io::Errno;

use serde::de::IgnoredAny;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{
    Backend, BackendError, DoctorCtx, Location, MAX_RETRIES, PutMode, Target, ToolStatus,
    WriteReport,
};
use crate::child::{self, ChildError, ChildOutput};
use crate::config::{BackendKind, Env, SopsStore};
use crate::display::escape;
use crate::lock::{self, LockError};
use crate::name::{Name, NameError};
use crate::report::Report;
use crate::secret::{MAX_VALUE_BYTES, SecretValue};
use crate::signals;
use crate::testhook;
use crate::trust::{self, TrustError};

const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// What `create_file` gives sops to encrypt.
const EMPTY_DOC: &[u8] = b"{}\n";
/// The cap on the sops output for a new, empty store file.
const MAX_NEW_FILE_BYTES: usize = 1024 * 1024;
/// The sops regex rules that leave some entries in cleartext. secrit v0.1
/// does not evaluate them, so it does not write a file that sets one. The
/// suffix rules are enforced by the name check instead.
const REGEX_RULES: &[&str] = &["unencrypted_regex", "encrypted_regex"];
/// The `.gitignore` pattern that matches every temp copy.
pub const TEMP_IGNORE: &str = ".*.secrit-*.yaml";
/// Backups kept for each store file; older ones are deleted.
pub const MAX_BACKUPS: usize = 10;
/// The oldest sops that has `set --value-stdin` and `unset` (PLAN 4.6).
pub const MIN_SOPS: (u64, u64) = (3, 11);
/// [`MIN_SOPS`] and the reason, for [`BackendError::ToolTooOld`].
pub const NEED_SOPS: &str = "3.11 or newer (for 'set --value-stdin' and 'unset')";
/// The tool name in [`BackendError`] messages.
const TOOL: &str = "sops";
/// What to do when sops stops to ask on the terminal.
pub const PROMPT_HINT: &str = "secrit v0.1 supports only an age key file without a passphrase: set age_key_file in the config";
/// What the store file must be, for [`BackendError::Parse`].
const FORMAT: &str = "sops YAML file";
/// The `HOME` that sops gets. sops looks for `~/.ssh/id_ed25519` and
/// `~/.ssh/id_rsa` as age identities, so the real HOME is never passed (R2).
const CHILD_HOME: &str = "/nonexistent";
const KEY_TYPES: &[&str] = &[
    "age",
    "pgp",
    "kms",
    "gcp_kms",
    "azure_kv",
    "hc_vault",
    "hckms",
    "key_groups",
];

#[derive(Debug)]
pub struct SopsBackend {
    file: PathBuf,
    /// `file` as a [`Location`], for messages and errors.
    location: Location,
    dir: PathBuf,
    base: OsString,
    sops: PathBuf,
    /// The `.sops.yaml` to pass, or `None` for `/dev/null`.
    sops_config: Option<PathBuf>,
    child_env: Vec<(OsString, OsString)>,
    runtime_dir: Option<PathBuf>,
    backup_dir: Option<PathBuf>,
    age_key_file: Option<PathBuf>,
    lock_timeout: Duration,
    /// Set once the sops version and the `.sops.yaml` passed their checks.
    checked: OnceLock<()>,
}

#[derive(Debug, Clone, Copy)]
enum Op<'a> {
    Put(&'a SecretValue, PutMode),
    Remove,
}

/// What `inspect` found in the store file. Holds names only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreFacts {
    /// Top-level entries outside `sops`.
    pub names: usize,
    /// Top-level names that hold a leaf that is not `ENC[...]`.
    pub plaintext: Vec<String>,
    /// The regex rules in the file's sops metadata.
    pub rules: Vec<&'static str>,
}

struct Snapshot {
    dev: Dev,
    ino: u64,
    size: u64,
    /// Seconds and nanoseconds. `i128` holds the nanoseconds of every
    /// platform (`u64` on Linux, `i64` on macOS).
    mtime: (i64, i128),
    mode: RawMode,
    hash: [u8; 32],
    bytes: Vec<u8>,
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
struct Backup {
    dir: OwnedFd,
    name: OsString,
    path: PathBuf,
}

#[derive(Debug)]
struct SopsDoc {
    entries: Map<String, Value>,
    meta: Map<String, Value>,
}

impl SopsBackend {
    /// `env` supplies `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME` and
    /// `XDG_RUNTIME_DIR`.
    pub fn new(
        store: &SopsStore,
        sops: PathBuf,
        lock_timeout: Duration,
        env: &Env,
    ) -> Result<Self, BackendError> {
        let file = store.file.clone();
        let (Some(dir), Some(base)) = (file.parent(), file.file_name()) else {
            return Err(BackendError::Unsafe {
                path: file,
                reason: "the store path has no directory or file name".into(),
            });
        };
        let abs = |var: &str| env(var).map(PathBuf::from).filter(|p| p.is_absolute());
        let home = abs("HOME");
        let child_env: Vec<(OsString, OsString)> = vec![
            ("SOPS_DISABLE_VERSION_CHECK".into(), "1".into()),
            ("HOME".into(), CHILD_HOME.into()),
        ];
        let mut backend = Self {
            dir: dir.to_path_buf(),
            base: base.to_os_string(),
            sops_config: store
                .sops_config
                .clone()
                .or_else(|| nearest_sops_config(dir)),
            backup_dir: abs("XDG_STATE_HOME")
                .or_else(|| home.as_ref().map(|h| h.join(".local").join("state")))
                .map(|s| {
                    s.join("secrit")
                        .join("backups")
                        .join(backup_key(&file, base))
                }),
            location: Location::File(file.clone()),
            file,
            sops,
            child_env,
            runtime_dir: abs("XDG_RUNTIME_DIR"),
            age_key_file: None,
            lock_timeout,
            checked: OnceLock::new(),
        };
        // sops's own default, made explicit because sops gets no real HOME.
        let key_file = store.age_key_file.clone().or_else(|| {
            abs("XDG_CONFIG_HOME")
                .or_else(|| home.map(|h| h.join(".config")))
                .map(|c| c.join("sops").join("age").join("keys.txt"))
        });
        if let Some(k) = &key_file {
            backend
                .child_env
                .push(("SOPS_AGE_KEY_FILE".into(), k.clone().into_os_string()));
        }
        backend.age_key_file = key_file;
        Ok(backend)
    }

    /// The path passed as `--config`. `/dev/null` turns off sops's upward
    /// search from the working directory (F10), so a stray `.sops.yaml`
    /// cannot apply.
    fn config_arg(&self) -> &Path {
        self.sops_config
            .as_deref()
            .unwrap_or(Path::new("/dev/null"))
    }

    /// Checks made once, before the first sops run: the `.sops.yaml` is as
    /// trusted as the config (SEC-12), and sops is new enough (PF-4).
    fn check_once(&self) -> Result<(), BackendError> {
        if self.checked.get().is_some() {
            return Ok(());
        }
        self.check_sops_config()?;
        self.checked_version()?;
        let _ = self.checked.set(());
        Ok(())
    }

    /// [`Self::sops_version`], refused when it is older than [`MIN_SOPS`].
    pub fn checked_version(&self) -> Result<(u64, u64, u64), BackendError> {
        let (a, b, c) = self.sops_version()?;
        if (a, b) < MIN_SOPS {
            return Err(self.too_old(format!("{a}.{b}.{c}")));
        }
        Ok((a, b, c))
    }

    fn too_old(&self, found: String) -> BackendError {
        BackendError::ToolTooOld {
            tool: TOOL,
            found,
            path: self.sops.clone(),
            need: NEED_SOPS,
        }
    }

    /// The version that `sops --version` reports.
    pub fn sops_version(&self) -> Result<(u64, u64, u64), BackendError> {
        let mut cmd = Command::new(&self.sops);
        cmd.env_clear()
            .envs(self.child_env.iter().map(|(k, v)| (k, v)))
            .args(["--version", "--disable-version-check"])
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        let target = Target {
            location: Location::File(self.sops.clone()),
            name: None,
        };
        let out = self.run_unchecked(cmd, None, 4096, "--version", target)?;
        let text = String::from_utf8_lossy(&out.stdout);
        match parse_sops_version(&text) {
            Some(v) if out.status.success() => Ok(v),
            _ => Err(self.too_old("an unknown version".into())),
        }
    }

    pub fn file(&self) -> &Path {
        &self.file
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn base(&self) -> &OsStr {
        &self.base
    }

    pub fn sops(&self) -> &Path {
        &self.sops
    }

    /// The `.sops.yaml` secrit passes to sops, if any.
    pub fn sops_config(&self) -> Option<&Path> {
        self.sops_config.as_deref()
    }

    /// The age key file sops gets as `SOPS_AGE_KEY_FILE`.
    pub fn age_key_file(&self) -> Option<&Path> {
        self.age_key_file.as_deref()
    }

    /// This store's backup directory.
    pub fn backup_dir(&self) -> Option<&Path> {
        self.backup_dir.as_deref()
    }

    /// The trust rule for the `.sops.yaml` (SEC-12).
    pub fn check_sops_config(&self) -> Result<(), BackendError> {
        let Some(p) = &self.sops_config else {
            return Ok(());
        };
        trust::check_file(p).map(|_| ()).map_err(|e| match e {
            TrustError::Io(source) => BackendError::Io {
                step: "check",
                path: p.clone(),
                source,
            },
            TrustError::Unsafe(reason) => BackendError::Unsafe {
                path: p.clone(),
                reason: reason.into(),
            },
        })
    }

    /// The store directory checks of the write path (section 8.1, step 2).
    pub fn check_store_dir(&self) -> Result<(), BackendError> {
        let dir = self.open_dir()?;
        self.check_dir(&dir).map(|_| ())
    }

    /// The store file under the write-path checks, without decrypting.
    pub fn inspect(&self) -> Result<StoreFacts, BackendError> {
        let dir = self.open_dir()?;
        let snap = self.snapshot(&dir, true)?;
        refuse_non_yaml(&snap.bytes, &self.file)?;
        let doc = parse_doc(&snap.bytes, &self.file)?;
        let rules = REGEX_RULES
            .iter()
            .copied()
            .filter(|k| {
                doc.meta
                    .get(*k)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            })
            .collect();
        let plaintext = doc
            .entries
            .iter()
            .filter(|(_, v)| has_plaintext(v))
            .map(|(k, _)| k.clone())
            .collect();
        Ok(StoreFacts {
            names: doc.entries.len(),
            plaintext,
            rules,
        })
    }

    /// Whether a creation rule of the `.sops.yaml` covers the store file:
    /// sops encrypts an empty document for it, and the output is dropped.
    pub fn rule_matches(&self) -> Result<bool, BackendError> {
        if self.sops_config.is_none() {
            return Ok(false);
        }
        let out = self.run(
            self.encrypt_empty(),
            Some(EMPTY_DOC),
            0,
            "encrypt",
            self.target(None),
        )?;
        if out.status.success() {
            return Ok(true);
        }
        if String::from_utf8_lossy(&out.stderr).contains("no matching creation rules") {
            return Ok(false);
        }
        Err(sops_failed("encrypt", self.target(None), &out, &[]))
    }

    /// The store file, and `name` when the step is about one.
    fn target(&self, name: Option<&Name>) -> Target {
        Target {
            location: self.location.clone(),
            name: name.cloned(),
        }
    }

    fn validation(&self, name: Option<&Name>, reason: impl Into<String>) -> BackendError {
        BackendError::Validation {
            target: self.target(name),
            reason: reason.into(),
        }
    }

    /// Create the store file with no entries (PLAN section 4.6, step 4): sops
    /// encrypts `{}` under the `.sops.yaml` rule, secrit writes a temp file,
    /// fsyncs it and renames it with `RENAME_NOREPLACE`, so an existing file
    /// is never replaced.
    pub fn create_file(&self) -> Result<(), BackendError> {
        let _critical = signals::Critical::enter();
        let dir = self.open_dir()?;
        self.check_dir(&dir)?;
        refuse_non_yaml_name(&self.file)?;
        if self.sops_config.is_none() {
            return Err(BackendError::NoSopsConfig(self.file.clone()));
        }
        let out = self.run(
            self.encrypt_empty(),
            Some(EMPTY_DOC),
            MAX_NEW_FILE_BYTES,
            "encrypt",
            self.target(None),
        )?;
        if !out.status.success() {
            return Err(sops_failed("encrypt", self.target(None), &out, &[]));
        }
        let doc = parse_doc(&out.stdout, &self.file)?;
        if !has_recipients(&doc.meta) {
            return Err(self.validation(None, "the new file has no recipients"));
        }
        let tmp = TempCopy::create(&dir, &self.dir, &self.base, &out.stdout)?;
        let (fd, _) = read_entry(&dir, &tmp.name, &tmp.path, true)?;
        fsync(&fd).map_err(|e| io_err("fsync the new store file", &tmp.path, e))?;
        if signals::pending() {
            return Err(BackendError::Interrupted);
        }
        renameat_with(&dir, &tmp.name, &dir, &self.base, RenameFlags::NOREPLACE).map_err(|e| {
            match e {
                Errno::EXIST => BackendError::Unsafe {
                    path: self.file.clone(),
                    reason: "it appeared while secrit created it; nothing was replaced".into(),
                },
                e => io_err("rename the new store file into place", &self.file, e),
            }
        })?;
        tmp.disarm();
        fsync(&dir).map_err(|e| io_err("fsync the store directory", &self.dir, e))
    }

    fn encrypt_empty(&self) -> Command {
        let mut cmd = self.command();
        cmd.current_dir("/")
            .args([
                "encrypt",
                "--input-type",
                "json",
                "--output-type",
                "yaml",
                "--filename-override",
            ])
            .arg(&self.file)
            .arg("/dev/stdin");
        cmd
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.sops);
        c.env_clear()
            .envs(self.child_env.iter().map(|(k, v)| (k, v)))
            .arg("--config")
            .arg(self.config_arg())
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // Own process group: a signal to secrit's group (Ctrl-C, the
            // stuck-process reaper) does not reach sops mid-write.
            .process_group(0);
        c
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

    fn check_dir(&self, dir: &OwnedFd) -> Result<rustix::fs::Stat, BackendError> {
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

    fn read_doc(&self) -> Result<(Snapshot, SopsDoc), BackendError> {
        let dir = self.open_dir()?;
        let snap = self.snapshot(&dir, false)?;
        let doc = parse_doc(&snap.bytes, &self.file)?;
        Ok((snap, doc))
    }

    fn write(&self, name: &Name, op: Op<'_>) -> Result<WriteReport, BackendError> {
        let runtime = self.runtime_dir.as_deref().ok_or(LockError::NoRuntimeDir)?;
        let dir = self.open_dir()?;
        let dst = self.check_dir(&dir)?;
        let lock_path = lock::lock_path(runtime, dst.st_dev, dst.st_ino, &self.base);
        signals::defer().map_err(|e| BackendError::Io {
            step: "install signal handlers",
            path: self.file.clone(),
            source: e,
        })?;
        // Until the rename (or the cleanup) is done, a signal only sets the
        // flag that the lock wait, the sops wait and the protocol poll.
        let _critical = signals::Critical::enter();
        let _lock = lock::acquire(&lock_path, self.lock_timeout)?;
        testhook::hook("after-lock");
        // The first try, then at most MAX_RETRIES more (PLAN 8.1, step 11).
        for _ in 0..=MAX_RETRIES {
            if let Some(report) = self.attempt(&dir, name, op)? {
                return Ok(report);
            }
        }
        Err(BackendError::Changed(self.file.clone()))
    }

    /// One pass of the write protocol. `Ok(None)` means the original changed
    /// under us and the caller should retry.
    fn attempt(
        &self,
        dir: &OwnedFd,
        name: &Name,
        op: Op<'_>,
    ) -> Result<Option<WriteReport>, BackendError> {
        // Steps 2 and 3 again, on the locked file: the directory may have
        // changed owner or mode while secrit waited for the lock (step 4).
        self.check_dir(dir)?;
        let snap = self.snapshot(dir, true)?;
        refuse_non_yaml(&snap.bytes, &self.file)?;
        let doc = parse_doc(&snap.bytes, &self.file)?;
        let existed = doc.entries.contains_key(name.as_str());
        match op {
            Op::Put(_, PutMode::CreateOnly) if existed => {
                return Err(self.exists_error(name));
            }
            Op::Remove if !existed => return Err(self.missing_error(name)),
            Op::Put(..) => self.check_cleartext_rules(name, &doc.meta)?,
            Op::Remove => {}
        }

        let tmp = TempCopy::create(dir, &self.dir, &self.base, &snap.bytes)?;
        testhook::hook("after-copy");
        match op {
            Op::Put(value, _) => self.sops_set(&tmp.path, name, value)?,
            Op::Remove => self.sops_unset(&tmp.path, name)?,
        }
        testhook::hook("after-sops");

        let (copy_fd, copy_bytes) = read_entry(dir, &tmp.name, &tmp.path, true)?;
        let copy = parse_doc(&copy_bytes, &tmp.path)?;
        validate(&doc, &copy, name, op).map_err(|reason| self.validation(Some(name), reason))?;
        if let Op::Put(value, _) = op {
            self.readback(&copy_bytes, name, value)?;
        }
        fsync(&copy_fd).map_err(|e| io_err("fsync the temp copy", &tmp.path, e))?;
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
                let _ = unlinkat(&b.dir, &b.name, AtFlags::empty());
            }
            return Err(io_err("rename the temp copy over", &self.file, e));
        }
        tmp.disarm();
        fsync(dir).map_err(|e| io_err("fsync the store directory", &self.dir, e))?;
        let backup = backup.map(|b| {
            prune_backups(&b);
            b.path
        });
        Ok(Some(WriteReport { backup }))
    }

    fn exists_error(&self, name: &Name) -> BackendError {
        BackendError::Exists {
            name: name.clone(),
            location: self.location.clone(),
        }
    }

    fn missing_error(&self, name: &Name) -> BackendError {
        BackendError::Missing {
            name: name.clone(),
            location: self.location.clone(),
        }
    }

    /// Refuse a file that already holds a cleartext entry other than NAME
    /// (written by another tool, or kept by sops under `unencrypted_suffix`).
    /// The copy validation refuses such a file after the write (PLAN 8.1,
    /// step 9); this check runs first, so nobody types a value for nothing.
    fn check_plaintext(
        &self,
        name: &Name,
        entries: &Map<String, Value>,
    ) -> Result<(), BackendError> {
        match entries
            .iter()
            .find(|(k, v)| k.as_str() != name.as_str() && has_plaintext(v))
        {
            Some((k, _)) => Err(BackendError::CleartextRule {
                path: self.file.clone(),
                reason: format!(
                    "entry '{}' is not encrypted, and secrit never writes a file with a cleartext entry; encrypt it or remove it with sops first",
                    escape(k)
                ),
            }),
            None => Ok(()),
        }
    }

    /// Refuse a name that sops would store in cleartext under the file's own
    /// rules (the metadata in its `sops` block, which `sops set` applies).
    fn check_cleartext_rules(
        &self,
        name: &Name,
        meta: &Map<String, Value>,
    ) -> Result<(), BackendError> {
        let rule = |k: &str| {
            meta.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        };
        for &key in REGEX_RULES {
            if rule(key).is_some() {
                return Err(BackendError::CleartextRule {
                    path: self.file.clone(),
                    reason: format!(
                        "the file sets {key}, and secrit v0.1 does not evaluate sops regex rules"
                    ),
                });
            }
        }
        if let Some(sfx) = rule("unencrypted_suffix")
            && name.as_str().ends_with(sfx)
        {
            return Err(NameError::UnencryptedSuffix {
                name: name.to_string(),
                suffix: escape(sfx).into_owned(),
            }
            .into());
        }
        if let Some(sfx) = rule("encrypted_suffix")
            && !name.as_str().ends_with(sfx)
        {
            return Err(NameError::MissingEncryptedSuffix {
                name: name.to_string(),
                suffix: escape(sfx).into_owned(),
            }
            .into());
        }
        Ok(())
    }

    fn sops_set(&self, path: &Path, name: &Name, value: &SecretValue) -> Result<(), BackendError> {
        let json = value
            .to_json_string()
            .map_err(|_| self.validation(Some(name), "the value is not UTF-8"))?;
        let mut cmd = self.command();
        cmd.args([
            "set",
            "--input-type",
            "yaml",
            "--output-type",
            "yaml",
            "--value-stdin",
        ])
        .arg(path)
        .arg(name.sops_path());
        let out = self.run(cmd, Some(&json), 0, "set", self.target(Some(name)))?;
        if !out.status.success() {
            let inner = &json[1..json.len() - 1];
            return Err(sops_failed(
                "set",
                self.target(Some(name)),
                &out,
                &[value.expose(), inner],
            ));
        }
        Ok(())
    }

    fn sops_unset(&self, path: &Path, name: &Name) -> Result<(), BackendError> {
        let mut cmd = self.command();
        cmd.args(["unset", "--input-type", "yaml", "--output-type", "yaml"])
            .arg(path)
            .arg(name.sops_path());
        let out = self.run(cmd, None, 0, "unset", self.target(Some(name)))?;
        if !out.status.success() {
            return Err(sops_failed("unset", self.target(Some(name)), &out, &[]));
        }
        Ok(())
    }

    /// Decrypt `name` from the validated copy bytes and compare it in
    /// constant time.
    fn readback(&self, copy: &[u8], name: &Name, value: &SecretValue) -> Result<(), BackendError> {
        let json = value
            .to_json_string()
            .map_err(|_| self.validation(Some(name), "the value is not UTF-8"))?;
        let inner = &json[1..json.len() - 1];
        let got = self.decrypt_one(copy, name, "readback decrypt", &[value.expose(), inner])?;
        if !value.ct_eq(got.expose()) {
            return Err(self.validation(
                Some(name),
                "the value read back from the new file differs from the input",
            ));
        }
        Ok(())
    }

    /// Decrypt one string entry of `bytes`, fed to sops on stdin. sops reads
    /// the bytes secrit checked, not a path that could change in between
    /// (SEC-11), and `--extract` prints the raw string into a fixed buffer
    /// (SEC-8).
    fn decrypt_one(
        &self,
        bytes: &[u8],
        name: &Name,
        step: &'static str,
        secrets: &[&[u8]],
    ) -> Result<SecretValue, BackendError> {
        let mut cmd = self.command();
        cmd.args([
            "decrypt",
            "--input-type",
            "yaml",
            "--output-type",
            "json",
            "--extract",
        ])
        .arg(name.sops_path())
        .arg("/dev/stdin");
        let out = self.run(
            cmd,
            Some(bytes),
            MAX_VALUE_BYTES,
            step,
            self.target(Some(name)),
        )?;
        if !out.status.success() {
            return Err(sops_failed(step, self.target(Some(name)), &out, secrets));
        }
        let mut stdout = out.stdout;
        Ok(SecretValue::new(std::mem::take(&mut *stdout)))
    }

    /// Write a copy of the old file to the private backup directory,
    /// outside the store's repository (SEC-2).
    fn backup(&self, bytes: &[u8]) -> Result<Backup, BackendError> {
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
                        let _ = unlinkat(&backup.dir, &backup.name, AtFlags::empty());
                        return Err(BackendError::Io {
                            step: "write the backup",
                            path: backup.path,
                            source: e,
                        });
                    }
                    fsync(&backup.dir)
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

    /// [`Self::run_unchecked`] after the once-only checks. `step` and
    /// `target` name the run in its errors (PLAN 14).
    fn run(
        &self,
        cmd: Command,
        stdin: Option<&[u8]>,
        stdout_cap: usize,
        step: &'static str,
        target: Target,
    ) -> Result<ChildOutput, BackendError> {
        self.check_once()?;
        self.run_unchecked(cmd, stdin, stdout_cap, step, target)
    }

    fn run_unchecked(
        &self,
        cmd: Command,
        stdin: Option<&[u8]>,
        stdout_cap: usize,
        step: &'static str,
        target: Target,
    ) -> Result<ChildOutput, BackendError> {
        let timeout = child::timeout();
        child::run(cmd, stdin, stdout_cap, timeout).map_err(|e| match e {
            ChildError::Io(source) => BackendError::Io {
                step: "run",
                path: self.sops.clone(),
                source,
            },
            ChildError::Interrupted => BackendError::Interrupted,
            ChildError::Stopped => BackendError::ToolPrompt {
                tool: TOOL,
                step,
                target,
                hint: PROMPT_HINT.into(),
            },
            ChildError::Timeout => BackendError::ToolTimeout {
                tool: TOOL,
                step,
                target,
                after: timeout,
            },
            ChildError::Overflow => BackendError::ToolOutputTooLarge {
                tool: TOOL,
                step,
                target,
            },
        })
    }
}

impl Backend for SopsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Sops
    }

    fn location(&self) -> &Location {
        &self.location
    }

    fn list(&self) -> Result<Vec<String>, BackendError> {
        let (_, doc) = self.read_doc()?;
        let mut names: Vec<String> = doc.entries.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    fn exists(&self, name: &Name) -> Result<bool, BackendError> {
        let (_, doc) = self.read_doc()?;
        Ok(doc.entries.contains_key(name.as_str()))
    }

    fn check_put(&self, name: &Name, mode: PutMode) -> Result<(), BackendError> {
        let (snap, doc) = self.read_doc()?;
        refuse_non_yaml(&snap.bytes, &self.file)?;
        if mode == PutMode::CreateOnly && doc.entries.contains_key(name.as_str()) {
            return Err(self.exists_error(name));
        }
        self.check_cleartext_rules(name, &doc.meta)?;
        self.check_plaintext(name, &doc.entries)
    }

    fn check_remove(&self, name: &Name) -> Result<(), BackendError> {
        let (snap, doc) = self.read_doc()?;
        refuse_non_yaml(&snap.bytes, &self.file)?;
        if !doc.entries.contains_key(name.as_str()) {
            return Err(self.missing_error(name));
        }
        self.check_plaintext(name, &doc.entries)
    }

    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError> {
        let (snap, doc) = self.read_doc()?;
        for n in names {
            let entry = doc
                .entries
                .get(n.as_str())
                .ok_or_else(|| self.missing_error(n))?;
            if let Some(kind) = non_string_kind(entry) {
                return Err(BackendError::NotString {
                    name: n.to_string(),
                    kind,
                });
            }
        }
        // One decrypt per name: each value lands in its own fixed buffer,
        // and no JSON parser holds a copy (SEC-8).
        names
            .iter()
            .map(|n| Ok((n.clone(), self.decrypt_one(&snap.bytes, n, "decrypt", &[])?)))
            .collect()
    }

    fn put(
        &self,
        name: &Name,
        value: &SecretValue,
        mode: PutMode,
    ) -> Result<WriteReport, BackendError> {
        self.write(name, Op::Put(value, mode))
    }

    fn remove(&self, name: &Name) -> Result<WriteReport, BackendError> {
        self.write(name, Op::Remove)
    }

    fn doctor(&self, report: &mut Report, ctx: &DoctorCtx<'_>) {
        // The rows stay in cmd/doctor.rs until the sops module split
        // (v0.2 plan S3) moves them next to this backend.
        crate::cmd::doctor::sops_rows(report, self, ctx);
    }
}

fn nearest_sops_config(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .map(|a| a.join(".sops.yaml"))
        .find(|p| p.is_file())
}

/// The kind of a ciphertext entry that does not decrypt to a string, from
/// the type tag sops writes into each `ENC[...]` value.
fn non_string_kind(entry: &Value) -> Option<&'static str> {
    match entry {
        Value::String(s) if !s.starts_with("ENC[") || s.ends_with(",type:str]") => None,
        Value::String(s) if s.ends_with(",type:int]") || s.ends_with(",type:float]") => {
            Some("number")
        }
        Value::String(s) if s.ends_with(",type:bool]") => Some("boolean"),
        Value::String(_) => Some("value of another type"),
        Value::Bool(_) => Some("boolean"),
        Value::Number(_) => Some("number"),
        Value::Null => Some("null"),
        Value::Array(_) => Some("list"),
        Value::Object(_) => Some("map"),
    }
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

/// Best effort: a failed prune leaves extra backups, never a broken write.
fn prune_backups(b: &Backup) {
    let Some(dir) = b.path.parent() else { return };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let names = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name())
        .collect();
    for name in backups_to_prune(names, MAX_BACKUPS) {
        let _ = unlinkat(&b.dir, &name, AtFlags::empty());
    }
}

fn parse_sops_version(text: &str) -> Option<(u64, u64, u64)> {
    let word = text
        .split_whitespace()
        .skip_while(|w| *w != "sops")
        .nth(1)?;
    let mut parts = word.trim_start_matches('v').splitn(3, '.');
    let mut next = || -> Option<u64> {
        let p = parts.next()?;
        let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    Some((next()?, next()?, next()?))
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

const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// The file name endings that sops reads as another format than YAML.
const NON_YAML_ENDINGS: [&str; 3] = [".json", ".env", ".ini"];

/// v0.1 runs `sops set` and `unset` with `--output-type yaml`, so a write
/// turns a JSON store into YAML, which a consumer that reads it as JSON
/// cannot parse (v0.2 plan, V14). The write path refuses such a file before
/// it reads a value. A YAML file in flow style also parses as JSON; sops
/// never writes one. A leading UTF-8 BOM does not hide a JSON file.
fn refuse_non_yaml(bytes: &[u8], path: &Path) -> Result<(), BackendError> {
    refuse_non_yaml_name(path)?;
    let body = bytes
        .strip_prefix(UTF8_BOM)
        .unwrap_or(bytes)
        .trim_ascii_start();
    let object = body.first() == Some(&b'{') && serde_json::from_slice::<IgnoredAny>(body).is_ok();
    if object {
        return Err(BackendError::Unsafe {
            path: path.to_path_buf(),
            reason: "it is a sops JSON file; secrit v0.1 writes YAML stores only, \
                     and a write would rewrite it as YAML"
                .into(),
        });
    }
    Ok(())
}

/// sops picks the format from the file name, so a YAML store file must not
/// have a name that sops reads as JSON, dotenv or INI.
fn refuse_non_yaml_name(path: &Path) -> Result<(), BackendError> {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match NON_YAML_ENDINGS.iter().find(|e| file_name.ends_with(*e)) {
        Some(ending) => Err(BackendError::Unsafe {
            path: path.to_path_buf(),
            reason: format!(
                "sops does not read a {ending} file as YAML; \
                 secrit v0.1 writes YAML stores only"
            ),
        }),
        None => Ok(()),
    }
}

fn parse_doc(bytes: &[u8], path: &Path) -> Result<SopsDoc, BackendError> {
    let parse_err = |what: &str| BackendError::Parse {
        location: Location::File(path.to_path_buf()),
        format: FORMAT,
        what: what.into(),
    };
    // The parser's own message can quote file content; it is not shown.
    let value: Value = serde_saphyr::from_slice(bytes).map_err(|_| parse_err("invalid YAML"))?;
    let Value::Object(mut entries) = value else {
        return Err(parse_err("the top level is not a mapping"));
    };
    let Some(Value::Object(meta)) = entries.remove("sops") else {
        return Err(parse_err("there is no sops metadata block"));
    };
    if !meta
        .get("mac")
        .and_then(Value::as_str)
        .is_some_and(|m| m.starts_with("ENC["))
    {
        return Err(parse_err("the sops block has no MAC"));
    }
    Ok(SopsDoc { entries, meta })
}

fn has_recipients(meta: &Map<String, Value>) -> bool {
    KEY_TYPES.iter().any(|k| {
        meta.get(*k)
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
    })
}

/// Whether `v` holds a leaf that sops did not encrypt. sops never encrypts
/// an empty string or a null; such a leaf holds no secret.
fn has_plaintext(v: &Value) -> bool {
    match v {
        Value::String(s) => !s.is_empty() && !s.starts_with("ENC["),
        Value::Bool(_) | Value::Number(_) => true,
        Value::Null => false,
        Value::Array(a) => a.iter().any(has_plaintext),
        Value::Object(m) => m.values().any(has_plaintext),
    }
}

/// The metadata that a `set` or `unset` must not change.
fn stable_meta(meta: &Map<String, Value>) -> Map<String, Value> {
    let mut m = meta.clone();
    for k in ["mac", "lastmodified", "version"] {
        m.remove(k);
    }
    m
}

/// PLAN section 8.1, step 9 (the structural part; the readback is separate).
/// The error is the reason; the caller adds the file and the name.
fn validate(orig: &SopsDoc, copy: &SopsDoc, name: &Name, op: Op<'_>) -> Result<(), String> {
    let fail = |m: String| Err(m);
    if !has_recipients(&copy.meta) {
        return fail("the new file has no recipients".into());
    }
    if stable_meta(&orig.meta) != stable_meta(&copy.meta) {
        return fail("the recipients or the sops settings changed".into());
    }
    for (k, v) in &orig.entries {
        if k != name.as_str() && copy.entries.get(k) != Some(v) {
            return fail(format!("entry '{}' changed or vanished", escape(k)));
        }
    }
    if let Some(k) = copy
        .entries
        .keys()
        .find(|k| k.as_str() != name.as_str() && !orig.entries.contains_key(*k))
    {
        return fail(format!("an unexpected entry '{}' appeared", escape(k)));
    }
    // No leaf of the new file is cleartext, not even an entry that was
    // cleartext before: secrit never writes such a file (PLAN 8.1, step 9).
    if let Some((k, _)) = copy.entries.iter().find(|(_, v)| has_plaintext(v)) {
        return fail(format!("entry '{}' is not encrypted", escape(k)));
    }
    match op {
        Op::Put(..) => match copy.entries.get(name.as_str()) {
            Some(Value::String(s))
                if s.starts_with("ENC[AES256_GCM,") && s.ends_with(",type:str]") =>
            {
                Ok(())
            }
            _ => fail(format!("'{name}' is not stored as an encrypted string")),
        },
        Op::Remove if copy.entries.contains_key(name.as_str()) => {
            fail(format!("'{name}' is still present"))
        }
        Op::Remove => Ok(()),
    }
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
            let hex = crate::lock::hex(&rnd);
            let mut raw = b".".to_vec();
            raw.extend_from_slice(base.as_bytes());
            raw.extend_from_slice(format!(".secrit-{hex}.yaml").as_bytes());
            let name = OsString::from_vec(raw);
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

fn sops_failed(
    step: &'static str,
    target: Target,
    out: &ChildOutput,
    secrets: &[&[u8]],
) -> BackendError {
    BackendError::Tool {
        tool: TOOL,
        step,
        target,
        status: ToolStatus(out.status.code()),
        stderr: redact(&out.stderr, secrets),
    }
}

/// Shortest line of a multiline value that is matched on its own.
const MIN_LINE_NEEDLE: usize = 4;
/// The most child stderr lines an error shows.
const MAX_STDERR_LINES: usize = 20;

/// Child stderr for an error message. A line that holds a secret, its JSON
/// form or one of its lines is dropped whole: an inline mark would show
/// where a short value sits in otherwise fixed text (SEC-15). The rest is
/// escaped and cut to [`MAX_STDERR_LINES`] lines; a note says how many more
/// there were.
fn redact(stderr: &[u8], secrets: &[&[u8]]) -> String {
    let mut needles: Vec<&[u8]> = Vec::new();
    for s in secrets.iter().filter(|s| !s.is_empty()) {
        needles.push(s);
        needles.extend(
            s.split(|b| *b == b'\n')
                .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
                .filter(|l| l.len() >= MIN_LINE_NEEDLE && l.len() < s.len()),
        );
    }
    let contains = |hay: &[u8], n: &[u8]| hay.windows(n.len()).any(|w| w == n);
    let mut hidden = 0usize;
    let mut cut = 0usize;
    let mut shown: Vec<String> = Vec::new();
    for line in stderr.split(|b| *b == b'\n') {
        if needles.iter().any(|n| contains(line, n)) {
            hidden += 1;
            continue;
        }
        let text = String::from_utf8_lossy(line);
        let text = text.trim_end();
        if text.trim().is_empty() {
            continue;
        }
        if shown.len() < MAX_STDERR_LINES {
            shown.push(escape(text).into_owned());
        } else {
            cut += 1;
        }
    }
    if cut > 0 {
        shown.push(format!("({cut} more line(s) not shown)"));
    }
    if hidden > 0 {
        shown.push(format!(
            "({hidden} line(s) not shown, because they may hold the value)"
        ));
    }
    if shown.is_empty() {
        String::new()
    } else {
        format!(":\n  {}", shown.join("\n  "))
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
    use crate::error::Exit;

    #[test]
    fn utc_stamp_known_dates() {
        assert_eq!(utc_stamp(UNIX_EPOCH), "19700101T000000Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400 + 3_723);
        assert_eq!(utc_stamp(leap), "20000229T010203Z");
        let d = UNIX_EPOCH + Duration::from_secs(1_791_331_199);
        assert_eq!(utc_stamp(d), "20261006T235959Z");
    }

    /// SEC-15: lines with a secret, its JSON form or one of its lines are
    /// dropped whole, and the rest is escaped.
    #[test]
    fn redact_drops_lines_that_hold_a_secret() {
        let out = redact(
            b"error: hunter2 is bad\nplain line\nsee \"multi\\nline\"\nthe second line here\n",
            &[b"hunter2", b"multi\\nline", b"first\nsecond line"],
        );
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("multi"));
        assert!(!out.contains("second line"));
        assert!(!out.contains("is bad"), "the whole line must go");
        assert!(out.contains("plain line"));
        assert!(out.contains("3 line(s) not shown"));

        let short = redact(b"error: the file\nthe end\n", &[b"e"]);
        assert!(!short.contains("the file") && !short.contains("the end"));
        assert!(short.contains("2 line(s) not shown"));

        let ctl = redact(b"bad \x1b[2J here\n", &[]);
        assert!(ctl.contains("\\x1b") && !ctl.contains('\x1b'));

        // The header line, 20 lines, and a note for the 30 that were cut.
        let many: Vec<u8> = (0..50)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .collect();
        let out = redact(&many, &[]);
        assert_eq!(out.lines().count(), 22);
        assert!(out.contains("line 19") && !out.contains("line 20"));
        assert!(out.contains("(30 more line(s) not shown)"), "{out}");

        // Cut lines and hidden lines are counted apart.
        let mixed: Vec<u8> = (0..25)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .chain(b"hunter2 leaked\n".iter().copied())
            .collect();
        let out = redact(&mixed, &[b"hunter2"]);
        assert!(out.contains("(5 more line(s) not shown)"), "{out}");
        assert!(out.contains("(1 line(s) not shown, because"), "{out}");
        assert!(!out.contains("hunter2"));

        let exact: Vec<u8> = (0..20)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .collect();
        assert!(!redact(&exact, &[]).contains("more line(s)"));
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
    fn sops_versions_parse() {
        assert_eq!(parse_sops_version("sops 3.13.3\n"), Some((3, 13, 3)));
        assert_eq!(
            parse_sops_version("sops 3.11.0 (latest)\n"),
            Some((3, 11, 0))
        );
        assert_eq!(parse_sops_version("sops 3.10.2-rc1"), Some((3, 10, 2)));
        assert_eq!(parse_sops_version("nothing here"), None);
        assert!((3, 10) < MIN_SOPS && (3, 11) >= MIN_SOPS && (4, 0) >= MIN_SOPS);
    }

    #[test]
    fn entry_kinds_come_from_the_ciphertext_tag() {
        let s = |v: &str| Value::String(v.into());
        assert_eq!(non_string_kind(&s("ENC[AES256_GCM,data:x,type:str]")), None);
        assert_eq!(non_string_kind(&s("cleartext")), None);
        assert_eq!(
            non_string_kind(&s("ENC[AES256_GCM,data:x,type:int]")),
            Some("number")
        );
        assert_eq!(
            non_string_kind(&s("ENC[AES256_GCM,data:x,type:bool]")),
            Some("boolean")
        );
        assert_eq!(non_string_kind(&serde_json::json!({"a": 1})), Some("map"));
        assert_eq!(non_string_kind(&serde_json::json!([1])), Some("list"));
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

    fn doc(yaml: &str) -> SopsDoc {
        parse_doc(yaml.as_bytes(), Path::new("/t.yaml")).unwrap()
    }

    const BASE: &str = "a: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  age:\n    - recipient: age1x\n      enc: blob\n  mac: ENC[AES256_GCM,data:m,type:str]\n  lastmodified: '1'\n  version: 3.13.3\n";

    #[test]
    fn parse_doc_requires_a_sops_block() {
        assert!(parse_doc(b"a: b\n", Path::new("/t")).is_err());
        assert!(parse_doc(b"- a\n", Path::new("/t")).is_err());
        assert!(parse_doc(b"sops:\n  age: []\n", Path::new("/t")).is_err());
        assert_eq!(doc(BASE).entries.len(), 1);
    }

    #[test]
    fn a_store_that_is_not_yaml_is_refused() {
        let yaml = Path::new("/s/main.yaml");
        assert!(refuse_non_yaml(BASE.as_bytes(), yaml).is_ok());
        let json = br#"{"a": "ENC[x]", "sops": {"mac": "ENC[m]"}}"#;
        let bom = b"\xEF\xBB\xBF{\"a\": \"ENC[x]\"}";
        let bom_space = b"\xEF\xBB\xBF \n {}";
        for bytes in [&json[..], b"\n  {}\n", &bom[..], &bom_space[..]] {
            let e = refuse_non_yaml(bytes, yaml).unwrap_err();
            assert!(e.to_string().contains("sops JSON file"), "{e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        // Flow-style YAML that is not JSON stays allowed, with a BOM too.
        assert!(refuse_non_yaml(b"{a: b}\n", yaml).is_ok());
        assert!(refuse_non_yaml(b"\xEF\xBB\xBF{a: b}\n", yaml).is_ok());
        let mut bom_yaml = b"\xEF\xBB\xBF".to_vec();
        bom_yaml.extend_from_slice(BASE.as_bytes());
        assert!(refuse_non_yaml(&bom_yaml, yaml).is_ok());
        for name in ["main.json", "MAIN.JSON", ".env", "a.env", "a.ini"] {
            let path = Path::new("/s").join(name);
            let e = refuse_non_yaml(BASE.as_bytes(), &path).unwrap_err();
            assert!(e.to_string().contains("YAML stores only"), "{name}: {e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        assert!(refuse_non_yaml_name(Path::new("/s/a.env.yaml")).is_ok());
    }

    #[test]
    fn validate_catches_tampering() {
        let orig = doc(BASE);
        let n = Name::parse("b").unwrap();
        let v = SecretValue::new(b"v".to_vec());
        let put = Op::Put(&v, PutMode::CreateOnly);
        let good = doc(
            &format!("{BASE}b: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n")
                .replace("mac: ENC[AES256_GCM,data:m", "mac: ENC[AES256_GCM,data:NEW"),
        );
        assert!(validate(&orig, &good, &n, put).is_ok());

        let cleartext = doc(&format!("{BASE}b: v\n"));
        assert!(validate(&orig, &cleartext, &n, put).is_err());

        let as_int = doc(&format!(
            "{BASE}b: ENC[AES256_GCM,data:q,iv:w,tag:e,type:int]\n"
        ));
        assert!(validate(&orig, &as_int, &n, put).is_err());

        let new_recipient = doc(
            &format!("{BASE}b: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n")
                .replace("recipient: age1x", "recipient: age1other"),
        );
        assert!(validate(&orig, &new_recipient, &n, put).is_err());

        let other_changed = doc(
            &format!("{BASE}b: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n")
                .replace("data:x", "data:CHANGED"),
        );
        assert!(validate(&orig, &other_changed, &n, put).is_err());

        let removed = doc(&BASE.replace("a: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n", ""));
        let a = Name::parse("a").unwrap();
        assert!(validate(&orig, &removed, &a, Op::Remove).is_ok());
        assert!(validate(&orig, &orig, &a, Op::Remove).is_err());

        // A cleartext leaf that was already in the file fails too (A-3),
        // and the reason names the entry, never its value.
        let orig_x = doc(&format!("{BASE}x: cleartext\n"));
        let copy_x = doc(&format!(
            "{BASE}x: cleartext\nb: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n"
        ));
        let reason = validate(&orig_x, &copy_x, &n, put).unwrap_err();
        assert!(reason.contains("'x' is not encrypted"), "{reason}");
        assert!(!reason.contains("cleartext"), "{reason}");
        let nested_yaml = format!("{BASE}x:\n  k: [1]\n");
        let nested = doc(&nested_yaml);
        let nested_removed =
            doc(&nested_yaml.replace("a: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n", ""));
        let reason = validate(&nested, &nested_removed, &a, Op::Remove).unwrap_err();
        assert!(reason.contains("'x' is not encrypted"), "{reason}");
    }

    #[test]
    fn a_cleartext_entry_is_refused_before_the_value() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), &format!("{BASE}x_unencrypted: plain\n"));
        let z = Name::parse("z").unwrap();
        let a = Name::parse("a").unwrap();
        let e = b.check_put(&z, PutMode::CreateOnly).unwrap_err();
        assert!(
            e.to_string().contains("'x_unencrypted' is not encrypted"),
            "{e}"
        );
        assert!(!e.to_string().contains("plain"), "{e}");
        assert_eq!(e.exit(), Exit::Refused);
        let e = b.check_remove(&a).unwrap_err();
        assert!(e.to_string().contains("is not encrypted"), "{e}");
        assert_eq!(e.exit(), Exit::Refused);

        // NAME itself may be the cleartext entry: the write replaces or
        // removes it.
        let b = backend_for(tmp.path(), &format!("{BASE}e: plain\n"));
        let e_name = Name::parse("e").unwrap();
        assert!(b.check_put(&e_name, PutMode::Replace).is_ok());
        assert!(b.check_remove(&e_name).is_ok());
        let e = b.check_remove(&z).unwrap_err();
        assert!(matches!(e, BackendError::Missing { .. }), "{e}");
    }

    /// sops never encrypts an empty string, so an empty leaf holds no
    /// secret, the same as a null leaf.
    #[test]
    fn an_empty_string_leaf_is_not_plaintext() {
        assert!(!has_plaintext(&Value::String(String::new())));
        assert!(!has_plaintext(&Value::Null));
        let nested: Value = serde_json::from_str(r#"{"k": ["", null], "m": {"n": ""}}"#).unwrap();
        assert!(!has_plaintext(&nested));
        assert!(has_plaintext(&Value::String(" ".into())));

        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), &format!("{BASE}e: \"\"\n"));
        let z = Name::parse("z").unwrap();
        let a = Name::parse("a").unwrap();
        assert!(b.check_put(&z, PutMode::CreateOnly).is_ok());
        assert!(b.check_remove(&a).is_ok());
        assert!(b.inspect().unwrap().plaintext.is_empty());

        // The copy validation keeps the empty entry too.
        let orig = doc(&format!("{BASE}e: \"\"\n"));
        let copy = doc(&format!(
            "{BASE}e: \"\"\nz: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n"
        ));
        let v = SecretValue::new(b"v".to_vec());
        assert!(validate(&orig, &copy, &z, Op::Put(&v, PutMode::CreateOnly)).is_ok());
    }

    fn backend_for(dir: &Path, yaml: &str) -> SopsBackend {
        let file = dir.join("main.yaml");
        std::fs::write(&file, yaml).unwrap();
        let store = SopsStore {
            file,
            sops_config: None,
            age_key_file: None,
        };
        SopsBackend::new(&store, "/nonexistent/sops".into(), Duration::ZERO, &|_| {
            None
        })
        .unwrap()
    }

    /// PLAN 4.1 step 1: `check_put` refuses before any value is read, with
    /// no sops run (the sops path here does not exist).
    #[test]
    fn check_put_refuses_without_a_value() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), BASE);
        let a = Name::parse("a").unwrap();
        let z = Name::parse("z").unwrap();
        let e = b.check_put(&a, PutMode::CreateOnly).unwrap_err();
        assert!(matches!(e, BackendError::Exists { .. }), "{e}");
        assert!(e.to_string().contains("main.yaml"), "{e}");
        assert!(b.check_put(&a, PutMode::Replace).is_ok());
        assert!(b.check_put(&z, PutMode::CreateOnly).is_ok());

        let regex = BASE.replace("  version:", "  unencrypted_regex: ^pub\n  version:");
        let b = backend_for(tmp.path(), &regex);
        let e = b.check_put(&z, PutMode::CreateOnly).unwrap_err();
        assert!(e.to_string().contains("unencrypted_regex"), "{e}");
        assert_eq!(e.exit(), Exit::Refused);

        let suffix = BASE.replace("  version:", "  unencrypted_suffix: _pub\n  version:");
        let b = backend_for(tmp.path(), &suffix);
        let e = b
            .check_put(&Name::parse("tok_pub").unwrap(), PutMode::Replace)
            .unwrap_err();
        assert!(e.to_string().contains("_pub"), "{e}");
        assert!(b.check_put(&z, PutMode::Replace).is_ok());
    }
}
