//! The sops backend (PLAN sections 6.2, 8.1 and 8.2).
//!
//! secrit runs the `sops` binary by absolute path with a cleared environment
//! and always passes `--config`. It never edits the store file in place: it
//! edits a ciphertext copy under a lock, validates the copy, and renames it
//! over the original.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::fs::{
    AtFlags, FileType, Mode, OFlags, fchmod, fstat, fsync, openat, renameat, unlinkat,
};
use rustix::io::Errno;
use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Backend, BackendError, PutMode, WriteReport};
use crate::config::{BackendKind, StoreConfig};
use crate::lock::{self, LockError};
use crate::name::{Name, NameError};
use crate::secret::{MAX_VALUE_BYTES, SecretValue};
use crate::signals;

const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_STDERR_BYTES: u64 = 64 * 1024;
const MAX_ATTEMPTS: usize = 3;
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
    dir: PathBuf,
    base: OsString,
    sops: PathBuf,
    sops_config: PathBuf,
    child_env: Vec<(OsString, OsString)>,
    runtime_dir: Option<PathBuf>,
    lock_timeout: Duration,
}

#[derive(Debug, Clone, Copy)]
enum Op<'a> {
    Put(&'a SecretValue, PutMode),
    Remove,
}

struct Snapshot {
    dev: u64,
    ino: u64,
    size: u64,
    mode: u32,
    hash: [u8; 32],
    bytes: Vec<u8>,
}

impl Snapshot {
    fn same_as(&self, other: &Snapshot) -> bool {
        (self.dev, self.ino, self.size, self.hash) == (other.dev, other.ino, other.size, other.hash)
    }
}

#[derive(Debug)]
struct SopsDoc {
    entries: Map<String, Value>,
    meta: Map<String, Value>,
}

impl SopsBackend {
    /// `env` supplies `HOME`, `XDG_CONFIG_HOME` and `XDG_RUNTIME_DIR`.
    pub fn new(
        store: &StoreConfig,
        sops: PathBuf,
        lock_timeout: Duration,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Self, BackendError> {
        let file = store.file.clone();
        let (Some(dir), Some(base)) = (file.parent(), file.file_name()) else {
            return Err(BackendError::Unsafe {
                path: file,
                reason: "the store path has no directory or file name".into(),
            });
        };
        let sops_config = match &store.sops_config {
            Some(p) => p.clone(),
            // `--config /dev/null` turns off the upward search from the
            // working directory (F10), so a stray .sops.yaml cannot apply.
            None => nearest_sops_config(dir).unwrap_or_else(|| PathBuf::from("/dev/null")),
        };
        let mut child_env: Vec<(OsString, OsString)> =
            vec![("SOPS_DISABLE_VERSION_CHECK".into(), "1".into())];
        for var in ["HOME", "XDG_CONFIG_HOME"] {
            if let Some(v) = env(var) {
                child_env.push((var.into(), v));
            }
        }
        if let Some(k) = &store.age_key_file {
            child_env.push(("SOPS_AGE_KEY_FILE".into(), k.clone().into_os_string()));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            base: base.to_os_string(),
            file,
            sops,
            sops_config,
            child_env,
            runtime_dir: env("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute()),
            lock_timeout,
        })
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.sops);
        c.env_clear()
            .envs(self.child_env.iter().map(|(k, v)| (k, v)))
            .arg("--config")
            .arg(&self.sops_config)
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
        if st.st_mode & 0o002 != 0 {
            return Err(unsafe_("the store directory is writable by others"));
        }
        Ok(st)
    }

    /// Read the store file through `dir`. `strict` adds the write-path checks.
    fn snapshot(&self, dir: &OwnedFd, strict: bool) -> Result<Snapshot, BackendError> {
        let (fd, bytes) = read_entry(dir, &self.base, &self.file, strict)?;
        let st = fstat(&fd).map_err(|e| io_err("stat the store file", &self.file, e))?;
        Ok(Snapshot {
            dev: st.st_dev,
            ino: st.st_ino,
            size: u64::try_from(st.st_size).unwrap_or(0),
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
        let _lock = lock::acquire(&lock_path, self.lock_timeout)?;
        signals::defer().map_err(|e| BackendError::Io {
            step: "install signal handlers",
            path: self.file.clone(),
            source: e,
        })?;
        for _ in 0..MAX_ATTEMPTS {
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
        let snap = self.snapshot(dir, true)?;
        let doc = parse_doc(&snap.bytes, &self.file)?;
        let existed = doc.entries.contains_key(name.as_str());
        match op {
            Op::Put(_, PutMode::CreateOnly) if existed => {
                return Err(BackendError::Exists(name.clone()));
            }
            Op::Remove if !existed => return Err(BackendError::Missing(name.clone())),
            Op::Put(..) => self.check_cleartext_rules(name, &doc.meta)?,
            Op::Remove => {}
        }

        let tmp = TempCopy::create(dir, &self.dir, &self.base, &snap.bytes)?;
        hook("after-copy");
        match op {
            Op::Put(value, _) => self.sops_set(&tmp.path, name, value)?,
            Op::Remove => self.sops_unset(&tmp.path, name)?,
        }
        hook("after-sops");

        let (copy_fd, copy_bytes) = read_entry(dir, &tmp.name, &tmp.path, true)?;
        let copy = parse_doc(&copy_bytes, &tmp.path)?;
        validate(&doc, &copy, name, op)?;
        if let Op::Put(value, _) = op {
            self.readback(&tmp.path, name, value)?;
        }
        fsync(&copy_fd).map_err(|e| io_err("fsync the temp copy", &tmp.path, e))?;
        fchmod(&copy_fd, Mode::from_raw_mode(snap.mode))
            .map_err(|e| io_err("chmod the temp copy", &tmp.path, e))?;

        if !self.snapshot(dir, true)?.same_as(&snap) {
            return Ok(None);
        }
        hook("before-rename");
        if signals::pending() {
            return Err(BackendError::Interrupted);
        }
        let backup = if existed {
            Some(self.backup(dir, &snap.bytes)?)
        } else {
            None
        };
        renameat(dir, &tmp.name, dir, &self.base)
            .map_err(|e| io_err("rename the temp copy over", &self.file, e))?;
        tmp.disarm();
        fsync(dir).map_err(|e| io_err("fsync the store directory", &self.dir, e))?;
        Ok(Some(WriteReport { backup }))
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
        for key in ["unencrypted_regex", "encrypted_regex"] {
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
                suffix: sfx.to_owned(),
            }
            .into());
        }
        if let Some(sfx) = rule("encrypted_suffix")
            && !name.as_str().ends_with(sfx)
        {
            return Err(NameError::MissingEncryptedSuffix {
                name: name.to_string(),
                suffix: sfx.to_owned(),
            }
            .into());
        }
        Ok(())
    }

    fn sops_set(&self, path: &Path, name: &Name, value: &SecretValue) -> Result<(), BackendError> {
        let json = value
            .to_json_string()
            .map_err(|_| BackendError::Validation("the value is not UTF-8".into()))?;
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
        let out = self.run(cmd, Some(&json), 0)?;
        if !out.status.success() {
            let inner = &json[1..json.len() - 1];
            return Err(sops_failed("set", &out, &[value.expose(), inner]));
        }
        Ok(())
    }

    fn sops_unset(&self, path: &Path, name: &Name) -> Result<(), BackendError> {
        let mut cmd = self.command();
        cmd.args(["unset", "--input-type", "yaml", "--output-type", "yaml"])
            .arg(path)
            .arg(name.sops_path());
        let out = self.run(cmd, None, 0)?;
        if !out.status.success() {
            return Err(sops_failed("unset", &out, &[]));
        }
        Ok(())
    }

    /// Decrypt only `name` from the copy and compare it in constant time.
    fn readback(&self, path: &Path, name: &Name, value: &SecretValue) -> Result<(), BackendError> {
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
        .arg(path);
        let out = self.run(cmd, None, MAX_VALUE_BYTES + 1)?;
        if !out.status.success() {
            return Err(sops_failed("readback decrypt", &out, &[value.expose()]));
        }
        if !value.ct_eq(&out.stdout) {
            return Err(BackendError::Validation(
                "the value read back from the new file differs from the input".into(),
            ));
        }
        Ok(())
    }

    fn backup(&self, dir: &OwnedFd, bytes: &[u8]) -> Result<PathBuf, BackendError> {
        let stamp = utc_stamp(SystemTime::now());
        for i in 0..100 {
            let mut name = self.base.clone();
            name.push(format!(".secrit-bak.{stamp}"));
            if i > 0 {
                name.push(format!("-{i}"));
            }
            let path = self.dir.join(&name);
            match create_exclusive(dir, &name) {
                Ok(fd) => {
                    let mut f = File::from(fd);
                    f.write_all(bytes)
                        .and_then(|()| f.sync_all())
                        .map_err(|e| BackendError::Io {
                            step: "write the backup",
                            path: path.clone(),
                            source: e,
                        })?;
                    return Ok(path);
                }
                Err(Errno::EXIST) => {}
                Err(e) => return Err(io_err("create the backup", &path, e)),
            }
        }
        Err(BackendError::Validation(
            "could not find a free backup file name".into(),
        ))
    }

    fn run(
        &self,
        cmd: Command,
        stdin: Option<&[u8]>,
        stdout_cap: usize,
    ) -> Result<ChildOutput, BackendError> {
        run_child(cmd, stdin, stdout_cap).map_err(|e| BackendError::Io {
            step: "run",
            path: self.sops.clone(),
            source: e,
        })
    }
}

impl Backend for SopsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Sops
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

    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError> {
        let (snap, doc) = self.read_doc()?;
        if let Some(n) = names.iter().find(|n| !doc.entries.contains_key(n.as_str())) {
            return Err(BackendError::Missing(n.clone()));
        }
        // Decrypted JSON is far smaller than the ciphertext YAML, even with
        // escapes; the buffer is fixed so it never reallocates.
        let size = usize::try_from(snap.size).unwrap_or(usize::MAX);
        let cap = size.saturating_mul(4).saturating_add(64 * 1024);
        let mut cmd = self.command();
        cmd.args(["decrypt", "--input-type", "yaml", "--output-type", "json"])
            .arg(&self.file);
        let out = self.run(cmd, None, cap)?;
        if !out.status.success() {
            return Err(sops_failed("decrypt", &out, &[]));
        }
        let mut slots = Selected { wanted: names }
            .deserialize(&mut serde_json::Deserializer::from_slice(&out.stdout))
            .map_err(|_| BackendError::Parse {
                path: self.file.clone(),
                what: "the sops decrypt output is not a JSON object".into(),
            })?;
        let mut values = Vec::with_capacity(names.len());
        for n in names {
            let pos = slots
                .iter()
                .position(|(k, _)| k == n)
                .ok_or_else(|| BackendError::Missing(n.clone()))?;
            match slots.swap_remove(pos).1 {
                Slot::Str(v) => values.push((n.clone(), v)),
                Slot::Other(kind) => {
                    return Err(BackendError::NotString {
                        name: n.to_string(),
                        kind,
                    });
                }
            }
        }
        Ok(values)
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
}

fn nearest_sops_config(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .map(|a| a.join(".sops.yaml"))
        .find(|p| p.is_file())
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

fn parse_doc(bytes: &[u8], path: &Path) -> Result<SopsDoc, BackendError> {
    let parse_err = |what: &str| BackendError::Parse {
        path: path.to_path_buf(),
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

/// The metadata that a `set` or `unset` must not change.
fn stable_meta(meta: &Map<String, Value>) -> Map<String, Value> {
    let mut m = meta.clone();
    for k in ["mac", "lastmodified", "version"] {
        m.remove(k);
    }
    m
}

/// PLAN section 8.1, step 9 (the structural part; the readback is separate).
fn validate(orig: &SopsDoc, copy: &SopsDoc, name: &Name, op: Op<'_>) -> Result<(), BackendError> {
    let fail = |m: String| Err(BackendError::Validation(m));
    if !has_recipients(&copy.meta) {
        return fail("the new file has no recipients".into());
    }
    if stable_meta(&orig.meta) != stable_meta(&copy.meta) {
        return fail("the recipients or the sops settings changed".into());
    }
    for (k, v) in &orig.entries {
        if k != name.as_str() && copy.entries.get(k) != Some(v) {
            return fail(format!("entry '{k}' changed or vanished"));
        }
    }
    if let Some(k) = copy
        .entries
        .keys()
        .find(|k| k.as_str() != name.as_str() && !orig.entries.contains_key(*k))
    {
        return fail(format!("an unexpected entry '{k}' appeared"));
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
            getrandom::fill(&mut rnd)
                .map_err(|_| BackendError::Validation("no randomness for the temp name".into()))?;
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
        Err(BackendError::Validation(
            "could not find a free temp file name".into(),
        ))
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

struct ChildOutput {
    status: ExitStatus,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}

/// Run `cmd`, feed `stdin`, and collect at most `stdout_cap` bytes of stdout
/// into a fixed buffer. Stdin, stdout and stderr are serviced concurrently,
/// so a large value or a chatty child cannot deadlock the pipes.
fn run_child(mut cmd: Command, stdin: Option<&[u8]>, stdout_cap: usize) -> io::Result<ChildOutput> {
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    if stdout_cap > 0 {
        cmd.stdout(Stdio::piped());
    }
    let mut child = cmd.spawn()?;
    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();
    std::thread::scope(|s| {
        let writer = s.spawn(move || -> io::Result<()> {
            if let (Some(mut w), Some(data)) = (child_stdin, stdin) {
                match w.write_all(data) {
                    Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(e),
                    _ => {}
                }
            }
            Ok(())
        });
        let err_reader = s.spawn(move || {
            let mut buf = Zeroizing::new(Vec::new());
            if let Some(e) = child_stderr {
                let _ = e.take(MAX_STDERR_BYTES).read_to_end(&mut buf);
            }
            buf
        });
        let mut out = Zeroizing::new(vec![0u8; stdout_cap]);
        let mut len = 0;
        let mut overflow = false;
        if let Some(mut o) = child_stdout {
            loop {
                if len == stdout_cap {
                    let mut probe = [0u8; 1];
                    match o.read(&mut probe) {
                        Ok(0) => break,
                        Ok(_) => {
                            overflow = true;
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                    continue;
                }
                match o.read(&mut out[len..]) {
                    Ok(0) => break,
                    Ok(n) => len += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        if overflow {
            let _ = child.kill();
        }
        let status = child.wait()?;
        writer
            .join()
            .map_err(|_| io::Error::other("stdin writer panicked"))??;
        let stderr = err_reader
            .join()
            .map_err(|_| io::Error::other("stderr reader panicked"))?;
        if overflow {
            return Err(io::Error::other("child output exceeded the size limit"));
        }
        out.truncate(len);
        Ok(ChildOutput {
            status,
            stdout: out,
            stderr,
        })
    })
}

fn sops_failed(step: &'static str, out: &ChildOutput, secrets: &[&[u8]]) -> BackendError {
    BackendError::Sops {
        step,
        status: match out.status.code() {
            Some(c) => format!("exit {c}"),
            None => "killed by a signal".into(),
        },
        stderr: redact(&out.stderr, secrets),
    }
}

/// Replace every occurrence of each secret with `[REDACTED]`, then keep at
/// most 20 lines.
fn redact(stderr: &[u8], secrets: &[&[u8]]) -> String {
    let mut buf = Zeroizing::new(stderr.to_vec());
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        let mut out = Zeroizing::new(Vec::with_capacity(buf.len()));
        let mut i = 0;
        while i < buf.len() {
            if buf[i..].starts_with(secret) {
                out.extend_from_slice(b"[REDACTED]");
                i += secret.len();
            } else {
                out.push(buf[i]);
                i += 1;
            }
        }
        buf = out;
    }
    let text = String::from_utf8_lossy(&buf);
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(20)
        .collect();
    if lines.is_empty() {
        String::new()
    } else {
        format!(":\n  {}", lines.join("\n  "))
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

enum Slot {
    Str(SecretValue),
    Other(&'static str),
}

struct SlotVisitor;

impl<'de> Visitor<'de> for SlotVisitor {
    type Value = Slot;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a value")
    }

    fn visit_str<E>(self, v: &str) -> Result<Slot, E> {
        Ok(Slot::Str(SecretValue::new(v.as_bytes().to_vec())))
    }

    fn visit_string<E>(self, v: String) -> Result<Slot, E> {
        Ok(Slot::Str(SecretValue::new(v.into_bytes())))
    }

    fn visit_bool<E>(self, _: bool) -> Result<Slot, E> {
        Ok(Slot::Other("boolean"))
    }

    fn visit_i64<E>(self, _: i64) -> Result<Slot, E> {
        Ok(Slot::Other("number"))
    }

    fn visit_u64<E>(self, _: u64) -> Result<Slot, E> {
        Ok(Slot::Other("number"))
    }

    fn visit_f64<E>(self, _: f64) -> Result<Slot, E> {
        Ok(Slot::Other("number"))
    }

    fn visit_unit<E>(self) -> Result<Slot, E> {
        Ok(Slot::Other("null"))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Slot, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Slot::Other("map"))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Slot, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Slot::Other("list"))
    }
}

impl<'de> serde::Deserialize<'de> for Slot {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(SlotVisitor)
    }
}

/// Deserialize only the wanted top-level entries; skip the rest unread.
struct Selected<'a> {
    wanted: &'a [Name],
}

impl<'de> DeserializeSeed<'de> for Selected<'_> {
    type Value = Vec<(Name, Slot)>;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Selected<'_> {
    type Value = Vec<(Name, Slot)>;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut found = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if let Some(n) = self.wanted.iter().find(|n| n.as_str() == key) {
                found.push((n.clone(), map.next_value::<Slot>()?));
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found)
    }
}

#[cfg(feature = "test-hooks")]
fn hook(step: &str) {
    let Ok(spec) = std::env::var("SECRIT_TEST_HOOK") else {
        return;
    };
    for item in spec.split(',') {
        if item.split_once('=').is_some_and(|(at, _)| at == step) {
            match item.split_once('=').map(|(_, a)| a) {
                Some("abort") => std::process::abort(),
                Some("sigint") => {
                    let _ = rustix::process::kill_process(
                        rustix::process::getpid(),
                        rustix::process::Signal::INT,
                    );
                }
                Some(a) => {
                    if let Some(ms) = a.strip_prefix("sleep-").and_then(|m| m.parse().ok()) {
                        std::thread::sleep(Duration::from_millis(ms));
                    }
                }
                None => {}
            }
        }
    }
}

#[cfg(not(feature = "test-hooks"))]
fn hook(_: &str) {}

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
    fn redact_removes_every_occurrence() {
        let out = redact(b"error: hunter2 is bad\nhunter2hunter2\n", &[b"hunter2"]);
        assert!(!out.contains("hunter2"));
        assert!(out.contains("[REDACTED] is bad"));
        let many: Vec<u8> = (0..50)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .collect();
        assert_eq!(redact(&many, &[]).lines().count(), 21);
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
    }
}
