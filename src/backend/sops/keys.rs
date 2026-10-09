//! The key sources of a sops store (v0.2 plan 5.6, 6.2 and 6.7.2).
//!
//! Each source reaches sops as a path in its cleared environment, never as
//! key material:
//!
//! | Config | Child variable |
//! |---|---|
//! | `age_key_file`, identity `file` | `SOPS_AGE_KEY_FILE` |
//! | `age_ssh_key_file`, identity `ssh-file` | `SOPS_AGE_SSH_PRIVATE_KEY_FILE` |
//! | `age_key_cmd`, identity `key-cmd` | `SOPS_AGE_KEY_CMD` |
//! | `age_plugin_dir` | `PATH=<dir>` |
//! | identity `plugin` | `SOPS_AGE_KEY_FILE=<stub>`, `PATH=<plugin_dir>` |
//!
//! Lab results that this module depends on (sops 3.13.3, rage 0.12.1):
//!
//! - sops splits `SOPS_AGE_KEY_CMD` with shlex, so a path with a space or a
//!   quote is refused here.
//! - The key command runs once per sops run that needs an identity, with
//!   sops's own environment: no `PATH` and `HOME=/nonexistent`. A command
//!   that needs `PATH` fails with "failed to execute command".
//! - A key command that reads `/dev/tty` stops in the background group, but
//!   sops waits, so only the deadline ends the run.
//! - A passphrase SSH key fails at once with no terminal, and stops sops on
//!   one.
//! - One decrypt through an age plugin is one plugin run in identity mode.
//!   The plugin's own stderr does not reach secrit.
//!
//! A `plugin` identity adds the checks of 6.7.2 rule 4 and the touch line.
//! Its level is the strictest one that this build supports, `touch`, unless
//! the config names one. `session` waits for the PIN check of slice S8b and
//! `strict` for v0.3, so both are refused after the slot check.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::backend::{BackendError, Target};
use crate::child;
use crate::config::{DEFAULT_KEY_CMD_TIMEOUT_SECS, Env, Identity, Level, SopsKeys, SopsStore};
use crate::paths;
use crate::trust::{self, TrustError};
use crate::tty;

/// The prompt hint when the age key file asked for a passphrase.
pub const AGE_KEY_HINT: &str = "The key in age_key_file must have no passphrase, because secrit never gives sops the terminal (ruling Q24)";
const SSH_KEY_HINT: &str = "The key in age_ssh_key_file must have no passphrase, because secrit never gives sops the terminal (ruling Q24); use an SSH key without one, or an age key file";
const PLUGIN_HINT: &str = "The age plugin asked on the terminal, for example for a PIN; secrit never gives sops the terminal (ruling Q24), so use a slot with PIN policy never (level 'touch')";
const KEY_CMD_HINT: &str = "The key command in age_key_cmd must not read the terminal: it runs with no terminal, no PATH and HOME=/nonexistent (see the README, 'Keys')";
const KEY_CMD_WAITS: &str = "The key command in age_key_cmd may wait for input on a terminal that it never gets: it runs with no terminal, no PATH and HOME=/nonexistent (see the README, 'Keys').";
const PLUGIN_DIR_WAITS: &str =
    "An age plugin from age_plugin_dir may wait for input on a terminal that it never gets.";
const PLUGIN_WAITS: &str = "The age plugin waited for a touch or a PIN: touch the key within touch_timeout_secs, and use a slot with PIN policy never.";
/// The note on a failed sops run when a key command is set.
const KEY_CMD_NOTE: &str = "note: the key command in age_key_cmd runs with no PATH and HOME=/nonexistent; give it an absolute shebang and absolute program paths (see the README, 'Keys')";
/// The level of a plugin identity with no `level` key.
pub const DEFAULT_PLUGIN_LEVEL: Level = Level::Touch;
/// The strictest level that this build can serve.
const MAX_LEVEL: Level = Level::Touch;
/// The deadline of `age-plugin-yubikey --list`.
const LIST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LIST_BYTES: usize = 64 * 1024;
/// The most bytes secrit reads of a stub file or a key header.
const MAX_STUB_BYTES: u64 = 16 * 1024;
const PLUGIN_PREFIX: &str = "age-plugin-";
const FIDO2_HMAC_HRP: &str = "age1fido2-hmac";

/// The key sources of one store, with the checks and the touch count.
#[derive(Debug)]
pub struct KeySources {
    /// The age key file that sops gets, if any. Not the plugin stub.
    age_key_file: Option<PathBuf>,
    ssh_key: Option<PathBuf>,
    key_cmd: Option<PathBuf>,
    plugin_dir: Option<PathBuf>,
    plugin: Option<Plugin>,
    /// The deadline of one sops run.
    timeout: Duration,
    /// Set once the key sources passed [`Self::check_sources`].
    checked: OnceLock<()>,
}

/// A `plugin` identity.
#[derive(Debug)]
pub struct Plugin {
    stub: PathBuf,
    /// The level from the config, if any.
    configured: Option<Level>,
    /// The store name in the touch line.
    label: String,
    /// The sops runs that decrypt in this command, and the ones done.
    planned: AtomicUsize,
    done: AtomicUsize,
    /// The plain keys that this user can read (6.7.2 rule 4): the default
    /// age key file and the default SSH public keys.
    plain_sources: Vec<PathBuf>,
    /// Set once the slot level passed.
    level_ok: OnceLock<()>,
}

impl KeySources {
    /// The sources of `store`. With no identity table and no other key
    /// source, the age key file defaults to sops's own default (v0.1).
    #[must_use]
    pub fn new(store: &SopsStore, env: &Env) -> Self {
        let keys: &SopsKeys = &store.keys;
        let label = store
            .file
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut s = Self {
            age_key_file: None,
            ssh_key: None,
            key_cmd: None,
            plugin_dir: keys.age_plugin_dir.clone(),
            plugin: None,
            timeout: child::TIMEOUT,
            checked: OnceLock::new(),
        };
        let mut touch_timeout = None;
        match &keys.identity {
            None => {
                s.ssh_key.clone_from(&keys.age_ssh_key_file);
                s.key_cmd.clone_from(&keys.age_key_cmd);
                s.age_key_file = store.age_key_file.clone().or_else(|| {
                    if s.ssh_key.is_none() && s.key_cmd.is_none() {
                        paths::default_age_key_file(env)
                    } else {
                        None
                    }
                });
            }
            Some(Identity::File(p)) => s.age_key_file = Some(p.clone()),
            Some(Identity::SshFile(p)) => s.ssh_key = Some(p.clone()),
            Some(Identity::KeyCmd(p)) => s.key_cmd = Some(p.clone()),
            Some(Identity::Plugin {
                stub,
                dir,
                level,
                touch_timeout_secs,
            }) => {
                s.plugin_dir = Some(dir.clone());
                touch_timeout = Some(Duration::from_secs(*touch_timeout_secs));
                let mut plain_sources: Vec<PathBuf> =
                    paths::default_age_key_file(env).into_iter().collect();
                if let Some(home) = env("HOME").map(PathBuf::from).filter(|h| h.is_absolute()) {
                    for k in ["id_ed25519.pub", "id_rsa.pub"] {
                        plain_sources.push(home.join(".ssh").join(k));
                    }
                }
                s.plugin = Some(Plugin {
                    stub: stub.clone(),
                    configured: *level,
                    label,
                    planned: AtomicUsize::new(0),
                    done: AtomicUsize::new(0),
                    plain_sources,
                    level_ok: OnceLock::new(),
                });
            }
        }
        if let Some(t) = touch_timeout {
            s.timeout = t;
        } else if s.key_cmd.is_some() || s.plugin_dir.is_some() {
            s.timeout = keys
                .age_key_cmd_timeout
                .unwrap_or(Duration::from_secs(DEFAULT_KEY_CMD_TIMEOUT_SECS));
        }
        s
    }

    /// The store name for the touch line.
    pub fn set_label(&mut self, name: &str) {
        if let Some(p) = &mut self.plugin {
            name.clone_into(&mut p.label);
        }
    }

    /// The age key file that sops gets (not a plugin stub).
    #[must_use]
    pub fn age_key_file(&self) -> Option<&Path> {
        self.age_key_file.as_deref()
    }

    #[must_use]
    pub fn ssh_key(&self) -> Option<&Path> {
        self.ssh_key.as_deref()
    }

    #[must_use]
    pub fn key_cmd(&self) -> Option<&Path> {
        self.key_cmd.as_deref()
    }

    #[must_use]
    pub fn plugin_dir(&self) -> Option<&Path> {
        self.plugin_dir.as_deref()
    }

    #[must_use]
    pub fn plugin(&self) -> Option<&Plugin> {
        self.plugin.as_ref()
    }

    /// The sops child variables of these sources.
    #[must_use]
    pub fn child_env(&self) -> Vec<(OsString, OsString)> {
        let mut env = Vec::new();
        let key_file = self
            .plugin
            .as_ref()
            .map(|p| p.stub.as_path())
            .or(self.age_key_file.as_deref());
        for (var, value) in [
            ("SOPS_AGE_KEY_FILE", key_file),
            ("SOPS_AGE_SSH_PRIVATE_KEY_FILE", self.ssh_key.as_deref()),
            ("SOPS_AGE_KEY_CMD", self.key_cmd.as_deref()),
            ("PATH", self.plugin_dir.as_deref()),
        ] {
            if let Some(v) = value {
                env.push((OsString::from(var), v.as_os_str().to_owned()));
            }
        }
        env
    }

    /// The deadline of one sops run: the test hook, else the deadline of
    /// the key source (v0.2 plan 6.2).
    #[must_use]
    pub fn timeout(&self) -> Duration {
        crate::testhook::child_timeout().unwrap_or(self.timeout)
    }

    /// What a run that hit its deadline may have waited on, if a key
    /// source can wait.
    #[must_use]
    pub fn waits(&self) -> Option<&'static str> {
        if self.plugin.is_some() {
            Some(PLUGIN_WAITS)
        } else if self.key_cmd.is_some() {
            Some(KEY_CMD_WAITS)
        } else if self.plugin_dir.is_some() {
            Some(PLUGIN_DIR_WAITS)
        } else {
            None
        }
    }

    /// The advice when sops stopped to ask on the terminal: it names each
    /// configured key source that can ask. A key command that reads the
    /// terminal stops the whole sops process group, so sops stops too
    /// (lab, S8).
    #[must_use]
    pub fn prompt_hint(&self) -> String {
        if self.plugin.is_some() {
            return PLUGIN_HINT.into();
        }
        let mut hints = Vec::new();
        if self.key_cmd.is_some() {
            hints.push(KEY_CMD_HINT);
        }
        if self.ssh_key.is_some() {
            hints.push(SSH_KEY_HINT);
        }
        if self.age_key_file.is_some() || hints.is_empty() {
            hints.push(AGE_KEY_HINT);
        }
        hints.join(". ")
    }

    /// The note for a failed sops run, when its stderr shows that the key
    /// command could not run.
    #[must_use]
    pub fn failure_note(&self, stderr: &[u8]) -> Option<&'static str> {
        let text = String::from_utf8_lossy(stderr);
        (self.key_cmd.is_some() && text.contains("failed to execute command"))
            .then_some(KEY_CMD_NOTE)
    }

    /// The checks of the key sources, once: the trust rule for the key
    /// command, the plugin directory and its programs, the SSH key and the
    /// plugin stub (T47, T48).
    pub fn check_sources(&self) -> Result<(), BackendError> {
        if self.checked.get().is_some() {
            return Ok(());
        }
        if let Some(cmd) = &self.key_cmd {
            check_key_cmd(cmd)?;
        }
        if let Some(dir) = &self.plugin_dir {
            check_plugin_dir(dir)?;
        }
        if let Some(key) = &self.ssh_key {
            check_private_key(key).map_err(|reason| unsafe_(key, reason))?;
        }
        if let Some(p) = &self.plugin {
            p.read_stub()?;
        }
        let _ = self.checked.set(());
        Ok(())
    }

    /// Everything that must pass before the first sops run of a command on
    /// the file whose sops metadata is `meta`. For a plugin identity: a
    /// terminal for the touch line, the recipients of 6.7.2 rule 4 and the
    /// slot level.
    pub fn preflight(&self, meta: &Map<String, Value>) -> Result<(), BackendError> {
        self.check_sources()?;
        let Some(p) = &self.plugin else {
            return Ok(());
        };
        if tty::open().is_err() {
            return Err(unsafe_(
                &p.stub,
                "a plugin identity needs /dev/tty to ask for the touch, and this process has no terminal".into(),
            ));
        }
        p.check_recipients(meta)?;
        if p.level_ok.get().is_none() {
            let dir = self.plugin_dir.as_deref().unwrap_or(Path::new("/"));
            p.check_level(dir)?;
            let _ = p.level_ok.set(());
        }
        Ok(())
    }

    /// The number of sops runs that decrypt in this command, for the
    /// touch line.
    pub fn plan(&self, runs: usize) {
        if let Some(p) = &self.plugin {
            p.planned.store(runs, Ordering::Relaxed);
            p.done.store(0, Ordering::Relaxed);
        }
    }

    /// For a plugin identity, write the touch line before a sops run that
    /// decrypts. `step` is the sops step.
    pub fn touch(&self, step: &str, target: &Target) -> Result<(), BackendError> {
        let Some(p) = &self.plugin else {
            return Ok(());
        };
        let Ok(tty) = tty::open() else {
            return Err(unsafe_(
                &p.stub,
                "a plugin identity needs /dev/tty to ask for the touch, and this process has no terminal".into(),
            ));
        };
        let k = p.done.fetch_add(1, Ordering::Relaxed) + 1;
        let n = p.planned.load(Ordering::Relaxed).max(k);
        let line = touch_line(step, target, &p.label, k, n);
        tty::say(&tty, &line).map_err(|source| BackendError::Io {
            step: "write the touch line to",
            path: PathBuf::from("/dev/tty"),
            source,
        })
    }
}

/// `secrit: touch your key to read 'NAME' from STORE (k of n)`.
fn touch_line(step: &str, target: &Target, store: &str, k: usize, n: usize) -> String {
    let (verb, prep) = match step {
        "set" => ("write", "to"),
        "unset" => ("remove", "from"),
        "readback decrypt" => ("check", "in"),
        _ => ("read", "from"),
    };
    let mut line = String::from("secrit: touch your key to ");
    match &target.name {
        Some(name) => {
            let _ = write!(line, "{verb} '{name}' {prep} {store}");
        }
        None => {
            let _ = write!(line, "{verb} {store}");
        }
    }
    let _ = writeln!(line, " ({k} of {n})");
    line
}

fn unsafe_(path: &Path, reason: String) -> BackendError {
    BackendError::Unsafe {
        path: path.to_path_buf(),
        reason,
    }
}

fn trust_error(path: &Path, step: &'static str, e: TrustError) -> BackendError {
    match e {
        TrustError::Io(source) => BackendError::Io {
            step,
            path: path.to_path_buf(),
            source,
        },
        TrustError::Unsafe(reason) => unsafe_(path, reason.into()),
    }
}

/// The rules for `age_key_cmd` (v0.2 plan 6.2, T47): an absolute path with
/// no character that sops's shlex split would change, to an executable that
/// passes the trust rule.
pub fn check_key_cmd(cmd: &Path) -> Result<(), BackendError> {
    let text = cmd.as_os_str().as_encoded_bytes();
    if !cmd.is_absolute() {
        return Err(unsafe_(cmd, "age_key_cmd must be an absolute path".into()));
    }
    if text
        .iter()
        .any(|b| b.is_ascii_whitespace() || matches!(b, b'\'' | b'"' | b'\\' | b'#'))
    {
        return Err(unsafe_(
            cmd,
            "the path holds a space, tab, quote, backslash or '#', which sops would split; move the key command to a path without them".into(),
        ));
    }
    trust::check_executable(cmd)
        .map(|_| ())
        .map_err(|e| trust_error(cmd, "check the key command", e))
}

/// The rules for an age plugin directory (v0.2 plan 6.2, T48): the
/// directory passes the trust rule, and it holds only `age-plugin-*`
/// programs that pass it too.
pub fn check_plugin_dir(dir: &Path) -> Result<(), BackendError> {
    trust::check_dir(dir).map_err(|e| trust_error(dir, "check the plugin directory", e))?;
    let entries = std::fs::read_dir(dir).map_err(|source| BackendError::Io {
        step: "read the plugin directory",
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| BackendError::Io {
            step: "read the plugin directory",
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(PLUGIN_PREFIX) {
            return Err(unsafe_(
                dir,
                format!(
                    "it holds '{}', which is not an age-plugin-* program; sops gets this directory as its only PATH",
                    crate::display::escape(&name.to_string_lossy())
                ),
            ));
        }
        trust::check_executable(&path).map_err(|e| trust_error(&path, "check the plugin", e))?;
    }
    Ok(())
}

/// Owner and mode of a private key file, as for the age key file: a
/// regular file (not a symlink) of this user, with no group or other bits.
pub fn check_private_key(path: &Path) -> Result<(), String> {
    let m = std::fs::symlink_metadata(path).map_err(|e| format!("cannot read it: {e}"))?;
    if m.is_symlink() {
        return Err("it is a symlink; point the config at the key file itself".into());
    }
    if !m.is_file() {
        return Err("not a regular file".into());
    }
    if m.uid() != rustix::process::getuid().as_raw() {
        return Err("owned by another user".into());
    }
    if m.mode() & 0o077 != 0 {
        return Err(format!(
            "it has mode {:04o}; it must be 0600",
            m.mode() & 0o7777
        ));
    }
    Ok(())
}

/// What the start of an OpenSSH private key says about its passphrase. It
/// reads only the armour line and the first base64 bytes, which hold the
/// cipher name, not the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshKeyHeader {
    Unencrypted,
    Encrypted,
    NotOpenSsh,
}

/// The armour line of an OpenSSH private key.
const OPENSSH_ARMOUR: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
/// Base64 of `openssh-key-v1\0` and the cipher name `none`.
const OPENSSH_NONE: &str = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU";
/// Base64 of `openssh-key-v1\0`, which every OpenSSH key starts with.
const OPENSSH_MAGIC: &str = "b3BlbnNzaC1rZXktdjEAAAAA";

/// Read the header of the SSH key at `path` (doctor, v0.2 plan 6.2).
pub fn ssh_key_header(path: &Path) -> std::io::Result<SshKeyHeader> {
    let mut buf = Zeroizing::new(vec![0u8; OPENSSH_ARMOUR.len() + 1 + OPENSSH_NONE.len()]);
    let mut f = std::fs::File::open(path)?;
    let mut len = 0;
    while len < buf.len() {
        match f.read(&mut buf[len..])? {
            0 => break,
            n => len += n,
        }
    }
    Ok(classify_ssh_header(&buf[..len]))
}

fn classify_ssh_header(head: &[u8]) -> SshKeyHeader {
    let Some(rest) = head
        .strip_prefix(OPENSSH_ARMOUR.as_bytes())
        .and_then(|r| r.strip_prefix(b"\n"))
    else {
        return SshKeyHeader::NotOpenSsh;
    };
    if rest.starts_with(OPENSSH_NONE.as_bytes()) {
        SshKeyHeader::Unencrypted
    } else if rest.starts_with(OPENSSH_MAGIC.as_bytes()) {
        SshKeyHeader::Encrypted
    } else {
        SshKeyHeader::NotOpenSsh
    }
}

/// What the first line of a key command says about how it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shebang {
    /// An ELF binary, or a script with an absolute interpreter.
    Absolute,
    /// `#!/usr/bin/env …`: it searches `PATH`, which sops does not pass.
    Env,
    /// No shebang and not ELF: the kernel refuses it.
    Missing,
}

/// Read the start of the key command at `path` (doctor, T47a).
pub fn shebang(path: &Path) -> std::io::Result<Shebang> {
    let mut buf = [0u8; 256];
    let mut f = std::fs::File::open(path)?;
    let n = f.read(&mut buf)?;
    Ok(classify_shebang(&buf[..n]))
}

fn classify_shebang(head: &[u8]) -> Shebang {
    if head.starts_with(b"\x7fELF") {
        return Shebang::Absolute;
    }
    let Some(rest) = head.strip_prefix(b"#!") else {
        return Shebang::Missing;
    };
    let line = rest.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut words = line.split_whitespace();
    match words.next() {
        Some(p) if p.ends_with("/env") => Shebang::Env,
        Some(p) if p.starts_with('/') => Shebang::Absolute,
        _ => Shebang::Missing,
    }
}

/// What a plugin stub file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stub {
    /// The plugin name: `yubikey` for `AGE-PLUGIN-YUBIKEY-1…`.
    pub plugin: String,
    /// The `# Recipient:` line, if any.
    pub recipient: Option<String>,
    /// The `# Serial: N, Slot: S` line of an age-plugin-yubikey stub.
    pub serial: Option<String>,
    pub slot: Option<String>,
}

/// Parse a stub. A plain age key is refused: a stub holds no secret.
pub fn parse_stub(text: &str) -> Result<Stub, String> {
    let mut plugin = None;
    let mut recipient = None;
    let mut serial = None;
    let mut slot = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with("AGE-SECRET-KEY-") {
            return Err(
                "it holds a plain age key, not a plugin identity; a plugin identity names a stub file".into(),
            );
        }
        if let Some(rest) = line.strip_prefix("AGE-PLUGIN-") {
            let Some(sep) = rest.rfind('1') else {
                return Err("its AGE-PLUGIN- line has no bech32 separator".into());
            };
            let name = rest[..sep].trim_end_matches('-').to_ascii_lowercase();
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err("its AGE-PLUGIN- line names no plugin".into());
            }
            if plugin.replace(name).is_some() {
                return Err("it holds more than one identity".into());
            }
        } else if let Some(c) = line.strip_prefix('#') {
            let c = c.trim();
            if let Some((k, v)) = c.split_once(':') {
                let v = v.trim();
                if k.trim().eq_ignore_ascii_case("recipient") {
                    recipient = Some(v.to_owned());
                } else if k.trim() == "Serial" {
                    let (s, rest) = v.split_once(',').unwrap_or((v, ""));
                    serial = Some(s.trim().to_owned());
                    slot = rest
                        .trim()
                        .strip_prefix("Slot:")
                        .map(|s| s.trim().to_owned());
                }
            }
        }
    }
    let plugin = plugin.ok_or("it holds no AGE-PLUGIN- identity line")?;
    Ok(Stub {
        plugin,
        recipient,
        serial,
        slot,
    })
}

/// A PIV PIN policy, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Pin {
    Unknown,
    Never,
    Once,
    Always,
}

/// A PIV touch policy. `Cached` is refused at every level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Touch {
    Unknown,
    Never,
    Cached,
    Always,
}

impl Pin {
    fn as_str(self) -> &'static str {
        match self {
            Pin::Unknown => "unknown",
            Pin::Never => "never",
            Pin::Once => "once",
            Pin::Always => "always",
        }
    }
}

impl Touch {
    fn as_str(self) -> &'static str {
        match self {
            Touch::Unknown => "unknown",
            Touch::Never => "never",
            Touch::Cached => "cached",
            Touch::Always => "always",
        }
    }
}

/// One slot of `age-plugin-yubikey --list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub serial: String,
    pub id: String,
    pub pin: Pin,
    pub touch: Touch,
    pub recipient: Option<String>,
}

/// Parse `age-plugin-yubikey --list` (0.5.1, English with no `LANG`).
/// Each slot is a block of `#` lines, then its `age1yubikey1…` recipient.
#[must_use]
pub fn parse_list(text: &str) -> Vec<Slot> {
    let mut slots = Vec::new();
    let mut cur: Option<Slot> = None;
    for line in text.lines().map(str::trim) {
        if let Some(c) = line.strip_prefix('#') {
            let Some((k, v)) = c.trim().split_once(':') else {
                continue;
            };
            let v = v.trim();
            let first = v.split_whitespace().next().unwrap_or_default();
            match k.trim() {
                "Serial" => {
                    if let Some(done) = cur.take() {
                        slots.push(done);
                    }
                    let (s, rest) = v.split_once(',').unwrap_or((v, ""));
                    cur = Some(Slot {
                        serial: s.trim().to_owned(),
                        id: rest
                            .trim()
                            .strip_prefix("Slot:")
                            .map(|s| s.trim().to_owned())
                            .unwrap_or_default(),
                        pin: Pin::Unknown,
                        touch: Touch::Unknown,
                        recipient: None,
                    });
                }
                "PIN policy" => {
                    if let Some(s) = &mut cur {
                        s.pin = match first {
                            "Never" => Pin::Never,
                            "Once" => Pin::Once,
                            "Always" => Pin::Always,
                            _ => Pin::Unknown,
                        };
                    }
                }
                "Touch policy" => {
                    if let Some(s) = &mut cur {
                        s.touch = match first {
                            "Never" => Touch::Never,
                            "Cached" => Touch::Cached,
                            "Always" => Touch::Always,
                            _ => Touch::Unknown,
                        };
                    }
                }
                _ => {}
            }
        } else if line.starts_with("age1")
            && let Some(mut s) = cur.take()
        {
            s.recipient = Some(line.to_owned());
            slots.push(s);
        }
    }
    if let Some(done) = cur {
        slots.push(done);
    }
    slots
}

/// Whether `slot` serves `level` (v0.2 plan 6.7.3 and 6.7.8 rules 4 and
/// 5). A slot weaker than the level is an error, never a downgrade, and
/// touch `cached` is refused at every level (6.7.2 rule 4).
pub fn check_slot(level: Level, slot: &Slot) -> Result<(), String> {
    let at = format!("slot {} on serial {}", slot.id, slot.serial);
    if slot.touch == Touch::Cached {
        return Err(format!(
            "{at} has touch policy cached: for 15 s after a touch any process decrypts with no touch, so secrit refuses it at every level"
        ));
    }
    let (pin, touch) = match level {
        Level::Strict => (Pin::Always, true),
        Level::Session => (Pin::Once, true),
        Level::Touch => (Pin::Unknown, true),
        Level::Unlock => (Pin::Once, false),
        Level::Open => (Pin::Unknown, false),
    };
    if slot.pin < pin {
        return Err(format!(
            "level '{}' needs PIN policy {}; {at} has {}",
            level.as_str(),
            pin.as_str(),
            slot.pin.as_str()
        ));
    }
    if touch && slot.touch != Touch::Always {
        return Err(format!(
            "level '{}' needs touch policy always; {at} has {}",
            level.as_str(),
            slot.touch.as_str()
        ));
    }
    Ok(())
}

impl Plugin {
    #[must_use]
    pub fn stub_path(&self) -> &Path {
        &self.stub
    }

    /// The level in use: the config level, else [`DEFAULT_PLUGIN_LEVEL`].
    #[must_use]
    pub fn level(&self) -> Level {
        self.configured.unwrap_or(DEFAULT_PLUGIN_LEVEL)
    }

    /// The stub under the trust rule, parsed.
    pub fn read_stub(&self) -> Result<Stub, BackendError> {
        let stub = &self.stub;
        trust::check_file(stub).map_err(|e| trust_error(stub, "check the identity stub", e))?;
        let mut text = Zeroizing::new(String::new());
        std::fs::File::open(stub)
            .and_then(|f| f.take(MAX_STUB_BYTES).read_to_string(&mut text))
            .map_err(|source| BackendError::Io {
                step: "read the identity stub",
                path: stub.clone(),
                source,
            })?;
        parse_stub(&text).map_err(|reason| unsafe_(stub, reason))
    }

    /// 6.7.2 rule 4 on the file's recipients: a fido2-hmac v2 recipient, a
    /// plain key that this user can read, or a non-age key type is refused
    /// (T70). A group-2 fido2-hmac recipient is a native X25519 `age1…`
    /// key, which secrit cannot tell apart from any other age key.
    pub fn check_recipients(&self, meta: &Map<String, Value>) -> Result<(), BackendError> {
        for kind in super::format::KEY_TYPES.iter().filter(|k| **k != "age") {
            if meta
                .get(*kind)
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty())
            {
                return Err(unsafe_(
                    &self.stub,
                    format!(
                        "the file has a {kind} recipient; a plugin identity needs age recipients only"
                    ),
                ));
            }
        }
        let plain = self.plain_recipients();
        for r in recipients(meta) {
            if r.starts_with(FIDO2_HMAC_HRP) {
                match fido2_hmac_version(&r) {
                    Some(1) => {}
                    Some(v) => {
                        return Err(unsafe_(
                            &self.stub,
                            format!(
                                "the file has a fido2-hmac recipient of format version {v}; its key is static, so one theft decrypts every value (refused at every level)"
                            ),
                        ));
                    }
                    None => {
                        return Err(unsafe_(
                            &self.stub,
                            "the file has a fido2-hmac recipient that secrit cannot decode".into(),
                        ));
                    }
                }
            }
            let key = first_two_fields(&r);
            if plain.contains(&key) {
                return Err(unsafe_(
                    &self.stub,
                    "a plain key that this user can read (the default age key file or SSH key) is a recipient of the file, so the touch protects nothing; remove it from the recipients".into(),
                ));
            }
        }
        Ok(())
    }

    /// The public keys of the plain identities in [`Plugin::plain_sources`].
    fn plain_recipients(&self) -> Vec<String> {
        let mut out = Vec::new();
        for p in &self.plain_sources {
            let Ok(f) = std::fs::File::open(p) else {
                continue;
            };
            let mut text = Zeroizing::new(String::new());
            if f.take(MAX_STUB_BYTES).read_to_string(&mut text).is_err() {
                continue;
            }
            for line in text.lines() {
                let line = line.trim();
                if let Some(pk) = line.strip_prefix("# public key:") {
                    out.push(pk.trim().to_owned());
                } else if line.starts_with("ssh-") {
                    out.push(first_two_fields(line));
                }
            }
        }
        out
    }

    /// The slot level check through `age-plugin-yubikey --list` (6.7.8
    /// rule 4), then the levels that this build cannot serve. Other plugins
    /// report no policy, so their level is not checked.
    pub fn check_level(&self, dir: &Path) -> Result<(), BackendError> {
        let stub = self.read_stub()?;
        let level = self.level();
        if stub.plugin == "yubikey" {
            let slot = self.find_slot(dir, &stub)?;
            check_slot(level, &slot).map_err(|reason| unsafe_(&self.stub, reason))?;
        }
        if level > MAX_LEVEL {
            return Err(unsafe_(
                &self.stub,
                format!(
                    "level '{}' is not in this build yet; set level = \"touch\" on a slot with PIN policy never",
                    level.as_str()
                ),
            ));
        }
        Ok(())
    }

    /// The slot of `stub` in `age-plugin-yubikey --list`.
    pub fn find_slot(&self, dir: &Path, stub: &Stub) -> Result<Slot, BackendError> {
        let text = list_slots(dir)?;
        let slots = parse_list(&text);
        slots
            .into_iter()
            .find(|s| match (&stub.recipient, &s.recipient) {
                (Some(a), Some(b)) => a == b,
                _ => stub.serial.as_ref() == Some(&s.serial) && stub.slot.as_ref() == Some(&s.id),
            })
            .ok_or_else(|| {
                unsafe_(
                    &self.stub,
                    "its slot is not in 'age-plugin-yubikey --list'; plug in the key that holds it"
                        .into(),
                )
            })
    }
}

/// Run `age-plugin-yubikey --list` from `dir`, bounded, with the cleared
/// environment and `PATH=<dir>`.
fn list_slots(dir: &Path) -> Result<String, BackendError> {
    let program = dir.join("age-plugin-yubikey");
    let mut cmd = Command::new(&program);
    cmd.env_clear()
        .env("HOME", "/nonexistent")
        .env("PATH", dir)
        .arg("--list")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let target = Target {
        location: crate::backend::Location::File(program.clone()),
        name: None,
    };
    let out = child::run(cmd, None, MAX_LIST_BYTES, LIST_TIMEOUT).map_err(|e| match e {
        child::ChildError::Interrupted => BackendError::Interrupted,
        child::ChildError::Io(source) => BackendError::Io {
            step: "run",
            path: program.clone(),
            source,
        },
        _ => BackendError::Tool {
            tool: "age-plugin-yubikey",
            step: "--list",
            target: target.clone(),
            status: crate::backend::ToolStatus(None),
            stderr: format!(": {e}"),
        },
    })?;
    if !out.status.success() {
        return Err(BackendError::Tool {
            tool: "age-plugin-yubikey",
            step: "--list",
            target,
            status: crate::backend::ToolStatus(out.status.code()),
            stderr: String::new(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The age recipients in sops metadata.
fn recipients(meta: &Map<String, Value>) -> Vec<String> {
    meta.get("age")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| e.get("recipient").and_then(Value::as_str))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// `ssh-ed25519 AAAA…` without the comment; an age key as it is.
fn first_two_fields(s: &str) -> String {
    s.split_whitespace().take(2).collect::<Vec<_>>().join(" ")
}

/// The format version of a fido2-hmac recipient: the first two bytes of
/// its bech32 payload, big-endian (`docs/spec-v2.md` of the plugin).
#[must_use]
pub fn fido2_hmac_version(recipient: &str) -> Option<u16> {
    let (hrp, data) = bech32_decode(recipient)?;
    if hrp != FIDO2_HMAC_HRP {
        return None;
    }
    let v = data.get(..2)?;
    Some(u16::from_be_bytes([v[0], v[1]]))
}

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(*v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Decode a lower-case bech32 string (BIP 173, no length limit, as age
/// uses it) into its HRP and 8-bit payload. `None` on any error.
#[must_use]
pub fn bech32_decode(s: &str) -> Option<(String, Vec<u8>)> {
    let sep = s.rfind('1')?;
    let (hrp, data) = (&s[..sep], &s[sep + 1..]);
    if hrp.is_empty() || data.len() < 6 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let values: Vec<u8> = data
        .bytes()
        .map(|c| {
            BECH32_CHARSET
                .iter()
                .position(|x| *x == c)
                .and_then(|p| u8::try_from(p).ok())
        })
        .collect::<Option<_>>()?;
    let mut check: Vec<u8> = hrp.bytes().map(|b| b >> 5).collect();
    check.push(0);
    check.extend(hrp.bytes().map(|b| b & 31));
    check.extend_from_slice(&values);
    if bech32_polymod(&check) != 1 {
        return None;
    }
    let payload = &values[..values.len() - 6];
    let mut out = Vec::with_capacity(payload.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for v in payload {
        acc = (acc << 5) | u32::from(*v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some((hrp.to_owned(), out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SopsKeys;
    use crate::name::Name;
    use std::collections::HashMap;

    /// Test recipients with dummy key, salt and credential bytes.
    const FIDO2_V2: &str = "age1fido2-hmac1qqpqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8cqyqsjygeyy5nzw2pf9g4jctfw9ucrzv3nxs6nvdec8yark0pa8clsqqgzqvzq2ps8pqys5zcvp58q7jnxqhl";
    const FIDO2_V1: &str = "age1fido2-hmac1qqqsqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8cqyqsjygeyy5nzw2pf9g4jctfw9ucrzv3nxs6nvdec8yark0pa8clsqqgzqvzq2ps8pqys5zcvp58q70jqr48";

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn store(age_key_file: Option<&str>, keys: SopsKeys) -> SopsStore {
        SopsStore {
            file: "/s/main.yaml".into(),
            format: None,
            sops_config: None,
            age_key_file: age_key_file.map(PathBuf::from),
            keys,
        }
    }

    fn vars(k: &KeySources) -> Vec<(String, String)> {
        k.child_env()
            .into_iter()
            .map(|(a, b)| (a.into_string().unwrap(), b.into_string().unwrap()))
            .collect()
    }

    fn pair(a: &str, b: &str) -> (String, String) {
        (a.to_owned(), b.to_owned())
    }

    /// Plan 6.2: each key source is one child variable that holds a path,
    /// and the deadline drops with a key command or a plugin directory.
    #[test]
    fn each_key_source_is_one_child_variable() {
        let env = env_of(&[("HOME", "/h")]);
        let v01 = KeySources::new(&store(None, SopsKeys::default()), &env);
        assert_eq!(
            vars(&v01),
            [pair("SOPS_AGE_KEY_FILE", "/h/.config/sops/age/keys.txt")]
        );
        assert_eq!(v01.timeout, child::TIMEOUT);
        assert_eq!(v01.prompt_hint(), AGE_KEY_HINT);
        assert_eq!(v01.waits(), None);

        let all = SopsKeys {
            age_ssh_key_file: Some("/k/ssh".into()),
            age_key_cmd: Some("/k/cmd".into()),
            age_key_cmd_timeout: Some(Duration::from_secs(3)),
            age_plugin_dir: Some("/k/plugins".into()),
            identity: None,
        };
        let k = KeySources::new(&store(Some("/k/age.txt"), all.clone()), &env);
        assert_eq!(
            vars(&k),
            [
                pair("SOPS_AGE_KEY_FILE", "/k/age.txt"),
                pair("SOPS_AGE_SSH_PRIVATE_KEY_FILE", "/k/ssh"),
                pair("SOPS_AGE_KEY_CMD", "/k/cmd"),
                pair("PATH", "/k/plugins"),
            ]
        );
        assert_eq!(k.timeout, Duration::from_secs(3));
        assert_eq!(
            k.prompt_hint(),
            format!("{KEY_CMD_HINT}. {SSH_KEY_HINT}. {AGE_KEY_HINT}")
        );
        assert_eq!(k.waits(), Some(KEY_CMD_WAITS));

        // An explicit key source turns off the default age key file.
        let ssh_only = SopsKeys {
            age_ssh_key_file: Some("/k/ssh".into()),
            ..SopsKeys::default()
        };
        let k = KeySources::new(&store(None, ssh_only), &env);
        assert_eq!(vars(&k), [pair("SOPS_AGE_SSH_PRIVATE_KEY_FILE", "/k/ssh")]);
        assert_eq!(k.timeout, child::TIMEOUT);

        let dir_only = SopsKeys {
            age_plugin_dir: Some("/k/plugins".into()),
            ..SopsKeys::default()
        };
        let k = KeySources::new(&store(None, dir_only), &env);
        assert_eq!(k.timeout, Duration::from_secs(DEFAULT_KEY_CMD_TIMEOUT_SECS));
        assert_eq!(k.waits(), Some(PLUGIN_DIR_WAITS));
    }

    /// A plugin identity passes its stub as the key file, never the
    /// default age key file, and its deadline is `touch_timeout_secs`.
    #[test]
    fn a_plugin_identity_never_falls_back_to_the_age_key_file() {
        let env = env_of(&[("HOME", "/h")]);
        let keys = SopsKeys {
            identity: Some(Identity::Plugin {
                stub: "/k/stub".into(),
                dir: "/k/plugins".into(),
                level: None,
                touch_timeout_secs: 7,
            }),
            ..SopsKeys::default()
        };
        let k = KeySources::new(&store(None, keys), &env);
        assert_eq!(
            vars(&k),
            [
                pair("SOPS_AGE_KEY_FILE", "/k/stub"),
                pair("PATH", "/k/plugins")
            ]
        );
        assert_eq!(k.age_key_file(), None);
        assert_eq!(k.timeout, Duration::from_secs(7));
        assert_eq!(k.prompt_hint(), PLUGIN_HINT);
        assert_eq!(k.plugin().unwrap().level(), Level::Touch);
        assert_eq!(
            k.plugin().unwrap().plain_sources,
            [
                PathBuf::from("/h/.config/sops/age/keys.txt"),
                "/h/.ssh/id_ed25519.pub".into(),
                "/h/.ssh/id_rsa.pub".into(),
            ]
        );

        for (id, var) in [
            (Identity::File("/k/f".into()), "SOPS_AGE_KEY_FILE"),
            (
                Identity::SshFile("/k/f".into()),
                "SOPS_AGE_SSH_PRIVATE_KEY_FILE",
            ),
            (Identity::KeyCmd("/k/f".into()), "SOPS_AGE_KEY_CMD"),
        ] {
            let keys = SopsKeys {
                identity: Some(id),
                ..SopsKeys::default()
            };
            let k = KeySources::new(&store(None, keys), &env);
            assert_eq!(vars(&k), [pair(var, "/k/f")]);
        }
    }

    #[test]
    fn touch_lines_name_the_step_the_name_and_the_count() {
        let target = Target {
            location: crate::backend::Location::File("/s/main.yaml".into()),
            name: Some(Name::parse("tok").unwrap()),
        };
        assert_eq!(
            touch_line("decrypt", &target, "vault", 2, 5),
            "secrit: touch your key to read 'tok' from vault (2 of 5)\n"
        );
        assert_eq!(
            touch_line("set", &target, "vault", 1, 2),
            "secrit: touch your key to write 'tok' to vault (1 of 2)\n"
        );
        assert_eq!(
            touch_line("readback decrypt", &target, "vault", 2, 2),
            "secrit: touch your key to check 'tok' in vault (2 of 2)\n"
        );
        assert_eq!(
            touch_line("unset", &target, "vault", 1, 1),
            "secrit: touch your key to remove 'tok' from vault (1 of 1)\n"
        );
    }

    #[test]
    fn key_command_paths_that_sops_would_split_are_refused() {
        for p in ["/a b/cmd", "/a\tb", "/it's", "/a\"b", "/a\\b", "/a#b"] {
            let e = check_key_cmd(Path::new(p)).unwrap_err();
            assert!(e.to_string().contains("sops would split"), "{p}: {e}");
            assert_eq!(e.exit(), crate::error::Exit::Refused);
        }
        let e = check_key_cmd(Path::new("/nonexistent/cmd")).unwrap_err();
        assert!(matches!(e, BackendError::Io { .. }), "{e}");
    }

    #[test]
    fn shebangs_are_classified() {
        assert_eq!(classify_shebang(b"\x7fELF\x02"), Shebang::Absolute);
        assert_eq!(classify_shebang(b"#!/bin/sh\necho"), Shebang::Absolute);
        assert_eq!(
            classify_shebang(b"#! /nix/store/x-bash/bin/bash -e\n"),
            Shebang::Absolute
        );
        assert_eq!(classify_shebang(b"#!/usr/bin/env sh\n"), Shebang::Env);
        assert_eq!(
            classify_shebang(b"#!/usr/bin/env -S bash -e\n"),
            Shebang::Env
        );
        assert_eq!(classify_shebang(b"#!bash\n"), Shebang::Missing);
        assert_eq!(classify_shebang(b"echo hi\n"), Shebang::Missing);
        assert_eq!(classify_shebang(b""), Shebang::Missing);
    }

    #[test]
    fn ssh_key_headers_are_classified_without_the_key() {
        let head = |b64: &str| format!("{OPENSSH_ARMOUR}\n{b64}");
        assert_eq!(
            classify_ssh_header(head("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ").as_bytes()),
            SshKeyHeader::Unencrypted
        );
        assert_eq!(
            classify_ssh_header(head("b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHI").as_bytes()),
            SshKeyHeader::Encrypted
        );
        assert_eq!(
            classify_ssh_header(b"-----BEGIN RSA PRIVATE KEY-----\nMIIE"),
            SshKeyHeader::NotOpenSsh
        );
        assert_eq!(classify_ssh_header(b""), SshKeyHeader::NotOpenSsh);
    }

    const YUBIKEY_STUB: &str = "#       Serial: 5555555, Slot: 1\n#         Name: age identity 1a2b3c4d\n#      Created: Thu, 08 Oct 2026 00:00:00 +0000\n#   PIN policy: Never  (A PIN is NOT required to decrypt)\n# Touch policy: Always (A physical touch is required for every decryption)\n#    Recipient: age1yubikey1qtest\nAGE-PLUGIN-YUBIKEY-1TESTSTUB\n";

    #[test]
    fn stubs_parse_and_a_plain_key_is_refused() {
        let s = parse_stub(YUBIKEY_STUB).unwrap();
        assert_eq!(s.plugin, "yubikey");
        assert_eq!(s.recipient.as_deref(), Some("age1yubikey1qtest"));
        assert_eq!(s.serial.as_deref(), Some("5555555"));
        assert_eq!(s.slot.as_deref(), Some("1"));
        let s = parse_stub(
            "# created: 2026-10-08T00:00:00Z\n# recipient: age1unencrypted1k5fr0r\nAGE-PLUGIN-UNENCRYPTED-1CR7ZD5\n",
        )
        .unwrap();
        assert_eq!(s.plugin, "unencrypted");
        assert_eq!(s.recipient.as_deref(), Some("age1unencrypted1k5fr0r"));
        assert!(
            parse_stub("AGE-SECRET-KEY-1XYZ\n")
                .unwrap_err()
                .contains("plain age key")
        );
        assert!(parse_stub("# nothing\n").is_err());
        assert!(parse_stub("AGE-PLUGIN-A-1X\nAGE-PLUGIN-B-1Y\n").is_err());
    }

    #[test]
    fn the_yubikey_list_parses_and_levels_are_checked() {
        let list = "#       Serial: 5555555, Slot: 1\n#         Name: a\n#      Created: x\n#   PIN policy: Once   (A PIN is required once per session, if set)\n# Touch policy: Always (A physical touch is required for every decryption)\nage1yubikey1qone\n\n#       Serial: 5555555, Slot: 2\n#   PIN policy: Never  (A PIN is NOT required to decrypt)\n# Touch policy: Cached (A physical touch is required for decryption, and is cached for 15 seconds)\nage1yubikey1qtwo\n";
        let slots = parse_list(list);
        assert_eq!(slots.len(), 2);
        assert_eq!(
            slots[0],
            Slot {
                serial: "5555555".into(),
                id: "1".into(),
                pin: Pin::Once,
                touch: Touch::Always,
                recipient: Some("age1yubikey1qone".into()),
            }
        );
        assert_eq!((slots[1].pin, slots[1].touch), (Pin::Never, Touch::Cached));

        assert_eq!(
            check_slot(Level::Strict, &slots[0]).unwrap_err(),
            "level 'strict' needs PIN policy always; slot 1 on serial 5555555 has once"
        );
        assert!(check_slot(Level::Session, &slots[0]).is_ok());
        assert!(check_slot(Level::Touch, &slots[0]).is_ok());
        for level in [Level::Open, Level::Touch, Level::Strict] {
            let e = check_slot(level, &slots[1]).unwrap_err();
            assert!(e.contains("touch policy cached"), "{e}");
        }
        let no_touch = Slot {
            touch: Touch::Never,
            ..slots[0].clone()
        };
        assert_eq!(
            check_slot(Level::Touch, &no_touch).unwrap_err(),
            "level 'touch' needs touch policy always; slot 1 on serial 5555555 has never"
        );
        assert!(check_slot(Level::Unlock, &no_touch).is_ok());
        let unknown = Slot {
            pin: Pin::Unknown,
            ..slots[0].clone()
        };
        assert!(check_slot(Level::Session, &unknown).is_err());
    }

    /// T70: the version of a fido2-hmac recipient comes from its payload.
    #[test]
    fn fido2_hmac_versions_decode() {
        assert_eq!(fido2_hmac_version(FIDO2_V2), Some(2));
        assert_eq!(fido2_hmac_version(FIDO2_V1), Some(1));
        // A changed character breaks the checksum.
        let bad = FIDO2_V2.replacen("qqpq", "qqpp", 1);
        assert_eq!(fido2_hmac_version(&bad), None);
        assert_eq!(fido2_hmac_version("age1unencrypted1k5fr0r"), None);
        let (hrp, data) = bech32_decode("age1unencrypted1k5fr0r").unwrap();
        assert_eq!(hrp, "age1unencrypted");
        assert!(data.is_empty());
        assert!(bech32_decode("AGE1X").is_none());
    }

    fn plugin_with(plain_sources: Vec<PathBuf>) -> Plugin {
        Plugin {
            stub: "/k/stub".into(),
            configured: None,
            label: "vault".into(),
            planned: AtomicUsize::new(0),
            done: AtomicUsize::new(0),
            plain_sources,
            level_ok: OnceLock::new(),
        }
    }

    fn meta(recipients: &[&str]) -> Map<String, Value> {
        let age: Vec<Value> = recipients
            .iter()
            .map(|r| serde_json::json!({ "recipient": r, "enc": "x" }))
            .collect();
        let mut m = Map::new();
        m.insert("age".into(), Value::Array(age));
        m
    }

    /// 6.7.2 rule 4 on the recipient set.
    #[test]
    fn rule_four_recipients_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let keys = d.path().join("keys.txt");
        std::fs::write(
            &keys,
            "# created: x\n# public key: age1plainkey\nAGE-SECRET-KEY-1DUMMY\n",
        )
        .unwrap();
        let ssh = d.path().join("id_ed25519.pub");
        std::fs::write(&ssh, "ssh-ed25519 AAAAplain user@host\n").unwrap();
        let p = plugin_with(vec![keys, ssh, d.path().join("missing.pub")]);

        assert!(
            p.check_recipients(&meta(&["age1unencrypted1k5fr0r", FIDO2_V1]))
                .is_ok()
        );
        for (r, said) in [
            (FIDO2_V2, "format version 2"),
            ("age1fido2-hmac1qqqq", "cannot decode"),
            ("age1plainkey", "plain key"),
            ("ssh-ed25519 AAAAplain", "plain key"),
        ] {
            let e = p
                .check_recipients(&meta(&["age1unencrypted1k5fr0r", r]))
                .unwrap_err();
            assert!(e.to_string().contains(said), "{r}: {e}");
            assert_eq!(e.exit(), crate::error::Exit::Refused);
        }
        let mut pgp = meta(&["age1unencrypted1k5fr0r"]);
        pgp.insert("pgp".into(), serde_json::json!([{ "fp": "X" }]));
        let e = p.check_recipients(&pgp).unwrap_err();
        assert!(e.to_string().contains("pgp recipient"), "{e}");
    }

    /// T48: a plugin directory holds only private `age-plugin-*` programs.
    #[test]
    fn plugin_directories_are_checked() {
        use std::os::unix::fs::PermissionsExt;
        let chmod = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        };
        let d = tempfile::tempdir().unwrap();
        chmod(d.path(), 0o700);
        let dir = d.path().join("plugins");
        std::fs::create_dir(&dir).unwrap();
        chmod(&dir, 0o700);
        let plugin = dir.join("age-plugin-x");
        std::fs::write(&plugin, "#!/bin/sh\n").unwrap();
        chmod(&plugin, 0o700);
        assert!(check_plugin_dir(&dir).is_ok());
        chmod(&plugin, 0o720);
        let e = check_plugin_dir(&dir).unwrap_err();
        assert!(e.to_string().contains("writable by group or others"), "{e}");
        chmod(&plugin, 0o700);
        std::fs::write(dir.join("sh"), "").unwrap();
        let e = check_plugin_dir(&dir).unwrap_err();
        assert!(e.to_string().contains("'sh'"), "{e}");
        std::fs::remove_file(dir.join("sh")).unwrap();
        chmod(&dir, 0o770);
        let e = check_plugin_dir(&dir).unwrap_err();
        assert!(e.to_string().contains("writable by group or others"), "{e}");
    }
}
