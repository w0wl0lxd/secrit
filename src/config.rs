//! Configuration (PLAN section 5).
//!
//! secrit has no built-in machine paths. Every path comes from the config file,
//! is absolute after `~` expansion, and unknown keys are an error.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

pub const ENV_CONFIG: &str = "SECRIT_CONFIG";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 30;

/// The environment as a lookup function, so tests can pass their own.
pub type Env = dyn Fn(&str) -> Option<OsString>;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("HOME is not set to an absolute path")]
    NoHome,
    #[error("{ENV_CONFIG} must be an absolute path")]
    RelativeEnvPath,
    #[error("no config file at {}; create it (see README) or pass --config", .0.display())]
    NotFound(PathBuf),
    #[error("refusing config file {}: {reason}", path.display())]
    Unsafe { path: PathBuf, reason: &'static str },
    #[error("could not read config file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("config file {} is larger than {MAX_CONFIG_BYTES} bytes", .0.display())]
    TooLarge(PathBuf),
    #[error("invalid config file {}: {message}", path.display())]
    Parse { path: PathBuf, message: String },
    #[error("config key {key}: path must be absolute or start with '~/'")]
    RelativePath { key: String },
    #[error("config key {key}: only '~' and '~/' are expanded, not '~user'")]
    TildeUser { key: String },
    #[error("no store named '{0}' in the config")]
    UnknownStore(String),
    #[error("no --store given and the config has no default_store")]
    NoDefaultStore,
    #[error("config key lock.timeout_secs must be at least 1")]
    ZeroTimeout,
    #[error("store {0} does not use the sops backend")]
    NotSops(String),
    #[error("config key {key} is required for the {backend} backend")]
    MissingKey { key: String, backend: &'static str },
    #[error("config key {key} does not apply to the {backend} backend; remove it")]
    ForeignKey { key: String, backend: &'static str },
    #[error(
        "config key {key}: use a relative path of plain directory names, with no '.', '..' or hidden part"
    )]
    BadPrefix { key: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    default_store: Option<String>,
    #[serde(default)]
    stores: BTreeMap<String, RawStore>,
    nix: Option<RawNix>,
    #[serde(default)]
    tools: RawTools,
    #[serde(default)]
    lock: RawLock,
}

/// One `[stores.NAME]` table. The `backend` key picks the backend (v0.2 plan
/// 5.8), and `parse` turns the table into that backend's settings.
///
/// The table is one flat struct, not an enum tagged by `backend`: serde
/// buffers a tagged enum, and toml then reports a bad key at the table
/// header, not at its own line. A key that only another backend takes
/// becomes an `Option` here, and `parse` refuses it for this backend.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStore {
    backend: BackendKind,
    file: Option<String>,
    sops_config: Option<String>,
    age_key_file: Option<String>,
    dir: Option<String>,
    prefix: Option<String>,
    gnupg_home: Option<String>,
    value: Option<PassValue>,
    pinentry: Option<Pinentry>,
    wire_hint: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNix {
    flake: String,
    host: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTools {
    sops: Option<String>,
    age_keygen: Option<String>,
    gpg: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawLock {
    timeout_secs: u64,
}

impl Default for RawLock {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    Sops,
    /// The password-store layout: one gpg file per name (v0.2 plan 6.4).
    Pass,
}

impl BackendKind {
    /// The value of the `backend` key.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            BackendKind::Sops => "sops",
            BackendKind::Pass => "pass",
        }
    }
}

/// Which part of a pass entry is the value (v0.2 plan 6.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PassValue {
    /// The whole file minus one trailing newline.
    #[default]
    Whole,
    /// The bytes before the first newline: the pass password.
    FirstLine,
}

/// Whether gpg may ask gpg-agent for a pinentry on `get` (v0.2 plan 6.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Pinentry {
    /// `--pinentry-mode error`: a needed passphrase fails at once.
    #[default]
    Error,
    /// gpg-agent's own pinentry, only with no agent and a terminal.
    Agent,
}

/// One store of the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreConfig {
    pub name: String,
    pub wire_hint: bool,
    pub backend: BackendConfig,
}

impl StoreConfig {
    /// The sops settings, or `None` for a store of another backend.
    #[must_use]
    pub fn sops(&self) -> Option<&SopsStore> {
        match &self.backend {
            BackendConfig::Sops(sops) => Some(sops),
            BackendConfig::Pass(_) => None,
        }
    }

    #[must_use]
    pub fn kind(&self) -> BackendKind {
        match &self.backend {
            BackendConfig::Sops(_) => BackendKind::Sops,
            BackendConfig::Pass(_) => BackendKind::Pass,
        }
    }

    /// [`Self::sops`], for the commands that only a sops store supports.
    pub fn require_sops(&self) -> Result<&SopsStore, ConfigError> {
        self.sops()
            .ok_or_else(|| ConfigError::NotSops(self.name.clone()))
    }
}

/// The backend of a store and its own settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendConfig {
    Sops(SopsStore),
    Pass(PassStore),
}

/// The settings of a pass layout store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassStore {
    /// The password-store directory, the one that holds the root `.gpg-id`.
    pub dir: PathBuf,
    /// The subdirectory of `dir` that holds this store's entries, as plain
    /// directory names joined by `/`; `None` for `dir` itself.
    pub prefix: Option<String>,
    /// `None`: `$GNUPGHOME` when it is absolute, else `~/.gnupg`.
    pub gnupg_home: Option<PathBuf>,
    pub value: PassValue,
    pub pinentry: Pinentry,
}

impl PassStore {
    /// The directory of the entries: `dir`, then `prefix`.
    #[must_use]
    pub fn entries_dir(&self) -> PathBuf {
        match &self.prefix {
            Some(p) => self.dir.join(p),
            None => self.dir.clone(),
        }
    }
}

/// The settings of a sops store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SopsStore {
    pub file: PathBuf,
    pub sops_config: Option<PathBuf>,
    pub age_key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NixConfig {
    pub flake: PathBuf,
    pub host: String,
}

/// `"auto"` (baked-in path, else PATH) or an absolute path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolSetting {
    Auto,
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsConfig {
    pub sops: ToolSetting,
    pub age_keygen: ToolSetting,
    pub gpg: ToolSetting,
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            sops: ToolSetting::Auto,
            age_keygen: ToolSetting::Auto,
            gpg: ToolSetting::Auto,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub path: PathBuf,
    pub default_store: Option<String>,
    pub stores: BTreeMap<String, StoreConfig>,
    pub nix: Option<NixConfig>,
    pub tools: ToolsConfig,
    pub lock_timeout: Duration,
}

/// Where the config path came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    Flag,
    /// `$SECRIT_CONFIG`. secrit names the file on stderr each time, because a
    /// variable is not visible on the command line (SEC-10).
    Env,
    Default,
}

/// The config file path: `--config`, then `$SECRIT_CONFIG`, then
/// `$XDG_CONFIG_HOME/secrit/config.toml`, then `~/.config/secrit/config.toml`.
pub fn config_path(
    flag: Option<&Path>,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<(PathBuf, ConfigSource), ConfigError> {
    if let Some(p) = flag {
        return std::path::absolute(p)
            .map(|p| (p, ConfigSource::Flag))
            .map_err(|source| ConfigError::Io {
                path: p.to_path_buf(),
                source,
            });
    }
    if let Some(v) = env(ENV_CONFIG).filter(|v| !v.is_empty()) {
        let p = PathBuf::from(v);
        return if p.is_absolute() {
            Ok((p, ConfigSource::Env))
        } else {
            Err(ConfigError::RelativeEnvPath)
        };
    }
    // The XDG spec says to ignore a relative XDG_CONFIG_HOME.
    let dir = match env("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        Some(x) => x,
        None => home(env)?.join(".config"),
    };
    Ok((
        dir.join("secrit").join("config.toml"),
        ConfigSource::Default,
    ))
}

/// `$HOME`, which must be absolute.
pub fn home(env: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf, ConfigError> {
    env("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .ok_or(ConfigError::NoHome)
}

impl Config {
    /// Read and parse the config file at `path` after the ownership and mode checks.
    pub fn load(path: &Path, home: &Path) -> Result<Self, ConfigError> {
        let text = read_checked(path)?;
        Self::parse(&text, path, home)
    }

    /// Parse config text. `path` is used in messages only.
    pub fn parse(text: &str, path: &Path, home: &Path) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            message: parse_message(text, &e),
        })?;
        if raw.lock.timeout_secs == 0 {
            return Err(ConfigError::ZeroTimeout);
        }
        let mut stores = BTreeMap::new();
        for (name, s) in raw.stores {
            let wire_hint = s.wire_hint.unwrap_or(false);
            let backend = parse_store(&name, s, home)?;
            let store = StoreConfig {
                name: name.clone(),
                wire_hint,
                backend,
            };
            stores.insert(name, store);
        }
        if let Some(d) = &raw.default_store
            && !stores.contains_key(d)
        {
            return Err(ConfigError::UnknownStore(d.clone()));
        }
        let nix = raw
            .nix
            .map(|n| -> Result<NixConfig, ConfigError> {
                Ok(NixConfig {
                    flake: expand(&n.flake, home, "nix.flake")?,
                    host: n.host,
                })
            })
            .transpose()?;
        Ok(Self {
            path: path.to_path_buf(),
            default_store: raw.default_store,
            stores,
            nix,
            tools: ToolsConfig {
                sops: tool_setting(raw.tools.sops.as_deref(), home, "tools.sops")?,
                age_keygen: tool_setting(
                    raw.tools.age_keygen.as_deref(),
                    home,
                    "tools.age_keygen",
                )?,
                gpg: tool_setting(raw.tools.gpg.as_deref(), home, "tools.gpg")?,
            },
            lock_timeout: Duration::from_secs(raw.lock.timeout_secs),
        })
    }

    /// The store named by `--store`, else `default_store`.
    pub fn store(&self, flag: Option<&str>) -> Result<&StoreConfig, ConfigError> {
        let name = flag
            .or(self.default_store.as_deref())
            .ok_or(ConfigError::NoDefaultStore)?;
        self.stores
            .get(name)
            .ok_or_else(|| ConfigError::UnknownStore(name.to_owned()))
    }
}

/// The toml error with the line and column where it starts, so a bad key
/// inside a store table points at its own line.
fn parse_message(text: &str, e: &toml::de::Error) -> String {
    let at = e
        .span()
        .and_then(|span| text.get(..span.start))
        .map(|before| {
            let line = before.matches('\n').count() + 1;
            let column = before
                .rsplit('\n')
                .next()
                .unwrap_or_default()
                .chars()
                .count()
                + 1;
            format!("line {line}, column {column}: ")
        })
        .unwrap_or_default();
    format!("{at}{}", e.message())
}

/// One store table as its backend's settings. A key that only another
/// backend takes is an error, so a typo of the `backend` value is not
/// silently a store with other defaults.
fn parse_store(name: &str, s: RawStore, home: &Path) -> Result<BackendConfig, ConfigError> {
    let backend = s.backend.name();
    let key = |k: &str| format!("stores.{name}.{k}");
    let refuse = |present: bool, k: &str| {
        if present {
            Err(ConfigError::ForeignKey {
                key: key(k),
                backend,
            })
        } else {
            Ok(())
        }
    };
    let path = |v: Option<String>, k: &str| v.map(|v| expand(&v, home, &key(k))).transpose();
    let required = |v: Option<String>, k: &str| -> Result<PathBuf, ConfigError> {
        let v = v.ok_or_else(|| ConfigError::MissingKey {
            key: key(k),
            backend,
        })?;
        expand(&v, home, &key(k))
    };
    match s.backend {
        BackendKind::Sops => {
            refuse(s.dir.is_some(), "dir")?;
            refuse(s.prefix.is_some(), "prefix")?;
            refuse(s.gnupg_home.is_some(), "gnupg_home")?;
            refuse(s.value.is_some(), "value")?;
            refuse(s.pinentry.is_some(), "pinentry")?;
            Ok(BackendConfig::Sops(SopsStore {
                file: required(s.file, "file")?,
                sops_config: path(s.sops_config, "sops_config")?,
                age_key_file: path(s.age_key_file, "age_key_file")?,
            }))
        }
        BackendKind::Pass => {
            refuse(s.file.is_some(), "file")?;
            refuse(s.sops_config.is_some(), "sops_config")?;
            refuse(s.age_key_file.is_some(), "age_key_file")?;
            // `wire` emits sops-nix stanzas only.
            refuse(s.wire_hint.is_some(), "wire_hint")?;
            Ok(BackendConfig::Pass(PassStore {
                dir: required(s.dir, "dir")?,
                prefix: s
                    .prefix
                    .map(|p| parse_prefix(&p, &key("prefix")))
                    .transpose()?
                    .flatten(),
                gnupg_home: path(s.gnupg_home, "gnupg_home")?,
                value: s.value.unwrap_or_default(),
                pinentry: s.pinentry.unwrap_or_default(),
            }))
        }
    }
}

/// The prefix as `a/b`, without a trailing `/`; `None` when it is empty.
fn parse_prefix(value: &str, key: &str) -> Result<Option<String>, ConfigError> {
    let parts: Vec<&str> = value.trim_end_matches('/').split('/').collect();
    if parts == [""] {
        return Ok(None);
    }
    let bad = |p: &&str| p.is_empty() || p.starts_with('.') || p.contains('\0');
    if parts.iter().any(bad) {
        return Err(ConfigError::BadPrefix {
            key: key.to_owned(),
        });
    }
    Ok(Some(parts.join("/")))
}

fn tool_setting(v: Option<&str>, home: &Path, key: &str) -> Result<ToolSetting, ConfigError> {
    match v {
        None | Some("auto") => Ok(ToolSetting::Auto),
        Some(p) => Ok(ToolSetting::Path(expand(p, home, key)?)),
    }
}

/// Expand a leading `~` or `~/`. Any other relative path is an error.
fn expand(value: &str, home: &Path, key: &str) -> Result<PathBuf, ConfigError> {
    if value == "~" {
        return Ok(home.to_path_buf());
    }
    if let Some(rest) = value.strip_prefix("~/") {
        return Ok(home.join(rest));
    }
    if value.starts_with('~') {
        return Err(ConfigError::TildeUser {
            key: key.to_owned(),
        });
    }
    let p = PathBuf::from(value);
    if p.is_absolute() {
        Ok(p)
    } else {
        Err(ConfigError::RelativePath {
            key: key.to_owned(),
        })
    }
}

/// Refuse a config file that another user owns or that group or others can
/// write. A symlink into `/nix/store` (home-manager) is accepted: store paths
/// are root-owned and read-only.
fn read_checked(path: &Path) -> Result<String, ConfigError> {
    let io = |source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };
    let target = match std::fs::canonicalize(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }
        Err(e) => return Err(io(e)),
    };
    let file = std::fs::File::open(&target).map_err(io)?;
    let meta = file.metadata().map_err(io)?;
    let unsafe_ = |reason| ConfigError::Unsafe {
        path: path.to_path_buf(),
        reason,
    };
    if !meta.is_file() {
        return Err(unsafe_("not a regular file"));
    }
    let uid = rustix::process::getuid().as_raw();
    if meta.uid() != uid && !crate::trust::in_nix_store(&target, &meta) {
        return Err(unsafe_("owned by another user"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(unsafe_("writable by group or others"));
    }
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge(path.to_path_buf()));
    }
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(io)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const HOME: &str = "/home/u";

    fn parse(text: &str) -> Result<Config, ConfigError> {
        Config::parse(text, Path::new("/c.toml"), Path::new(HOME))
    }

    const FULL: &str = r#"
default_store = "main"

[stores.main]
backend = "sops"
file = "/etc/nixos/secrets/secrit.yaml"
sops_config = "/etc/nixos/.sops.yaml"
age_key_file = "~/.config/sops/age/keys.txt"
wire_hint = true

[nix]
flake = "/etc/nixos"
host = "myhost"

[tools]
sops = "auto"
age_keygen = "/nix/store/x-age/bin/age-keygen"

[lock]
timeout_secs = 5
"#;

    fn sops_of(s: &StoreConfig) -> &SopsStore {
        s.sops().unwrap()
    }

    #[test]
    fn parses_the_plan_example() {
        let c = parse(FULL).unwrap();
        let s = c.store(None).unwrap();
        assert_eq!(sops_of(s).file, Path::new("/etc/nixos/secrets/secrit.yaml"));
        assert_eq!(
            sops_of(s).age_key_file.as_deref(),
            Some(Path::new("/home/u/.config/sops/age/keys.txt"))
        );
        assert!(s.wire_hint);
        assert_eq!(c.tools.sops, ToolSetting::Auto);
        assert_eq!(
            c.tools.age_keygen,
            ToolSetting::Path("/nix/store/x-age/bin/age-keygen".into())
        );
        assert_eq!(c.lock_timeout, Duration::from_secs(5));
        assert_eq!(c.nix.unwrap().host, "myhost");
    }

    /// init and wire need a sops store, and say so for another backend.
    #[test]
    fn a_sops_store_gives_its_settings() {
        let c = parse(FULL).unwrap();
        let s = c.store(None).unwrap();
        assert_eq!(s.require_sops().unwrap(), sops_of(s));
        assert_eq!(
            ConfigError::NotSops("main".into()).to_string(),
            "store main does not use the sops backend"
        );
    }

    #[test]
    fn minimal_config_uses_defaults() {
        let c = parse("[stores.a]\nbackend = \"sops\"\nfile = \"~/s.yaml\"\n").unwrap();
        assert_eq!(
            c.lock_timeout,
            Duration::from_secs(DEFAULT_LOCK_TIMEOUT_SECS)
        );
        assert!(matches!(c.store(None), Err(ConfigError::NoDefaultStore)));
        assert_eq!(
            sops_of(c.store(Some("a")).unwrap()).file,
            Path::new("/home/u/s.yaml")
        );
        assert!(matches!(
            c.store(Some("b")),
            Err(ConfigError::UnknownStore(_))
        ));
    }

    #[test]
    fn unknown_keys_are_an_error() {
        let typo = "[stores.a]\nbackend = \"sops\"\nfile = \"/s.yaml\"\nfiel = \"/x\"\n";
        assert!(matches!(parse(typo), Err(ConfigError::Parse { .. })));
        assert!(matches!(
            parse("defualt_store = \"a\"\n"),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn unknown_backend_is_an_error() {
        let t = "[stores.a]\nbackend = \"keepassxc\"\nfile = \"/s.yaml\"\n";
        assert!(matches!(parse(t), Err(ConfigError::Parse { .. })));
        let e = parse("[stores.a]\nfile = \"/s.yaml\"\n").unwrap_err();
        assert!(e.to_string().contains("backend"), "{e}");
    }

    /// The config shapes that v0.1 and its test suite write parse to the
    /// same settings as in v0.1 (v0.2 plan, S1a).
    #[test]
    fn v01_configs_parse_unchanged() {
        let store = "[stores.main]\nbackend = \"sops\"\nfile = \"/r/secrets/main.yaml\"\nage_key_file = \"/r/keys/key1.txt\"\n";
        let tail = "\n[tools]\nsops = \"/nix/store/x-sops/bin/sops\"\n\n[lock]\ntimeout_secs = 2\n";
        let want = |wire_hint, sops_config: Option<&str>| StoreConfig {
            name: "main".into(),
            wire_hint,
            backend: BackendConfig::Sops(SopsStore {
                file: "/r/secrets/main.yaml".into(),
                sops_config: sops_config.map(PathBuf::from),
                age_key_file: Some("/r/keys/key1.txt".into()),
            }),
        };
        for (extra, expected) in [
            ("", want(false, None)),
            ("wire_hint = true\n", want(true, None)),
            ("wire_hint = false\n", want(false, None)),
            (
                "sops_config = \"/r/.sops.yaml\"\n",
                want(false, Some("/r/.sops.yaml")),
            ),
        ] {
            let text = format!("default_store = \"main\"\n\n{store}{extra}{tail}");
            let c = parse(&text).unwrap();
            assert_eq!(c.store(None).unwrap(), &expected, "{text}");
            assert_eq!(c.lock_timeout, Duration::from_secs(2));
        }
        // The form that init writes for a new config.
        let init = format!("default_store = \"main\"\n\n{store}");
        assert_eq!(
            parse(&init).unwrap().store(None).unwrap(),
            &want(false, None)
        );
    }

    /// A bad key or value inside a store table names its own line and
    /// column, and the unknown-key error lists every key that a store takes.
    #[test]
    fn store_errors_name_the_line_and_every_key() {
        let head = "default_store = \"main\"\n\n[stores.main]\nbackend = \"sops\"\n";
        let e = parse(&format!("{head}file = \"/s.yaml\"\nfiel = \"/x\"\n")).unwrap_err();
        assert_eq!(
            e.to_string(),
            "invalid config file /c.toml: line 6, column 1: unknown field `fiel`, expected one of `backend`, `file`, `sops_config`, `age_key_file`, `dir`, `prefix`, `gnupg_home`, `value`, `pinentry`, `wire_hint`"
        );
        let e = parse(&format!("{head}file = 5\n")).unwrap_err();
        assert_eq!(
            e.to_string(),
            "invalid config file /c.toml: line 5, column 8: invalid type: integer `5`, expected a string"
        );
        let e = parse("[stores.main]\nbackend = \"keepassxc\"\nfile = \"/s.yaml\"\n").unwrap_err();
        assert!(
            e.to_string().contains("line 2, column 11: unknown variant"),
            "{e}"
        );
    }

    /// Each backend refuses the keys that it does not take (v0.2 plan 5.8).
    #[test]
    fn each_backend_refuses_unknown_keys() {
        for (backend, keys) in [
            ("sops", "file = \"/s.yaml\"\n"),
            ("pass", "dir = \"~/.password-store\"\n"),
        ] {
            let good = format!("[stores.a]\nbackend = \"{backend}\"\n{keys}");
            assert!(parse(&good).is_ok(), "{good}");
            for typo in [
                "fiel = \"/x\"\n",
                "wire-hint = true\n",
                "format = \"yaml\"\n",
            ] {
                let bad = format!("{good}{typo}");
                let e = parse(&bad).unwrap_err();
                assert!(matches!(e, ConfigError::Parse { .. }), "{bad}");
                assert!(e.to_string().contains("unknown field"), "{bad}: {e}");
            }
        }
    }

    /// A key of another backend, or a missing required key, names the key
    /// and the backend.
    #[test]
    fn each_backend_refuses_the_keys_of_another() {
        for (backend, good, foreign) in [
            (
                "sops",
                "file = \"/s.yaml\"\n",
                &[
                    "dir = \"/d\"\n",
                    "prefix = \"p\"\n",
                    "gnupg_home = \"/g\"\n",
                    "value = \"whole\"\n",
                    "pinentry = \"error\"\n",
                ][..],
            ),
            (
                "pass",
                "dir = \"/d\"\n",
                &[
                    "file = \"/s.yaml\"\n",
                    "sops_config = \"/c\"\n",
                    "age_key_file = \"/k\"\n",
                    "wire_hint = false\n",
                ][..],
            ),
        ] {
            let head = format!("[stores.a]\nbackend = \"{backend}\"\n");
            for extra in foreign {
                let e = parse(&format!("{head}{good}{extra}")).unwrap_err();
                let key = extra.split(' ').next().unwrap();
                assert_eq!(
                    e.to_string(),
                    format!(
                        "config key stores.a.{key} does not apply to the {backend} backend; remove it"
                    )
                );
            }
            let e = parse(&head).unwrap_err();
            assert!(matches!(e, ConfigError::MissingKey { .. }), "{e}");
            assert!(e.to_string().contains(backend), "{e}");
        }
    }

    #[test]
    fn a_pass_store_parses_with_defaults() {
        let c = parse("[stores.p]\nbackend = \"pass\"\ndir = \"~/.password-store\"\n").unwrap();
        let s = c.store(Some("p")).unwrap();
        assert_eq!(s.kind(), BackendKind::Pass);
        assert!(s.sops().is_none());
        assert!(matches!(s.require_sops(), Err(ConfigError::NotSops(_))));
        let BackendConfig::Pass(p) = &s.backend else {
            panic!("not a pass store");
        };
        assert_eq!(
            p,
            &PassStore {
                dir: "/home/u/.password-store".into(),
                prefix: None,
                gnupg_home: None,
                value: PassValue::Whole,
                pinentry: Pinentry::Error,
            }
        );
        assert_eq!(c.tools.gpg, ToolSetting::Auto);

        let c = parse(
            "[stores.p]\nbackend = \"pass\"\ndir = \"/d\"\nprefix = \"team/x/\"\ngnupg_home = \"~/g\"\nvalue = \"first-line\"\npinentry = \"agent\"\n\n[tools]\ngpg = \"/nix/store/x-gnupg/bin/gpg\"\n",
        )
        .unwrap();
        let BackendConfig::Pass(p) = &c.store(Some("p")).unwrap().backend else {
            panic!("not a pass store");
        };
        assert_eq!(p.prefix.as_deref(), Some("team/x"));
        assert_eq!(p.entries_dir(), Path::new("/d/team/x"));
        assert_eq!(p.gnupg_home.as_deref(), Some(Path::new("/home/u/g")));
        assert_eq!(p.value, PassValue::FirstLine);
        assert_eq!(p.pinentry, Pinentry::Agent);
        assert_eq!(
            c.tools.gpg,
            ToolSetting::Path("/nix/store/x-gnupg/bin/gpg".into())
        );
    }

    #[test]
    fn a_pass_prefix_stays_inside_the_store() {
        let with = |prefix: &str| {
            parse(&format!(
                "[stores.p]\nbackend = \"pass\"\ndir = \"/d\"\nprefix = \"{prefix}\"\n"
            ))
        };
        for bad in ["..", "a/../b", "/abs", "a//b", ".hidden", "a/./b"] {
            assert!(
                matches!(with(bad), Err(ConfigError::BadPrefix { .. })),
                "{bad}"
            );
        }
        let c = with("").unwrap();
        let BackendConfig::Pass(p) = &c.store(Some("p")).unwrap().backend else {
            panic!("not a pass store");
        };
        assert_eq!(p.prefix, None);
        assert!(matches!(
            parse("[stores.p]\nbackend = \"pass\"\ndir = \"/d\"\nvalue = \"all\"\n"),
            Err(ConfigError::Parse { .. })
        ));
    }

    #[test]
    fn relative_paths_are_an_error() {
        let t = "[stores.a]\nbackend = \"sops\"\nfile = \"secrets/s.yaml\"\n";
        assert!(matches!(parse(t), Err(ConfigError::RelativePath { .. })));
        let t = "[stores.a]\nbackend = \"sops\"\nfile = \"~root/s.yaml\"\n";
        assert!(matches!(parse(t), Err(ConfigError::TildeUser { .. })));
        let t = "[tools]\nsops = \"sops\"\n";
        assert!(matches!(parse(t), Err(ConfigError::RelativePath { .. })));
    }

    #[test]
    fn default_store_must_exist() {
        assert!(matches!(
            parse("default_store = \"nope\"\n"),
            Err(ConfigError::UnknownStore(_))
        ));
    }

    #[test]
    fn zero_timeout_is_an_error() {
        assert!(matches!(
            parse("[lock]\ntimeout_secs = 0\n"),
            Err(ConfigError::ZeroTimeout)
        ));
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn search_order() {
        let all = env_of(&[
            ("SECRIT_CONFIG", "/env/c.toml"),
            ("XDG_CONFIG_HOME", "/xdg"),
            ("HOME", "/home/u"),
        ]);
        assert_eq!(
            config_path(Some(Path::new("/flag.toml")), &all).unwrap(),
            (PathBuf::from("/flag.toml"), ConfigSource::Flag)
        );
        assert_eq!(
            config_path(None, &all).unwrap(),
            (PathBuf::from("/env/c.toml"), ConfigSource::Env)
        );
        let xdg = env_of(&[("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/home/u")]);
        assert_eq!(
            config_path(None, &xdg).unwrap(),
            (
                PathBuf::from("/xdg/secrit/config.toml"),
                ConfigSource::Default
            )
        );
        let rel_xdg = env_of(&[("XDG_CONFIG_HOME", "rel"), ("HOME", "/home/u")]);
        assert_eq!(
            config_path(None, &rel_xdg).unwrap().0,
            Path::new("/home/u/.config/secrit/config.toml")
        );
        let rel_env = env_of(&[("SECRIT_CONFIG", "c.toml")]);
        assert!(matches!(
            config_path(None, &rel_env),
            Err(ConfigError::RelativeEnvPath)
        ));
        assert!(matches!(
            config_path(None, &env_of(&[])),
            Err(ConfigError::NoHome)
        ));
    }

    #[test]
    fn load_refuses_group_writable_and_accepts_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("config.toml");
        std::fs::write(&p, "").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(matches!(
            Config::load(&p, Path::new(HOME)),
            Err(ConfigError::Unsafe { .. })
        ));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Config::load(&p, Path::new(HOME)).is_ok());
        assert!(matches!(
            Config::load(&dir.path().join("missing.toml"), Path::new(HOME)),
            Err(ConfigError::NotFound(_))
        ));
    }
}
