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

use crate::backend::sops::SopsFormat;

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
    /// A sops key source key that does not fit the others (v0.2 plan 5.8).
    #[error("config key {key}: {reason}")]
    KeySource { key: String, reason: &'static str },
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
    file: String,
    format: Option<SopsFormat>,
    sops_config: Option<String>,
    age_key_file: Option<String>,
    #[serde(default)]
    wire_hint: bool,
    // v0.2 S8: sops key sources (plan 5.6, 6.2).
    age_ssh_key_file: Option<String>,
    age_key_cmd: Option<String>,
    age_key_cmd_timeout_secs: Option<u64>,
    age_plugin_dir: Option<String>,
    identity: Option<RawIdentity>,
}

/// One `[stores.NAME.identity]` table (v0.2 plan 5.6, 5.8). Flat for the
/// same reason as [`RawStore`]; `parse_keys` checks each key against
/// `kind`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    kind: IdentityKind,
    path: Option<String>,
    stub: Option<String>,
    plugin_dir: Option<String>,
    level: Option<Level>,
    touch_timeout_secs: Option<u64>,
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
    #[expect(
        clippy::unnecessary_wraps,
        reason = "None once a second backend exists (v0.2 plan 5.1)"
    )]
    pub fn sops(&self) -> Option<&SopsStore> {
        match &self.backend {
            BackendConfig::Sops(sops) => Some(sops),
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
}

/// The settings of a sops store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SopsStore {
    pub file: PathBuf,
    /// The `format` key. With none, the backend takes the format from the
    /// file name (v0.2 plan 5.8).
    pub format: Option<SopsFormat>,
    pub sops_config: Option<PathBuf>,
    pub age_key_file: Option<PathBuf>,
    /// The key sources of v0.2 (plan 6.2). The default is v0.1: the age
    /// key file only.
    pub keys: SopsKeys,
}

/// The `kind` of an identity table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityKind {
    File,
    SshFile,
    KeyCmd,
    Plugin,
}

/// A security level (v0.2 plan 6.7.3), weakest first, so `>` means
/// stricter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Open,
    Unlock,
    Touch,
    Session,
    Strict,
}

impl Level {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Open => "open",
            Level::Unlock => "unlock",
            Level::Touch => "touch",
            Level::Session => "session",
            Level::Strict => "strict",
        }
    }
}

/// The one identity of a store with an identity table (v0.2 plan 5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    File(PathBuf),
    SshFile(PathBuf),
    KeyCmd(PathBuf),
    /// An age plugin identity. It never falls back to the age key file.
    /// `level: None` means the strictest level that this build supports.
    Plugin {
        stub: PathBuf,
        dir: PathBuf,
        level: Option<Level>,
        touch_timeout_secs: u64,
    },
}

/// The default of `touch_timeout_secs` (v0.2 plan S8, LT3).
pub const DEFAULT_TOUCH_TIMEOUT_SECS: u64 = 30;
/// The default of `age_key_cmd_timeout_secs` (v0.2 plan 6.2).
pub const DEFAULT_KEY_CMD_TIMEOUT_SECS: u64 = 20;

/// The sops key sources of a store other than `age_key_file`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SopsKeys {
    pub age_ssh_key_file: Option<PathBuf>,
    pub age_key_cmd: Option<PathBuf>,
    /// `age_key_cmd_timeout_secs`, or `None` for the default.
    pub age_key_cmd_timeout: Option<Duration>,
    pub age_plugin_dir: Option<PathBuf>,
    pub identity: Option<Identity>,
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
            let key = |k: &str| format!("stores.{name}.{k}");
            let backend = match s.backend {
                BackendKind::Sops => BackendConfig::Sops(SopsStore {
                    file: expand(&s.file, home, &key("file"))?,
                    format: s.format,
                    sops_config: s
                        .sops_config
                        .as_ref()
                        .map(|v| expand(v, home, &key("sops_config")))
                        .transpose()?,
                    age_key_file: s
                        .age_key_file
                        .as_ref()
                        .map(|v| expand(v, home, &key("age_key_file")))
                        .transpose()?,
                    keys: parse_keys(&s, home, &key)?,
                }),
            };
            let store = StoreConfig {
                name: name.clone(),
                wire_hint: s.wire_hint,
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

/// The v0.2 key source keys of one sops store (v0.2 plan 5.8). A store
/// with an identity table takes its key from the table only.
fn parse_keys(
    s: &RawStore,
    home: &Path,
    key: &dyn Fn(&str) -> String,
) -> Result<SopsKeys, ConfigError> {
    let path = |v: &Option<String>, k: &str| -> Result<Option<PathBuf>, ConfigError> {
        v.as_ref().map(|v| expand(v, home, &key(k))).transpose()
    };
    let bad = |k: String, reason: &'static str| ConfigError::KeySource { key: k, reason };
    let secs = |v: Option<u64>, k: &str| -> Result<Option<Duration>, ConfigError> {
        match v {
            Some(0) => Err(bad(key(k), "must be at least 1")),
            v => Ok(v.map(Duration::from_secs)),
        }
    };
    let mut keys = SopsKeys {
        age_ssh_key_file: path(&s.age_ssh_key_file, "age_ssh_key_file")?,
        age_key_cmd: path(&s.age_key_cmd, "age_key_cmd")?,
        age_key_cmd_timeout: secs(s.age_key_cmd_timeout_secs, "age_key_cmd_timeout_secs")?,
        age_plugin_dir: path(&s.age_plugin_dir, "age_plugin_dir")?,
        identity: None,
    };
    let Some(id) = &s.identity else {
        return Ok(keys);
    };
    for (k, set) in [
        ("age_key_file", s.age_key_file.is_some()),
        ("age_ssh_key_file", s.age_ssh_key_file.is_some()),
        ("age_key_cmd", s.age_key_cmd.is_some()),
    ] {
        if set {
            return Err(bad(
                key(k),
                "a store with an identity table takes its key from that table only",
            ));
        }
    }
    let ik = |k: &str| key(&format!("identity.{k}"));
    let plugin = id.kind == IdentityKind::Plugin;
    for (k, set, allowed) in [
        ("path", id.path.is_some(), !plugin),
        ("stub", id.stub.is_some(), plugin),
        ("plugin_dir", id.plugin_dir.is_some(), plugin),
        ("level", id.level.is_some(), plugin),
        (
            "touch_timeout_secs",
            id.touch_timeout_secs.is_some(),
            plugin,
        ),
    ] {
        if set && !allowed {
            return Err(bad(ik(k), "this identity kind does not take it"));
        }
    }
    let need = |v: &Option<String>, k: &str| -> Result<PathBuf, ConfigError> {
        match v {
            Some(v) => expand(v, home, &ik(k)),
            None => Err(bad(ik(k), "this identity kind needs it")),
        }
    };
    keys.identity = Some(match id.kind {
        IdentityKind::File => Identity::File(need(&id.path, "path")?),
        IdentityKind::SshFile => Identity::SshFile(need(&id.path, "path")?),
        IdentityKind::KeyCmd => Identity::KeyCmd(need(&id.path, "path")?),
        IdentityKind::Plugin => {
            if s.age_plugin_dir.is_some() {
                return Err(bad(
                    key("age_plugin_dir"),
                    "a plugin identity names its directory as identity.plugin_dir",
                ));
            }
            Identity::Plugin {
                stub: need(&id.stub, "stub")?,
                dir: need(&id.plugin_dir, "plugin_dir")?,
                level: id.level,
                touch_timeout_secs: match id.touch_timeout_secs {
                    Some(0) => return Err(bad(ik("touch_timeout_secs"), "must be at least 1")),
                    v => v.unwrap_or(DEFAULT_TOUCH_TIMEOUT_SECS),
                },
            }
        }
    });
    Ok(keys)
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
                format: None,
                sops_config: sops_config.map(PathBuf::from),
                age_key_file: Some("/r/keys/key1.txt".into()),
                keys: SopsKeys::default(),
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
            "invalid config file /c.toml: line 6, column 1: unknown field `fiel`, expected one of `backend`, `file`, `format`, `sops_config`, `age_key_file`, `wire_hint`, `age_ssh_key_file`, `age_key_cmd`, `age_key_cmd_timeout_secs`, `age_plugin_dir`, `identity`"
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
        for (backend, keys) in [("sops", "file = \"/s.yaml\"\n")] {
            let good = format!("[stores.a]\nbackend = \"{backend}\"\n{keys}");
            assert!(parse(&good).is_ok(), "{good}");
            for typo in [
                "fiel = \"/x\"\n",
                "wire-hint = true\n",
                "Format = \"json\"\n",
            ] {
                let bad = format!("{good}{typo}");
                let e = parse(&bad).unwrap_err();
                assert!(matches!(e, ConfigError::Parse { .. }), "{bad}");
                assert!(e.to_string().contains("unknown field"), "{bad}: {e}");
            }
        }
    }

    /// The `format` key of a sops store takes `yaml` or `json` (v0.2 plan
    /// 5.8). A format that secrit does not support yet is refused at its
    /// own line.
    #[test]
    fn the_sops_format_key_is_checked() {
        let head = "[stores.a]\nbackend = \"sops\"\nfile = \"/s.sops\"\n";
        for (value, want) in [
            ("yaml", Some(SopsFormat::Yaml)),
            ("json", Some(SopsFormat::Json)),
        ] {
            let c = parse(&format!("{head}format = \"{value}\"\n")).unwrap();
            assert_eq!(sops_of(c.store(Some("a")).unwrap()).format, want);
        }
        let c = parse(head).unwrap();
        assert_eq!(sops_of(c.store(Some("a")).unwrap()).format, None);
        for value in ["\"dotenv\"", "\"ini\"", "\"JSON\"", "5"] {
            let e = parse(&format!("{head}format = {value}\n")).unwrap_err();
            assert!(matches!(e, ConfigError::Parse { .. }), "{value}");
            assert!(e.to_string().contains("line 4, column 10"), "{value}: {e}");
        }
    }

    // v0.2 S8: sops key sources and the identity table (plan 5.6, 5.8).

    fn keys_of(extra: &str) -> Result<SopsKeys, ConfigError> {
        let text = format!("[stores.a]\nbackend = \"sops\"\nfile = \"/s.yaml\"\n{extra}");
        parse(&text).map(|c| sops_of(c.store(Some("a")).unwrap()).keys.clone())
    }

    #[test]
    fn the_store_level_key_sources_parse() {
        assert_eq!(keys_of("").unwrap(), SopsKeys::default());
        let k = keys_of(
            "age_ssh_key_file = \"~/.ssh/sops\"\nage_key_cmd = \"/k/cmd\"\nage_key_cmd_timeout_secs = 3\nage_plugin_dir = \"/p\"\n",
        )
        .unwrap();
        assert_eq!(
            k.age_ssh_key_file.as_deref(),
            Some(Path::new("/home/u/.ssh/sops"))
        );
        assert_eq!(k.age_key_cmd.as_deref(), Some(Path::new("/k/cmd")));
        assert_eq!(k.age_key_cmd_timeout, Some(Duration::from_secs(3)));
        assert_eq!(k.age_plugin_dir.as_deref(), Some(Path::new("/p")));
        assert!(k.identity.is_none());
        let e = keys_of("age_key_cmd_timeout_secs = 0\n").unwrap_err();
        assert_eq!(
            e.to_string(),
            "config key stores.a.age_key_cmd_timeout_secs: must be at least 1"
        );
        assert!(matches!(
            keys_of("age_key_cmd = \"cmd\"\n"),
            Err(ConfigError::RelativePath { .. })
        ));
    }

    #[test]
    fn each_identity_kind_parses() {
        let id = |body: &str| keys_of(&format!("[stores.a.identity]\n{body}")).map(|k| k.identity);
        assert_eq!(
            id("kind = \"file\"\npath = \"/k.txt\"\n").unwrap(),
            Some(Identity::File("/k.txt".into()))
        );
        assert_eq!(
            id("kind = \"ssh-file\"\npath = \"~/k\"\n").unwrap(),
            Some(Identity::SshFile("/home/u/k".into()))
        );
        assert_eq!(
            id("kind = \"key-cmd\"\npath = \"/c\"\n").unwrap(),
            Some(Identity::KeyCmd("/c".into()))
        );
        assert_eq!(
            id("kind = \"plugin\"\nstub = \"/s\"\nplugin_dir = \"/p\"\n").unwrap(),
            Some(Identity::Plugin {
                stub: "/s".into(),
                dir: "/p".into(),
                level: None,
                touch_timeout_secs: DEFAULT_TOUCH_TIMEOUT_SECS,
            })
        );
        assert_eq!(
            id("kind = \"plugin\"\nstub = \"/s\"\nplugin_dir = \"/p\"\nlevel = \"touch\"\ntouch_timeout_secs = 9\n")
                .unwrap(),
            Some(Identity::Plugin {
                stub: "/s".into(),
                dir: "/p".into(),
                level: Some(Level::Touch),
                touch_timeout_secs: 9,
            })
        );
        // Each kind refuses the keys of the others, and an unknown key.
        for (body, key) in [
            (
                "kind = \"file\"\n",
                "identity.path: this identity kind needs it",
            ),
            (
                "kind = \"file\"\npath = \"/k\"\nstub = \"/s\"\n",
                "identity.stub: this identity kind does not take it",
            ),
            (
                "kind = \"ssh-file\"\npath = \"/k\"\nlevel = \"touch\"\n",
                "identity.level: this identity kind does not take it",
            ),
            (
                "kind = \"key-cmd\"\npath = \"/k\"\nplugin_dir = \"/p\"\n",
                "identity.plugin_dir: this identity kind does not take it",
            ),
            (
                "kind = \"plugin\"\nstub = \"/s\"\n",
                "identity.plugin_dir: this identity kind needs it",
            ),
            (
                "kind = \"plugin\"\nplugin_dir = \"/p\"\n",
                "identity.stub: this identity kind needs it",
            ),
            (
                "kind = \"plugin\"\npath = \"/k\"\nstub = \"/s\"\nplugin_dir = \"/p\"\n",
                "identity.path: this identity kind does not take it",
            ),
            (
                "kind = \"plugin\"\nstub = \"/s\"\nplugin_dir = \"/p\"\ntouch_timeout_secs = 0\n",
                "identity.touch_timeout_secs: must be at least 1",
            ),
        ] {
            let e = id(body).unwrap_err();
            assert_eq!(
                e.to_string(),
                format!("config key stores.a.{key}"),
                "{body}"
            );
        }
        for body in [
            "kind = \"file\"\npath = \"/k\"\npaht = \"/x\"\n",
            "kind = \"yubikey\"\n",
            "kind = \"plugin\"\nstub = \"/s\"\nplugin_dir = \"/p\"\nlevel = \"high\"\n",
        ] {
            assert!(matches!(id(body), Err(ConfigError::Parse { .. })), "{body}");
        }
    }

    /// A store with an identity table takes no other key source.
    #[test]
    fn an_identity_table_excludes_the_other_key_sources() {
        let table = "[stores.a.identity]\nkind = \"plugin\"\nstub = \"/s\"\nplugin_dir = \"/p\"\n";
        for k in [
            "age_key_file",
            "age_ssh_key_file",
            "age_key_cmd",
            "age_plugin_dir",
        ] {
            let e = keys_of(&format!("{k} = \"/x\"\n{table}")).unwrap_err();
            assert!(matches!(e, ConfigError::KeySource { .. }), "{k}: {e}");
            assert!(e.to_string().contains(&format!("stores.a.{k}")), "{e}");
        }
        // A file identity may sit beside a plugin directory.
        let k = keys_of(
            "age_plugin_dir = \"/p\"\n[stores.a.identity]\nkind = \"file\"\npath = \"/k\"\n",
        )
        .unwrap();
        assert_eq!(k.age_plugin_dir.as_deref(), Some(Path::new("/p")));
    }

    #[test]
    fn levels_order_from_open_to_strict() {
        assert!(Level::Strict > Level::Session);
        assert!(Level::Session > Level::Touch);
        assert!(Level::Touch > Level::Unlock);
        assert!(Level::Unlock > Level::Open);
        assert_eq!(Level::Session.as_str(), "session");
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
