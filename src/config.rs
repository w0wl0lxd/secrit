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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStore {
    backend: BackendKind,
    file: String,
    sops_config: Option<String>,
    age_key_file: Option<String>,
    #[serde(default)]
    wire_hint: bool,
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
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Sops,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreConfig {
    pub name: String,
    pub backend: BackendKind,
    pub file: PathBuf,
    pub sops_config: Option<PathBuf>,
    pub age_key_file: Option<PathBuf>,
    pub wire_hint: bool,
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

/// The config file path: `--config`, then `$SECRIT_CONFIG`, then
/// `$XDG_CONFIG_HOME/secrit/config.toml`, then `~/.config/secrit/config.toml`.
pub fn config_path(
    flag: Option<&Path>,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, ConfigError> {
    if let Some(p) = flag {
        return std::path::absolute(p).map_err(|source| ConfigError::Io {
            path: p.to_path_buf(),
            source,
        });
    }
    if let Some(v) = env(ENV_CONFIG).filter(|v| !v.is_empty()) {
        let p = PathBuf::from(v);
        return if p.is_absolute() {
            Ok(p)
        } else {
            Err(ConfigError::RelativeEnvPath)
        };
    }
    // The XDG spec says to ignore a relative XDG_CONFIG_HOME.
    if let Some(x) = env("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
    {
        return Ok(x.join("secrit").join("config.toml"));
    }
    Ok(home(env)?
        .join(".config")
        .join("secrit")
        .join("config.toml"))
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
            message: e.message().to_owned(),
        })?;
        if raw.lock.timeout_secs == 0 {
            return Err(ConfigError::ZeroTimeout);
        }
        let mut stores = BTreeMap::new();
        for (name, s) in raw.stores {
            let key = |k: &str| format!("stores.{name}.{k}");
            let store = StoreConfig {
                backend: s.backend,
                file: expand(&s.file, home, &key("file"))?,
                sops_config: s
                    .sops_config
                    .map(|v| expand(&v, home, &key("sops_config")))
                    .transpose()?,
                age_key_file: s
                    .age_key_file
                    .map(|v| expand(&v, home, &key("age_key_file")))
                    .transpose()?,
                wire_hint: s.wire_hint,
                name: name.clone(),
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
    let in_nix_store = meta.uid() == 0 && target.starts_with("/nix/store/");
    if meta.uid() != uid && !in_nix_store {
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

    #[test]
    fn parses_the_plan_example() {
        let c = parse(FULL).unwrap();
        let s = c.store(None).unwrap();
        assert_eq!(s.file, Path::new("/etc/nixos/secrets/secrit.yaml"));
        assert_eq!(
            s.age_key_file.as_deref(),
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

    #[test]
    fn minimal_config_uses_defaults() {
        let c = parse("[stores.a]\nbackend = \"sops\"\nfile = \"~/s.yaml\"\n").unwrap();
        assert_eq!(
            c.lock_timeout,
            Duration::from_secs(DEFAULT_LOCK_TIMEOUT_SECS)
        );
        assert!(matches!(c.store(None), Err(ConfigError::NoDefaultStore)));
        assert_eq!(
            c.store(Some("a")).unwrap().file,
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
            Path::new("/flag.toml")
        );
        assert_eq!(config_path(None, &all).unwrap(), Path::new("/env/c.toml"));
        let xdg = env_of(&[("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/home/u")]);
        assert_eq!(
            config_path(None, &xdg).unwrap(),
            Path::new("/xdg/secrit/config.toml")
        );
        let rel_xdg = env_of(&[("XDG_CONFIG_HOME", "rel"), ("HOME", "/home/u")]);
        assert_eq!(
            config_path(None, &rel_xdg).unwrap(),
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
