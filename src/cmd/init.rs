//! `secrit init` (PLAN section 4.6). Sets up what is missing: the age key,
//! the `.sops.yaml` (only with `--write-sops-config`), the store file and the
//! config. It never replaces or edits a file that exists.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Serialize;

use super::{interrupted, shell_path};
use crate::backend::BackendError;
use crate::backend::sops::{MIN_SOPS, NEED_SOPS, SopsBackend};
use crate::child;
use crate::config::{
    BackendConfig, Config, ConfigError, Env, SopsStore, StoreConfig, ToolSetting, ToolsConfig,
    config_path, home,
};
use crate::display::escape;
use crate::error::{Error, Exit};
use crate::git::{Repo, find_root};
use crate::signals;
use crate::tools;

const DEFAULT_STORE: &str = "main";
/// `age-keygen -y` prints one recipient per identity.
const MAX_RECIPIENTS_BYTES: usize = 64 * 1024;

/// The flags of `secrit init`.
#[derive(Debug)]
pub struct InitArgs {
    pub sops_file: Option<PathBuf>,
    pub sops_config: Option<PathBuf>,
    pub age_key: Option<PathBuf>,
    pub write_sops_config: bool,
    pub dry_run: bool,
}

struct Out {
    quiet: bool,
    dry_run: bool,
}

impl Out {
    fn step(&self, msg: &str) {
        if !self.quiet {
            eprintln!("{}{msg}", if self.dry_run { "would: " } else { "" });
        }
    }

    fn note(&self, msg: &str) {
        if !self.quiet {
            eprintln!("{msg}");
        }
    }
}

pub fn run(
    config_flag: Option<&Path>,
    store_flag: Option<&str>,
    quiet: bool,
    args: &InitArgs,
) -> Result<(), Error> {
    // An earlier step may have made a file, so "nothing was changed" (and
    // the backend's "the original file is untouched") would be false here.
    steps(config_flag, store_flag, quiet, args).map_err(|e| {
        if e.exit() == Exit::Interrupted {
            Error::InitInterrupted
        } else {
            e
        }
    })
}

fn steps(
    config_flag: Option<&Path>,
    store_flag: Option<&str>,
    quiet: bool,
    args: &InitArgs,
) -> Result<(), Error> {
    let env = |k: &str| std::env::var_os(k);
    let out = Out {
        quiet,
        dry_run: args.dry_run,
    };
    let home = home(&env)?;
    let (config_file, source) = config_path(config_flag, &env)?;
    // Before step 1: the config names the tools that init runs.
    super::note_config_source(&config_file, source, quiet);
    let existing = match Config::load(&config_file, &home) {
        Ok(c) => Some(c),
        Err(ConfigError::NotFound(_)) => None,
        Err(e) => return Err(e.into()),
    };
    let store = store_config(args, store_flag, existing.as_ref())?;
    let sops_store = sops_of(&store);
    let tools_config = existing.as_ref().map_or(
        ToolsConfig {
            sops: ToolSetting::Auto,
            age_keygen: ToolSetting::Auto,
        },
        |c| c.tools.clone(),
    );
    let lock_timeout = existing
        .as_ref()
        .map_or(Duration::from_secs(30), |c| c.lock_timeout);

    // 1. Tools.
    let path_env = env("PATH");
    let sops = tools::resolve(tools::SOPS, &tools_config.sops, path_env.as_deref())?;
    let keygen = tools::resolve(
        tools::AGE_KEYGEN,
        &tools_config.age_keygen,
        path_env.as_deref(),
    )?;
    let backend = SopsBackend::new(sops_store, sops.path.clone(), lock_timeout, &env)?;
    let (a, b, c) = backend.sops_version()?;
    if (a, b) < MIN_SOPS {
        return Err(BackendError::ToolTooOld {
            tool: "sops",
            found: format!("{a}.{b}.{c}"),
            path: sops.path,
            need: NEED_SOPS,
        }
        .into());
    }
    out.note(&format!(
        "sops {a}.{b}.{c} at {}; age-keygen at {}",
        escape(&sops.path.to_string_lossy()),
        escape(&keygen.path.to_string_lossy())
    ));

    // 2. Age key.
    let Some(key) = backend.age_key_file().map(Path::to_path_buf) else {
        return Err(Error::Usage(
            "no age key path: pass --age-key, or set HOME or XDG_CONFIG_HOME".into(),
        ));
    };
    let recipients = age_key(&keygen.path, &key, &out)?;
    interrupted()?;

    // 3 and 4. The store file, and the .sops.yaml it needs when it is new.
    if sops_store.file.exists() {
        let facts = backend.inspect()?;
        out.note(&format!(
            "store file {} exists ({} names); unchanged",
            escape(&sops_store.file.to_string_lossy()),
            facts.names
        ));
    } else {
        let backend = sops_config(
            backend,
            sops_store,
            &env,
            args,
            &recipients,
            lock_timeout,
            &out,
        )?;
        interrupted()?;
        new_store_file(&backend, &out)?;
    }
    interrupted()?;

    // 5. Config.
    write_config(&config_file, existing.as_ref(), &store, args, &out)?;
    interrupted()?;

    // 6. Next steps.
    next_steps(&sops_store.file, &env, &out)?;
    interrupted()
}

/// The sops settings of a store. sops is the only backend that init sets up.
fn sops_of(store: &StoreConfig) -> &SopsStore {
    let BackendConfig::Sops(sops) = &store.backend;
    sops
}

/// The store that this run sets up: the flags, else the config.
fn store_config(
    args: &InitArgs,
    store_flag: Option<&str>,
    existing: Option<&Config>,
) -> Result<StoreConfig, Error> {
    let name = store_flag
        .or(existing.and_then(|c| c.default_store.as_deref()))
        .unwrap_or(DEFAULT_STORE)
        .to_owned();
    let configured = existing.and_then(|c| c.stores.get(&name));
    let configured_sops = configured.map(sops_of);
    let absolute = |p: &Path| {
        std::path::absolute(p).map_err(|e| Error::Usage(format!("{}: {e}", p.display())))
    };
    let file = match (&args.sops_file, configured_sops) {
        (Some(f), _) => absolute(f)?,
        (None, Some(s)) => s.file.clone(),
        (None, None) => {
            return Err(Error::Usage(format!(
                "no config names store '{name}'; pass --sops-file PATH"
            )));
        }
    };
    let sops = SopsStore {
        file,
        sops_config: match &args.sops_config {
            Some(p) => Some(absolute(p)?),
            None => configured_sops.and_then(|s| s.sops_config.clone()),
        },
        age_key_file: match &args.age_key {
            Some(p) => Some(absolute(p)?),
            None => configured_sops.and_then(|s| s.age_key_file.clone()),
        },
    };
    if let Some(have) = configured_sops {
        refuse_a_differing_flag(have, &sops, &name)?;
    }
    Ok(StoreConfig {
        wire_hint: configured.is_some_and(|s| s.wire_hint),
        name,
        backend: BackendConfig::Sops(sops),
    })
}

/// init never edits the config, so a flag that names another file than the
/// configured store would set up files that the config does not use.
fn refuse_a_differing_flag(have: &SopsStore, store: &SopsStore, name: &str) -> Result<(), Error> {
    let shown = |p: Option<&Path>| {
        p.map_or_else(
            || "(not set)".to_owned(),
            |p| escape(&p.to_string_lossy()).into_owned(),
        )
    };
    let mut differ = Vec::new();
    if have.file != store.file {
        differ.push(format!(
            "--sops-file (the config has file = {})",
            shown(Some(&have.file))
        ));
    }
    if have.sops_config != store.sops_config {
        differ.push(format!(
            "--sops-config (the config has sops_config = {})",
            shown(have.sops_config.as_deref())
        ));
    }
    if have.age_key_file != store.age_key_file {
        differ.push(format!(
            "--age-key (the config has age_key_file = {})",
            shown(have.age_key_file.as_deref())
        ));
    }
    if differ.is_empty() {
        return Ok(());
    }
    Err(Error::Usage(format!(
        "the config already names store '{}', and {} differs; init never edits the config. Drop the flag, pass --store with a new name, or edit the config first",
        name,
        differ.join(" and ")
    )))
}

fn new_store_file(backend: &SopsBackend, out: &Out) -> Result<(), Error> {
    let dir = backend.dir();
    if !dir.exists() {
        out.step(&format!(
            "create the directory {} (mode 0700)",
            escape(&dir.to_string_lossy())
        ));
        if !out.dry_run {
            make_dir(dir)?;
        }
    }
    out.step(&format!(
        "create the store file {} with no entries",
        escape(&backend.file().to_string_lossy())
    ));
    if !out.dry_run {
        backend.create_file()?;
    }
    Ok(())
}

/// `mkdir -p -m 700`. Directories that exist keep their mode.
fn make_dir(dir: &Path) -> Result<(), Error> {
    let _critical = signals::Critical::enter();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| Error::Failed(format!("create {}: {e}", dir.display())))
}

fn keygen_command(keygen: &Path) -> Command {
    let mut cmd = Command::new(keygen);
    cmd.env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    cmd
}

fn run_keygen(cmd: Command, cap: usize, what: &str) -> Result<child::ChildOutput, Error> {
    let out = child::run(cmd, None, cap, child::timeout()).map_err(|e| match e {
        child::ChildError::Interrupted => Error::Interrupted,
        e => Error::Failed(format!("age-keygen {what}: {e}")),
    })?;
    if out.status.success() {
        Ok(out)
    } else {
        // age-keygen errors name the file, never key material.
        Err(Error::Failed(format!(
            "age-keygen {what} failed ({}): {}",
            out.status,
            escape(String::from_utf8_lossy(&out.stderr).trim())
        )))
    }
}

/// Use the key at `key`, or create it. Returns its public recipients.
fn age_key(keygen: &Path, key: &Path, out: &Out) -> Result<Vec<String>, Error> {
    let shown = escape(&key.to_string_lossy()).into_owned();
    match std::fs::symlink_metadata(key) {
        Ok(m) => {
            if !m.is_file() {
                return Err(Error::Refused(format!(
                    "the age key {shown} is a symlink or not a regular file"
                )));
            }
            if m.uid() != rustix::process::getuid().as_raw() || m.mode() & 0o077 != 0 {
                return Err(Error::Refused(format!(
                    "the age key {shown} must be yours with mode 0600; run 'chmod 600 {}'",
                    shell_path(key)
                )));
            }
            if m.len() == 0 {
                return Err(Error::Refused(format!(
                    "the age key {shown} is empty, so it holds no key; remove it ('rm {}') and run 'secrit init' again",
                    shell_path(key)
                )));
            }
            out.note(&format!("age key {shown} exists; unchanged"));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            out.step(&format!("create the age key {shown} (mode 0600)"));
            if out.dry_run {
                return Ok(Vec::new());
            }
            if let Some(dir) = key.parent()
                && !dir.exists()
            {
                make_dir(dir)?;
            }
            new_key(keygen, key)?;
            eprintln!(
                "secrit: warning: back up {shown} now. Without it, nobody can decrypt the secrets."
            );
        }
        Err(e) => return Err(Error::Failed(format!("{shown}: {e}"))),
    }
    let mut cmd = keygen_command(keygen);
    cmd.arg("-y").arg(key);
    let found = run_keygen(cmd, MAX_RECIPIENTS_BYTES, "-y")?;
    let recipients: Vec<String> = String::from_utf8_lossy(&found.stdout)
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("age1") && l.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_owned)
        .collect();
    if recipients.is_empty() {
        return Err(Error::Failed(format!(
            "age-keygen -y found no age recipient in {shown}"
        )));
    }
    out.note(&format!("age recipient: {}", recipients.join(", ")));
    Ok(recipients)
}

/// A directory that this run made next to the new key, removed with what is
/// left in it when it drops.
struct KeyTemp(PathBuf);

impl KeyTemp {
    /// `mkdir` with mode 0700 under a random name. `mkdir` fails on a name
    /// that exists, so the directory and all it holds are this run's.
    fn create(dir: &Path, base: &std::ffi::OsStr) -> Result<Self, Error> {
        for _ in 0..8 {
            let mut rnd = [0u8; 8];
            getrandom::fill(&mut rnd)
                .map_err(|_| Error::Failed("no randomness for a temp name".into()))?;
            let mut name = OsString::from(".");
            name.push(base);
            name.push(format!(".secrit-{}.tmp", crate::lock::hex(&rnd)));
            let path = dir.join(name);
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(Error::Failed(format!("create {}: {e}", path.display())));
                }
            }
        }
        Err(Error::Failed(format!(
            "could not find a free temp name in {}",
            dir.display()
        )))
    }
}

impl Drop for KeyTemp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `age-keygen -o` into a temp directory next to `key`, then a rename with
/// `RENAME_NOREPLACE`. age-keygen creates its output file before it writes
/// the key, so a run stopped in between must not leave that empty file at
/// `key`, where the next init would take it for the key.
fn new_key(keygen: &Path, key: &Path) -> Result<(), Error> {
    let shown = escape(&key.to_string_lossy()).into_owned();
    let (Some(dir), Some(base)) = (key.parent(), key.file_name()) else {
        return Err(Error::Usage(format!(
            "the age key path {shown} names no file"
        )));
    };
    // A signal must not end secrit while the temp directory holds the key.
    let _critical = signals::Critical::enter();
    let temp = KeyTemp::create(dir, base)?;
    let made = temp.0.join(base);
    let mut cmd = keygen_command(keygen);
    cmd.arg("-o").arg(&made);
    run_keygen(cmd, 0, "-o")?;
    let fail = |step: &str, e: &dyn std::fmt::Display| {
        Error::Failed(format!("{step} the new age key {shown}: {e}"))
    };
    std::fs::File::open(&made)
        .and_then(|f| f.sync_all())
        .map_err(|e| fail("fsync", &e))?;
    interrupted()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &made,
        rustix::fs::CWD,
        key,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|e| match e {
        rustix::io::Errno::EXIST => Error::Refused(format!(
            "the age key {shown} appeared while init created it; nothing was replaced"
        )),
        e => fail("rename", &e),
    })?;
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| fail("fsync the directory of", &e))
}

/// The `.sops.yaml` that covers a new store file. Returns the backend to
/// create the file with.
fn sops_config(
    backend: SopsBackend,
    store: &SopsStore,
    env: &Env,
    args: &InitArgs,
    recipients: &[String],
    lock_timeout: Duration,
    out: &Out,
) -> Result<SopsBackend, Error> {
    if let Some(p) = backend.sops_config().map(Path::to_path_buf)
        && p.exists()
    {
        backend.check_sops_config()?;
        if backend.rule_matches()? {
            out.note(&format!(
                "{} has a creation rule for the store file",
                escape(&p.to_string_lossy())
            ));
            return Ok(backend);
        }
        let dir = p.parent().unwrap_or(Path::new("/"));
        print_snippet(&rule_snippet(dir, &store.file, recipients));
        return Err(Error::Failed(format!(
            "{} has no creation rule for {}; add the rule above (secrit never edits an existing .sops.yaml)",
            p.display(),
            store.file.display()
        )));
    }
    let target = backend.sops_config().map_or_else(
        || {
            let dir = store.file.parent().unwrap_or(Path::new("/"));
            find_root(dir)
                .unwrap_or_else(|| dir.to_path_buf())
                .join(".sops.yaml")
        },
        Path::to_path_buf,
    );
    let dir = target.parent().unwrap_or(Path::new("/"));
    let snippet = rule_snippet(dir, &store.file, recipients);
    if !args.write_sops_config {
        print_snippet(&snippet);
        return Err(Error::Failed(format!(
            "no .sops.yaml covers {}; save the rule above as {}, or rerun with --write-sops-config",
            store.file.display(),
            target.display()
        )));
    }
    out.step(&format!(
        "create {} with one creation rule",
        escape(&target.to_string_lossy())
    ));
    if args.dry_run {
        return Ok(backend);
    }
    if !dir.exists() {
        make_dir(dir)?;
    }
    create_new(&target, snippet.as_bytes(), 0o644)?;
    let mut with_config = store.clone();
    with_config.sops_config = Some(target);
    Ok(SopsBackend::new(
        &with_config,
        backend.sops().to_path_buf(),
        lock_timeout,
        env,
    )?)
}

fn print_snippet(snippet: &str) {
    print!("{snippet}");
}

/// A `.sops.yaml` with one rule for `file`, matched relative to `dir`.
fn rule_snippet(dir: &Path, file: &Path, recipients: &[String]) -> String {
    let rel = file.strip_prefix(dir).unwrap_or(file);
    let regex = format!("(^|/){}$", regex_escape(&rel.to_string_lossy()));
    let age = if recipients.is_empty() {
        "age1... # the recipient of your age key".to_owned()
    } else {
        recipients.join(",")
    };
    format!(
        "creation_rules:\n  - path_regex: '{}'\n    age: {age}\n",
        regex.replace('\'', "''")
    )
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        if "\\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Create `path` with `O_EXCL` and `O_NOFOLLOW`, write `bytes` and fsync.
fn create_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    let _critical = signals::Critical::enter();
    let fail = |e: std::io::Error| Error::Failed(format!("create {}: {e}", path.display()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)
        .map_err(fail)?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(fail(e));
    }
    Ok(())
}

#[derive(Serialize)]
struct NewConfig<'a> {
    default_store: &'a str,
    stores: std::collections::BTreeMap<&'a str, NewStore<'a>>,
}

#[derive(Serialize)]
struct NewStore<'a> {
    backend: &'static str,
    file: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    sops_config: Option<&'a Path>,
    #[serde(skip_serializing_if = "Option::is_none")]
    age_key_file: Option<&'a Path>,
}

fn write_config(
    path: &Path,
    existing: Option<&Config>,
    store: &StoreConfig,
    args: &InitArgs,
    out: &Out,
) -> Result<(), Error> {
    let shown = escape(&path.to_string_lossy()).into_owned();
    if let Some(config) = existing {
        if config.stores.contains_key(&store.name) {
            // store_config refused every flag that differs from this store.
            out.note(&format!("config {shown} exists; unchanged"));
        } else {
            out.note(&format!(
                "config {shown} has no store '{}'; unchanged. Add it by hand:",
                store.name
            ));
            print!("{}", store_section(store, args)?);
        }
        return Ok(());
    }
    out.step(&format!("write the config {shown} (mode 0600)"));
    if args.dry_run {
        return Ok(());
    }
    let text = config_text(store, args)?;
    if let Some(dir) = path.parent()
        && !dir.exists()
    {
        make_dir(dir)?;
    }
    create_new(path, text.as_bytes(), 0o600)
}

/// Only the store's table, for an existing config: a top-level key appended
/// after its last table would land inside that table.
#[derive(Serialize)]
struct NewSection<'a> {
    stores: std::collections::BTreeMap<&'a str, NewStore<'a>>,
}

fn new_stores<'a>(
    store: &'a StoreConfig,
    args: &InitArgs,
) -> std::collections::BTreeMap<&'a str, NewStore<'a>> {
    let sops = sops_of(store);
    let mut stores = std::collections::BTreeMap::new();
    stores.insert(
        store.name.as_str(),
        NewStore {
            backend: "sops",
            file: &sops.file,
            sops_config: args.sops_config.as_ref().and(sops.sops_config.as_deref()),
            age_key_file: args.age_key.as_ref().and(sops.age_key_file.as_deref()),
        },
    );
    stores
}

fn to_toml(value: &impl Serialize) -> Result<String, Error> {
    toml::to_string(value).map_err(|e| Error::Failed(format!("could not write the config: {e}")))
}

fn config_text(store: &StoreConfig, args: &InitArgs) -> Result<String, Error> {
    to_toml(&NewConfig {
        default_store: &store.name,
        stores: new_stores(store, args),
    })
}

fn store_section(store: &StoreConfig, args: &InitArgs) -> Result<String, Error> {
    to_toml(&NewSection {
        stores: new_stores(store, args),
    })
}

fn next_steps(file: &Path, env: &dyn Fn(&str) -> Option<OsString>, out: &Out) -> Result<(), Error> {
    if let Some(repo) = file
        .parent()
        .and_then(|d| Repo::open(d, env).ok().flatten())
    {
        if let Some(hint) = super::ignore_hint(&repo, file)? {
            out.note(&format!("next: ignore temp copies: {hint}"));
        }
        let tracked = if file.exists() {
            repo.is_tracked(file)
        } else {
            Ok(true)
        };
        super::git_interrupted(&tracked)?;
        if tracked.is_ok_and(|t| !t) {
            out.note(&format!(
                "next: {}",
                super::doctor::git_add_hint(&repo, file)
            ));
            out.note(&format!("next: {}", super::spell_hint(&repo, file)));
        }
    }
    out.note(
        "next: with home-manager, set programs.secrit.settings to the config (README, section 'Install')",
    );
    out.note("next: 'secrit store NAME', then 'secrit wire NAME' for the sops-nix stanza");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rule_matches_the_relative_path() {
        let s = rule_snippet(
            Path::new("/etc/nixos"),
            Path::new("/etc/nixos/secrets/secrit.yaml"),
            &["age1abc".into()],
        );
        assert_eq!(
            s,
            "creation_rules:\n  - path_regex: '(^|/)secrets/secrit\\.yaml$'\n    age: age1abc\n"
        );
        let s = rule_snippet(Path::new("/x"), Path::new("/x/it's.yaml"), &[]);
        assert!(s.contains("path_regex: '(^|/)it''s\\.yaml$'"), "{s}");
        assert!(s.contains("age: age1..."), "{s}");
    }
}
