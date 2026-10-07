//! Test harness (PLAN section 15.1).
//!
//! Every test gets a temp HOME, `XDG_CONFIG_HOME` and `XDG_RUNTIME_DIR`, two new
//! age keys from `age-keygen`, a `.sops.yaml`, an empty sops store and a
//! config naming them. HOME also holds a decoy `~/.ssh/id_ed25519`: it has a
//! passphrase and is not a recipient, so a sops that reads it would prompt
//! (PLAN 15.1, T19). The secrit child runs with a cleared environment, so
//! sops can never pick up the user's real key. Tests compare decrypted values
//! in the test process and never print them.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

pub const BIN: &str = env!("CARGO_BIN_EXE_secrit");

fn tool(env_var: &str, name: &str) -> PathBuf {
    if let Some(p) = std::env::var_os(env_var).filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    let found = which::which(name).unwrap_or_else(|_| {
        panic!("{name} not found: set {env_var} to its absolute path, or run in 'nix develop'")
    });
    assert!(
        !found.to_string_lossy().contains("/mise/shims/"),
        "{name} resolves to a mise shim, which needs the real HOME; set {env_var} to a Nix store path"
    );
    found
}

pub struct TestEnv {
    pub root: TempDir,
    pub home: PathBuf,
    pub config_home: PathBuf,
    pub runtime: PathBuf,
    pub store_dir: PathBuf,
    pub store_file: PathBuf,
    pub sops_config: PathBuf,
    pub key_file: PathBuf,
    pub second_key_file: PathBuf,
    pub recipients: Vec<String>,
    pub config_file: PathBuf,
    pub sops: PathBuf,
    pub age_keygen: PathBuf,
    pub ssh_keygen: PathBuf,
}

/// The git binary for the repository tests.
pub fn git() -> PathBuf {
    tool("SECRIT_TEST_GIT", "git")
}

/// The absolute path of a helper program for shell scripts that secrit or
/// sops run with a cleared PATH.
pub fn bin(name: &str) -> PathBuf {
    which::which(name).unwrap_or_else(|_| panic!("{name} not found on PATH"))
}

impl TestEnv {
    pub fn new() -> Self {
        let sops = tool("SECRIT_TEST_SOPS", "sops");
        let age_keygen = tool("SECRIT_TEST_AGE_KEYGEN", "age-keygen");
        let ssh_keygen = tool("SECRIT_TEST_SSH_KEYGEN", "ssh-keygen");
        let root = tempfile::tempdir().expect("tempdir");
        let r = root.path();
        let home = r.join("home");
        let config_home = r.join("config");
        let runtime = r.join("runtime");
        let store_root = r.join("store");
        let store_dir = store_root.join("secrets");
        for d in [&home, &config_home, &runtime, &store_dir] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key_file = r.join("keys").join("key1.txt");
        let second_key_file = r.join("keys").join("key2.txt");
        std::fs::create_dir_all(key_file.parent().unwrap()).unwrap();
        let recipients = [&key_file, &second_key_file]
            .iter()
            .map(|k| keygen(&age_keygen, k))
            .collect::<Vec<_>>();
        let sops_config = store_root.join(".sops.yaml");
        write_sops_config(&sops_config, &recipients);
        let env = Self {
            store_file: store_dir.join("main.yaml"),
            config_file: config_home.join("secrit").join("config.toml"),
            root,
            home,
            config_home,
            runtime,
            store_dir,
            sops_config,
            key_file,
            second_key_file,
            recipients,
            sops,
            age_keygen,
            ssh_keygen,
        };
        env.ssh_key(
            &env.home.join(".ssh").join("id_ed25519"),
            Some("decoy-pass"),
        );
        env.create_store(&env.store_file);
        env.write_config("");
        env
    }

    /// Make an ed25519 SSH key at `path` and return its public key line.
    pub fn ssh_key(&self, path: &Path, passphrase: Option<&str>) -> String {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("pub"));
        let st = Command::new(&self.ssh_keygen)
            .env_clear()
            .args([
                "-q",
                "-t",
                "ed25519",
                "-C",
                "decoy",
                "-N",
                passphrase.unwrap_or(""),
            ])
            .arg("-f")
            .arg(path)
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "ssh-keygen failed");
        std::fs::read_to_string(path.with_extension("pub"))
            .unwrap()
            .trim()
            .to_owned()
    }

    /// Write the config. `extra` is appended inside `[stores.main]`.
    pub fn write_config(&self, extra: &str) {
        self.write_config_with(&self.sops, extra);
    }

    pub fn write_config_with(&self, sops: &Path, extra: &str) {
        self.write_config_full(sops, extra, 120);
    }

    pub fn write_config_full(&self, sops: &Path, extra: &str, lock_timeout_secs: u64) {
        std::fs::create_dir_all(self.config_file.parent().unwrap()).unwrap();
        let text = format!(
            "default_store = \"main\"\n\n[stores.main]\nbackend = \"sops\"\nfile = \"{}\"\nage_key_file = \"{}\"\n{extra}\n[tools]\nsops = \"{}\"\n\n[lock]\ntimeout_secs = {lock_timeout_secs}\n",
            self.store_file.display(),
            self.key_file.display(),
            sops.display(),
        );
        std::fs::write(&self.config_file, text).unwrap();
        std::fs::set_permissions(&self.config_file, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    /// An empty sops file encrypted to both recipients, made by the real sops.
    pub fn create_store(&self, path: &Path) {
        self.create_store_with(path, &[], b"{}\n");
    }

    /// A sops file with the JSON `content`, made by the real sops. `extra`
    /// is passed to `sops encrypt` (for example `--age <recipient>`).
    pub fn create_store_with(&self, path: &Path, extra: &[&str], content: &[u8]) {
        let mut child = self
            .sops_cmd()
            .arg("encrypt")
            .args(extra)
            .args([
                "--input-type",
                "json",
                "--output-type",
                "yaml",
                "--filename-override",
            ])
            .arg(path)
            .arg("/dev/stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(content).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "sops encrypt failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::fs::write(path, &out.stdout).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// sops in the test process, with a cleared environment and the temp key.
    pub fn sops_cmd(&self) -> Command {
        let mut c = Command::new(&self.sops);
        c.env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("SOPS_DISABLE_VERSION_CHECK", "1")
            .env("SOPS_AGE_KEY_FILE", &self.key_file)
            .arg("--config")
            .arg(&self.sops_config);
        c
    }

    /// Decrypt the whole store in the test process. Never printed.
    pub fn decrypt(&self) -> serde_json::Map<String, Value> {
        let out = self
            .sops_cmd()
            .args(["decrypt", "--input-type", "yaml", "--output-type", "json"])
            .arg(&self.store_file)
            .output()
            .unwrap();
        assert!(out.status.success(), "test decrypt failed");
        match serde_json::from_slice(&out.stdout).unwrap() {
            Value::Object(m) => m,
            _ => panic!("decrypt output is not an object"),
        }
    }

    /// Assert that `name` decrypts to the string `want`, without printing it.
    pub fn assert_value(&self, name: &str, want: &str) {
        let all = self.decrypt();
        match all.get(name) {
            Some(Value::String(s)) => {
                assert!(s == want, "stored value of {name} differs from the input");
            }
            Some(_) => panic!("{name} is not stored as a string"),
            None => panic!("{name} is missing"),
        }
    }

    /// The secrit command with a cleared, controlled environment.
    pub fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        let path = std::env::join_paths(
            [&self.sops, &self.age_keygen]
                .iter()
                .filter_map(|p| p.parent())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        c.env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env("SECRIT_CONFIG", &self.config_file)
            .env("PATH", path)
            .current_dir(self.root.path())
            .stdin(Stdio::null());
        c
    }

    pub fn run<I, S>(&self, args: I, stdin: Option<&[u8]>) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        run_cmd(self.cmd(), args, stdin)
    }

    pub fn store_value(&self, name: &str, value: &[u8]) -> Output {
        self.run(["store", name], Some(value))
    }

    pub fn ls(&self) -> Vec<String> {
        let out = self.run(["ls"], None);
        assert!(out.status.success(), "ls failed: {}", stderr(&out));
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    pub fn store_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.store_file).unwrap()
    }

    /// Leftover temp copies in the store directory.
    pub fn temp_files(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.store_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains(".secrit-")
                    && !p.to_string_lossy().contains("secrit-bak")
            })
            .collect()
    }

    /// The backup directory root: `$HOME/.local/state/secrit/backups`
    /// (the tests set no `XDG_STATE_HOME`).
    pub fn backup_root(&self) -> PathBuf {
        self.home
            .join(".local")
            .join("state")
            .join("secrit")
            .join("backups")
    }

    /// Every backup file, in every per-store directory.
    pub fn backups(&self) -> Vec<PathBuf> {
        let Ok(dirs) = std::fs::read_dir(self.backup_root()) else {
            return Vec::new();
        };
        let mut all: Vec<PathBuf> = dirs
            .flat_map(|d| std::fs::read_dir(d.unwrap().path()).unwrap())
            .map(|e| e.unwrap().path())
            .collect();
        all.sort();
        all
    }

    /// A shell script in the temp dir, mode 0700.
    pub fn script(&self, name: &str, body: &str) -> PathBuf {
        let p = self.root.path().join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    /// A fake sops: answers `--version` as sops 3.13.3, else runs `body`.
    pub fn fake_sops(&self, name: &str, body: &str) -> PathBuf {
        self.script(
            name,
            &format!(
                "for a in \"$@\"; do [ \"$a\" = --version ] && {{ echo 'sops 3.13.3'; exit 0; }}; done\n{body}"
            ),
        )
    }

    /// A directory for the `pause` test hook.
    pub fn hook_dir(&self) -> PathBuf {
        let d = self.root.path().join("hook");
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Wait until the hook log holds `want` lines, at most 30 s.
    pub fn wait_for_hook(&self, want: usize) -> Vec<String> {
        let log = self.hook_dir().join("log");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let lines: Vec<String> = std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect();
            if lines.len() >= want {
                return lines;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the hook log never reached {want} line(s)"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Run `inner` through `/bin/sh` under util-linux `script`, which gives
    /// it a controlling terminal, with `input` typed into that terminal.
    /// Panics when `script` is missing, so a pty test never passes unrun.
    pub fn under_script(&self, inner: &str) -> Output {
        self.under_script_with(inner, b"")
    }

    pub fn under_script_with(&self, inner: &str, input: &[u8]) -> Output {
        let script = which::which("script")
            .expect("util-linux 'script' is needed for the pty tests; run in 'nix develop'");
        let mut s = Command::new(script);
        s.env_clear();
        for (k, v) in self.cmd().get_envs() {
            if let Some(v) = v {
                s.env(k, v);
            }
        }
        s.env("SHELL", "/bin/sh").current_dir(self.root.path());
        run_cmd(s, ["-q", "-e", "-c", inner, "/dev/null"], Some(input))
    }

    /// [`Self::under_script`], with `script`'s stdin held open until it
    /// exits, so no end-of-input reaches the terminal.
    pub fn under_script_held(&self, inner: &str) -> Output {
        let mut s = Command::new(bin("script"));
        s.env_clear();
        for (k, v) in self.cmd().get_envs() {
            if let Some(v) = v {
                s.env(k, v);
            }
        }
        s.env("SHELL", "/bin/sh")
            .current_dir(self.root.path())
            .args(["-q", "-e", "-c", inner, "/dev/null"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = s.spawn().expect("spawn script");
        let held = child.stdin.take();
        let mut out_pipe = child.stdout.take().unwrap();
        let mut err_pipe = child.stderr.take().unwrap();
        let out = std::thread::spawn(move || {
            let mut b = Vec::new();
            std::io::Read::read_to_end(&mut out_pipe, &mut b).unwrap();
            b
        });
        let err = std::thread::spawn(move || {
            let mut b = Vec::new();
            std::io::Read::read_to_end(&mut err_pipe, &mut b).unwrap();
            b
        });
        let status = child.wait().unwrap();
        drop(held);
        Output {
            status,
            stdout: out.join().unwrap(),
            stderr: err.join().unwrap(),
        }
    }

    /// The `recipient:` values in the store file's sops block.
    pub fn file_recipients(&self) -> Vec<String> {
        let text = String::from_utf8(self.store_bytes()).unwrap();
        let mut r: Vec<String> = text
            .lines()
            .filter_map(|l| l.trim().strip_prefix("recipient: "))
            .map(str::to_owned)
            .collect();
        r.sort();
        r
    }
}

/// `cmd` in a new session with no controlling terminal (util-linux
/// `setsid -w`), so a no-tty case is tested even from a terminal.
pub fn no_tty(cmd: &Command) -> Command {
    let mut c = Command::new(bin("setsid"));
    c.arg("-w").arg(cmd.get_program()).args(cmd.get_args());
    c.env_clear();
    for (k, v) in cmd.get_envs() {
        if let Some(v) = v {
            c.env(k, v);
        }
    }
    if let Some(d) = cmd.get_current_dir() {
        c.current_dir(d);
    }
    c.stdin(Stdio::null());
    c
}

pub fn run_cmd<I, S>(mut c: Command, args: I, stdin: Option<&[u8]>) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        c.stdin(Stdio::piped());
    }
    let mut child = c.spawn().expect("spawn secrit");
    if let Some(data) = stdin {
        // secrit may refuse and exit before it reads stdin.
        match child.stdin.take().unwrap().write_all(data) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            r => r.unwrap(),
        }
    }
    child.wait_with_output().unwrap()
}

fn keygen(age_keygen: &Path, out: &Path) -> String {
    let st = Command::new(age_keygen)
        .env_clear()
        .arg("-o")
        .arg(out)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "age-keygen failed");
    let pubkey = Command::new(age_keygen)
        .env_clear()
        .arg("-y")
        .arg(out)
        .output()
        .unwrap();
    assert!(pubkey.status.success());
    String::from_utf8(pubkey.stdout).unwrap().trim().to_owned()
}

pub fn write_sops_config(path: &Path, recipients: &[String]) {
    let text = format!(
        "creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    age: {}\n",
        recipients.join(",")
    );
    std::fs::write(path, text).unwrap();
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

/// Assert that `needle` is in neither stdout nor stderr.
pub fn assert_absent(out: &Output, needle: &str) {
    let n = needle.as_bytes();
    let has = |hay: &[u8]| hay.windows(n.len()).any(|w| w == n);
    assert!(!has(&out.stdout), "a secret reached stdout");
    assert!(!has(&out.stderr), "a secret reached stderr");
}
