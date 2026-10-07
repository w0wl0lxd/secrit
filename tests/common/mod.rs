//! Test harness (PLAN section 15.1).
//!
//! Every test gets a temp HOME, `XDG_CONFIG_HOME` and `XDG_RUNTIME_DIR`, two new
//! age keys from `age-keygen`, a `.sops.yaml`, an empty sops store and a
//! config naming them. The secrit child runs with a cleared environment, so
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
}

impl TestEnv {
    pub fn new() -> Self {
        let sops = tool("SECRIT_TEST_SOPS", "sops");
        let age_keygen = tool("SECRIT_TEST_AGE_KEYGEN", "age-keygen");
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
        };
        env.create_store(&env.store_file);
        env.write_config("");
        env
    }

    /// Write the config. `extra` is appended inside `[stores.main]`.
    pub fn write_config(&self, extra: &str) {
        self.write_config_with(&self.sops, extra);
    }

    pub fn write_config_with(&self, sops: &Path, extra: &str) {
        std::fs::create_dir_all(self.config_file.parent().unwrap()).unwrap();
        let text = format!(
            "default_store = \"main\"\n\n[stores.main]\nbackend = \"sops\"\nfile = \"{}\"\nage_key_file = \"{}\"\n{extra}\n[tools]\nsops = \"{}\"\n\n[lock]\ntimeout_secs = 120\n",
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
        let mut child = self
            .sops_cmd()
            .args([
                "encrypt",
                "--input-type",
                "yaml",
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
        child.stdin.take().unwrap().write_all(b"{}\n").unwrap();
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

    pub fn backups(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.store_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .contains(".secrit-bak.")
            })
            .collect()
    }

    /// A shell script in the temp dir, mode 0700.
    pub fn script(&self, name: &str, body: &str) -> PathBuf {
        let p = self.root.path().join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    /// Run `inner` through `/bin/sh` under util-linux `script`, which gives
    /// it a controlling terminal. `None` when `script` is not installed.
    pub fn under_script(&self, inner: &str) -> Option<Output> {
        let Ok(script) = which::which("script") else {
            eprintln!("skipped: util-linux 'script' not found");
            return None;
        };
        let mut s = Command::new(script);
        s.env_clear();
        for (k, v) in self.cmd().get_envs() {
            if let Some(v) = v {
                s.env(k, v);
            }
        }
        s.env("SHELL", "/bin/sh").current_dir(self.root.path());
        Some(run_cmd(
            s,
            ["-q", "-e", "-c", inner, "/dev/null"],
            Some(b""),
        ))
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
