//! The pass layout fixture (v0.2 plan 6.4, S11): a password-store
//! directory with a `.gpg-id`, and a throwaway `GNUPGHOME` in the temp
//! directory with a key made by `gpg --quick-gen-key`. The fixture reads
//! entries back with the real gpg, never with secrit, and never prints a
//! value. Dropping it stops the gpg-agent of its `GNUPGHOME`.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::env::{Dirs, sh_quote, tool};
use super::fixture::{Caps, ECHO_PREFIX, Fixture};

/// A key in the fixture's keyring.
#[derive(Debug, Clone)]
pub struct Key {
    pub email: String,
    /// The primary key fingerprint.
    pub fpr: String,
    /// The long key IDs of the encryption subkeys.
    pub enc_ids: Vec<String>,
}

pub struct PassFixture {
    dirs: Dirs,
    pub gpg: PathBuf,
    pub gnupg_home: PathBuf,
    /// The password-store directory (`dir` in the config).
    pub store_dir: PathBuf,
    /// The key that the root `.gpg-id` names. It has no passphrase.
    pub key: Key,
}

impl std::ops::Deref for PassFixture {
    type Target = Dirs;

    fn deref(&self) -> &Dirs {
        &self.dirs
    }
}

impl Drop for PassFixture {
    fn drop(&mut self) {
        let _ = self.stop_daemons();
    }
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

impl PassFixture {
    pub fn gpgconf(&self) -> PathBuf {
        self.gpg.with_file_name("gpgconf")
    }

    /// gpg in the test process, with a cleared environment and the temp
    /// `GNUPGHOME` only.
    pub fn gpg_cmd(&self) -> Command {
        let mut c = Command::new(&self.gpg);
        c.env_clear()
            .env("GNUPGHOME", &self.gnupg_home)
            .args(["--batch", "--no-tty"])
            .stdin(Stdio::null());
        c
    }

    /// Make a key for `email`. With `passphrase`, the secret key needs it.
    pub fn gen_key(&self, email: &str, passphrase: Option<&str>) -> Key {
        let mut c = self.gpg_cmd();
        c.args(["--pinentry-mode", "loopback", "--passphrase"])
            .arg(passphrase.unwrap_or(""))
            .arg("--quick-gen-key")
            .arg(format!("secrit test <{email}>"))
            .args(["default", "default", "never"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        assert!(c.status().unwrap().success(), "gpg --quick-gen-key failed");
        self.key_of(email)
    }

    /// The fingerprint and the encryption subkey IDs of `email`.
    pub fn key_of(&self, email: &str) -> Key {
        let out = self
            .gpg_cmd()
            .args(["--with-colons", "--list-keys", "--"])
            .arg(email)
            .output()
            .unwrap();
        assert!(out.status.success(), "gpg --list-keys {email} failed");
        let text = String::from_utf8(out.stdout).unwrap();
        let mut fpr = None;
        let mut enc_ids = Vec::new();
        let mut last = "";
        for line in text.lines() {
            let f: Vec<&str> = line.split(':').collect();
            match f[0] {
                "fpr" if last == "pub" && fpr.is_none() => fpr = Some(f[9].to_owned()),
                "sub" if f[11].contains('e') => enc_ids.push(f[4].to_owned()),
                _ => {}
            }
            if f[0] != "fpr" && f[0] != "grp" {
                last = f[0];
            }
        }
        Key {
            email: email.to_owned(),
            fpr: fpr.expect("no fingerprint"),
            enc_ids,
        }
    }

    /// The path of the entry `name` (`a/b` for a nested one).
    pub fn entry(&self, name: &str) -> PathBuf {
        self.store_dir.join(format!("{name}.gpg"))
    }

    /// The raw decrypted bytes of the file at `path`, or `None` when it does
    /// not exist. Never printed.
    pub fn decrypt_file(&self, path: &Path) -> Option<Vec<u8>> {
        if !path.exists() {
            return None;
        }
        let out = self
            .gpg_cmd()
            .args(["--quiet", "--pinentry-mode", "error", "--decrypt"])
            .arg(path)
            .stderr(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "test decrypt failed");
        Some(out.stdout)
    }

    /// The key IDs of the public-key packets of the file at `path`, sorted.
    /// Decrypts nothing.
    pub fn packet_ids(&self, path: &Path) -> Vec<String> {
        let out = self
            .gpg_cmd()
            .args(["--list-only", "--list-packets"])
            .arg(path)
            .stderr(Stdio::null())
            .output()
            .unwrap();
        let text = String::from_utf8(out.stdout).unwrap();
        let mut ids: Vec<String> = text
            .lines()
            .filter(|l| l.starts_with(":pubkey enc packet:"))
            .filter_map(|l| l.rsplit("keyid ").next())
            .map(|s| s.trim().to_owned())
            .collect();
        ids.sort();
        ids
    }

    /// Write an entry with exactly `bytes` inside, encrypted to `key` with
    /// gpg itself, as another tool would.
    pub fn write_entry_with_gpg(&self, name: &str, key: &Key, bytes: &[u8]) {
        let path = self.entry(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut c = self.gpg_cmd();
        c.args(["--yes", "--trust-model", "always", "--encrypt", "-r"])
            .arg(&key.fpr)
            .arg("-o")
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = c.spawn().unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        assert!(child.wait().unwrap().success(), "gpg --encrypt failed");
    }

    /// Write the config with the gpg at `gpg` and `extra` appended inside
    /// `[stores.main]`.
    pub fn write_config_with(&self, gpg: &Path, extra: &str) {
        self.dirs.write_store_config(
            &format!("{}{extra}", self.config_section()),
            &format!("gpg = \"{}\"", gpg.display()),
            120,
        );
    }

    pub fn write_config(&self, extra: &str) {
        self.write_config_with(&self.gpg, extra);
    }

    /// A gpg-agent config whose pinentry writes `marker` and fails, so a
    /// test sees whether any pinentry started. Stops the running agent, so
    /// the next gpg run starts one that reads it and has nothing cached.
    pub fn marker_pinentry(&self, marker: &Path) {
        let pinentry = self.dirs.script(
            "pinentry-marker",
            &format!(": > {}\nexit 1", sh_quote(marker)),
        );
        std::fs::write(
            self.gnupg_home.join("gpg-agent.conf"),
            format!("pinentry-program {}\n", pinentry.display()),
        )
        .unwrap();
        self.kill_agent();
    }

    /// Stop every gpg daemon of the fixture's `GNUPGHOME` (gpg-agent,
    /// keyboxd, dirmngr). Returns whether `gpgconf --kill all` worked.
    pub fn stop_daemons(&self) -> bool {
        Command::new(self.gpgconf())
            .env_clear()
            .env("GNUPGHOME", &self.gnupg_home)
            .args(["--kill", "all"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|st| st.success())
    }

    pub fn kill_agent(&self) {
        let st = Command::new(self.gpgconf())
            .env_clear()
            .env("GNUPGHOME", &self.gnupg_home)
            .args(["--kill", "gpg-agent"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "gpgconf --kill failed");
    }
}

impl Fixture for PassFixture {
    const CAPS: Caps = Caps {
        names_without_decrypt: true,
        backups: true,
        child_tool: true,
    };
    const REDACTION_NOTE: &'static str = "line(s) not shown, because they may hold the value";

    fn new() -> Self {
        let gpg = tool("SECRIT_TEST_GPG", "gpg");
        let dirs = Dirs::new(&[&gpg]);
        let root = dirs.root.path().to_path_buf();
        let gnupg_home = root.join("gnupg");
        let store_dir = root.join("store");
        for d in [&gnupg_home, &store_dir] {
            std::fs::create_dir_all(d).unwrap();
            chmod(d, 0o700);
        }
        let mut f = Self {
            dirs,
            gpg,
            gnupg_home,
            store_dir,
            key: Key {
                email: String::new(),
                fpr: String::new(),
                enc_ids: Vec::new(),
            },
        };
        f.key = f.gen_key("a@secrit.test", None);
        std::fs::write(f.store_dir.join(".gpg-id"), "a@secrit.test\n").unwrap();
        f.write_config("");
        f
    }

    fn dirs(&self) -> &Dirs {
        &self.dirs
    }

    fn config_section(&self) -> String {
        format!(
            "backend = \"pass\"\ndir = \"{}\"\ngnupg_home = \"{}\"\n",
            self.store_dir.display(),
            self.gnupg_home.display(),
        )
    }

    /// The pass value rule: the file minus one trailing newline.
    fn read_back(&self, name: &str) -> Option<Vec<u8>> {
        let mut bytes = self.decrypt_file(&self.entry(name))?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        Some(bytes)
    }

    fn names(&self) -> Vec<String> {
        fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') {
                    continue;
                }
                let t = e.file_type().unwrap();
                if t.is_dir() {
                    walk(&e.path(), &format!("{prefix}{name}/"), out);
                } else if let Some(stem) = name.strip_suffix(".gpg") {
                    out.push(format!("{prefix}{stem}"));
                }
            }
        }
        let mut names = Vec::new();
        walk(&self.store_dir, "", &mut names);
        names.sort();
        names
    }

    /// The file names list the entries; the secret key decrypts them.
    fn lock_values(&self) {
        let st = self
            .gpg_cmd()
            .args(["--yes", "--delete-secret-keys"])
            .arg(&self.key.fpr)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "gpg --delete-secret-keys failed");
    }

    fn log_tool_argv(&self, log: &Path) {
        let wrapper = self.dirs.script(
            "gpg-argv",
            &format!(
                "for a in \"$@\"; do printf '%s\\n' \"$a\" >> {}; done\nexec {} \"$@\"",
                sh_quote(log),
                sh_quote(&self.gpg)
            ),
        );
        self.write_config_with(&wrapper, "");
    }

    /// Only the encrypt run echoes: the recipient lookup before it must
    /// work, so the value reaches the fake tool.
    fn fail_tool_echoing_stdin(&self) {
        let fake = self.dirs.script(
            "gpg-echo",
            &format!(
                "case \" $* \" in *\" --encrypt \"*)\n  while IFS= read -r l || [ -n \"$l\" ]; do printf '{ECHO_PREFIX}%s\\n' \"$l\" >&2; done\n  exit 1;;\nesac\nexec {} \"$@\"",
                sh_quote(&self.gpg)
            ),
        );
        self.write_config_with(&fake, "");
    }
}
