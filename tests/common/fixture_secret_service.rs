//! The Secret Service fixture (v0.2 plan S10, lab V24). Each fixture runs
//! its own `dbus-daemon` on `unix:path=<runtime>/bus` and its own
//! `gnome-keyring-daemon`, unlocked with a fixed test password and keeping
//! its keyrings in a temp `XDG_DATA_HOME`. The user's session bus and
//! keyring are never touched: every daemon and helper runs with a cleared
//! environment. Values are read back with `secret-tool`, in the test
//! process, and never printed.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::env::{Dirs, bin, tool};
use super::fixture::{Caps, Fixture};

/// The keyring password of the fixture. It protects only a temp keyring.
const KEYRING_PASSWORD: &[u8] = b"secrit-fixture";
/// The object path of the login collection, which `default` names.
pub const LOGIN_COLLECTION: &str = "/org/freedesktop/secrets/collection/login";

/// The programs that the fixture runs.
pub struct Tools {
    pub dbus_daemon: PathBuf,
    pub dbus_config: PathBuf,
    pub dbus_send: PathBuf,
    pub keyring: PathBuf,
    pub secret_tool: PathBuf,
}

impl Tools {
    pub fn find() -> Self {
        let dbus_daemon = tool("SECRIT_TEST_DBUS_DAEMON", "dbus-daemon");
        let dbus_config = std::env::var_os("SECRIT_TEST_DBUS_CONFIG")
            .filter(|p| !p.is_empty())
            .map_or_else(
                || {
                    // <dbus>/bin/dbus-daemon -> <dbus>/share/dbus-1/session.conf
                    let real = std::fs::canonicalize(&dbus_daemon).unwrap();
                    real.parent()
                        .and_then(Path::parent)
                        .unwrap()
                        .join("share/dbus-1/session.conf")
                },
                PathBuf::from,
            );
        Self {
            dbus_daemon,
            dbus_config,
            dbus_send: tool("SECRIT_TEST_DBUS_SEND", "dbus-send"),
            keyring: tool("SECRIT_TEST_GNOME_KEYRING", "gnome-keyring-daemon"),
            secret_tool: tool("SECRIT_TEST_SECRET_TOOL", "secret-tool"),
        }
    }
}

/// A store in the default collection of a private gnome-keyring.
pub struct SecretServiceFixture {
    dirs: Dirs,
    pub tools: Tools,
    /// The bus socket: `<XDG_RUNTIME_DIR>/bus`.
    pub bus: PathBuf,
    data_home: PathBuf,
    dbus: Child,
    keyring: Option<Child>,
}

impl SecretServiceFixture {
    /// `unix:path=<bus>`, as secrit and the helpers get it.
    pub fn address(&self) -> OsString {
        let mut a = OsString::from("unix:path=");
        a.push(&self.bus);
        a
    }

    /// A helper program with the fixture's environment only.
    fn helper(&self, program: &Path) -> Command {
        let mut c = Command::new(program);
        c.env_clear()
            .env("HOME", &self.dirs.home)
            .env("XDG_RUNTIME_DIR", &self.dirs.runtime)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("DBUS_SESSION_BUS_ADDRESS", self.address())
            .current_dir(self.dirs.root.path())
            .stdin(Stdio::null());
        c
    }

    fn output(mut c: Command) -> Output {
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        c.output().expect("run a fixture helper")
    }

    /// A `dbus-send --print-reply` call on the fixture bus.
    pub fn dbus_send(&self, dest: &str, path: &str, method: &str, args: &[&str]) -> Output {
        let mut c = self.helper(&self.tools.dbus_send);
        c.arg("--session")
            .arg("--print-reply")
            .arg(format!("--dest={dest}"))
            .arg(path)
            .arg(method)
            .args(args);
        Self::output(c)
    }

    /// Whether a daemon owns `org.freedesktop.secrets` on the fixture bus.
    pub fn secrets_owned(&self) -> bool {
        let out = self.dbus_send(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            &["string:org.freedesktop.secrets"],
        );
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("boolean true")
    }

    /// Start gnome-keyring on the fixture bus. With `login`, it unlocks
    /// (and on the first start creates) the login keyring with the test
    /// password; without it, the keyring on disk stays locked.
    fn start_keyring(&mut self, login: bool) {
        // A daemon that was killed leaves its control socket; the next one
        // must not find it, or `--start` would fork a daemon of its own.
        let _ = std::fs::remove_dir_all(self.dirs.runtime.join("keyring"));
        let mut c = self.helper(&self.tools.keyring);
        c.arg("--foreground");
        if login {
            c.arg("--login");
        }
        c.arg("--components=secrets")
            .stdin(if login { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = c.spawn().expect("start gnome-keyring-daemon");
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(KEYRING_PASSWORD).unwrap();
        }
        self.keyring = Some(child);
        let control = self.dirs.runtime.join("keyring").join("control");
        wait_for("the gnome-keyring control socket", || control.exists());
        // Lab V24: only `--start` registers org.freedesktop.secrets.
        let mut start = self.helper(&self.tools.keyring);
        start
            .args(["--start", "--components=secrets"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        assert!(
            start.status().unwrap().success(),
            "gnome-keyring-daemon --start failed"
        );
        wait_for("org.freedesktop.secrets on the fixture bus", || {
            self.secrets_owned()
        });
    }

    fn stop_keyring(&mut self) {
        if let Some(mut k) = self.keyring.take() {
            signal(&k, "TERM");
            let _ = k.wait();
        }
        wait_for("org.freedesktop.secrets to leave the bus", || {
            !self.secrets_owned()
        });
    }

    /// Stop gnome-keyring and start it again without the password: the
    /// login keyring on disk stays locked, and the daemon shows only hashed
    /// attributes until it is unlocked.
    pub fn restart_locked(&mut self) {
        self.stop_keyring();
        self.start_keyring(false);
    }

    /// Send `SIGSTOP` or `SIGCONT` to gnome-keyring, so a D-Bus call to
    /// it blocks or goes on.
    pub fn signal_keyring(&self, sig: &str) {
        signal(self.keyring.as_ref().expect("gnome-keyring runs"), sig);
    }

    /// The `attribute.secrit-name` values of every item of store `main`,
    /// from `secret-tool search`. Its other output (the values) is dropped
    /// unread.
    fn search_names(&self, extra: &[&str]) -> Vec<String> {
        let mut c = self.helper(&self.tools.secret_tool);
        c.args(["search", "--all", "secrit-store", "main"])
            .args(extra);
        let out = Self::output(c);
        let mut names: Vec<String> = [&out.stdout, &out.stderr]
            .into_iter()
            .flat_map(|b| {
                String::from_utf8_lossy(b)
                    .lines()
                    .filter_map(|l| l.strip_prefix("attribute.secrit-name = "))
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect();
        names.sort();
        names
    }

    /// How many items hold `name` in store `main`.
    pub fn item_count(&self, name: &str) -> usize {
        self.search_names(&["secrit-name", name]).len()
    }

    /// `secret-tool store` of `value` as item `name` of store `main`, with
    /// the attributes that secrit uses: another program that writes the
    /// same name.
    pub fn tool_store(&self, name: &str, value: &[u8]) {
        let mut c = self.helper(&self.tools.secret_tool);
        c.arg("store")
            .arg(format!("--label=secrit: {name}"))
            .args([
                "application",
                "secrit",
                "secrit-store",
                "main",
                "secrit-name",
                name,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = c.spawn().expect("run secret-tool");
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(value)
            .expect("write the value to secret-tool");
        assert!(child.wait().expect("wait for secret-tool").success());
    }

    /// `secret-tool lookup` with `attrs`; `None` when no item matches.
    pub fn lookup(&self, attrs: &[&str]) -> Option<Vec<u8>> {
        let mut c = self.helper(&self.tools.secret_tool);
        c.arg("lookup").args(attrs);
        let out = Self::output(c);
        out.status.success().then_some(out.stdout)
    }
}

impl Fixture for SecretServiceFixture {
    const CAPS: Caps = Caps {
        names_without_decrypt: true,
        backups: false,
        child_tool: false,
    };
    const REDACTION_NOTE: &'static str = "";

    fn new() -> Self {
        let tools = Tools::find();
        let mut dirs = Dirs::new(&[]);
        let data_home = dirs.root.path().join("data");
        std::fs::create_dir_all(&data_home).unwrap();
        let bus = dirs.runtime.join("bus");
        let dbus = Command::new(&tools.dbus_daemon)
            .env_clear()
            .env("HOME", &dirs.home)
            .env("XDG_RUNTIME_DIR", &dirs.runtime)
            .arg(format!("--config-file={}", tools.dbus_config.display()))
            .arg(format!("--address=unix:path={}", bus.display()))
            .args(["--nofork", "--nopidfile"])
            .current_dir(dirs.root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start dbus-daemon");
        wait_for("the fixture bus socket", || bus.exists());
        let mut address = OsString::from("unix:path=");
        address.push(&bus);
        dirs.set_env("DBUS_SESSION_BUS_ADDRESS", address);
        let mut f = Self {
            dirs,
            tools,
            bus,
            data_home,
            dbus,
            keyring: None,
        };
        f.start_keyring(true);
        let section = f.config_section();
        f.dirs.write_store_config(&section, "", 120);
        f
    }

    fn dirs(&self) -> &Dirs {
        &self.dirs
    }

    fn config_section(&self) -> String {
        "backend = \"secret-service\"\n".to_owned()
    }

    fn read_back(&self, name: &str) -> Option<Vec<u8>> {
        self.lookup(&["secrit-store", "main", "secrit-name", name])
    }

    fn names(&self) -> Vec<String> {
        let mut names = self.search_names(&[]);
        names.dedup();
        names
    }

    /// Lock the login collection (lab V24: `secret-tool lock` hangs, so
    /// the fixture calls `Lock` itself). The daemon still shows the item
    /// attributes, so the names stay readable.
    fn lock_values(&self) {
        let out = self.dbus_send(
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.Secret.Service.Lock",
            &[&format!("array:objpath:{LOGIN_COLLECTION}")],
        );
        assert!(out.status.success(), "the Lock call failed");
    }

    fn log_tool_argv(&self, _: &Path) {
        unreachable!("the Secret Service backend runs no child tool");
    }

    fn fail_tool_echoing_stdin(&self) {
        unreachable!("the Secret Service backend runs no child tool");
    }
}

impl Drop for SecretServiceFixture {
    fn drop(&mut self) {
        if let Some(k) = self.keyring.as_mut() {
            signal(k, "CONT");
            let _ = k.kill();
            let _ = k.wait();
        }
        let _ = self.dbus.kill();
        let _ = self.dbus.wait();
    }
}

/// `kill -<sig> <pid>` with util-linux or coreutils `kill`.
fn signal(child: &Child, sig: &str) {
    let _ = Command::new(bin("kill"))
        .arg(format!("-{sig}"))
        .arg(child.id().to_string())
        .status();
}

/// Poll `ready` every 20 ms, at most 20 s.
fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}
