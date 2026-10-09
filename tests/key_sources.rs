//! sops key sources (v0.2 plan 6.2, slice S8): `age_ssh_key_file`,
//! `age_key_cmd`, `age_plugin_dir` and the `plugin` identity, with the real
//! sops, temp keys and the rage `age-plugin-unencrypted` example as a
//! stand-in for a hardware plugin. A counter wrapper around the plugin
//! counts its unwraps ("touches"). No test touches a real token.

mod common;

use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::{BIN, TestEnv, bin, code, no_tty, run_cmd, sh_quote, stderr, tool};

/// A fido2-hmac plugin recipient of format version 2 (v0.2 plan 6.7.2
/// rule 4), with dummy key, salt and credential bytes.
const FIDO2_V2: &str = "age1fido2-hmac1qqpqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8cqyqsjygeyy5nzw2pf9g4jctfw9ucrzv3nxs6nvdec8yark0pa8clsqqgzqvzq2ps8pqys5zcvp58q7jnxqhl";

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// An executable script at `path` with `body` after the `shebang` line.
fn script_at(path: &Path, shebang: &str, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("{shebang}\n{body}\n")).unwrap();
    chmod(path, 0o700);
}

/// Encrypt `content` (JSON) to `recipients` only, with no `.sops.yaml`,
/// into the store file of `env`. `path` is the `PATH` that sops gets, for a
/// plugin recipient.
fn encrypt_store(env: &TestEnv, recipients: &[&str], path: Option<&Path>, content: &[u8]) {
    let mut c = Command::new(&env.sops);
    c.env_clear()
        .env("HOME", "/nonexistent")
        .env("SOPS_DISABLE_VERSION_CHECK", "1");
    if let Some(p) = path {
        c.env("PATH", p);
    }
    let mut child = c
        .args(["--config", "/dev/null", "encrypt", "--age"])
        .arg(recipients.join(","))
        .args(["--input-type", "json", "--output-type", "yaml"])
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
        stderr(&out)
    );
    std::fs::write(&env.store_file, &out.stdout).unwrap();
    chmod(&env.store_file, 0o600);
}

/// The `[stores.main]` body with no key source.
fn bare_section(env: &TestEnv) -> String {
    format!(
        "backend = \"sops\"\nfile = \"{}\"\n",
        env.store_file.display()
    )
}

fn write_section(env: &TestEnv, section: &str) {
    env.write_store_config(section, &format!("sops = \"{}\"", env.sops.display()), 30);
}

/// Run `inner` under `script` with `vars` in the environment, so secrit has
/// a terminal. `script` joins its arguments into one shell string, so paths
/// reach `inner` only as variables.
fn under_tty(env: &TestEnv, inner: &str, vars: &[(&str, &OsStr)]) -> Output {
    let mut all: Vec<(&str, &OsStr)> = vec![("S_BIN", OsStr::new(BIN))];
    all.extend_from_slice(vars);
    env.under_script_env(inner, &all)
}

/// `get NAME --stdout` into a file under a terminal. Returns the output and
/// the bytes that reached the file.
fn get_under_tty(env: &TestEnv, name: &str) -> (Output, Vec<u8>) {
    let dest = env.root.path().join("got.out");
    let _ = std::fs::remove_file(&dest);
    let out = under_tty(
        env,
        "umask 077; \"$S_BIN\" get \"$S_NAME\" --stdout > \"$S_OUT\"",
        &[("S_NAME", OsStr::new(name)), ("S_OUT", dest.as_os_str())],
    );
    let got = std::fs::read(&dest).unwrap_or_default();
    (out, got)
}

/// `printf VALUE | secrit ARGS` under a terminal.
fn pipe_under_tty(env: &TestEnv, value: &str, args: &str) -> Output {
    under_tty(
        env,
        &format!("printf %s \"$S_VALUE\" | \"$S_BIN\" {args}"),
        &[("S_VALUE", OsStr::new(value))],
    )
}

/// The `doctor` row whose check is `store main: CHECK`, or `None`.
fn doctor_row(env: &TestEnv, check: &str) -> Option<String> {
    let out = env.run(["doctor"], None);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let want = format!("store main: {check}:");
    text.lines().find(|l| l.contains(&want)).map(str::to_owned)
}

fn pty_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

// ---------------------------------------------------------------------------
// age_ssh_key_file

/// Q18: an unencrypted ed25519 key from `ssh-keygen`, as the only
/// recipient and the only key source, gives a round trip.
#[test]
fn an_ssh_key_round_trips() {
    let env = TestEnv::new();
    let key = env.root.path().join("keys").join("sops_ed25519");
    let public = env.ssh_key(&key, None);
    let recipient = public
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    encrypt_store(&env, &[&recipient], None, b"{}\n");
    write_section(
        &env,
        &format!(
            "{}age_ssh_key_file = \"{}\"\n",
            bare_section(&env),
            key.display()
        ),
    );
    let out = env.store_value("n", b"ssh-value");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let (out, got) = get_under_tty(&env, "n");
    assert_eq!(code(&out), 0, "{}", pty_text(&out));
    assert!(got == b"ssh-value", "the value read back differs");
    assert_eq!(env.file_recipients(), [recipient]);
    // doctor reads the key header only, and has no age key row here.
    let row = doctor_row(&env, "ssh key").expect("no ssh key row");
    assert!(
        row.starts_with("ok") && row.contains("no passphrase"),
        "{row}"
    );
    assert_eq!(doctor_row(&env, "age key"), None);
}

/// T19 style: the decoy passphrase key as `age_ssh_key_file` fails fast,
/// with no terminal and under one, and the message names the key source.
#[test]
fn a_passphrase_ssh_key_fails_fast() {
    let env = TestEnv::new();
    let decoy = env.home.join(".ssh").join("id_ed25519");
    let public = std::fs::read_to_string(decoy.with_extension("pub")).unwrap();
    let recipient = public
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    encrypt_store(&env, &[&recipient], None, b"{\"n\":\"v\"}\n");
    write_section(
        &env,
        &format!(
            "{}age_ssh_key_file = \"{}\"\n",
            bare_section(&env),
            decoy.display()
        ),
    );
    let started = Instant::now();
    let out = run_cmd(no_tty(&env.cmd()), ["store", "m"], Some(b"v"));
    assert_ne!(code(&out), 0, "{}", stderr(&out));
    assert!(started.elapsed() < Duration::from_secs(20));

    let started = Instant::now();
    let (out, got) = get_under_tty(&env, "n");
    assert_ne!(code(&out), 0, "{}", pty_text(&out));
    assert!(got.is_empty());
    assert!(started.elapsed() < Duration::from_secs(20));
    let text = pty_text(&out);
    assert!(text.contains("age_ssh_key_file"), "{text}");
    assert!(text.contains("passphrase"), "{text}");
    let row = doctor_row(&env, "ssh key").expect("no ssh key row");
    assert!(
        row.starts_with("fail") && row.contains("has a passphrase"),
        "{row}"
    );
}

// ---------------------------------------------------------------------------
// age_key_cmd

/// A key command with an absolute shebang that prints the test age key:
/// a round trip, and the counter file shows one run per sops run that
/// decrypts (set and readback for `store`, one for `get`).
#[test]
fn a_key_command_round_trips_and_runs_once_per_sops_run() {
    let env = TestEnv::new();
    let counter = env.root.path().join("key-cmd.count");
    let cmd = env.root.path().join("bin").join("age-key");
    script_at(
        &cmd,
        "#!/bin/sh",
        &format!(
            "echo run >> {}\nexec {} {}",
            sh_quote(&counter),
            sh_quote(&bin("cat")),
            sh_quote(&env.key_file)
        ),
    );
    chmod(cmd.parent().unwrap(), 0o700);
    write_section(
        &env,
        &format!(
            "{}age_key_cmd = \"{}\"\n",
            bare_section(&env),
            cmd.display()
        ),
    );
    let runs = || {
        std::fs::read_to_string(&counter)
            .unwrap_or_default()
            .lines()
            .count()
    };
    let out = env.store_value("a", b"cmd-value");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    env.assert_value("a", "cmd-value");
    assert_eq!(runs(), 2, "set and readback");
    let (out, got) = get_under_tty(&env, "a");
    assert_eq!(code(&out), 0, "{}", pty_text(&out));
    assert!(got == b"cmd-value", "the value read back differs");
    assert_eq!(runs(), 3);
    assert_eq!(env.ls(), ["a"]);
    assert_eq!(runs(), 3, "ls decrypts nothing");
}

/// T47a: a key command that needs `PATH` (an env shebang and a bare `cat`)
/// fails with the documented environment message, and `doctor` warns
/// about the shebang.
#[test]
fn a_key_command_that_needs_path_fails_with_the_environment_message() {
    let env = TestEnv::new();
    let dir = env.root.path().join("bin");
    let cmd = dir.join("age-key");
    script_at(
        &cmd,
        "#!/usr/bin/env sh",
        &format!("cat {}", sh_quote(&env.key_file)),
    );
    chmod(&dir, 0o700);
    write_section(
        &env,
        &format!(
            "{}age_key_cmd = \"{}\"\n",
            bare_section(&env),
            cmd.display()
        ),
    );
    let out = env.store_value("a", b"v");
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("key command"), "{err}");
    assert!(err.contains("PATH"), "{err}");
    assert!(err.contains("HOME=/nonexistent"), "{err}");
    assert_eq!(env.ls(), Vec::<String>::new());

    let out = env.run(["doctor"], None);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let row = text
        .lines()
        .find(|l| l.contains("key command") && l.contains("shebang"))
        .unwrap_or_else(|| panic!("no shebang row: {text}"));
    assert!(row.contains("warn"), "{row}");
}

/// A key command at `bin/age-key` that runs `body` and then prints the
/// test age key, with `age_key_cmd_timeout_secs = 3`.
fn key_cmd_env(body: &str) -> TestEnv {
    let env = TestEnv::new();
    let dir = env.root.path().join("bin");
    let cmd = dir.join("age-key");
    script_at(
        &cmd,
        "#!/bin/sh",
        &format!(
            "{body}\nexec {} {}",
            sh_quote(&bin("cat")),
            sh_quote(&env.key_file)
        ),
    );
    chmod(&dir, 0o700);
    write_section(
        &env,
        &format!(
            "{}age_key_cmd = \"{}\"\nage_key_cmd_timeout_secs = 3\n",
            bare_section(&env),
            cmd.display()
        ),
    );
    env
}

/// T47a: a key command that reads `/dev/tty` gets SIGTTIN, which the
/// kernel sends to the whole sops process group. So sops stops too, and
/// secrit ends the run at once, well within `age_key_cmd_timeout_secs`.
/// The message names the key command.
#[test]
fn a_key_command_that_reads_the_terminal_ends_within_its_deadline() {
    let env = key_cmd_env("read x < /dev/tty");
    let started = Instant::now();
    let out = pipe_under_tty(&env, "v", "store a");
    let took = started.elapsed();
    assert_ne!(code(&out), 0, "{}", pty_text(&out));
    assert!(
        took < Duration::from_secs(3),
        "{took:?}: {}",
        pty_text(&out)
    );
    let text = pty_text(&out);
    assert!(
        text.contains("stopped to ask for input on the terminal"),
        "{text}"
    );
    assert!(
        text.contains("age_key_cmd must not read the terminal"),
        "{text}"
    );
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// T47a: a key command that hangs for another reason ends at
/// `age_key_cmd_timeout_secs`, not at the 120 s sops deadline, and the
/// message says that it may wait for a terminal.
#[test]
fn a_hanging_key_command_ends_at_its_deadline() {
    let env = key_cmd_env(&format!("exec {} 30", sh_quote(&bin("sleep"))));
    let started = Instant::now();
    let out = pipe_under_tty(&env, "v", "store a");
    let took = started.elapsed();
    assert_ne!(code(&out), 0, "{}", pty_text(&out));
    assert!(
        took >= Duration::from_secs(3),
        "{took:?}: {}",
        pty_text(&out)
    );
    assert!(took < Duration::from_secs(15), "{took:?}");
    let text = pty_text(&out);
    assert!(text.contains("did not finish within 3000 ms"), "{text}");
    assert!(text.contains("key command"), "{text}");
    assert!(text.contains("terminal"), "{text}");
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// T47: a key command in a group-writable directory, a group-writable key
/// command, and a path with a space (sops splits it) are refused with
/// exit 3 before any sops run.
#[test]
fn an_unsafe_key_command_is_refused() {
    let env = TestEnv::new();
    let counter = env.root.path().join("key-cmd.count");
    let body = format!(
        "echo run >> {}\nexec {} {}",
        sh_quote(&counter),
        sh_quote(&bin("cat")),
        sh_quote(&env.key_file)
    );
    let shared = env.root.path().join("shared");
    let in_shared = shared.join("age-key");
    script_at(&in_shared, "#!/bin/sh", &body);
    chmod(&shared, 0o770);
    let private = env.root.path().join("private");
    let writable = private.join("age-key");
    script_at(&writable, "#!/bin/sh", &body);
    chmod(&private, 0o700);
    chmod(&writable, 0o720);
    let spaced_dir = env.root.path().join("my bin");
    let spaced = spaced_dir.join("age-key");
    script_at(&spaced, "#!/bin/sh", &body);
    chmod(&spaced_dir, 0o700);

    for (cmd, said) in [
        (&in_shared, "writable by group or others"),
        (&writable, "writable by group or others"),
        (&spaced, "space"),
    ] {
        write_section(
            &env,
            &format!(
                "{}age_key_cmd = \"{}\"\n",
                bare_section(&env),
                cmd.display()
            ),
        );
        let out = env.store_value("a", b"v");
        assert_eq!(code(&out), 3, "{}: {}", cmd.display(), stderr(&out));
        assert!(stderr(&out).contains(said), "{}", stderr(&out));
        assert!(!counter.exists(), "the key command ran");
    }
}

// ---------------------------------------------------------------------------
// age_plugin_dir and the plugin identity

/// A store encrypted to one `age-plugin-unencrypted` identity, with the
/// plugin behind a wrapper that logs each run.
struct PluginEnv {
    env: TestEnv,
    dir: PathBuf,
    log: PathBuf,
    stub: PathBuf,
    recipient: String,
}

impl PluginEnv {
    fn new() -> Self {
        let env = TestEnv::new();
        let real = tool(
            "SECRIT_TEST_AGE_PLUGIN_UNENCRYPTED",
            "age-plugin-unencrypted",
        );
        let dir = env.root.path().join("plugins");
        let log = env.root.path().join("plugin.log");
        script_at(
            &dir.join("age-plugin-unencrypted"),
            "#!/bin/sh",
            &format!(
                "printf '%s\\n' \"$*\" >> {}\nexec {} \"$@\"",
                sh_quote(&log),
                sh_quote(&real)
            ),
        );
        chmod(&dir, 0o700);
        let out = Command::new(&real).env_clear().output().unwrap();
        assert!(out.status.success(), "age-plugin-unencrypted failed");
        let text = String::from_utf8(out.stdout).unwrap();
        let recipient = text
            .lines()
            .find_map(|l| l.strip_prefix("# recipient: "))
            .expect("no recipient line")
            .to_owned();
        let stub = env.root.path().join("keys").join("vault.identity");
        std::fs::write(&stub, &text).unwrap();
        chmod(&stub, 0o600);
        let p = Self {
            env,
            dir,
            log,
            stub,
            recipient,
        };
        p.encrypt(&[]);
        p.write_config("");
        p
    }

    /// Encrypt an empty store to the plugin recipient and `more`.
    fn encrypt(&self, more: &[&str]) {
        let mut all = vec![self.recipient.as_str()];
        all.extend_from_slice(more);
        encrypt_store(&self.env, &all, Some(&self.dir), b"{}\n");
        let _ = std::fs::remove_file(&self.log);
    }

    /// The config with a plugin identity; `extra` goes into its table.
    fn write_config(&self, extra: &str) {
        write_section(
            &self.env,
            &format!(
                "{}\n[stores.main.identity]\nkind = \"plugin\"\nstub = \"{}\"\nplugin_dir = \"{}\"\n{extra}",
                bare_section(&self.env),
                self.stub.display(),
                self.dir.display()
            ),
        );
    }

    /// How often the plugin ran as an identity, that is, unwrapped.
    fn unwraps(&self) -> usize {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains("identity-v1"))
            .count()
    }
}

/// T65: through the plugin identity, `store` unwraps twice (set and
/// readback) and `get` of one name unwraps once. Before each unwrap secrit
/// writes one touch line to the terminal with the count.
#[test]
fn a_plugin_identity_touches_once_per_decrypt() {
    let p = PluginEnv::new();
    let out = pipe_under_tty(&p.env, "plugin-value", "store n");
    assert_eq!(code(&out), 0, "{}", pty_text(&out));
    assert_eq!(p.unwraps(), 2);
    let text = pty_text(&out);
    assert!(
        text.contains("touch your key to write 'n' to main (1 of 2)"),
        "{text}"
    );
    assert!(
        text.contains("touch your key to check 'n' in main (2 of 2)"),
        "{text}"
    );

    let (out, got) = get_under_tty(&p.env, "n");
    assert_eq!(code(&out), 0, "{}", pty_text(&out));
    assert!(got == b"plugin-value", "the value read back differs");
    assert_eq!(p.unwraps(), 3, "one get of one name is one unwrap");
    assert!(
        pty_text(&out).contains("touch your key to read 'n' from main (1 of 1)"),
        "{}",
        pty_text(&out)
    );
    assert_eq!(p.env.ls(), ["n"]);
    assert_eq!(p.unwraps(), 3, "ls unwraps nothing");
    assert_eq!(p.env.file_recipients(), std::slice::from_ref(&p.recipient));
    // doctor cannot read the policy of a plugin other than age-plugin-yubikey.
    let row = doctor_row(&p.env, "identity").expect("no identity row");
    assert!(
        row.starts_with("warn") && row.contains("not checked"),
        "{row}"
    );
    let row = doctor_row(&p.env, "age plugin directory").expect("no plugin dir row");
    assert!(row.starts_with("ok"), "{row}");
    assert_eq!(p.unwraps(), 3, "doctor unwraps nothing");
}

/// With no `/dev/tty`, a plugin identity refuses every command that would
/// decrypt, before sops runs and before the value is read.
#[test]
fn a_plugin_identity_needs_a_terminal() {
    let p = PluginEnv::new();
    for args in [&["store", "n"][..], &["rm", "n", "--yes"][..]] {
        let out = run_cmd(no_tty(&p.env.cmd()), args, Some(b"v"));
        assert_eq!(code(&out), 3, "{args:?}: {}", stderr(&out));
        assert!(stderr(&out).contains("/dev/tty"), "{}", stderr(&out));
    }
    assert_eq!(p.unwraps(), 0);
}

/// 6.7.2 rule 4: a plain age key that this user can read (the default age
/// key file) as a recipient of the file makes the touch pointless, so a
/// plugin identity refuses it before any unwrap.
#[test]
fn a_plugin_identity_refuses_a_plain_recipient() {
    let p = PluginEnv::new();
    let default_key = p.env.config_home.join("sops").join("age").join("keys.txt");
    std::fs::create_dir_all(default_key.parent().unwrap()).unwrap();
    std::fs::copy(&p.env.key_file, &default_key).unwrap();
    chmod(&default_key, 0o600);
    let plain = p.env.recipients[0].clone();
    p.encrypt(&[&plain]);
    let out = pipe_under_tty(&p.env, "v", "store n");
    assert_eq!(code(&out), 3, "{}", pty_text(&out));
    assert!(pty_text(&out).contains("plain"), "{}", pty_text(&out));
    assert_eq!(p.unwraps(), 0);
}

/// T70: a fido2-hmac v2 recipient in the file's recipient set is refused
/// before any unwrap.
#[test]
fn a_fido2_hmac_v2_recipient_is_refused() {
    let p = PluginEnv::new();
    let text = std::fs::read_to_string(&p.env.store_file).unwrap();
    let forged = text.replacen(
        "    age:\n",
        &format!("    age:\n        - recipient: {FIDO2_V2}\n          enc: x\n"),
        1,
    );
    assert_ne!(forged, text);
    std::fs::write(&p.env.store_file, forged).unwrap();
    let out = pipe_under_tty(&p.env, "v", "store n");
    assert_eq!(code(&out), 3, "{}", pty_text(&out));
    assert!(pty_text(&out).contains("fido2-hmac"), "{}", pty_text(&out));
    assert_eq!(p.unwraps(), 0);
}

/// A `YubiKey` stub and a fake `age-plugin-yubikey` that answers `--list`
/// with one slot of the given policies and logs any other run.
fn fake_yubikey(p: &PluginEnv, pin: &str, touch: &str) -> PathBuf {
    let meta = format!(
        "#       Serial: 5555555, Slot: 1\n#         Name: age identity 1a2b3c4d\n#      Created: Thu, 08 Oct 2026 00:00:00 +0000\n#   PIN policy: {pin}\n# Touch policy: {touch}\n"
    );
    let recipient = "age1yubikey1qtestrecipient";
    let list = p.env.root.path().join("list.txt");
    std::fs::write(&list, format!("{meta}{recipient}\n\n")).unwrap();
    script_at(
        &p.dir.join("age-plugin-yubikey"),
        "#!/bin/sh",
        &format!(
            "if [ \"$1\" = --list ]; then exec {} {}; fi\nprintf '%s\\n' \"identity-v1 yubikey $*\" >> {}\nexit 1",
            sh_quote(&bin("cat")),
            sh_quote(&list),
            sh_quote(&p.log)
        ),
    );
    let stub = p.env.root.path().join("keys").join("yubikey.identity");
    std::fs::write(
        &stub,
        format!("{meta}#    Recipient: {recipient}\nAGE-PLUGIN-YUBIKEY-1TESTSTUB\n"),
    )
    .unwrap();
    chmod(&stub, 0o600);
    stub
}

fn write_yubikey_config(p: &PluginEnv, stub: &Path, level: &str) {
    write_section(
        &p.env,
        &format!(
            "{}\n[stores.main.identity]\nkind = \"plugin\"\nstub = \"{}\"\nplugin_dir = \"{}\"\nlevel = \"{level}\"\n",
            bare_section(&p.env),
            stub.display(),
            p.dir.display()
        ),
    );
}

/// T68: a config level stricter than the slot is an error, not a
/// downgrade.
#[test]
fn a_level_stricter_than_the_slot_is_refused() {
    let p = PluginEnv::new();
    let stub = fake_yubikey(
        &p,
        "Once   (A PIN is required once per session, if set)",
        "Always (A physical touch is required for every decryption)",
    );
    write_yubikey_config(&p, &stub, "strict");
    let out = pipe_under_tty(&p.env, "v", "store n");
    assert_eq!(code(&out), 3, "{}", pty_text(&out));
    assert!(
        pty_text(&out)
            .contains("level 'strict' needs PIN policy always; slot 1 on serial 5555555 has once"),
        "{}",
        pty_text(&out)
    );
    assert_eq!(p.unwraps(), 0);
    let row = doctor_row(&p.env, "identity").expect("no identity row");
    assert!(
        row.starts_with("fail") && row.contains("needs PIN policy always"),
        "{row}"
    );
}

/// T69: a slot with touch policy `cached` is refused at every level.
#[test]
fn a_cached_touch_slot_is_refused() {
    let p = PluginEnv::new();
    let stub = fake_yubikey(
        &p,
        "Never  (A PIN is NOT required to decrypt)",
        "Cached (A physical touch is required for decryption, and is cached for 15 seconds)",
    );
    write_yubikey_config(&p, &stub, "touch");
    let out = pipe_under_tty(&p.env, "v", "store n");
    assert_eq!(code(&out), 3, "{}", pty_text(&out));
    assert!(pty_text(&out).contains("cached"), "{}", pty_text(&out));
    assert_eq!(p.unwraps(), 0);
}

/// T48: `age_plugin_dir` with a group-writable entry, or with a file that
/// is not an `age-plugin-*` program, is refused before sops runs.
#[test]
fn an_unsafe_plugin_dir_is_refused() {
    let p = PluginEnv::new();
    // The plugin directory as a store-level key, with the age key file.
    let section = format!(
        "{}age_plugin_dir = \"{}\"\n",
        p.env.sops_section(),
        p.dir.display()
    );
    std::fs::copy(&p.env.store_file, p.env.root.path().join("plugin-store")).unwrap();
    p.env.create_store(&p.env.store_file);
    write_section(&p.env, &section);
    let out = p.env.store_value("a", b"v");
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let wrapper = p.dir.join("age-plugin-unencrypted");
    chmod(&wrapper, 0o720);
    let out = p.env.store_value("b", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("writable by group or others"),
        "{}",
        stderr(&out)
    );
    chmod(&wrapper, 0o700);

    std::fs::write(p.dir.join("sh"), "").unwrap();
    let out = p.env.store_value("b", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("age-plugin-"), "{}", stderr(&out));
    assert_eq!(p.env.ls(), ["a"]);
}
