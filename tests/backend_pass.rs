//! The conformance suite (v0.2 plan 10.1) on a pass layout store (6.4,
//! S11), with the real gpg and a throwaway `GNUPGHOME` in the temp
//! directory, plus the pass checks: T34 to T37 and exact-byte interop with
//! pass 1.7.4 and a gopass store (`gpgcli` crypto, `fs` storage).

mod common;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::conformance::get_to_file;
use common::fixture::Fixture;
use common::fixture_pass::PassFixture;
use common::{bin, code, git, run_cmd, stderr, tool};

crate::conformance_suite!(common::fixture_pass::PassFixture);

/// `get NAME --stdout` on a terminal, with no agent. Returns the bytes.
fn get(f: &PassFixture, name: &str) -> Vec<u8> {
    let (out, got) = get_to_file(f, false, name);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    got
}

fn gpg_dir(f: &PassFixture) -> OsString {
    f.gpg.parent().unwrap().as_os_str().to_owned()
}

/// pass 1.7.4 on the fixture's store, with a cleared environment.
fn pass(f: &PassFixture, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut c = Command::new(tool("SECRIT_TEST_PASS", "pass"));
    c.env_clear()
        .env("HOME", &f.home)
        .env("GNUPGHOME", &f.gnupg_home)
        .env("PASSWORD_STORE_DIR", &f.store_dir)
        .env("PATH", gpg_dir(f))
        .stdin(Stdio::null());
    let out = run_cmd(c, args, stdin);
    assert_eq!(code(&out), 0, "pass {args:?}: {}", stderr(&out));
    out
}

/// gopass on the fixture's store, with a cleared environment and no sync.
fn gopass(f: &PassFixture, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut c = Command::new(tool("SECRIT_TEST_GOPASS", "gopass"));
    c.env_clear()
        .env("HOME", &f.home)
        .env("GNUPGHOME", &f.gnupg_home)
        .env("PATH", gpg_dir(f))
        .env("GOPASS_NO_NOTIFY", "true")
        .env("GOPASS_NO_AUTOSYNC", "true")
        .stdin(Stdio::null());
    let out = run_cmd(c, args, stdin);
    assert_eq!(code(&out), 0, "gopass {args:?}: {}", stderr(&out));
    out
}

/// A gopass store (`gpgcli`, `fs`) in place of the fixture's store. gopass
/// writes its own `.gpg-id`, with the key ID in `0x` form.
fn gopass_store(f: &PassFixture) {
    std::fs::remove_file(f.store_dir.join(".gpg-id")).unwrap();
    let dir = f.store_dir.to_str().unwrap();
    gopass(
        f,
        &[
            "init",
            "--crypto",
            "gpgcli",
            "--storage",
            "fs",
            "--path",
            dir,
            &f.key.email,
        ],
        None,
    );
    let id = std::fs::read_to_string(f.store_dir.join(".gpg-id")).unwrap();
    assert!(id.trim().starts_with("0x"), "gopass wrote {id:?}");
}

/// pass 1.7.4 to secrit: `insert` of `pw` reads back as `pw`; `insert -m`
/// of `pw\nlogin: a\n` reads back whole, and as `pw` under `first-line`.
#[test]
fn pass_entries_read_back_exactly() {
    let f = PassFixture::new();
    pass(&f, &["insert", "-e", "one"], Some(b"pw\n"));
    pass(&f, &["insert", "-m", "two"], Some(b"pw\nlogin: a\n"));
    pass(&f, &["insert", "-e", "x/three"], Some(b"pw\n"));
    assert_eq!(f.decrypt_file(&f.entry("one")).unwrap(), b"pw\n");
    assert_eq!(f.decrypt_file(&f.entry("two")).unwrap(), b"pw\nlogin: a\n");

    assert_eq!(f.ls(), ["one", "two", "x/three"]);
    assert!(get(&f, "one") == b"pw", "whole value of one differs");
    assert!(
        get(&f, "two") == b"pw\nlogin: a",
        "whole value of two differs"
    );

    f.write_config("value = \"first-line\"\n");
    assert!(get(&f, "one") == b"pw", "first line of one differs");
    assert!(get(&f, "two") == b"pw", "first line of two differs");
}

/// secrit to pass 1.7.4: a secrit-written `pw` is `pw` plus one newline,
/// so `pass show` prints the line `pw` and its first line (what
/// `pass show -c` copies) is `pw`.
#[test]
fn secrit_entries_show_in_pass() {
    let f = PassFixture::new();
    assert_eq!(code(&f.store_value("one", b"pw")), 0);
    let out = f.run(["store", "two", "--raw"], Some(b"pw\nlogin: a\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let shown = pass(&f, &["show", "one"], None).stdout;
    assert!(shown == b"pw\n", "pass show of one differs");
    assert_eq!(shown.split(|b| *b == b'\n').next(), Some(&b"pw"[..]));
    // A value that ends in a newline gets one more, so the round trip is
    // exact both ways.
    let shown = pass(&f, &["show", "two"], None).stdout;
    assert!(shown == b"pw\nlogin: a\n\n", "pass show of two differs");
    assert!(
        get(&f, "two") == b"pw\nlogin: a\n",
        "round trip of two differs"
    );
    assert_eq!(pass(&f, &["ls"], None).status.code(), Some(0));
}

/// The same cases against a gopass store: gopass `insert` reads back
/// exactly, and a secrit-written `pw` shows as `pw`.
#[test]
fn gopass_store_interop_is_exact() {
    let f = PassFixture::new();
    gopass_store(&f);
    gopass(&f, &["insert", "-f", "one"], Some(b"pw\n"));
    gopass(&f, &["insert", "-m", "-f", "two"], Some(b"pw\nlogin: a\n"));
    assert_eq!(f.ls(), ["one", "two"]);
    assert!(get(&f, "one") == b"pw", "whole value of one differs");
    assert!(
        get(&f, "two") == b"pw\nlogin: a",
        "whole value of two differs"
    );
    f.write_config("value = \"first-line\"\n");
    assert!(get(&f, "two") == b"pw", "first line of two differs");

    f.write_config("");
    assert_eq!(code(&f.store_value("mine", b"pw")), 0);
    let shown = gopass(&f, &["show", "mine"], None).stdout;
    assert!(shown == b"pw\n", "gopass show of mine differs");
    let password = gopass(&f, &["show", "-o", "mine"], None).stdout;
    assert!(password == b"pw", "gopass show -o of mine differs");
    assert_eq!(f.packet_ids(&f.entry("mine")), f.key.enc_ids);
}

/// `first-line` keeps the pass password only: a value with a newline is
/// refused, and nothing is written.
#[test]
fn first_line_refuses_a_value_with_a_newline() {
    let f = PassFixture::new();
    f.write_config("value = \"first-line\"\n");
    let out = f.run(["store", "n", "--raw"], Some(b"a\nb"));
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("first-line"), "{}", stderr(&out));
    assert_eq!(f.names(), Vec::<String>::new());
    assert_eq!(code(&f.store_value("n", b"one-line")), 0);
    assert!(get(&f, "n") == b"one-line", "first-line value differs");
}

/// T34: SIGKILL at the hook before the rename leaves the old entry
/// byte-identical.
#[cfg(feature = "test-hooks")]
#[test]
fn a_kill_before_the_rename_keeps_the_old_entry() {
    let f = PassFixture::new();
    assert_eq!(code(&f.store_value("n", b"old")), 0);
    let before = std::fs::read(f.entry("n")).unwrap();
    let mut cmd = f.cmd();
    cmd.env("SECRIT_TEST_HOOK", "before-rename=pause")
        .env("SECRIT_TEST_HOOK_DIR", f.hook_dir())
        .args(["store", "n", "--replace"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(b"new").unwrap();
    }
    assert_eq!(f.wait_for_hook(1), ["before-rename"]);
    let st = Command::new(bin("kill"))
        .args(["-s", "KILL", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), None, "secrit was not killed");
    assert_eq!(std::fs::read(f.entry("n")).unwrap(), before);
    assert_eq!(f.read_back("n").as_deref(), Some(&b"old"[..]));
    assert_eq!(f.ls(), ["n"]);
}

/// T35: the nearest `.gpg-id` upward from the entry's directory names the
/// recipients. Here the store prefix `team` has its own `.gpg-id`.
#[test]
fn a_gpg_id_in_a_subdirectory_picks_the_recipients() {
    let f = PassFixture::new();
    let b = f.gen_key("b@secrit.test", None);
    let team = f.store_dir.join("team");
    std::fs::create_dir(&team).unwrap();
    std::fs::write(team.join(".gpg-id"), format!("# team key\n{}\n", b.fpr)).unwrap();
    f.write_config("prefix = \"team\"\n");
    let out = f.store_value("n", b"v");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(f.packet_ids(&team.join("n.gpg")), b.enc_ids);
    assert_eq!(f.ls(), ["n"]);
    assert!(get(&f, "n") == b"v", "value in the prefix differs");

    // The root store, with the root .gpg-id, still uses key a.
    f.write_config("");
    assert_eq!(code(&f.store_value("r", b"v")), 0);
    assert_eq!(f.packet_ids(&f.entry("r")), f.key.enc_ids);
}

/// T35: a gpg that adds a recipient of its own is caught by the packet
/// check, and nothing is written.
#[test]
fn a_forged_recipient_is_caught() {
    let f = PassFixture::new();
    let b = f.gen_key("b@secrit.test", None);
    assert_eq!(code(&f.store_value("n", b"old")), 0);
    let fake = f.script(
        "gpg-forge",
        &format!(
            "case \" $* \" in *\" --encrypt \"*) exec '{}' \"$@\" --recipient {};; esac\nexec '{}' \"$@\"",
            f.gpg.display(),
            b.fpr,
            f.gpg.display()
        ),
    );
    f.write_config_with(&fake, "");
    let out = f.store_value("m", b"v");
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("check of the new copy"),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&out).contains(&b.enc_ids[0]), "{}", stderr(&out));
    let before = std::fs::read(f.entry("n")).unwrap();
    let out = f.run(["store", "n", "--replace"], Some(b"new"));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(std::fs::read(f.entry("n")).unwrap(), before);
    assert_eq!(f.names(), ["n"]);
    assert_eq!(temp_files(&f.store_dir), Vec::<PathBuf>::new());
}

/// Leftover temp copies in `dir`.
fn temp_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .contains(".secrit-")
        })
        .collect()
}

/// T35: `encrypt-to` in the user's `gpg.conf` adds no recipient, and a
/// write to a passphrase key needs no pinentry.
#[test]
fn gpg_conf_and_passphrase_keys_change_no_write() {
    let f = PassFixture::new();
    let b = f.gen_key("b@secrit.test", Some("test-passphrase"));
    std::fs::write(
        f.gnupg_home.join("gpg.conf"),
        format!("encrypt-to {}\nhidden-encrypt-to {}\n", b.fpr, b.fpr),
    )
    .unwrap();
    let out = f.store_value("n", b"v");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(f.packet_ids(&f.entry("n")), f.key.enc_ids);

    std::fs::remove_file(f.gnupg_home.join("gpg.conf")).unwrap();
    let marker = f.root.path().join("pinentry-ran");
    f.marker_pinentry(&marker);
    std::fs::write(f.store_dir.join(".gpg-id"), format!("{}\n", b.email)).unwrap();
    let out = f.store_value("p", b"v");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(f.packet_ids(&f.entry("p")), b.enc_ids);
    assert!(!marker.exists(), "a write started a pinentry");
}

/// T36: secrit never commits. In a git repository, `store` and `rm` print
/// the git commands, and `git status` shows the change uncommitted.
#[test]
fn writes_are_never_committed() {
    let f = PassFixture::new();
    let git = git();
    let st = Command::new(&git)
        .env_clear()
        .args(["init", "-q"])
        .arg(&f.store_dir)
        .status()
        .unwrap();
    assert!(st.success());
    let status = || {
        let out = Command::new(&git)
            .env_clear()
            .env("HOME", &f.home)
            .arg("-C")
            .arg(&f.store_dir)
            .args(["status", "--porcelain", "--untracked-files=all"])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let out = f.store_value("n", b"v");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("secrit never commits"), "{err}");
    assert!(err.contains("git -C "), "{err}");
    assert!(err.contains(" add -A -- n.gpg && git -C "), "{err}");
    assert!(err.contains(" commit -m "), "{err}");
    assert!(status().contains("?? n.gpg"), "{}", status());

    let log = Command::new(&git)
        .env_clear()
        .arg("-C")
        .arg(&f.store_dir)
        .args(["rev-parse", "--verify", "-q", "HEAD"])
        .output()
        .unwrap();
    assert!(!log.status.success(), "a commit exists");

    let out = f.run(["rm", "n", "--yes"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("secrit never commits"),
        "{}",
        stderr(&out)
    );
    assert!(!status().contains("n.gpg"), "{}", status());
}

/// T37: with a passphrase key and nothing cached, `get` fails at once with
/// the caching hint, and no pinentry starts.
#[test]
fn a_needed_passphrase_fails_fast_without_a_pinentry() {
    let f = PassFixture::new();
    let b = f.gen_key("b@secrit.test", Some("test-passphrase"));
    f.write_entry_with_gpg("n", &b, b"pinentry-canary-1e4f\n");
    let marker = f.root.path().join("pinentry-ran");
    f.marker_pinentry(&marker);
    for extra in ["", "pinentry = \"agent\"\n"] {
        f.write_config(extra);
        let started = Instant::now();
        let (out, got) = get_to_file(&f, false, "n");
        let text = String::from_utf8_lossy(&out.stdout);
        if extra.is_empty() {
            assert_eq!(code(&out), 1, "{text}");
            assert!(text.contains("needs the passphrase"), "{text}");
            assert!(text.contains("pinentry = \"agent\""), "{text}");
            assert!(started.elapsed() < Duration::from_secs(5));
            assert!(!marker.exists(), "a pinentry started");
        } else {
            // The agent runs the marker pinentry, which gives no
            // passphrase, so the read still fails.
            assert_eq!(code(&out), 1, "{text}");
            assert!(marker.exists(), "pinentry = agent did not use the agent");
        }
        assert!(got.is_empty());
        assert!(!text.contains("pinentry-canary-1e4f"));
    }
}

/// A `.gpg-id.sig` (pass signing) refuses every write; reads still work.
#[test]
fn a_gpg_id_signature_refuses_writes() {
    let f = PassFixture::new();
    assert_eq!(code(&f.store_value("n", b"v")), 0);
    std::fs::write(f.store_dir.join(".gpg-id.sig"), b"sig").unwrap();
    let out = f.store_value("m", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains(".gpg-id.sig"), "{}", stderr(&out));
    let out = f.run(["store", "n", "--replace"], Some(b"w"));
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    let out = f.run(["rm", "n", "--yes"], None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert_eq!(f.names(), ["n"]);
    assert!(get(&f, "n") == b"v", "read with a signature differs");
}

/// A store with no `.gpg-id`, and a `.gpg-id` that names no key, fail
/// before any value is read.
#[test]
fn recipients_must_resolve_before_the_value() {
    let f = PassFixture::new();
    std::fs::write(f.store_dir.join(".gpg-id"), "nobody@secrit.test\n").unwrap();
    let out = f.store_value("n", b"v");
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("nobody@secrit.test"),
        "{}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("not in the keyring"),
        "{}",
        stderr(&out)
    );
    std::fs::remove_file(f.store_dir.join(".gpg-id")).unwrap();
    let out = f.store_value("n", b"v");
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("no .gpg-id"), "{}", stderr(&out));
    assert_eq!(f.names(), Vec::<String>::new());
}

/// A gpg wrapper that logs each run as one line of its arguments.
fn gpg_run_log(f: &PassFixture, log: &Path) {
    let wrapper = f.script(
        "gpg-runs",
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"",
            log.display(),
            f.gpg.display()
        ),
    );
    f.write_config_with(&wrapper, "");
}

/// The number of `gpg --list-keys` runs in the log, and then a clear log.
fn list_key_runs(log: &Path) -> usize {
    let n = std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("--list-keys"))
        .count();
    let _ = std::fs::remove_file(log);
    n
}

/// One `store` resolves each `.gpg-id` recipient once: the check before
/// the value and the write share one `gpg --list-keys` run.
#[test]
fn a_write_resolves_each_recipient_once() {
    let f = PassFixture::new();
    let log = f.root.path().join("gpg-runs.log");
    gpg_run_log(&f, &log);
    let out = f.store_value("n", b"v");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(list_key_runs(&log), 1, "store n");
    let out = f.run(["store", "n", "--replace"], Some(b"w"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(list_key_runs(&log), 1, "store n --replace");
    assert!(get(&f, "n") == b"w", "replaced value differs");
}

/// A `.gpg-id` that changes while `store` waits for the value is read
/// again, and the write goes to the keys that it names now.
#[test]
fn a_gpg_id_change_during_the_prompt_is_resolved_again() {
    let f = PassFixture::new();
    let b = f.gen_key("b@secrit.test", None);
    let log = f.root.path().join("gpg-runs.log");
    gpg_run_log(&f, &log);
    let mut cmd = f.cmd();
    cmd.args(["store", "n"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !std::fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("--list-keys")
    {
        assert!(Instant::now() < deadline, "no recipient check ran");
        std::thread::sleep(Duration::from_millis(20));
    }
    std::fs::write(f.store_dir.join(".gpg-id"), format!("{}\n", b.fpr)).unwrap();
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(b"v").unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(list_key_runs(&log), 2);
    assert_eq!(f.packet_ids(&f.entry("n")), b.enc_ids);
}

/// gpg runs with a cleared environment: `GNUPGHOME` only, no `HOME` and
/// no `GPG_TTY`.
#[test]
fn gpg_gets_gnupghome_only() {
    let f = PassFixture::new();
    let log = f.root.path().join("env.log");
    let wrapper = f.script(
        "gpg-env",
        &format!(
            "'{}' >> '{}'\nexec '{}' \"$@\"",
            bin("env").display(),
            log.display(),
            f.gpg.display()
        ),
    );
    f.write_config_with(&wrapper, "");
    let mut cmd = f.cmd();
    cmd.env("GPG_TTY", "/dev/pts/99");
    let out = run_cmd(cmd, ["store", "n"], Some(b"v"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let logged = std::fs::read_to_string(&log).unwrap();
    let names: std::collections::BTreeSet<&str> = logged
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k))
        .collect();
    // sh adds PWD (and SHLVL); secrit passes GNUPGHOME only.
    for name in &names {
        assert!(
            ["GNUPGHOME", "PWD", "SHLVL", "OLDPWD", "_"].contains(name),
            "gpg got {name}: {logged}"
        );
    }
    assert!(names.contains("GNUPGHOME"), "{logged}");
    let home = format!("GNUPGHOME={}", f.gnupg_home.display());
    assert!(logged.lines().any(|l| l == home), "{logged}");
}

/// `doctor` has the pass rows, and a store with a signature warns.
#[test]
fn doctor_reports_the_pass_store() {
    let f = PassFixture::new();
    assert_eq!(code(&f.store_value("n", b"v")), 0);
    let out = f.run(["doctor"], None);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(code(&out), 0, "{text}{}", stderr(&out));
    for row in [
        "ok    gpg: ",
        "ok    gpg version: ",
        "ok    store main: directory: ",
        "ok    store main: GNUPGHOME: ",
        "ok    store main: .gpg-id: ",
        "ok    store main: recipients: ",
        "info  store main: git: ",
    ] {
        assert!(text.contains(row), "no row {row:?}: {text}");
    }
    assert!(!text.contains("sops"), "{text}");

    std::fs::write(f.store_dir.join(".gpg-id.sig"), b"sig").unwrap();
    std::fs::write(f.store_dir.join(".gpg-id"), "nobody@secrit.test\n").unwrap();
    let out = f.run(["doctor"], None);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(code(&out), 1, "{text}");
    assert!(text.contains("warn  store main: .gpg-id.sig: "), "{text}");
    assert!(text.contains("fail  store main: recipients: "), "{text}");
}

/// `init --backend pass` checks the store and its recipients. With a config
/// that has no such store, it prints the section and leaves the config as
/// it is; a directory with no `.gpg-id` fails with the `pass init` hint.
#[test]
fn init_checks_a_pass_store_and_prints_its_section() {
    let f = PassFixture::new();
    // The printed section names no gnupg_home, so secrit takes $GNUPGHOME.
    let run = |args: &[&str], stdin: Option<&[u8]>| {
        let mut c = f.cmd();
        c.env("GNUPGHOME", &f.gnupg_home);
        run_cmd(c, args, stdin)
    };
    let tools = format!("\n[tools]\ngpg = \"{}\"\n", f.gpg.display());
    std::fs::write(&f.config_file, &tools).unwrap();
    let dir = f.store_dir.to_str().unwrap();
    let out = run(&["init", "--backend", "pass", "--pass-dir", dir], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let printed = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(printed.contains("[stores.main]"), "{printed}");
    assert!(printed.contains("backend = \"pass\""), "{printed}");
    assert!(printed.contains(&format!("dir = \"{dir}\"")), "{printed}");
    assert!(
        stderr(&out).contains("recipients: a@secrit.test"),
        "{}",
        stderr(&out)
    );
    assert_eq!(std::fs::read_to_string(&f.config_file).unwrap(), tools);

    // The printed section works as the config.
    std::fs::write(
        &f.config_file,
        format!("default_store = \"main\"\n\n{printed}{tools}"),
    )
    .unwrap();
    let out = run(&["store", "n"], Some(b"v"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = run(&["ls"], None);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "n\n");
    let out = run(&["init", "--backend", "pass"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    // A directory with no .gpg-id is not set up.
    let empty = f.root.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let out = run(
        &[
            "init",
            "--backend",
            "pass",
            "--store",
            "other",
            "--pass-dir",
            empty.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("pass init"), "{}", stderr(&out));
}
