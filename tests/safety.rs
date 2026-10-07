//! Integration tests for the safety rules: bounded sops runs, key isolation,
//! file trust, exit codes and process hardening. Threat ids refer to PLAN 13;
//! finding ids (R1, SEC-4, ...) to the review of 2026-10-07.

mod common;

use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use common::{TestEnv, bin, code, stderr};

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn signal(child: &Child, sig: &str) {
    let st = std::process::Command::new(bin("kill"))
        .args(["-s", sig, &child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
}

/// Spawn `secrit store NAME` with an open stdin pipe that stays empty.
fn spawn_store(cmd: &mut std::process::Command, name: &str) -> Child {
    cmd.args(["store", name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// R2, T19: sops never sees the real HOME, so `~/.ssh/id_ed25519` is not
/// used as an identity. The store is encrypted only to that SSH key; the
/// real sops with HOME set can use it, secrit cannot.
#[test]
fn ssh_key_in_home_is_not_used() {
    let env = TestEnv::new();
    let ssh = env.home.join(".ssh").join("id_ed25519");
    let public = env.ssh_key(&ssh, None);
    std::fs::remove_file(&env.store_file).unwrap();
    env.create_store_with(&env.store_file, &["--age", &public], b"{}\n");

    // Control: with HOME, sops finds the SSH key and can decrypt.
    let mut control = env.sops_cmd();
    control.env_remove("SOPS_AGE_KEY_FILE");
    let st = control
        .args(["decrypt", "--input-type", "yaml", "--output-type", "json"])
        .arg(&env.store_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "control decrypt with HOME failed");

    let out = env.store_value("viassh", b"v");
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("sops set failed"), "{}", stderr(&out));
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// SEC-16, T19: the harness's passphrase-protected decoy key does not make
/// sops prompt, even with a terminal.
#[test]
fn decoy_ssh_key_does_not_prompt() {
    let env = TestEnv::new();
    assert!(env.home.join(".ssh").join("id_ed25519").is_file());
    let inner = format!("printf v | '{}' store n", common::BIN);
    let started = Instant::now();
    let out = env.under_script(&inner);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    assert!(started.elapsed() < Duration::from_secs(20));
    env.assert_value("n", "v");
}

/// R1, SEC-6: a sops that reads the terminal (a passphrase prompt) stops in
/// its background group. secrit ends it and fails fast instead of hanging.
#[test]
fn sops_reading_the_terminal_fails_fast() {
    let env = TestEnv::new();
    let fake = env.fake_sops(
        "sops-prompt",
        &format!(
            "printf 'Enter passphrase: ' >/dev/tty\nread x </dev/tty\nexec '{}' \"$@\"",
            env.sops.display()
        ),
    );
    env.write_config_with(&fake, "");
    let before = env.store_bytes();
    let inner = format!("printf v | '{}' store n", common::BIN);
    let started = Instant::now();
    let out = env.under_script(&inner);
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(code(&out), 1, "{text}");
    assert!(text.contains("stopped to ask for input"), "{text}");
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(env.store_bytes(), before);
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
}

/// R1: TERM while sops runs ends sops and secrit (exit 130), and removes the
/// temp copy.
#[test]
fn a_signal_ends_a_running_sops() {
    let env = TestEnv::new();
    let pid_file = env.root.path().join("sops.pid");
    let fake = env.fake_sops(
        "sops-hang",
        &format!(
            "echo $$ > '{}'\nexec '{}' 30",
            pid_file.display(),
            bin("sleep").display()
        ),
    );
    env.write_config_with(&fake, "");
    let mut child = spawn_store(&mut env.cmd(), "n");
    child.stdin.take().unwrap().write_all(b"v").unwrap();
    wait_for("the fake sops to start", || {
        std::fs::read_to_string(&pid_file).is_ok_and(|s| s.ends_with('\n'))
    });
    let sops_pid = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .to_owned();
    let started = Instant::now();
    signal(&child, "TERM");
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 130, "{}", stderr(&out));
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(
        !Path::new(&format!("/proc/{sops_pid}")).exists(),
        "sops outlived secrit"
    );
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
}

/// R1: a sops run that never ends is stopped at the deadline.
#[cfg(feature = "test-hooks")]
#[test]
fn a_hung_sops_times_out() {
    let env = TestEnv::new();
    let fake = env.fake_sops(
        "sops-hang",
        &format!("exec '{}' 30", bin("sleep").display()),
    );
    env.write_config_with(&fake, "");
    let mut cmd = env.cmd();
    cmd.env("SECRIT_TEST_CHILD_TIMEOUT_MS", "500");
    let out = common::run_cmd(cmd, ["store", "n"], Some(b"v"));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("did not finish within 500 ms"));
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
}

/// R4 (2): exit 4 when the lock is held past the timeout, and a signal
/// while waiting for the lock exits 130.
#[cfg(feature = "test-hooks")]
#[test]
fn lock_timeout_exits_4_and_a_signal_stops_the_wait() {
    let env = TestEnv::new();
    env.write_config_full(&env.sops, "", 1);
    let mut holder = env.cmd();
    holder
        .env("SECRIT_TEST_HOOK", "after-copy=pause")
        .env("SECRIT_TEST_HOOK_DIR", env.hook_dir());
    let mut holder = spawn_store(&mut holder, "first");
    holder.stdin.take().unwrap().write_all(b"v").unwrap();
    env.wait_for_hook(1);

    let out = env.store_value("second", b"v");
    assert_eq!(code(&out), 4, "{}", stderr(&out));
    assert!(stderr(&out).contains("timed out"));

    env.write_config_full(&env.sops, "", 120);
    let mut waiter = spawn_store(&mut env.cmd(), "third");
    waiter.stdin.take().unwrap().write_all(b"v").unwrap();
    std::thread::sleep(Duration::from_millis(500));
    signal(&waiter, "TERM");
    let out = waiter.wait_with_output().unwrap();
    assert_eq!(code(&out), 130, "{}", stderr(&out));

    std::fs::write(env.hook_dir().join("go"), b"").unwrap();
    let out = holder.wait_with_output().unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(env.ls(), ["first"]);
}

/// R4 (2): exit 4 when the file changes under secrit on every attempt.
#[test]
fn a_file_that_keeps_changing_exits_4() {
    let env = TestEnv::new();
    let real = env.sops.display().to_string();
    let fake = env.fake_sops(
        "sops-meddle",
        &format!(
            "if [ \"$3\" = set ]; then printf '\"%s\"' $$ | '{real}' --config '{cfg}' set --value-stdin '{store}' '[\"raw\"]'; fi\nexec '{real}' \"$@\"",
            cfg = env.sops_config.display(),
            store = env.store_file.display(),
        ),
    );
    env.write_config_with(&fake, "");
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 4, "{}", stderr(&out));
    assert!(stderr(&out).contains("changed while secrit was writing it"));
    assert_eq!(env.ls(), ["raw"]);
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
}

/// R4 (1): the suffix rules in the file's sops metadata.
#[test]
fn suffix_rules_from_the_file_are_enforced() {
    for (rule, refused, accepted) in [
        ("unencrypted_suffix: _pub", "x_pub", "x"),
        ("encrypted_suffix: _secret", "plain", "x_secret"),
    ] {
        let env = TestEnv::new();
        std::fs::write(
            &env.sops_config,
            format!(
                "creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    {rule}\n    age: {}\n",
                env.recipients.join(",")
            ),
        )
        .unwrap();
        std::fs::remove_file(&env.store_file).unwrap();
        env.create_store(&env.store_file);
        let out = env.store_value(refused, b"v");
        assert_eq!(code(&out), 3, "{rule}: {}", stderr(&out));
        let out = env.store_value(accepted, b"v");
        assert_eq!(code(&out), 0, "{rule}: {}", stderr(&out));
        env.assert_value(accepted, "v");
    }
}

/// SEC-4, R4 (7): a store directory that group or others can write is
/// refused, unless it is sticky.
#[test]
fn shared_store_directories_are_refused() {
    let env = TestEnv::new();
    for mode in [0o775, 0o757] {
        chmod(&env.store_dir, mode);
        let out = env.store_value("n", b"v");
        assert_eq!(code(&out), 3, "mode {mode:o}: {}", stderr(&out));
        assert!(stderr(&out).contains("writable by group or others"));
    }
    chmod(&env.store_dir, 0o1777);
    assert_eq!(code(&env.store_value("n", b"v")), 0);
    chmod(&env.store_dir, 0o755);
}

/// SEC-12: a `.sops.yaml` that others can write is refused (exit 3).
#[test]
fn shared_sops_config_is_refused() {
    let env = TestEnv::new();
    chmod(&env.sops_config, 0o666);
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains(".sops.yaml"));
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// SEC-10: a config from `SECRIT_CONFIG` is named on stderr, and a configured
/// sops that others can write is refused.
#[test]
fn config_source_is_shown_and_tools_are_checked() {
    let env = TestEnv::new();
    let out = env.run(["ls"], None);
    assert!(stderr(&out).contains(&format!(
        "using config {} from SECRIT_CONFIG",
        env.config_file.display()
    )));
    let out = env.run(["ls", "-q"], None);
    assert!(!stderr(&out).contains("using config"));

    let shared = env.fake_sops("sops-shared", "exit 1");
    chmod(&shared, 0o777);
    env.write_config_with(&shared, "");
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("writable by group or others"));
}

/// PF-4: a sops older than 3.11 is refused before it runs.
#[test]
fn old_sops_is_refused() {
    let env = TestEnv::new();
    let old = env.script(
        "sops-old",
        "for a in \"$@\"; do [ \"$a\" = --version ] && { echo 'sops 3.10.0'; exit 0; }; done\nexit 1",
    );
    env.write_config_with(&old, "");
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("is sops 3.10.0; secrit needs sops 3.11"));
}

/// R5: `ls` escapes control characters in key names that another tool wrote.
#[test]
fn ls_escapes_control_characters() {
    let env = TestEnv::new();
    std::fs::remove_file(&env.store_file).unwrap();
    env.create_store_with(
        &env.store_file,
        &[],
        "{\"\\u001b]0;pwned\\u0007\\u001b[2Jx\": \"v\"}\n".as_bytes(),
    );
    let out = env.run(["ls"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(!out.stdout.contains(&0x1b) && !out.stdout.contains(&0x07));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap().trim(),
        "\\x1b]0;pwned\\x07\\x1b[2Jx"
    );
    let json = env.run(["ls", "--json"], None);
    assert!(String::from_utf8(json.stdout).unwrap().contains("\\u001b"));
}

/// R6: the name rules come before the config, so a bad name exits 3 even
/// with no config.
#[test]
fn bad_names_exit_3_without_a_config() {
    let env = TestEnv::new();
    std::fs::remove_file(&env.config_file).unwrap();
    for args in [
        &["store", "a b"][..],
        &["get", "a b", "--stdout"],
        &["rm", "a b"],
    ] {
        let out = env.run(args, Some(b"v"));
        assert_eq!(code(&out), 3, "{args:?}: {}", stderr(&out));
    }
}

/// UX-4: a missing store file says how to go on.
#[test]
fn missing_store_file_says_create_it() {
    let env = TestEnv::new();
    std::fs::remove_file(&env.store_file).unwrap();
    let out = env.run(["ls"], None);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("create it first"), "{}", stderr(&out));
}

/// SEC-2: only the newest backups are kept.
#[test]
fn old_backups_are_pruned() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"v0")), 0);
    for i in 1..=12 {
        let out = env.run(
            ["store", "n", "--replace"],
            Some(format!("v{i}").as_bytes()),
        );
        assert_eq!(code(&out), 0, "{}", stderr(&out));
    }
    assert_eq!(env.backups().len(), 10);
}

/// T6: the real binary hardens itself before it reads input: umask 077, no
/// core dumps, not dumpable. TERM during the stdin wait exits 130.
#[test]
fn the_binary_hardens_itself() {
    let env = TestEnv::new();
    let child = spawn_store(&mut env.cmd(), "n");
    let proc_dir = format!("/proc/{}", child.id());
    wait_for("the umask", || {
        std::fs::read_to_string(format!("{proc_dir}/status"))
            .is_ok_and(|s| s.contains("Umask:\t0077"))
    });
    // Give secrit time to reach the stdin wait.
    std::thread::sleep(Duration::from_millis(300));
    let limits = std::fs::read_to_string(format!("{proc_dir}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap();
    let words: Vec<&str> = core.split_whitespace().collect();
    assert_eq!(words[4..6], ["0", "0"], "{core}");
    let environ = std::fs::metadata(format!("{proc_dir}/environ")).unwrap();
    assert_eq!(environ.uid(), 0, "a dumpable process owns its environ");
    signal(&child, "TERM");
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 130, "{}", stderr(&out));
    assert_eq!(env.ls(), Vec::<String>::new());
}
