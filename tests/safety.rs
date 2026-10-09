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
    // PLAN 14: the error names the step, the name and the file.
    assert!(
        stderr(&out).contains(&format!(
            "sops set for 'n' in {} did not finish within 500 ms",
            env.store_file.display()
        )),
        "{}",
        stderr(&out)
    );
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
}

/// C-1 (PLAN 14): a failed sops run names the step, the name and the file.
#[test]
fn a_failed_sops_names_the_step_name_and_file() {
    let env = TestEnv::new();
    let fake = env.fake_sops(
        "sops-fail-set",
        &format!(
            "if [ \"$3\" = set ]; then echo 'sops: it broke' >&2; exit 1; fi\nexec '{}' \"$@\"",
            env.sops.display()
        ),
    );
    env.write_config_with(&fake, "");
    let before = env.store_bytes();
    let out = env.store_value("tok", b"hunter2-value");
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(
        err.contains(&format!(
            "sops set failed for 'tok' in {} (exit 1)",
            env.store_file.display()
        )),
        "{err}"
    );
    assert!(err.contains("sops: it broke"), "{err}");
    common::assert_absent(&out, "hunter2-value");
    assert_eq!(env.store_bytes(), before);
}

/// Wait for `child` at most 20 s; kill it and fail when it takes longer.
fn wait_bounded(mut child: Child) -> std::process::Output {
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("secrit waited for a value it should have refused first");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

/// A-1 (PLAN 4.1, step 1): the file's own rules refuse a name before secrit
/// reads the value. stdin stays open and empty, so a read would block.
#[test]
fn file_rules_refuse_before_the_value_is_read() {
    for (rule, name, said) in [
        ("unencrypted_regex: ^pub", "anything", "unencrypted_regex"),
        ("unencrypted_suffix: _pub", "x_pub", "_pub"),
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
        let before = env.store_bytes();
        let mut child = spawn_store(&mut env.cmd(), name);
        let held = child.stdin.take();
        let out = wait_bounded(child);
        drop(held);
        assert_eq!(code(&out), 3, "{rule}: {}", stderr(&out));
        assert!(stderr(&out).contains(said), "{rule}: {}", stderr(&out));
        assert_eq!(env.store_bytes(), before);
    }
}

/// A sops file at `path` with the JSON `content`, written by the real sops
/// in the `output` format. The `.sops.yaml` rule must cover `path`.
fn sops_file(env: &TestEnv, path: &Path, output: &str, content: &[u8]) {
    let mut child = env
        .sops_cmd()
        .args(["encrypt", "--input-type", "json", "--output-type", output])
        .arg("--filename-override")
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
    chmod(path, 0o600);
}

/// v0.2 V14: v0.1 writes YAML only, so `store` and `rm` on a store that is
/// not YAML (by its content or by its name) exit 3 and leave the file
/// byte-identical. `ls` still reads it.
#[test]
fn a_store_that_is_not_yaml_is_refused_and_unchanged() {
    for (file, output, said) in [
        ("main.json", "json", "a .json file"),
        ("main.yaml", "json", "a sops JSON file"),
        ("main.json", "yaml", "a .json file"),
    ] {
        let mut env = TestEnv::new();
        std::fs::write(
            &env.sops_config,
            format!(
                "creation_rules:\n  - path_regex: secrets/main\\.(yaml|json)$\n    age: {}\n",
                env.recipients.join(",")
            ),
        )
        .unwrap();
        env.store_file = env.store_dir.join(file);
        sops_file(&env, &env.store_file, output, br#"{"old": "v"}"#);
        env.write_config("");
        let before = env.store_bytes();
        let case = format!("{file} as {output}");

        let out = env.store_value("new", b"v");
        assert_eq!(code(&out), 3, "{case}: {}", stderr(&out));
        assert!(stderr(&out).contains(said), "{case}: {}", stderr(&out));
        let out = env.run(["rm", "--yes", "old"], None);
        assert_eq!(code(&out), 3, "{case}: {}", stderr(&out));
        assert_eq!(env.store_bytes(), before, "{case}");
        assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
        assert_eq!(env.ls(), ["old"], "{case}");
    }
}

/// sops never encrypts an empty string: `sops encrypt` keeps `a: ""` in
/// clear. Such an entry holds no secret, so `store` and `rm` accept the
/// file, the copy validation and the readback pass, and the entry stays.
#[test]
fn an_empty_value_from_sops_does_not_block_a_write() {
    let env = TestEnv::new();
    env.create_store_with(&env.store_file, &[], br#"{"a": "", "b": "x"}"#);
    let text = String::from_utf8(env.store_bytes()).unwrap();
    assert!(text.contains("a: \"\""), "sops encrypted the empty value");
    assert!(!text.contains("b: x"), "sops did not encrypt b");

    let out = env.store_value("c", b"new value");
    assert_eq!(code(&out), 0, "store: {}", stderr(&out));
    env.assert_value("c", "new value");
    let out = env.run(["rm", "--yes", "b"], None);
    assert_eq!(code(&out), 0, "rm: {}", stderr(&out));

    let all = env.decrypt();
    assert_eq!(
        all.get("a"),
        Some(&serde_json::Value::String(String::new()))
    );
    assert!(!all.contains_key("b"));
    assert_eq!(env.ls(), ["a", "c"]);
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
}

/// A-5 (PLAN 8.1, step 4): the store directory is checked again after the
/// lock is taken, so a chmod while secrit waited for the lock is seen.
#[cfg(feature = "test-hooks")]
#[test]
fn a_directory_made_shared_during_the_lock_wait_is_refused() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("a", b"v")), 0);
    let before = env.store_bytes();
    let mut cmd = env.cmd();
    cmd.env("SECRIT_TEST_HOOK", "after-lock=pause")
        .env("SECRIT_TEST_HOOK_DIR", env.hook_dir());
    let mut child = spawn_store(&mut cmd, "b");
    child.stdin.take().unwrap().write_all(b"v").unwrap();
    env.wait_for_hook(1);
    chmod(&env.store_dir, 0o775);
    std::fs::write(env.hook_dir().join("go"), b"").unwrap();
    let out = child.wait_with_output().unwrap();
    chmod(&env.store_dir, 0o755);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("writable by group or others"),
        "{}",
        stderr(&out)
    );
    assert_eq!(env.store_bytes(), before);
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

/// R4 (2), A-4: exit 4 when the file changes under secrit on every attempt:
/// the first try and 3 retries, so 4 `sops set` runs (PLAN 8.1, step 11).
#[test]
fn a_file_that_keeps_changing_exits_4() {
    let env = TestEnv::new();
    let real = env.sops.display().to_string();
    let count = env.root.path().join("set-count");
    let fake = env.fake_sops(
        "sops-meddle",
        &format!(
            "if [ \"$3\" = set ]; then echo x >> '{count}'; printf '\"%s\"' $$ | '{real}' --config '{cfg}' set --value-stdin '{store}' '[\"raw\"]'; fi\nexec '{real}' \"$@\"",
            count = count.display(),
            cfg = env.sops_config.display(),
            store = env.store_file.display(),
        ),
    );
    env.write_config_with(&fake, "");
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 4, "{}", stderr(&out));
    assert!(stderr(&out).contains("changed while secrit was writing it"));
    assert!(stderr(&out).contains("on 3 retries"), "{}", stderr(&out));
    assert_eq!(std::fs::read_to_string(&count).unwrap().lines().count(), 4);
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

    // B-2: init and doctor name the file too, and -q hides it.
    let line = format!(
        "secrit: using config {} from SECRIT_CONFIG\n",
        env.config_file.display()
    );
    for args in [&["init", "--dry-run"][..], &["doctor"][..]] {
        let out = env.run(args, None);
        assert_eq!(code(&out), 0, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).starts_with(&line),
            "{args:?}: {}",
            stderr(&out)
        );
        let quiet = env.run(args.iter().chain(&["-q"]), None);
        assert_eq!(code(&quiet), 0, "{args:?}: {}", stderr(&quiet));
        assert!(!stderr(&quiet).contains("using config"), "{args:?}");
    }

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
    // A process that is not dumpable has its /proc files owned by root. In a
    // user namespace (the Nix sandbox) root shows as the overflow uid, so the
    // test checks only that the owner is not this user. Run as root (a
    // container CI job, act), the owner is root either way, so the check
    // cannot tell and is skipped.
    let me = std::fs::metadata("/proc/self").unwrap().uid();
    let environ = std::fs::metadata(format!("{proc_dir}/environ")).unwrap();
    if me == 0 {
        eprintln!("running as root: the not-dumpable check cannot tell, skipped");
    } else {
        assert_ne!(environ.uid(), me, "a dumpable process owns its environ");
    }
    signal(&child, "TERM");
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 130, "{}", stderr(&out));
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// REG-1: outside a critical section a signal keeps its default action. `ls`
/// blocked on a full pipe that nobody reads ends at TERM.
#[test]
fn term_ends_a_write_to_a_stalled_pipe() {
    use std::os::unix::process::ExitStatusExt;

    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"v")), 0);
    let (reader, mut writer) = std::io::pipe().unwrap();
    rustix::fs::fcntl_setfl(&writer, rustix::fs::OFlags::NONBLOCK).unwrap();
    let page = [0u8; 4096];
    loop {
        match writer.write(&page) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("filling the pipe: {e}"),
        }
    }
    rustix::fs::fcntl_setfl(&writer, rustix::fs::OFlags::empty()).unwrap();
    let mut child = env
        .cmd()
        .arg("ls")
        .stdout(Stdio::from(writer))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // secrit is not dumpable, so /proc/<pid>/wchan reads "0". A full pipe
    // is the only thing `ls` can still wait on after this long.
    std::thread::sleep(Duration::from_millis(500));
    assert!(child.try_wait().unwrap().is_none(), "ls did not block");
    signal(&child, "TERM");
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("TERM did not end secrit blocked on a stalled pipe");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(reader);
    assert_eq!(status.signal(), Some(15), "{status:?}");
}
