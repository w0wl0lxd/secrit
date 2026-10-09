//! Integration tests: the real secrit binary, the real sops and age-keygen,
//! a temp directory only (PLAN section 15.3). Threat ids refer to PLAN 13.

mod common;

use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

use common::{TestEnv, assert_absent, code, run_cmd, stderr};

#[test]
fn store_ls_rm_round_trip() {
    let env = TestEnv::new();
    assert_eq!(env.ls(), Vec::<String>::new());

    let out = env.store_value("b.key", b"value-b\n");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("stored b.key in main"));
    let out = env.store_value("a-key_1", b"value-a");
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    assert_eq!(env.ls(), ["a-key_1", "b.key"]);
    env.assert_value("a-key_1", "value-a");
    env.assert_value("b.key", "value-b");

    let json = env.run(["ls", "--json"], None);
    assert_eq!(
        String::from_utf8(json.stdout).unwrap().trim(),
        r#"["a-key_1","b.key"]"#
    );

    let out = env.run(["rm", "a-key_1", "--yes"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("removed a-key_1"));
    assert_eq!(env.ls(), ["b.key"]);
    let backups = env.backups();
    assert_eq!(backups.len(), 1);
    assert_eq!(
        std::fs::metadata(&backups[0]).unwrap().mode() & 0o777,
        0o600
    );
    // SEC-2: backups live in a private directory outside the store's tree.
    assert!(!backups[0].starts_with(&env.store_dir));
    let dir = backups[0].parent().unwrap();
    assert_eq!(std::fs::metadata(dir).unwrap().mode() & 0o777, 0o700);
    assert!(stderr(&out).contains(&dir.display().to_string()));
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
}

/// G4: `ls` decrypts nothing, so it works with no key at all.
#[test]
fn ls_works_without_any_key() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"v")), 0);
    std::fs::remove_file(&env.key_file).unwrap();
    assert_eq!(env.ls(), ["n"]);
}

#[test]
fn rm_of_a_missing_name_fails_and_needs_yes_without_tty() {
    let env = TestEnv::new();
    let out = env.run(["rm", "nope", "--yes"], None);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("does not exist"));

    assert_eq!(code(&env.store_value("n", b"v")), 0);
    let out = env.run(["rm", "n"], None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert_eq!(env.ls(), ["n"]);
}

/// T12: no silent overwrite; `--replace` keeps a 0600 ciphertext backup.
#[test]
fn replace_is_required_and_keeps_a_backup() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"old")), 0);
    let before = env.store_bytes();

    let out = env.store_value("n", b"new");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("already exists"));
    assert_eq!(env.store_bytes(), before);
    env.assert_value("n", "old");

    let out = env.run(["store", "n", "--replace"], Some(b"new"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    env.assert_value("n", "new");
    let backups = env.backups();
    assert_eq!(backups.len(), 1);
    assert_eq!(std::fs::read(&backups[0]).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&backups[0]).unwrap().mode() & 0o777,
        0o600
    );
}

/// T1, T2: values on argv are refused with a fixed message that never
/// repeats them.
#[test]
fn values_on_argv_are_refused_without_echo() {
    let env = TestEnv::new();
    for args in [
        &["store", "N", "hunter2"][..],
        &["store", "N", "--", "hunter2"],
        &["store", "N", "--value=hunter2"],
        &["store", "N", "--value", "hunter2"],
        &["stroe", "hunter2"],
        &["store", "--replace=hunter2", "N"],
    ] {
        let out = env.run(args, Some(b""));
        assert_eq!(code(&out), 2, "args {args:?}");
        assert_absent(&out, "hunter2");
    }
    let out = env.run(["store", "N", "hunter2"], Some(b""));
    assert!(stderr(&out).contains("a value on the command line is already in shell history"));
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// T15 and the name rules: refused with exit 3.
#[test]
fn bad_names_are_refused() {
    let env = TestEnv::new();
    for name in ["a\"][\"b", "sops", "x_unencrypted", ".x", "a b"] {
        let out = env.store_value(name, b"v");
        assert_eq!(code(&out), 3, "name {name:?}: {}", stderr(&out));
    }
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// T16, T17: always a string; one trailing newline stripped unless --raw.
#[test]
fn input_normalisation_reaches_the_file() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("num", b"123\n")), 0);
    env.assert_value("num", "123");
    assert_eq!(code(&env.store_value("crlf", b"v\r\n")), 0);
    env.assert_value("crlf", "v");
    let out = env.run(["store", "raw", "--raw"], Some(b"v\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    env.assert_value("raw", "v\n");
    let out = env.run(["store", "multi", "--multiline"], Some(b"l1\nl2\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    env.assert_value("multi", "l1\nl2");
    let quoted = "q\"uo\\te\t\u{e9}";
    assert_eq!(code(&env.store_value("quoted", quoted.as_bytes())), 0);
    env.assert_value("quoted", quoted);

    let out = env.store_value("nl", b"l1\nl2");
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("--multiline"));
    let out = env.store_value("empty", b"\n");
    assert_eq!(code(&out), 1);
    let out = env.store_value("ctl", b"a\x1bb");
    assert_eq!(code(&out), 1);
    let too_big = vec![b'x'; 64 * 1024 + 1];
    assert_eq!(code(&env.store_value("big", &too_big)), 1);
    assert_eq!(env.ls(), ["crlf", "multi", "num", "quoted", "raw"]);
}

/// T1: the value reaches sops on stdin, never on its argv.
#[test]
fn value_never_reaches_child_argv() {
    let env = TestEnv::new();
    let log = env.root.path().join("argv.log");
    let wrapper = env.script(
        "sops-wrapper",
        &format!(
            "for a in \"$@\"; do printf '%s\\n' \"$a\" >> '{}'; done\nexec '{}' \"$@\"",
            log.display(),
            env.sops.display()
        ),
    );
    env.write_config_with(&wrapper, "");
    let out = env.store_value("n", b"argv-canary-91f3");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    env.assert_value("n", "argv-canary-91f3");
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(logged.contains("set") && logged.contains("--value-stdin"));
    assert!(
        !logged.contains("argv-canary-91f3"),
        "the value reached a child argv"
    );
}

/// T8, T20: a failing sops that echoes its stdin to stderr leaks nothing and
/// leaves no temp file; the original is untouched.
#[test]
fn sops_failure_is_redacted_and_cleaned_up() {
    let env = TestEnv::new();
    let before = env.store_bytes();
    let fake = env.fake_sops(
        "sops-fail",
        "echo 'sops: a fixed line' >&2\nwhile IFS= read -r l || [ -n \"$l\" ]; do printf 'sops says: %s\\n' \"$l\" >&2; done\nexit 1",
    );
    env.write_config_with(&fake, "");
    let out = env.store_value("n", b"stderr-canary-5c2e");
    assert_eq!(code(&out), 1);
    assert_absent(&out, "stderr-canary-5c2e");
    // SEC-15: the whole line goes, and the rest is kept.
    assert!(!stderr(&out).contains("sops says"), "{}", stderr(&out));
    assert!(stderr(&out).contains("sops: a fixed line"));
    assert!(stderr(&out).contains("1 line(s) not shown"));
    assert_eq!(
        env.temp_files(),
        Vec::<std::path::PathBuf>::new(),
        "a temp copy was left behind"
    );
    assert_eq!(env.store_bytes(), before);
}

/// T11: symlinked and hard-linked store files are refused.
#[test]
fn linked_store_files_are_refused() {
    let env = TestEnv::new();
    let real = env.store_dir.join("real.yaml");
    std::fs::rename(&env.store_file, &real).unwrap();
    std::os::unix::fs::symlink(&real, &env.store_file).unwrap();
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("symlink"));

    std::fs::remove_file(&env.store_file).unwrap();
    std::fs::hard_link(&real, &env.store_file).unwrap();
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("hard link"));
}

#[test]
fn group_writable_store_file_is_refused() {
    let env = TestEnv::new();
    std::fs::set_permissions(&env.store_file, std::fs::Permissions::from_mode(0o620)).unwrap();
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
}

/// T14: a different `.sops.yaml` in the working directory cannot change the
/// recipients, and the file mode is kept.
#[test]
fn recipients_and_mode_survive_a_stray_sops_config() {
    let env = TestEnv::new();
    let want = {
        let mut r = env.recipients.clone();
        r.sort();
        r
    };
    assert_eq!(env.file_recipients(), want);
    std::fs::set_permissions(&env.store_file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let stray = env.root.path().join("stray");
    std::fs::create_dir_all(&stray).unwrap();
    common::write_sops_config(
        &stray.join(".sops.yaml"),
        &["age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq".into()],
    );
    let mut cmd = env.cmd();
    cmd.current_dir(&stray);
    let out = run_cmd(cmd, ["store", "n"], Some(b"v"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(env.file_recipients(), want);
    assert_eq!(
        std::fs::metadata(&env.store_file).unwrap().mode() & 0o777,
        0o640
    );
}

/// T19: key variables in secrit's environment never reach sops. With a key
/// file that is not a recipient, the write must fail even though
/// `SOPS_AGE_KEY` holds a working key.
#[test]
fn key_variables_are_not_passed_to_sops() {
    let env = TestEnv::new();
    let stranger = env.root.path().join("keys").join("stranger.txt");
    let st = Command::new(&env.age_keygen)
        .env_clear()
        .arg("-o")
        .arg(&stranger)
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    let good_key = std::fs::read_to_string(&env.key_file).unwrap();
    let text = std::fs::read_to_string(&env.config_file).unwrap().replace(
        &format!("age_key_file = \"{}\"", env.key_file.display()),
        &format!("age_key_file = \"{}\"", stranger.display()),
    );
    std::fs::write(&env.config_file, text).unwrap();
    let mut cmd = env.cmd();
    cmd.env("SOPS_AGE_KEY", good_key.trim())
        .env("SOPS_AGE_KEY_FILE", &env.key_file);
    let out = run_cmd(cmd, ["store", "n"], Some(b"v"));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(env.ls(), Vec::<String>::new());
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
}

/// T9: 40 parallel writers, no lost update.
#[test]
fn forty_parallel_writers_lose_nothing() {
    let env = TestEnv::new();
    let children: Vec<_> = (0..40)
        .map(|i| {
            let mut c = env.cmd();
            c.args(["store", &format!("k{i:02}")])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let mut child = c.spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("v{i}").as_bytes())
                .unwrap();
            child
        })
        .collect();
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert_eq!(code(&out), 0, "{}", stderr(&out));
    }
    let names = env.ls();
    assert_eq!(names.len(), 40);
    let all = env.decrypt();
    for i in 0..40 {
        let got = all.get(&format!("k{i:02}")).and_then(|v| v.as_str());
        assert!(got == Some(format!("v{i}").as_str()), "k{i:02} is wrong");
    }
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
}

/// T13: a file whose sops rules use a regex is not written in v0.1.
#[test]
fn files_with_regex_rules_are_not_written() {
    let env = TestEnv::new();
    std::fs::write(
        &env.sops_config,
        format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    encrypted_regex: ^data$\n    age: {}\n",
            env.recipients.join(",")
        ),
    )
    .unwrap();
    std::fs::remove_file(&env.store_file).unwrap();
    env.create_store(&env.store_file);
    let before = env.store_bytes();
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("encrypted_regex"));
    assert_eq!(env.store_bytes(), before);
}

#[test]
fn writes_need_xdg_runtime_dir() {
    let env = TestEnv::new();
    let mut cmd = env.cmd();
    cmd.env_remove("XDG_RUNTIME_DIR");
    let out = run_cmd(cmd, ["store", "n"], Some(b"v"));
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("XDG_RUNTIME_DIR"));
}

/// T4: `get` is refused for agents and when there is no terminal.
#[test]
fn get_is_refused_for_agents_and_without_tty() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"get-canary-77aa")), 0);
    let mut cmd = env.cmd();
    cmd.env("CLAUDECODE", "1");
    let out = run_cmd(cmd, ["get", "n", "--stdout"], None);
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("CLAUDECODE"));
    assert_absent(&out, "get-canary-77aa");

    // A new session with no controlling terminal: always "no tty" (R9).
    let mut cmd = common::no_tty(&env.cmd());
    cmd.args(["get", "n", "--stdout"]);
    let out = run_cmd(cmd, std::iter::empty::<&str>(), None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("there is no terminal"));
    assert_absent(&out, "get-canary-77aa");
}

/// `get --stdout` to a pipe returns the exact bytes. `script` gives the child
/// a controlling terminal, so agent detection passes.
#[test]
fn get_stdout_to_a_pipe_returns_exact_bytes() {
    let env = TestEnv::new();
    let out = env.run(["store", "n", "--raw"], Some(b"exact\nbytes\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let dest = env.root.path().join("out.bin");
    let inner = format!(
        "'{}' get n --stdout | '{}' > '{}'",
        common::BIN,
        common::bin("cat").display(),
        dest.display()
    );
    let out = env.under_script(&inner);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        std::fs::read(&dest).unwrap() == b"exact\nbytes\n",
        "get --stdout bytes differ"
    );
}

/// SEC-3: a plain file that group or others can read is refused; a private
/// one is accepted.
#[test]
fn get_stdout_refuses_a_shared_file() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"file-canary-3a1f")), 0);
    let shared = env.root.path().join("shared.out");
    let inner = format!(
        "umask 022; '{}' get n --stdout > '{}'",
        common::BIN,
        shared.display()
    );
    let out = env.under_script(&inner);
    assert_eq!(code(&out), 3, "{}", String::from_utf8_lossy(&out.stdout));
    assert_absent(&out, "file-canary-3a1f");
    assert_eq!(std::fs::read(&shared).unwrap(), b"");

    let private = env.root.path().join("private.out");
    let inner = format!(
        "umask 077; '{}' get n --stdout > '{}'",
        common::BIN,
        private.display()
    );
    let out = env.under_script(&inner);
    assert_eq!(code(&out), 0, "{}", String::from_utf8_lossy(&out.stdout));
    assert!(
        std::fs::read(&private).unwrap() == b"file-canary-3a1f",
        "get --stdout bytes differ"
    );
}

#[test]
fn get_with_tty_refuses_stdout_and_fails_on_missing_names() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"tty-canary-0b1d")), 0);
    let inner = format!("'{}' get nope --stdout > /dev/null", common::BIN);
    let out = env.under_script(&inner);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    // stdout is the terminal here, so --stdout is refused (T3).
    let inner = format!("'{}' get n --stdout", common::BIN);
    let out = env.under_script(&inner);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert_absent(&out, "tty-canary-0b1d");
}

/// PF-1: every command in the help works, and no command says it is
/// unfinished. `run` is listed from v0.2 (S13).
#[test]
fn every_listed_command_exists() {
    let env = TestEnv::new();
    let help = env.run(["--help"], None);
    let text = String::from_utf8_lossy(&help.stdout);
    for cmd in ["store", "get", "ls", "rm", "run", "init", "doctor", "wire"] {
        assert!(text.contains(&format!("  {cmd} ")), "{cmd} missing: {text}");
    }
    assert!(!text.contains("not implemented"), "{text}");
}

#[test]
fn completions_and_help_work_without_config() {
    let env = TestEnv::new();
    std::fs::remove_file(&env.config_file).unwrap();
    for shell in ["bash", "fish", "zsh"] {
        let out = env.run(["completions", shell], None);
        assert_eq!(code(&out), 0);
        assert!(String::from_utf8_lossy(&out.stdout).contains("secrit"));
    }
    let out = env.run(["--help"], None);
    assert_eq!(code(&out), 0);
    let out = env.run(["ls"], None);
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("no config file"));
}

#[test]
fn unsafe_config_is_refused() {
    let env = TestEnv::new();
    std::fs::set_permissions(&env.config_file, std::fs::Permissions::from_mode(0o666)).unwrap();
    let out = env.run(["ls"], None);
    // R3: an unsafe file is a refusal (exit 3), as PLAN section 4 says.
    assert_eq!(code(&out), 3);
    assert!(stderr(&out).contains("writable by group or others"));
}

/// T10: a crash just before the rename leaves the original byte-identical.
#[cfg(feature = "test-hooks")]
#[test]
fn crash_before_rename_leaves_original_intact() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("keep", b"v")), 0);
    let before = env.store_bytes();
    let mut cmd = env.cmd();
    cmd.env("SECRIT_TEST_HOOK", "before-rename=abort");
    let out = run_cmd(cmd, ["store", "n"], Some(b"v2"));
    assert!(!out.status.success());
    assert_eq!(env.store_bytes(), before);
    assert_eq!(env.ls(), ["keep"]);
    // A crash leaves one ciphertext-only temp copy; doctor will report it.
    assert_eq!(env.temp_files().len(), 1);
}

/// A signal during the write cancels it cleanly: exit 130, no temp file.
/// SIGQUIT is deferred too, so Ctrl-\ leaves no temp copy (SEC-14).
#[cfg(feature = "test-hooks")]
#[test]
fn signal_during_write_cancels_cleanly() {
    let env = TestEnv::new();
    let before = env.store_bytes();
    for sig in ["sigint", "sigterm", "sigquit"] {
        let mut cmd = env.cmd();
        cmd.env("SECRIT_TEST_HOOK", format!("after-sops={sig}"));
        let out = run_cmd(cmd, ["store", "n"], Some(b"v"));
        assert_eq!(code(&out), 130, "{sig}: {}", stderr(&out));
        assert_eq!(env.store_bytes(), before, "{sig}");
        assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new(), "{sig}");
    }
}

/// A concurrent change between snapshot and rename is detected and retried.
/// The hook pauses secrit after its first sops run until the raw write is
/// done, and its log shows the second pass (R9).
#[cfg(feature = "test-hooks")]
#[test]
fn concurrent_raw_change_is_retried() {
    let env = TestEnv::new();
    let mut cmd = env.cmd();
    cmd.env("SECRIT_TEST_HOOK", "after-sops=pause")
        .env("SECRIT_TEST_HOOK_DIR", env.hook_dir());
    cmd.args(["store", "slow"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    {
        child.stdin.take().unwrap().write_all(b"v").unwrap();
    }
    env.wait_for_hook(1);
    // A raw sops write that ignores secrit's lock, like a manual `sops set`.
    let st = env
        .sops_cmd()
        .args(["set", "--value-stdin"])
        .arg(&env.store_file)
        .arg("[\"raw\"]")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().unwrap().write_all(b"\"r\"")?;
            c.wait()
        })
        .unwrap();
    assert!(st.success());
    std::fs::write(env.hook_dir().join("go"), b"").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(env.ls(), ["raw", "slow"]);
    assert_eq!(env.wait_for_hook(2), ["after-sops", "after-sops"]);
}
