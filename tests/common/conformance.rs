//! The backend conformance suite (v0.2 plan 10.1). Each case is generic over
//! a [`Fixture`], and `conformance_suite!(Fixture)` makes one `#[test]` per
//! case in a backend's test file. Threat ids refer to PLAN 13 and the v0.2
//! plan 9. The write gate case (T27) joins when slice S1b merges.

use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::process::Output;

use super::env::{BIN, assert_absent, code, no_tty, run_cmd, stderr};
use super::fixture::{ECHO_PREFIX, Fixture};

/// Every case, as `#[test]` functions that run it on `$fixture`.
#[macro_export]
macro_rules! conformance_suite {
    ($fixture:ty) => {
        $crate::conformance_suite!(@cases $fixture;
            round_trip,
            get_stdout_returns_the_exact_value,
            create_only_keeps_the_old_value,
            replace_changes_the_value,
            rm_needs_an_existing_name_and_a_confirmation,
            ls_never_decrypts,
            values_never_reach_a_child_argv,
            child_stderr_never_shows_a_value,
            get_is_refused_for_agents,
        );
    };
    (@cases $fixture:ty; $($case:ident),* $(,)?) => {
        $(
            #[test]
            fn $case() {
                $crate::common::conformance::$case::<$fixture>();
            }
        )*
    };
}

fn assert_stored<F: Fixture>(f: &F, name: &str, want: &[u8]) {
    assert!(
        f.read_back(name).as_deref() == Some(want),
        "stored value of {name} differs from the input"
    );
}

/// The backups that the last write made: one 0600 file in a 0700
/// directory when the backend keeps backups, else none.
fn assert_backups<F: Fixture>(f: &F, want_with_backups: usize) {
    let backups = f.dirs().backups();
    if !F::CAPS.backups {
        assert_eq!(backups, Vec::<std::path::PathBuf>::new());
        return;
    }
    assert_eq!(backups.len(), want_with_backups);
    for b in &backups {
        assert_eq!(std::fs::metadata(b).unwrap().mode() & 0o777, 0o600);
        let dir = b.parent().unwrap();
        assert_eq!(std::fs::metadata(dir).unwrap().mode() & 0o777, 0o700);
    }
}

/// `get NAME --stdout` into a private file, under `script` so that agent
/// detection sees a terminal; `agent` sets `CLAUDECODE=1`. The paths and
/// the name reach the shell as positional parameters, never as shell text;
/// the quote in the file name proves it. No pipe, so the exit status is
/// secrit's.
fn get_to_file<F: Fixture>(f: &F, agent: bool, name: &str) -> (Output, Vec<u8>) {
    let dest = f.dirs().root.path().join("get 'it'.out");
    let _ = std::fs::remove_file(&dest);
    let mut envs = vec![
        ("GET_BIN", OsStr::new(BIN)),
        ("GET_NAME", OsStr::new(name)),
        ("GET_OUT", dest.as_os_str()),
    ];
    if agent {
        envs.push(("CLAUDECODE", OsStr::new("1")));
    }
    let inner = "umask 077; set -- \"$GET_BIN\" \"$GET_NAME\" \"$GET_OUT\"; \
                 unset GET_BIN GET_NAME GET_OUT; exec \"$1\" get \"$2\" --stdout > \"$3\"";
    let out = f.dirs().under_script_env(inner, &envs);
    (out, std::fs::read(&dest).unwrap_or_default())
}

pub fn round_trip<F: Fixture>() {
    let f = F::new();
    let d = f.dirs();
    assert_eq!(d.ls(), Vec::<String>::new());

    let out = d.store_value("b.key", b"value-b\n");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("stored b.key in main"));
    let out = d.store_value("a-key_1", b"value-a");
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    assert_eq!(d.ls(), ["a-key_1", "b.key"]);
    assert_eq!(f.names(), ["a-key_1", "b.key"]);
    assert_stored(&f, "a-key_1", b"value-a");
    assert_stored(&f, "b.key", b"value-b");
    let json = d.run(["ls", "--json"], None);
    assert_eq!(
        String::from_utf8(json.stdout).unwrap().trim(),
        r#"["a-key_1","b.key"]"#
    );
    assert_backups(&f, 0);

    let out = d.run(["rm", "a-key_1", "--yes"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("removed a-key_1"));
    assert_eq!(d.ls(), ["b.key"]);
    assert_eq!(f.names(), ["b.key"]);
    assert_eq!(f.read_back("a-key_1"), None);
    assert_backups(&f, 1);
}

/// `get --stdout` to a pipe gives back the exact bytes that `store --raw`
/// read.
pub fn get_stdout_returns_the_exact_value<F: Fixture>() {
    let f = F::new();
    let out = f
        .dirs()
        .run(["store", "n", "--raw"], Some(b"exact\nbytes\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let (out, got) = get_to_file(&f, false, "n");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(got == b"exact\nbytes\n", "get --stdout bytes differ");
}

/// T12: no silent overwrite.
pub fn create_only_keeps_the_old_value<F: Fixture>() {
    let f = F::new();
    assert_eq!(code(&f.dirs().store_value("n", b"old")), 0);
    let out = f.dirs().store_value("n", b"new");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("already exists"));
    assert_stored(&f, "n", b"old");
    assert_backups(&f, 0);
}

/// T12: `--replace` changes the value, with a backup when the backend
/// keeps backups.
pub fn replace_changes_the_value<F: Fixture>() {
    let f = F::new();
    assert_eq!(code(&f.dirs().store_value("n", b"old")), 0);
    let out = f.dirs().run(["store", "n", "--replace"], Some(b"new"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_stored(&f, "n", b"new");
    assert_eq!(f.names(), ["n"]);
    assert_backups(&f, 1);
}

/// `rm` of a missing name fails; with no terminal it needs `--yes`.
pub fn rm_needs_an_existing_name_and_a_confirmation<F: Fixture>() {
    let f = F::new();
    let out = f.dirs().run(["rm", "nope", "--yes"], None);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("does not exist"));

    assert_eq!(code(&f.dirs().store_value("n", b"v")), 0);
    let mut cmd = no_tty(&f.dirs().cmd());
    cmd.args(["rm", "n"]);
    let out = run_cmd(cmd, std::iter::empty::<&str>(), None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert_eq!(f.dirs().ls(), ["n"]);
    assert_stored(&f, "n", b"v");
    assert_backups(&f, 0);
}

/// G4: `ls` lists names with no way to decrypt a value. The failed `get`
/// proves that the values are locked.
pub fn ls_never_decrypts<F: Fixture>() {
    assert!(
        F::CAPS.names_without_decrypt,
        "write the case for a backend whose ls unlocks the store (v0.2 plan 5.2)"
    );
    let f = F::new();
    assert_eq!(code(&f.dirs().store_value("n", b"locked-canary-6d0e")), 0);
    f.lock_values();
    assert_eq!(f.dirs().ls(), ["n"]);
    let (out, got) = get_to_file(&f, false, "n");
    assert_ne!(code(&out), 0, "get worked on a locked store");
    assert_absent(&out, "locked-canary-6d0e");
    assert!(got.is_empty(), "get wrote a value from a locked store");
}

/// T1: a value reaches the child tool on stdin, never on its argv: not on
/// store, replace, get or rm.
pub fn values_never_reach_a_child_argv<F: Fixture>() {
    let f = F::new();
    let log = f.dirs().root.path().join("argv 'it'.log");
    if F::CAPS.child_tool {
        f.log_tool_argv(&log);
    }
    let d = f.dirs();
    let out = d.store_value("n", b"argv-canary-91f3");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = d.run(["store", "n", "--replace"], Some(b"argv-canary-2b7c"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let (out, got) = get_to_file(&f, false, "n");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(got == b"argv-canary-2b7c", "get --stdout bytes differ");
    let out = d.run(["rm", "n", "--yes"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let logged = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        !logged.is_empty(),
        F::CAPS.child_tool,
        "the argv log does not match the child_tool capability"
    );
    for canary in ["argv-canary-91f3", "argv-canary-2b7c"] {
        assert!(!logged.contains(canary), "a value reached a child argv");
    }
}

/// T8, T20: a failing child tool that copies its stdin to stderr shows no
/// value, and the store keeps its old value. A daemon backend has no child
/// stderr.
pub fn child_stderr_never_shows_a_value<F: Fixture>() {
    if !F::CAPS.child_tool {
        return;
    }
    let f = F::new();
    assert_eq!(code(&f.dirs().store_value("n", b"old")), 0);
    f.fail_tool_echoing_stdin();
    let out = f.dirs().store_value("m", b"stderr-canary-5c2e");
    assert_redacted::<F>(&out, "stderr-canary-5c2e");
    let out = f
        .dirs()
        .run(["store", "n", "--replace"], Some(b"stderr-canary-8a41"));
    assert_redacted::<F>(&out, "stderr-canary-8a41");
    assert_eq!(f.names(), ["n"]);
    assert_stored(&f, "n", b"old");
}

/// A failed write shows no value and drops each echoed line whole (SEC-15).
/// The redaction note proves that the value reached the tool.
fn assert_redacted<F: Fixture>(out: &Output, value: &str) {
    assert_eq!(code(out), 1, "{}", stderr(out));
    assert_absent(out, value);
    let err = stderr(out);
    assert!(!err.contains(ECHO_PREFIX), "{err}");
    assert!(
        err.contains(F::REDACTION_NOTE),
        "the value never reached the tool: {err}"
    );
}

/// T4: `get` is refused when an agent is detected, even on a terminal, and
/// when there is no terminal.
pub fn get_is_refused_for_agents<F: Fixture>() {
    let f = F::new();
    assert_eq!(code(&f.dirs().store_value("n", b"get-canary-77aa")), 0);

    let mut cmd = f.dirs().cmd();
    cmd.env("CLAUDECODE", "1");
    let out = run_cmd(cmd, ["get", "n", "--stdout"], None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("CLAUDECODE"));
    assert_absent(&out, "get-canary-77aa");

    let (out, got) = get_to_file(&f, true, "n");
    assert_eq!(code(&out), 3, "get on a terminal for an agent");
    assert!(String::from_utf8_lossy(&out.stdout).contains("CLAUDECODE"));
    assert_absent(&out, "get-canary-77aa");
    assert!(got.is_empty(), "get wrote a value for an agent");

    let mut cmd = no_tty(&f.dirs().cmd());
    cmd.args(["get", "n", "--stdout"]);
    let out = run_cmd(cmd, std::iter::empty::<&str>(), None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("there is no terminal"));
    assert_absent(&out, "get-canary-77aa");
}
