//! Terminal tests through util-linux `script`, which gives secrit a
//! controlling terminal: the no-echo prompt, the rm confirmation, and the
//! reveal screen (PLAN T3). Finding ids refer to the review of 2026-10-07.

mod common;

use common::{TestEnv, bin, code};

const ALT_ON: &[u8] = b"\x1b[?1049h";
const ALT_OFF: &[u8] = b"\x1b[?1049l";

fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    hay.windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect()
}

fn text(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// SEC-5, R13: a tab typed at the prompt reaches the file, and the value is
/// asked twice.
#[test]
fn prompt_keeps_a_tab_and_asks_twice() {
    let env = TestEnv::new();
    let inner = format!("'{}' store tabbed", common::BIN);
    let out = env.under_script_with(&inner, b"a\tb\na\tb\n");
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(text(&out).contains("again: "));
    env.assert_value("tabbed", "a\tb");
}

/// R4 (3): two different entries fail with exit 1 and store nothing.
#[test]
fn prompt_mismatch_fails() {
    let env = TestEnv::new();
    let inner = format!("'{}' store n", common::BIN);
    let out = env.under_script_with(&inner, b"one\ntwo\n");
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(text(&out).contains("do not match"), "{}", text(&out));
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// SEC-7, R4 (5): a multiline value is read in one no-echo session until a
/// line that holds only '.'.
#[test]
fn multiline_prompt_reads_until_a_dot() {
    let env = TestEnv::new();
    let inner = format!("'{}' store multi --multiline", common::BIN);
    let out = env.under_script_with(&inner, b"l1\nl2\n.\n");
    assert_eq!(code(&out), 0, "{}", text(&out));
    env.assert_value("multi", "l1\nl2");
}

/// A line the terminal driver may have cut short is refused.
#[test]
fn an_over_long_line_is_refused() {
    let env = TestEnv::new();
    let inner = format!("'{}' store long", common::BIN);
    let mut input = vec![b'x'; 5000];
    input.push(b'\n');
    let out = env.under_script_with(&inner, &input);
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// R4 (5), R13: rm asks on the terminal; "y" removes and "n" keeps.
#[test]
fn rm_confirms_on_the_terminal() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("keep", b"v")), 0);
    assert_eq!(code(&env.store_value("gone", b"v")), 0);
    let out = env.under_script_with(&format!("'{}' rm keep", common::BIN), b"n\n");
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(text(&out).contains("not removed"));
    let out = env.under_script_with(&format!("'{}' rm gone", common::BIN), b"y\n");
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(env.ls(), ["keep"]);
}

/// T3, TEST-1: reveal shows the value only on the alternate screen, and
/// leaves it after one key.
#[test]
fn reveal_keeps_the_value_on_the_alternate_screen() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"reveal-canary-4e1c")), 0);
    let out = env.under_script_with(&format!("'{}' get n", common::BIN), b"k");
    assert_eq!(code(&out), 0, "{}", text(&out));
    let on = find_all(&out.stdout, ALT_ON);
    let off = find_all(&out.stdout, ALT_OFF);
    let canary = find_all(&out.stdout, b"reveal-canary-4e1c");
    assert_eq!(
        (on.len(), off.len(), canary.len()),
        (1, 1, 1),
        "{}",
        text(&out)
    );
    assert!(on[0] < canary[0] && canary[0] < off[0]);
}

/// SEC-1: escape sequences inside a stored value are shown as text. The
/// value cannot leave the alternate screen early or write the clipboard.
#[test]
fn reveal_escapes_terminal_sequences() {
    let env = TestEnv::new();
    let st =
        env.sops_cmd()
            .args(["set", "--value-stdin"])
            .arg(&env.store_file)
            .arg("[\"esc\"]")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.take().unwrap().write_all(
                    b"\"canaryA\\u001b[?1049lcanaryB\\u001b]52;c;aGk=\\u0007canaryC\"",
                )?;
                c.wait()
            })
            .unwrap();
    assert!(st.success());
    let out = env.under_script_with(&format!("'{}' get esc", common::BIN), b"k");
    assert_eq!(code(&out), 0, "{}", text(&out));
    let off = find_all(&out.stdout, ALT_OFF);
    let b = find_all(&out.stdout, b"canaryB");
    assert_eq!(off.len(), 1, "a raw alternate-screen exit got through");
    assert!(b[0] < off[0], "canaryB reached the main screen");
    assert!(
        find_all(&out.stdout, b"\x1b]52").is_empty(),
        "OSC 52 got through"
    );
    assert!(text(&out).contains("\\x1b") && text(&out).contains("]52;c;aGk="));
}

/// SEC-13, R8: TERM during reveal leaves the alternate screen, restores the
/// terminal settings and exits 130.
#[test]
fn a_signal_during_reveal_restores_the_terminal() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"term-canary-77d0")), 0);
    let stty = bin("stty").display().to_string();
    let inner = format!(
        "'{stty}' -a > before; '{secrit}' get n & pid=$!; '{sleep}' 1; kill -TERM $pid; wait $pid; echo \"rc=$?\"; '{stty}' -a > after; '{cmp}' -s before after && echo SAME-STTY",
        secrit = common::BIN,
        sleep = bin("sleep").display(),
        cmp = bin("cmp").display(),
    );
    // stdin stays open: `script` types ^D when its stdin ends, and in raw
    // mode that is a key press.
    let out = env.under_script_held(&inner);
    let t = text(&out);
    assert!(t.contains("rc=130"), "{t}");
    assert!(t.contains("SAME-STTY"), "{t}");
    let canary = find_all(&out.stdout, b"term-canary-77d0");
    let off = find_all(&out.stdout, ALT_OFF);
    assert_eq!(canary.len(), 1, "{t}");
    assert!(
        off.iter().any(|o| *o > canary[0]),
        "no exit from the alternate screen"
    );
}

/// REG-1: `get --stdout` blocked on a pipe that nobody reads ends at TERM.
/// 1000 bytes in the pipe plus a 65000-byte value exceed any pipe buffer.
/// A sops wrapper marks the end of the decrypt, so TERM lands in the write.
#[test]
fn term_ends_get_stdout_on_a_stalled_pipe() {
    let env = TestEnv::new();
    let value = vec![b'x'; 65_000];
    let out = env.store_value("big", &value);
    assert_eq!(code(&out), 0, "{}", common::stderr(&out));
    let marker = env.root.path().join("decrypted");
    let wrapper = env.script(
        "sops-marker",
        &format!(
            "'{}' \"$@\"\nrc=$?\necho done >> '{}'\nexit $rc",
            env.sops.display(),
            marker.display()
        ),
    );
    env.write_config_with(&wrapper, "");
    let inner = format!(
        "( printf '%01000d' 0; '{secrit}' get big --stdout & echo $! > pid; wait $!; echo $? > rc ) | '{sleep}' 60 &
reader=$!
i=0; while [ ! -s '{marker}' ] && [ $i -lt 600 ]; do '{sleep}' 0.05; i=$((i+1)); done
'{sleep}' 0.5
read p < pid
kill -TERM $p
i=0; while [ ! -s rc ] && [ $i -lt 200 ]; do '{sleep}' 0.05; i=$((i+1)); done
if [ -s rc ]; then read r < rc; echo \"rc=$r\"; else echo STILL-RUNNING; kill -KILL $p; fi
kill $reader",
        secrit = common::BIN,
        sleep = bin("sleep").display(),
        marker = marker.display(),
    );
    let out = env.under_script(&inner);
    let t = text(&out);
    assert!(marker.exists(), "the decrypt never finished: {t}");
    // 143 = 128 + SIGTERM: the default action, not the deferred exit 130.
    assert!(t.contains("rc=143"), "{t}");
}

// The write gate (PLAN-v0.2 section 4, T27, T27a, T28).

const PROMPT: &[u8] = b"type the name: ";

/// The gate command with an agent variable set on `script`, so `sh` and
/// secrit inherit it.
fn agent_cmd(env: &TestEnv) -> std::process::Command {
    let mut c = env.gate_cmd();
    c.env("CLAUDECODE", "1");
    c
}

/// T27: under an agent, the name typed on the terminal confirms a store of a
/// piped value.
#[test]
fn the_typed_name_confirms_a_store_under_an_agent() {
    let env = TestEnv::new();
    let inner = format!("printf gate-value | '{}' store n", common::BIN);
    let out = env.under_script_answer(&agent_cmd(&env), &inner, PROMPT, b"n\n");
    let t = text(&out);
    assert_eq!(code(&out), 0, "{t}");
    assert!(
        t.contains("an agent runs secrit (CLAUDECODE is set)"),
        "{t}"
    );
    assert!(t.contains("To store 'n' in "), "{t}");
    env.assert_value("n", "gate-value");
}

/// T27: `y` is not the name; the store stays byte-identical (exit 3).
#[test]
fn y_does_not_confirm_a_store() {
    let env = TestEnv::new();
    let before = env.store_bytes();
    let inner = format!("printf v | '{}' store n", common::BIN);
    let out = env.under_script_answer(&agent_cmd(&env), &inner, PROMPT, b"y\n");
    let t = text(&out);
    assert_eq!(code(&out), 3, "{t}");
    assert!(t.contains("not confirmed"), "{t}");
    assert_eq!(env.store_bytes(), before);
}

/// T28: a name typed before the prompt is discarded. The hook holds secrit
/// before the flush, so the early input is in the terminal queue by then.
#[test]
fn input_typed_before_the_gate_prompt_is_discarded() {
    let env = TestEnv::new();
    let hook = env.hook_dir();
    let mut base = agent_cmd(&env);
    base.env("SECRIT_TEST_HOOK", "gate-flush=pause")
        .env("SECRIT_TEST_HOOK_DIR", &hook);
    let before = env.store_bytes();
    let inner = format!("printf v | '{}' store n", common::BIN);
    let out = env.under_script_typing(
        &base,
        &inner,
        |input| {
            env.wait_for_hook(1);
            std::io::Write::write_all(input, b"n\n").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(500));
            std::fs::write(hook.join("go"), "").unwrap();
        },
        PROMPT,
        b"x\n",
    );
    let t = text(&out);
    assert_eq!(code(&out), 3, "{t}");
    assert!(t.contains("not confirmed"), "{t}");
    assert_eq!(env.store_bytes(), before);
}

/// T27: `rm --yes` under an agent still asks for the name, and says so.
#[test]
fn rm_yes_still_asks_under_an_agent() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"v")), 0);
    let inner = format!("'{}' rm n --yes", common::BIN);
    let out = env.under_script_answer(&agent_cmd(&env), &inner, PROMPT, b"n\n");
    let t = text(&out);
    assert_eq!(code(&out), 0, "{t}");
    assert!(t.contains("--yes does not skip"), "{t}");
    assert!(t.contains("To remove 'n' from "), "{t}");
    assert_eq!(env.ls(), Vec::<String>::new());
}

/// T27a: an agent that unsets its variable for secrit is still found in
/// the ancestors, and the question names that process.
#[test]
fn the_ancestor_walk_finds_an_unset_variable() {
    let env = TestEnv::new();
    let before = env.store_bytes();
    let inner = format!(
        "printf v | '{}' -u CLAUDECODE '{}' store n",
        bin("env").display(),
        common::BIN
    );
    let out = env.under_script_answer(&agent_cmd(&env), &inner, PROMPT, b"no\n");
    let t = text(&out);
    assert_eq!(code(&out), 3, "{t}");
    assert!(t.contains("CLAUDECODE is set in ancestor process "), "{t}");
    assert_eq!(env.store_bytes(), before);
}

/// T27a, the documented bypass (PLAN-v0.2 4.4): a command that leaves the
/// agent's process tree and has no agent variable stores with no question.
///
/// The plan names `systemd-run --user --pty`, which reparents the command
/// to the user service manager. The Nix build sandbox has no user service
/// manager, so this test reparents the same way by hand: a helper loses
/// its parent, waits until the parent is gone, and then runs secrit. secrit
/// keeps the `script` terminal.
#[test]
fn a_reparented_command_without_the_variable_bypasses_the_gate() {
    let env = TestEnv::new();
    let value = env.root.path().join("value");
    std::fs::write(&value, "bypass-value").unwrap();
    let rc = env.root.path().join("rc");
    let log = env.root.path().join("log");
    let parents = env.root.path().join("parents");
    let sh = "/bin/sh";
    let sleep = bin("sleep").display().to_string();
    let helper = env.script(
        "orphan",
        &format!(
            "parent=$1\nwhile kill -0 \"$parent\" 2>/dev/null; do '{sleep}' 0.05; done\nread -r s < /proc/$$/stat; set -- $s; echo \"$parent $4\" > '{parents}'\n'{secrit}' store n < '{value}' > '{log}' 2>&1\necho $? > '{rc}'",
            secrit = common::BIN,
            value = value.display(),
            log = log.display(),
            rc = rc.display(),
            parents = parents.display(),
        ),
    );
    let inner = format!(
        "'{sh}' -c '\"{env}\" -u CLAUDECODE \"{helper}\" $$ & exit 0'\ni=0; while [ ! -s '{rc}' ] && [ $i -lt 600 ]; do '{sleep}' 0.05; i=$((i+1)); done",
        env = bin("env").display(),
        helper = helper.display(),
        rc = rc.display(),
    );
    let out = env.under_script_held_with(&agent_cmd(&env), &inner);
    let log = std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        std::fs::read_to_string(&rc).unwrap_or_default().trim(),
        "0",
        "{log}{}",
        text(&out)
    );
    assert!(!log.contains("type the name"), "{log}");
    env.assert_value("n", "bypass-value");
    // The helper ran secrit after it lost its first parent.
    let parents = std::fs::read_to_string(&parents).unwrap();
    let (first, now) = parents.trim().split_once(' ').unwrap();
    assert_ne!(first, now, "the helper was not reparented");
}
