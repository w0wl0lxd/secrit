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
