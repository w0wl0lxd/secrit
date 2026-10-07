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
