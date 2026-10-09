//! `secrit run` (v0.2 plan 7.1, slice S13): the memfd hand-off, `--env`,
//! `--pristine`, masking, signals and the exit status. Linux only: the
//! memfd hand-off needs `memfd_create`.
//!
//! A test that needs "no agent" runs under util-linux `script`, which gives
//! secrit a terminal. Every other test runs with no terminal, so secrit sees
//! an agent (`/dev/tty` cannot be opened) and masks.

#![cfg(target_os = "linux")]

mod common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{TestEnv, bin, code, stderr};

const VALUE: &str = "run-canary-7f3e2a91";

fn env_with_value() -> TestEnv {
    let env = TestEnv::new();
    let out = env.store_value("n", VALUE.as_bytes());
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    env
}

fn sh() -> String {
    bin("sh").display().to_string()
}

fn tool(name: &str) -> String {
    bin(name).display().to_string()
}

fn read(env: &TestEnv, file: &str) -> Vec<u8> {
    std::fs::read(env.root.path().join(file)).unwrap_or_default()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `'s'` as one shell word.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// T5, 7.1 step 2: `VAR=/dev/fd/N` can be opened twice, and each open
/// reads the whole value from offset 0.
#[test]
fn the_file_path_reads_the_value_twice() {
    let env = env_with_value();
    let out = env.run(
        [
            "run",
            "--file",
            "V=n",
            "--",
            &sh(),
            "-c",
            &format!("{cat} \"$V\" > a; {cat} \"$V\" > b", cat = tool("cat")),
        ],
        None,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(read(&env, "a"), VALUE.as_bytes());
    assert_eq!(read(&env, "b"), VALUE.as_bytes());
}

/// T42, T5: the child environment holds the path, not the value. The fd is
/// the memfd named `secrit`, so `/proc/<pid>/fd` shows no secret name.
#[test]
fn the_environment_holds_the_path_only() {
    let env = env_with_value();
    let script = format!(
        "{cat} /proc/$$/environ > environ; {readlink} /proc/$$/fd/${{V#/dev/fd/}} > link",
        cat = tool("cat"),
        readlink = tool("readlink"),
    );
    let out = env.run(["run", "--file", "V=n", "--", &sh(), "-c", &script], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let environ = read(&env, "environ");
    assert!(
        !contains(&environ, VALUE.as_bytes()),
        "the value is in environ"
    );
    let vars: Vec<&[u8]> = environ.split(|&b| b == 0).collect();
    assert!(
        vars.iter().any(|v| v.starts_with(b"V=/dev/fd/")),
        "no V=/dev/fd/N in environ"
    );
    assert_eq!(read(&env, "link"), b"/memfd:secrit (deleted)\n");
}

/// 7.1 step 2: the memfd is sealed. An append and a truncate both fail,
/// and the value stays the same.
#[test]
fn the_memfd_refuses_writes() {
    let env = env_with_value();
    let script = format!(
        "( printf x >> \"$V\" ) 2>/dev/null; echo $? > append; ( : > \"$V\" ) 2>/dev/null; echo $? > trunc; {cat} \"$V\" > after",
        cat = tool("cat"),
    );
    let out = env.run(["run", "--file", "V=n", "--", &sh(), "-c", &script], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_ne!(read(&env, "append"), b"0\n", "an append succeeded");
    assert_ne!(read(&env, "trunc"), b"0\n", "a truncate succeeded");
    assert_eq!(read(&env, "after"), VALUE.as_bytes());
}

/// 7.1 step 1: with no agent, `--env` puts the value in the child
/// environment.
#[test]
fn env_passes_the_value_with_no_agent() {
    let env = env_with_value();
    let inner = format!(
        "{secrit} run --env V=n -- {sh} -c 'printf %s \"$V\" > out'; echo \"rc=$?\"",
        secrit = quote(common::BIN),
        sh = quote(&sh()),
    );
    let out = env.under_script(&inner);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("rc=0"), "{text}");
    assert_eq!(read(&env, "out"), VALUE.as_bytes());
}

/// Q27, T42: under agent detection `--env` exits 3 before any decrypt.
/// With no terminal at all it is refused too.
#[test]
fn an_agent_cannot_use_env() {
    let env = env_with_value();
    let mut c = env.cmd();
    c.env("CLAUDECODE", "1");
    let out = common::run_cmd(c, ["run", "--env", "V=n", "--", &tool("true")], None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("--file"), "{}", stderr(&out));
    let out = common::run_cmd(
        common::no_tty(&env.cmd()),
        ["run", "--env", "V=n", "--", &tool("true")],
        None,
    );
    assert_eq!(code(&out), 3, "{}", stderr(&out));
}

/// Q27: under agent detection `--file` runs.
#[test]
fn an_agent_can_use_file() {
    let env = env_with_value();
    let mut c = env.cmd();
    c.env("CLAUDECODE", "1");
    let script = format!("{cat} \"$V\" > out", cat = tool("cat"));
    let out = common::run_cmd(
        c,
        ["run", "--file", "V=n", "--", &sh(), "-c", &script],
        None,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(read(&env, "out"), VALUE.as_bytes());
}

/// 7.1 step 3: `--pristine` starts the child with only the `--file` and
/// `--env` variables. Without it the child inherits secrit's environment.
#[test]
fn pristine_clears_the_environment() {
    let env = env_with_value();
    let out = env.run(
        ["run", "--pristine", "--file", "V=n", "--", &tool("env")],
        None,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "{text}");
    assert!(lines[0].starts_with("V=/dev/fd/"), "{text}");
    let out = env.run(["run", "--file", "V=n", "--", &tool("env")], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.lines().any(|l| l.starts_with("HOME=")), "{text}");
    assert!(text.lines().any(|l| l.starts_with("V=/dev/fd/")), "{text}");
}

fn base64(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(alphabet[((n >> (18 - 6 * i)) & 63) as usize]));
        }
        if pad {
            for _ in chunk.len()..3 {
                out.push('=');
            }
        }
    }
    out
}

/// T40, T4: a child that prints the value in its raw form, in base64 at
/// each of three offsets (standard and URL-safe), percent-encoded, as a
/// JSON string and in hex, each split over two writes. Every form is
/// masked.
#[test]
fn every_printed_form_is_masked() {
    let env = TestEnv::new();
    let value = "r/u\"n&<é>+ ~ca?nary";
    assert_eq!(code(&env.store_value("n", value.as_bytes())), 0);
    let std64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let url64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut forms = vec![value.to_owned()];
    for prefix in ["", "x", "xy"] {
        let data = [prefix.as_bytes(), value.as_bytes()].concat();
        forms.push(base64(&data, std64, true));
        forms.push(base64(&data, url64, false));
    }
    forms.push(
        value
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect(),
    );
    let json = serde_json::to_string(value).unwrap();
    forms.push(json[1..json.len() - 1].to_owned());
    forms.push(value.bytes().fold(String::new(), |mut hex, b| {
        let _ = write!(hex, "{b:02x}");
        hex
    }));
    let mut body = String::new();
    for form in &forms {
        let cut = form.len() / 2;
        let cut = (cut..form.len())
            .find(|&i| form.is_char_boundary(i))
            .unwrap();
        let _ = writeln!(
            body,
            "printf '%s' {}\nprintf '%s\\n' {}",
            quote(&format!("form: {}", &form[..cut])),
            quote(&form[cut..])
        );
    }
    let child = env.script("print-forms", &body);
    let out = env.run(
        ["run", "--file", "V=n", "--", child.to_str().unwrap()],
        None,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), forms.len(), "{}", lines.len());
    for (form, line) in forms.iter().zip(&lines) {
        assert!(!line.contains(form.as_str()), "a form was not masked");
        assert!(line.contains("[secrit:n]"), "no mask in a line");
    }
}

/// 7.1 step 4: a value shorter than 4 bytes is not masked, with a warning.
#[test]
fn a_short_value_warns() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("tiny", b"abc")), 0);
    let out = env.run(["run", "--file", "T=tiny", "--", &tool("true")], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("tiny is shorter than 4 bytes"),
        "{}",
        stderr(&out)
    );
}

/// T45: the exit code of CMD is secrit's exit code, and a signal that ends
/// CMD ends secrit.
#[test]
fn the_exit_status_passes_through() {
    let env = env_with_value();
    let out = env.run(["run", "--file", "V=n", "--", &sh(), "-c", "exit 7"], None);
    assert_eq!(code(&out), 7, "{}", stderr(&out));
    let out = env.run(
        ["run", "--file", "V=n", "--", &sh(), "-c", "kill -TERM $$"],
        None,
    );
    assert_eq!(out.status.signal(), Some(15), "{:?}", out.status);
}

/// A running child with its stdout read by a thread.
struct Running {
    child: Child,
    output: Arc<Mutex<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl Running {
    fn start(mut c: Command, stdin: Stdio) -> Self {
        c.stdin(stdin).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = c.spawn().expect("spawn");
        let mut pipe = child.stdout.take().unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&output);
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                }
            }
        });
        Self {
            child,
            output,
            reader: Some(reader),
        }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    /// Wait until stdout holds `needle`, at most 30 s.
    fn wait_for(&self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.text().contains(needle) {
            assert!(
                Instant::now() < deadline,
                "never saw {needle:?}: {}",
                self.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        let stdin = self.child.stdin.as_mut().unwrap();
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    fn finish(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("the child did not end: {}", self.text());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(self.child.stdin.take());
        self.reader.take().unwrap().join().unwrap();
        let mut err = Vec::new();
        if let Some(mut e) = self.child.stderr.take() {
            let _ = e.read_to_end(&mut err);
        }
        Output {
            status,
            stdout: self.output.lock().unwrap().clone(),
            stderr: err,
        }
    }
}

/// `script` running `inner` with a terminal, stdin kept open for keys.
fn interactive(env: &TestEnv, inner: &str, extra_env: &[(&str, &str)]) -> Running {
    let mut s = Command::new(bin("script"));
    s.env_clear();
    for (k, v) in env.cmd().get_envs() {
        if let Some(v) = v {
            s.env(k, v);
        }
    }
    for (k, v) in extra_env {
        s.env(k, v);
    }
    s.env("SHELL", "/bin/sh")
        .current_dir(env.root.path())
        .args(["-q", "-e", "-c", inner, "/dev/null"]);
    Running::start(s, Stdio::piped())
}

/// A loop that waits for the file `go` in the test directory, at most 30 s.
fn wait_for_go(sleep: &str) -> String {
    format!("i=0; while [ ! -e go ] && [ $i -lt 300 ]; do {sleep} 0.1; i=$((i+1)); done")
}

/// T41, F31: with `CLAUDECODE=1` under `script` (so masking is on), a
/// prompt with no newline appears before the child reads. The prompt is a
/// proper prefix of the value, so the masker holds it until the idle flush.
#[test]
fn a_prompt_with_no_newline_appears_while_masking() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("pw", b"Pass-canary-5a1f9c")), 0);
    let child = env.script(
        "prompt",
        &format!(
            "printf 'Pass'\n{wait}\n{cat} \"$V\"\necho\necho end",
            wait = wait_for_go(&tool("sleep")),
            cat = tool("cat"),
        ),
    );
    let inner = format!(
        "{secrit} run --file V=pw -- {child}",
        secrit = quote(common::BIN),
        child = quote(child.to_str().unwrap()),
    );
    let run = interactive(&env, &inner, &[("CLAUDECODE", "1")]);
    run.wait_for("Pass");
    assert!(!run.text().contains("end"), "{}", run.text());
    std::fs::write(env.root.path().join("go"), b"").unwrap();
    run.wait_for("end");
    let out = run.finish();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(code(&out), 0, "{text}");
    assert!(
        text.contains("[secrit:pw]"),
        "masking is not active: {text}"
    );
    assert!(
        !text.contains("Pass-canary"),
        "the value reached the output"
    );
}

/// 7.1 step 5: Ctrl-C reaches CMD and secrit together. A CMD that traps INT
/// and exits 0 gives exit 0, not 130.
#[test]
fn ctrl_c_to_a_child_that_traps_it_gives_its_exit_code() {
    let env = env_with_value();
    let child = env.script(
        "trap-int",
        &format!(
            "trap 'echo trapped; exit 0' INT\necho ready\ni=0; while [ $i -lt 300 ]; do {sleep} 0.1; i=$((i+1)); done\nexit 9",
            sleep = tool("sleep"),
        ),
    );
    // The outer shell ignores INT, so it lives to print the exit code.
    let inner = format!(
        "trap '' INT; {secrit} run --file V=n -- {child}; echo \"rc=$?\"",
        secrit = quote(common::BIN),
        child = quote(child.to_str().unwrap()),
    );
    let mut run = interactive(&env, &inner, &[("CLAUDECODE", "1")]);
    run.wait_for("ready");
    run.send(b"\x03");
    run.wait_for("rc=");
    let out = run.finish();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("trapped"), "{text}");
    assert!(text.contains("rc=0"), "{text}");
}

/// 7.1 step 5: Ctrl-Z stops CMD and then secrit, so the shell sees the job
/// stop. After `fg`, CMD runs again and completes.
#[test]
fn ctrl_z_stops_the_job_and_fg_resumes_it() {
    let env = env_with_value();
    let child = env.script(
        "stoppable",
        &format!(
            "echo $$ > cmdpid\necho ready\n{wait}\necho finished",
            wait = wait_for_go(&tool("sleep")),
        ),
    );
    let inner = format!(
        "set -m\n{secrit} run --file V=n -- {child}\necho \"stopped rc=$?\"\nread p < cmdpid\necho \"state=$({cut} -d' ' -f3 /proc/$p/stat)\"\n{touch} go\nfg\necho \"rc=$?\"",
        secrit = quote(common::BIN),
        child = quote(child.to_str().unwrap()),
        cut = tool("cut"),
        touch = tool("touch"),
    );
    let mut run = interactive(&env, &inner, &[("CLAUDECODE", "1")]);
    run.wait_for("ready");
    run.send(b"\x1a");
    run.wait_for("rc=0");
    let out = run.finish();
    let text = String::from_utf8_lossy(&out.stdout);
    let state = text.find("state=T").expect(&text);
    let finished = text.find("finished").expect(&text);
    assert!(state < finished, "{text}");
}

/// 7.1 step 5: TERM to secrit is forwarded to CMD; secrit keeps waiting
/// and passes on CMD's exit code.
#[test]
fn term_is_forwarded_to_the_child() {
    let env = env_with_value();
    let child = env.script(
        "trap-term",
        &format!(
            "trap 'echo got-term; exit 5' TERM\necho ready\ni=0; while [ $i -lt 300 ]; do {sleep} 0.1; i=$((i+1)); done\nexit 9",
            sleep = tool("sleep"),
        ),
    );
    let mut c = env.cmd();
    c.args(["run", "--file", "V=n", "--", child.to_str().unwrap()]);
    let run = Running::start(c, Stdio::null());
    run.wait_for("ready");
    let st = Command::new(bin("kill"))
        .args(["-TERM", &run.child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
    let out = run.finish();
    assert_eq!(code(&out), 5, "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("got-term"));
}

/// Q5: `--no-mask` is refused under agent detection.
#[test]
fn no_mask_is_refused_for_an_agent() {
    let env = env_with_value();
    let mut c = env.cmd();
    c.env("CLAUDECODE", "1");
    let out = common::run_cmd(
        c,
        ["run", "--no-mask", "--file", "V=n", "--", &tool("true")],
        None,
    );
    assert_eq!(code(&out), 3, "{}", stderr(&out));
}

/// 7.1 step 6: `--no-mask` replaces secrit with CMD: CMD has secrit's pid,
/// and the memfd stays open in the new image.
#[test]
fn no_mask_replaces_the_process() {
    let env = env_with_value();
    let inner = format!(
        "{secrit} run --no-mask --file V=n -- {sh} -c 'echo $$ > cmdpid; {cat} \"$V\" > out' & echo $! > spid; wait",
        secrit = quote(common::BIN),
        sh = quote(&sh()),
        cat = tool("cat"),
    );
    let out = env.under_script(&inner);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let spid = read(&env, "spid");
    assert!(!spid.is_empty());
    assert_eq!(read(&env, "cmdpid"), spid);
    assert_eq!(read(&env, "out"), VALUE.as_bytes());
}

/// 7.1 step 1: a value with NUL cannot go into an environment variable.
#[test]
fn env_refuses_a_value_with_nul() {
    let env = TestEnv::new();
    let mut c = env
        .sops_cmd()
        .args(["set", "--value-stdin"])
        .arg(&env.store_file)
        .arg("[\"nul\"]")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin
        .take()
        .unwrap()
        .write_all(b"\"ab\\u0000cdef\"")
        .unwrap();
    assert!(c.wait().unwrap().success());
    let inner = format!(
        "{secrit} run --env V=nul -- {t}; echo \"rc=$?\"",
        secrit = quote(common::BIN),
        t = quote(&tool("true")),
    );
    let out = env.under_script(&inner);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("rc=3"), "{text}");
    assert!(text.contains("NUL"), "{text}");
}

/// The command line: VAR must be a shell name, every VAR is set once, and
/// at least one `--file` or `--env` is given. A missing CMD is an error.
#[test]
fn bad_command_lines_are_usage_errors() {
    let env = env_with_value();
    let t = tool("true");
    for args in [
        vec!["run", "--file", "1V=n", "--", &t],
        vec!["run", "--file", "V-X=n", "--", &t],
        vec!["run", "--file", "Vn", "--", &t],
        vec!["run", "--file", "V=n", "--file", "V=n", "--", &t],
        vec!["run", "--", &t],
        vec!["run", "--file", "V=n"],
    ] {
        let out = env.run(&args, None);
        assert_eq!(code(&out), 2, "{args:?}: {}", stderr(&out));
    }
    let out = env.run(["run", "--file", "V=bad/name", "--", &t], None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    let missing = env.root.path().join("no-such-program");
    let out = env.run(
        ["run", "--file", "V=n", "--", missing.to_str().unwrap()],
        None,
    );
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let out = env.run(["run", "--file", "V=n", "--", "no-such-program-x"], None);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("not found"), "{}", stderr(&out));
}
