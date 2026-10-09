//! Every sops run (PLAN sections 6.2 and 8.2).
//!
//! secrit runs the `sops` binary by absolute path with a cleared environment
//! and always passes `--config`. Every run is bounded (R1). sops runs in its
//! own process group, so a Ctrl-C to secrit's group does not reach it
//! mid-write. secrit polls the child: a deferred signal, a stop (sops read
//! the terminal from a background group, for example a passphrase prompt)
//! or [`child::TIMEOUT`] kills the whole sops group. `setsid` would give
//! sops no terminal at all, but `CommandExt::setsid` is unstable and the
//! crate forbids `unsafe`, so the stop is detected instead.
//!
//! Each run takes its own cap on the bytes it accepts on stdout.

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use super::format::SopsFormat;
use crate::backend::{BackendError, Location, Target, ToolStatus};
use crate::child::{self, ChildError, ChildOutput};
use crate::display::escape;
use crate::name::Name;
use crate::secret::{MAX_VALUE_BYTES, SecretValue};
use crate::trust::{self, TrustError};

/// The oldest sops that has `set --value-stdin` and `unset` (PLAN 4.6).
pub const MIN_SOPS: (u64, u64) = (3, 11);
/// [`MIN_SOPS`] and the reason, for [`BackendError::ToolTooOld`].
pub const NEED_SOPS: &str = "3.11 or newer (for 'set --value-stdin' and 'unset')";
/// What to do when sops stops to ask on the terminal.
pub const PROMPT_HINT: &str = "secrit v0.1 supports only an age key file without a passphrase: set age_key_file in the config";
/// The tool name in [`BackendError`] messages.
const TOOL: &str = "sops";
/// The `HOME` that sops gets. sops looks for `~/.ssh/id_ed25519` and
/// `~/.ssh/id_rsa` as age identities, so the real HOME is never passed (R2).
const CHILD_HOME: &str = "/nonexistent";
/// The cap on the sops output for a new, empty store file.
pub const MAX_NEW_FILE_BYTES: usize = 1024 * 1024;

/// How secrit runs sops for one store.
#[derive(Debug)]
pub struct Runner {
    sops: PathBuf,
    /// The `.sops.yaml` to pass, or `None` for `/dev/null`.
    sops_config: Option<PathBuf>,
    child_env: Vec<(OsString, OsString)>,
    /// The working directory of a run on the store: the store directory.
    dir: PathBuf,
    /// Set once the sops version and the `.sops.yaml` passed their checks.
    checked: OnceLock<()>,
}

impl Runner {
    /// `age_key_file` reaches sops as `SOPS_AGE_KEY_FILE`.
    pub fn new(
        sops: PathBuf,
        sops_config: Option<PathBuf>,
        age_key_file: Option<&Path>,
        dir: PathBuf,
    ) -> Self {
        let mut child_env: Vec<(OsString, OsString)> = vec![
            ("SOPS_DISABLE_VERSION_CHECK".into(), "1".into()),
            ("HOME".into(), CHILD_HOME.into()),
        ];
        if let Some(k) = age_key_file {
            child_env.push(("SOPS_AGE_KEY_FILE".into(), k.as_os_str().to_owned()));
        }
        Self {
            sops,
            sops_config,
            child_env,
            dir,
            checked: OnceLock::new(),
        }
    }

    pub fn sops(&self) -> &Path {
        &self.sops
    }

    /// The `.sops.yaml` secrit passes to sops, if any.
    pub fn sops_config(&self) -> Option<&Path> {
        self.sops_config.as_deref()
    }

    /// The path passed as `--config`. `/dev/null` turns off sops's upward
    /// search from the working directory (F10), so a stray `.sops.yaml`
    /// cannot apply.
    fn config_arg(&self) -> &Path {
        self.sops_config
            .as_deref()
            .unwrap_or(Path::new("/dev/null"))
    }

    /// The trust rule for the `.sops.yaml` (SEC-12).
    pub fn check_sops_config(&self) -> Result<(), BackendError> {
        let Some(p) = &self.sops_config else {
            return Ok(());
        };
        trust::check_file(p).map(|_| ()).map_err(|e| match e {
            TrustError::Io(source) => BackendError::Io {
                step: "check",
                path: p.clone(),
                source,
            },
            TrustError::Unsafe(reason) => BackendError::Unsafe {
                path: p.clone(),
                reason: reason.into(),
            },
        })
    }

    /// Checks made once, before the first sops run: the `.sops.yaml` is as
    /// trusted as the config (SEC-12), and sops is new enough (PF-4).
    fn check_once(&self) -> Result<(), BackendError> {
        if self.checked.get().is_some() {
            return Ok(());
        }
        self.check_sops_config()?;
        self.checked_version()?;
        let _ = self.checked.set(());
        Ok(())
    }

    /// [`Self::version`], refused when it is older than [`MIN_SOPS`].
    pub fn checked_version(&self) -> Result<(u64, u64, u64), BackendError> {
        let (a, b, c) = self.version()?;
        if (a, b) < MIN_SOPS {
            return Err(self.too_old(format!("{a}.{b}.{c}")));
        }
        Ok((a, b, c))
    }

    fn too_old(&self, found: String) -> BackendError {
        BackendError::ToolTooOld {
            tool: TOOL,
            found,
            path: self.sops.clone(),
            need: NEED_SOPS,
        }
    }

    /// The version that `sops --version` reports.
    pub fn version(&self) -> Result<(u64, u64, u64), BackendError> {
        let mut cmd = Command::new(&self.sops);
        cmd.env_clear()
            .envs(self.child_env.iter().map(|(k, v)| (k, v)))
            .args(["--version", "--disable-version-check"])
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .process_group(0);
        let target = Target {
            location: Location::File(self.sops.clone()),
            name: None,
        };
        let out = self.run_unchecked(cmd, None, 4096, "--version", target)?;
        let text = String::from_utf8_lossy(&out.stdout);
        match parse_sops_version(&text) {
            Some(v) if out.status.success() => Ok(v),
            _ => Err(self.too_old("an unknown version".into())),
        }
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.sops);
        c.env_clear()
            .envs(self.child_env.iter().map(|(k, v)| (k, v)))
            .arg("--config")
            .arg(self.config_arg())
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // Own process group: a signal to secrit's group (Ctrl-C, the
            // stuck-process reaper) does not reach sops mid-write.
            .process_group(0);
        c
    }

    /// `sops encrypt` of the empty document of `format`, as if it were
    /// `file`, so the creation rules of the `.sops.yaml` apply. The output
    /// cap is `stdout_cap`; 0 drops the output.
    pub fn encrypt_empty(
        &self,
        format: SopsFormat,
        file: &Path,
        stdout_cap: usize,
        target: Target,
    ) -> Result<ChildOutput, BackendError> {
        let mut cmd = self.command();
        cmd.current_dir("/")
            .args(["encrypt", "--input-type", "json", "--output-type"])
            .arg(format.input_type())
            .arg("--filename-override")
            .arg(file)
            .arg("/dev/stdin");
        self.run(cmd, Some(format.empty_doc()), stdout_cap, "encrypt", target)
    }

    /// `sops set` of `name` in the temp copy at `path`, with the value as
    /// JSON on stdin.
    pub fn set(
        &self,
        format: SopsFormat,
        path: &Path,
        name: &Name,
        value: &SecretValue,
        target: Target,
    ) -> Result<(), BackendError> {
        let json = value
            .to_json_string()
            .map_err(|_| BackendError::Validation {
                target: target.clone(),
                reason: "the value is not UTF-8".into(),
            })?;
        let mut cmd = self.command();
        cmd.args(["set", "--input-type"])
            .arg(format.input_type())
            .arg("--output-type")
            .arg(format.input_type())
            .arg("--value-stdin")
            .arg(path)
            .arg(name.sops_path());
        let out = self.run(cmd, Some(&json), 0, "set", target.clone())?;
        if !out.status.success() {
            let inner = &json[1..json.len() - 1];
            return Err(failed("set", target, &out, &[value.expose(), inner]));
        }
        Ok(())
    }

    /// `sops unset` of `name` in the temp copy at `path`.
    pub fn unset(
        &self,
        format: SopsFormat,
        path: &Path,
        name: &Name,
        target: Target,
    ) -> Result<(), BackendError> {
        let mut cmd = self.command();
        cmd.args(["unset", "--input-type"])
            .arg(format.input_type())
            .arg("--output-type")
            .arg(format.input_type())
            .arg(path)
            .arg(name.sops_path());
        let out = self.run(cmd, None, 0, "unset", target.clone())?;
        if !out.status.success() {
            return Err(failed("unset", target, &out, &[]));
        }
        Ok(())
    }

    /// Decrypt one string entry of `bytes`, fed to sops on stdin. sops reads
    /// the bytes secrit checked, not a path that could change in between
    /// (SEC-11), and `--extract` prints the raw string into a fixed buffer
    /// (SEC-8).
    pub fn decrypt_one(
        &self,
        format: SopsFormat,
        bytes: &[u8],
        name: &Name,
        step: &'static str,
        target: Target,
        secrets: &[&[u8]],
    ) -> Result<SecretValue, BackendError> {
        let mut cmd = self.command();
        cmd.args(["decrypt", "--input-type"])
            .arg(format.input_type())
            .args(["--output-type", "json", "--extract"])
            .arg(name.sops_path())
            .arg("/dev/stdin");
        let out = self.run(cmd, Some(bytes), MAX_VALUE_BYTES, step, target.clone())?;
        if !out.status.success() {
            return Err(failed(step, target, &out, secrets));
        }
        let mut stdout = out.stdout;
        Ok(SecretValue::new(std::mem::take(&mut *stdout)))
    }

    /// [`Self::run_unchecked`] after the once-only checks. `step` and
    /// `target` name the run in its errors (PLAN 14).
    fn run(
        &self,
        cmd: Command,
        stdin: Option<&[u8]>,
        stdout_cap: usize,
        step: &'static str,
        target: Target,
    ) -> Result<ChildOutput, BackendError> {
        self.check_once()?;
        self.run_unchecked(cmd, stdin, stdout_cap, step, target)
    }

    fn run_unchecked(
        &self,
        cmd: Command,
        stdin: Option<&[u8]>,
        stdout_cap: usize,
        step: &'static str,
        target: Target,
    ) -> Result<ChildOutput, BackendError> {
        let timeout = child::timeout();
        child::run(cmd, stdin, stdout_cap, timeout).map_err(|e| match e {
            ChildError::Io(source) => BackendError::Io {
                step: "run",
                path: self.sops.clone(),
                source,
            },
            ChildError::Interrupted => BackendError::Interrupted,
            ChildError::Stopped => BackendError::ToolPrompt {
                tool: TOOL,
                step,
                target,
                hint: PROMPT_HINT.into(),
            },
            ChildError::Timeout => BackendError::ToolTimeout {
                tool: TOOL,
                step,
                target,
                after: timeout,
            },
            ChildError::Overflow => BackendError::ToolOutputTooLarge {
                tool: TOOL,
                step,
                target,
            },
        })
    }
}

/// The error of a sops run that exited with a failure. Its stderr is
/// redacted against `secrets`.
pub fn failed(
    step: &'static str,
    target: Target,
    out: &ChildOutput,
    secrets: &[&[u8]],
) -> BackendError {
    BackendError::Tool {
        tool: TOOL,
        step,
        target,
        status: ToolStatus(out.status.code()),
        stderr: redact(&out.stderr, secrets),
    }
}

fn parse_sops_version(text: &str) -> Option<(u64, u64, u64)> {
    let word = text
        .split_whitespace()
        .skip_while(|w| *w != "sops")
        .nth(1)?;
    let mut parts = word.trim_start_matches('v').splitn(3, '.');
    let mut next = || -> Option<u64> {
        let p = parts.next()?;
        let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    Some((next()?, next()?, next()?))
}

/// Shortest line of a multiline value that is matched on its own.
const MIN_LINE_NEEDLE: usize = 4;
/// The most child stderr lines an error shows.
const MAX_STDERR_LINES: usize = 20;

/// Child stderr for an error message. A line that holds a secret, its JSON
/// form or one of its lines is dropped whole: an inline mark would show
/// where a short value sits in otherwise fixed text (SEC-15). The rest is
/// escaped and cut to [`MAX_STDERR_LINES`] lines; a note says how many more
/// there were.
pub fn redact(stderr: &[u8], secrets: &[&[u8]]) -> String {
    let mut needles: Vec<&[u8]> = Vec::new();
    for s in secrets.iter().filter(|s| !s.is_empty()) {
        needles.push(s);
        needles.extend(
            s.split(|b| *b == b'\n')
                .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
                .filter(|l| l.len() >= MIN_LINE_NEEDLE && l.len() < s.len()),
        );
    }
    let contains = |hay: &[u8], n: &[u8]| hay.windows(n.len()).any(|w| w == n);
    let mut hidden = 0usize;
    let mut cut = 0usize;
    let mut shown: Vec<String> = Vec::new();
    for line in stderr.split(|b| *b == b'\n') {
        if needles.iter().any(|n| contains(line, n)) {
            hidden += 1;
            continue;
        }
        let text = String::from_utf8_lossy(line);
        let text = text.trim_end();
        if text.trim().is_empty() {
            continue;
        }
        if shown.len() < MAX_STDERR_LINES {
            shown.push(escape(text).into_owned());
        } else {
            cut += 1;
        }
    }
    if cut > 0 {
        shown.push(format!("({cut} more line(s) not shown)"));
    }
    if hidden > 0 {
        shown.push(format!(
            "({hidden} line(s) not shown, because they may hold the value)"
        ));
    }
    if shown.is_empty() {
        String::new()
    } else {
        format!(":\n  {}", shown.join("\n  "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-15: lines with a secret, its JSON form or one of its lines are
    /// dropped whole, and the rest is escaped.
    #[test]
    fn redact_drops_lines_that_hold_a_secret() {
        let out = redact(
            b"error: hunter2 is bad\nplain line\nsee \"multi\\nline\"\nthe second line here\n",
            &[b"hunter2", b"multi\\nline", b"first\nsecond line"],
        );
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("multi"));
        assert!(!out.contains("second line"));
        assert!(!out.contains("is bad"), "the whole line must go");
        assert!(out.contains("plain line"));
        assert!(out.contains("3 line(s) not shown"));

        let short = redact(b"error: the file\nthe end\n", &[b"e"]);
        assert!(!short.contains("the file") && !short.contains("the end"));
        assert!(short.contains("2 line(s) not shown"));

        let ctl = redact(b"bad \x1b[2J here\n", &[]);
        assert!(ctl.contains("\\x1b") && !ctl.contains('\x1b'));

        // The header line, 20 lines, and a note for the 30 that were cut.
        let many: Vec<u8> = (0..50)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .collect();
        let out = redact(&many, &[]);
        assert_eq!(out.lines().count(), 22);
        assert!(out.contains("line 19") && !out.contains("line 20"));
        assert!(out.contains("(30 more line(s) not shown)"), "{out}");

        // Cut lines and hidden lines are counted apart.
        let mixed: Vec<u8> = (0..25)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .chain(b"hunter2 leaked\n".iter().copied())
            .collect();
        let out = redact(&mixed, &[b"hunter2"]);
        assert!(out.contains("(5 more line(s) not shown)"), "{out}");
        assert!(out.contains("(1 line(s) not shown, because"), "{out}");
        assert!(!out.contains("hunter2"));

        let exact: Vec<u8> = (0..20)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .collect();
        assert!(!redact(&exact, &[]).contains("more line(s)"));
    }

    #[test]
    fn sops_versions_parse() {
        assert_eq!(parse_sops_version("sops 3.13.3\n"), Some((3, 13, 3)));
        assert_eq!(
            parse_sops_version("sops 3.11.0 (latest)\n"),
            Some((3, 11, 0))
        );
        assert_eq!(parse_sops_version("sops 3.10.2-rc1"), Some((3, 10, 2)));
        assert_eq!(parse_sops_version("nothing here"), None);
        assert!((3, 10) < MIN_SOPS && (3, 11) >= MIN_SOPS && (4, 0) >= MIN_SOPS);
    }
}
