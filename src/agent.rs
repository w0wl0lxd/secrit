//! Agent detection (PLAN section 8.3) and the write gate (PLAN-v0.2
//! section 4).
//!
//! An agent is detected when a known agent variable is set and not empty in
//! secrit's own environment or in the environment of an ancestor process,
//! or when `/dev/tty` cannot be opened. There is no override variable: an
//! agent can set any variable. This prevents accidents; it is not a security
//! boundary (PLAN N1, PLAN-v0.2 4.4).

use std::ffi::OsString;
use std::fmt;

/// Variables that coding agents set in the shells they run.
pub const AGENT_VARS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "AI_AGENT",
    "AGENT",
    // Codex sets CODEX_SANDBOX on macOS only (the Seatbelt sandbox). On Linux
    // CODEX_THREAD_ID is the signal.
    "CODEX_SANDBOX",
    "CODEX_THREAD_ID",
    "CURSOR_AGENT",
    "GEMINI_CLI",
    "CLINE_ACTIVE",
    // opencode sets OPENCODE=1 at start (packages/opencode/src/index.ts).
    "OPENCODE",
    "OPENCODE_CLIENT",
    // Copilot CLI sets COPILOT_CLI=1 for its subprocesses. Source: the
    // vendor changelog only; the program source is not public.
    "COPILOT_CLI",
];

/// The most ancestors the walk reads. It also ends a cycle in `/proc`.
pub const MAX_ANCESTORS: usize = 64;

/// The most bytes read from the environment of one ancestor. The kernel
/// keeps the arguments and the environment in at most a quarter of the
/// stack limit, so a larger read is rare.
#[cfg(target_os = "linux")]
const MAX_ENVIRON_BYTES: u64 = 4 << 20;

/// The text of every write refusal with no terminal (Q19).
pub const NO_TTY_REFUSAL: &str = "refused: no terminal to confirm on. CI or a remote job: use 'secrit seal'. A scheduled job: run it as its own system service. Over ssh: use ssh -t.";

/// A process name as the kernel keeps it (`comm`): at most 15 bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Comm {
    bytes: [u8; 16],
    len: u8,
}

impl Comm {
    #[must_use]
    pub fn new(name: &[u8]) -> Self {
        let mut bytes = [0u8; 16];
        let len = name.len().min(bytes.len());
        bytes[..len].copy_from_slice(&name[..len]);
        Self {
            bytes,
            len: u8::try_from(len).unwrap_or(16),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Display for Comm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::display::escape(&String::from_utf8_lossy(
            self.as_bytes(),
        )))
    }
}

impl fmt::Debug for Comm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Comm({self})")
    }
}

/// Why secrit thinks an agent runs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Variable(&'static str),
    /// An ancestor process has the variable in its environment.
    Ancestor {
        var: &'static str,
        pid: u32,
        comm: Comm,
    },
    NoTty,
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Agent::Variable(v) => write!(f, "{v} is set"),
            Agent::Ancestor { var, pid, comm } => {
                write!(f, "{var} is set in ancestor process {pid} ({comm})")
            }
            Agent::NoTty => f.write_str("/dev/tty cannot be opened"),
        }
    }
}

/// Detect an agent from an environment lookup, an ancestor walk and the
/// `/dev/tty` result. The walk runs only when the own environment has no
/// variable.
pub fn detect_with(
    env: &dyn Fn(&str) -> Option<OsString>,
    ancestors: &dyn Fn() -> Option<Agent>,
    tty_opens: bool,
) -> Option<Agent> {
    for var in AGENT_VARS {
        if env(var).is_some_and(|v| !v.is_empty()) {
            return Some(Agent::Variable(var));
        }
    }
    if let Some(a) = ancestors() {
        return Some(a);
    }
    if tty_opens { None } else { Some(Agent::NoTty) }
}

/// Detect an agent in the current process.
#[must_use]
pub fn detect() -> Option<Agent> {
    detect_tty(tty_opens())
}

/// [`detect`] with a `/dev/tty` result that the caller already has.
#[must_use]
pub fn detect_tty(tty_opens: bool) -> Option<Agent> {
    detect_with(&|k| std::env::var_os(k), &ancestor_agent, tty_opens)
}

/// Whether this process has a controlling terminal it can open.
#[must_use]
pub fn tty_opens() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

/// What the write gate does (PLAN-v0.2 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteGate {
    Allow,
    /// Ask for the name on `/dev/tty`.
    ConfirmOnTty(Agent),
    /// Refuse with [`NO_TTY_REFUSAL`].
    Refuse,
}

/// The write gate of `store`, `rm`, `generate` and `init`.
#[must_use]
pub fn write_gate(agent: Option<Agent>, tty_opens: bool) -> WriteGate {
    match (agent, tty_opens) {
        (None, true) => WriteGate::Allow,
        (Some(Agent::NoTty) | None, _) | (_, false) => WriteGate::Refuse,
        (Some(a), true) => WriteGate::ConfirmOnTty(a),
    }
}

/// What a decrypt of a gated store does (PLAN-v0.2 6.7.2 rules 5 and 6).
/// There is no typed-name path: it would train the owner to touch the token
/// for a command that an agent started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), expect(dead_code, reason = "S8b adds the gated store"))]
pub enum GatedDecrypt {
    Allow,
    RefuseAgent(Agent),
    RefuseNoTty,
}

/// The decrypt gate of a gated store.
///
/// TODO(S8b): the gated store (`format = "yaml-dir"` with a `plugin`
/// identity) calls this before sops runs, for `get`, `run` and every other
/// decrypt. No store is gated before S8b, so nothing calls it yet.
#[must_use]
#[cfg_attr(not(test), expect(dead_code, reason = "S8b adds the gated store"))]
pub fn gated_decrypt(agent: Option<Agent>, tty_opens: bool) -> GatedDecrypt {
    match (agent, tty_opens) {
        (Some(Agent::NoTty), _) | (_, false) => GatedDecrypt::RefuseNoTty,
        (Some(a), true) => GatedDecrypt::RefuseAgent(a),
        (None, true) => GatedDecrypt::Allow,
    }
}

/// One process as the walk sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcInfo {
    pub ppid: u32,
    pub comm: Comm,
    /// The first agent variable in its environment, if it can be read.
    pub var: Option<&'static str>,
}

/// Walk from `first` up the parents, at most [`MAX_ANCESTORS`] steps, and
/// return the first process with an agent variable. The walk ends at pid 0,
/// after pid 1, at `stop`, or at a process that `read` cannot see.
pub fn walk(
    first: u32,
    stop: Option<u32>,
    read: &dyn Fn(u32) -> Option<ProcInfo>,
) -> Option<Agent> {
    let mut pid = first;
    for _ in 0..MAX_ANCESTORS {
        if pid == 0 || Some(pid) == stop {
            return None;
        }
        let info = read(pid)?;
        if let Some(var) = info.var {
            return Some(Agent::Ancestor {
                var,
                pid,
                comm: info.comm,
            });
        }
        if pid == 1 {
            return None;
        }
        pid = info.ppid;
    }
    None
}

/// The parent pid and the name in `/proc/PID/stat`. The name is in
/// parentheses and can hold spaces and `)`, so the fields after it start
/// after the last `)`.
#[must_use]
pub fn parse_stat(stat: &[u8]) -> Option<(Comm, u32)> {
    let open = stat.iter().position(|&b| b == b'(')?;
    let close = stat.iter().rposition(|&b| b == b')')?;
    let comm = Comm::new(stat.get(open + 1..close)?);
    let rest = std::str::from_utf8(stat.get(close + 1..)?).ok()?;
    let mut fields = rest.split_ascii_whitespace();
    let _state = fields.next()?;
    let ppid = fields.next()?.parse().ok()?;
    Some((comm, ppid))
}

/// The first agent variable that is set and not empty in a
/// `/proc/PID/environ` block (`NAME=value` entries, each ended by a NUL).
#[must_use]
pub fn environ_var(environ: &[u8]) -> Option<&'static str> {
    let set: Vec<&[u8]> = environ
        .split(|&b| b == 0)
        .filter_map(|entry| {
            let eq = entry.iter().position(|&b| b == b'=')?;
            (eq + 1 < entry.len()).then(|| &entry[..eq])
        })
        .collect();
    AGENT_VARS
        .iter()
        .copied()
        .find(|var| set.contains(&var.as_bytes()))
}

/// The ancestor walk over `/proc` (PLAN-v0.2 4.1).
#[cfg(target_os = "linux")]
fn ancestor_agent() -> Option<Agent> {
    let parent = rustix::process::getppid()?.as_raw_pid().cast_unsigned();
    walk(parent, crate::testhook::ancestor_stop(), &read_proc)
}

#[cfg(not(target_os = "linux"))]
fn ancestor_agent() -> Option<Agent> {
    None
}

#[cfg(target_os = "linux")]
fn read_proc(pid: u32) -> Option<ProcInfo> {
    use std::io::Read;
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let (comm, parent) = parse_stat(&stat)?;
    // The environment of another process can hold secrets of its own, so
    // the copy is wiped. A process that secrit cannot read has no variable.
    let mut environ = zeroize::Zeroizing::new(Vec::new());
    let var = std::fs::File::open(format!("/proc/{pid}/environ"))
        .and_then(|f| f.take(MAX_ENVIRON_BYTES).read_to_end(&mut environ))
        .ok()
        .and_then(|_| environ_var(&environ));
    Some(ProcInfo {
        ppid: parent,
        comm,
        var,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        move |k| map.get(k).cloned()
    }

    fn no_ancestor() -> Option<Agent> {
        None
    }

    fn sh_ancestor() -> Agent {
        Agent::Ancestor {
            var: "CLAUDECODE",
            pid: 42,
            comm: Comm::new(b"sh"),
        }
    }

    #[test]
    fn no_agent_with_tty_and_clean_env() {
        assert_eq!(detect_with(&env_of(&[]), &no_ancestor, true), None);
    }

    #[test]
    fn every_listed_variable_is_detected() {
        for var in AGENT_VARS {
            let env = env_of(&[(var, "1")]);
            assert_eq!(
                detect_with(&env, &no_ancestor, true),
                Some(Agent::Variable(var))
            );
        }
    }

    #[test]
    fn empty_variable_is_ignored() {
        assert_eq!(
            detect_with(&env_of(&[("CLAUDECODE", "")]), &no_ancestor, true),
            None
        );
    }

    #[test]
    fn no_tty_is_detected() {
        assert_eq!(
            detect_with(&env_of(&[]), &no_ancestor, false),
            Some(Agent::NoTty)
        );
    }

    #[test]
    fn variable_wins_over_tty() {
        let env = env_of(&[("CODEX_SANDBOX", "seatbelt")]);
        assert_eq!(
            detect_with(&env, &no_ancestor, false),
            Some(Agent::Variable("CODEX_SANDBOX"))
        );
    }

    /// The own variable comes first, so the walk does not run; an ancestor
    /// comes before the tty result.
    #[test]
    fn ancestor_order() {
        let env = env_of(&[("AGENT", "x")]);
        let never = || -> Option<Agent> { panic!("the walk ran") };
        assert_eq!(
            detect_with(&env, &never, true),
            Some(Agent::Variable("AGENT"))
        );
        assert_eq!(
            detect_with(&env_of(&[]), &|| Some(sh_ancestor()), false),
            Some(sh_ancestor())
        );
    }

    /// PLAN-v0.2 4.1: one case per row of the table, plus an ancestor.
    #[test]
    fn write_gate_matrix() {
        let v = Agent::Variable("CLAUDECODE");
        assert_eq!(write_gate(None, true), WriteGate::Allow);
        assert_eq!(write_gate(Some(v), true), WriteGate::ConfirmOnTty(v));
        assert_eq!(write_gate(Some(v), false), WriteGate::Refuse);
        assert_eq!(write_gate(Some(Agent::NoTty), false), WriteGate::Refuse);
        let a = sh_ancestor();
        assert_eq!(write_gate(Some(a), true), WriteGate::ConfirmOnTty(a));
        assert_eq!(write_gate(Some(a), false), WriteGate::Refuse);
        // Not produced by detection, but never an Allow.
        assert_eq!(write_gate(None, false), WriteGate::Refuse);
        assert_eq!(write_gate(Some(Agent::NoTty), true), WriteGate::Refuse);
    }

    /// PLAN-v0.2 6.7.2 rules 5 and 6: no typed-name path for a gated
    /// decrypt.
    #[test]
    fn gated_decrypt_matrix() {
        let v = Agent::Variable("CLAUDECODE");
        assert_eq!(gated_decrypt(None, true), GatedDecrypt::Allow);
        assert_eq!(gated_decrypt(Some(v), true), GatedDecrypt::RefuseAgent(v));
        assert_eq!(gated_decrypt(Some(v), false), GatedDecrypt::RefuseNoTty);
        assert_eq!(
            gated_decrypt(Some(Agent::NoTty), false),
            GatedDecrypt::RefuseNoTty
        );
        assert_eq!(gated_decrypt(None, false), GatedDecrypt::RefuseNoTty);
    }

    #[test]
    fn stat_is_parsed_after_the_last_parenthesis() {
        let (comm, ppid) = parse_stat(b"123 (a) (b c) S 77 123 123 0 -1").unwrap();
        assert_eq!(comm.to_string(), "a) (b c");
        assert_eq!(ppid, 77);
        let (comm, ppid) = parse_stat(b"9 (sh) R 1 9 9").unwrap();
        assert_eq!((comm.to_string().as_str(), ppid), ("sh", 1));
        assert_eq!(parse_stat(b"9 sh R 1"), None);
        assert_eq!(parse_stat(b"9 (sh) R"), None);
    }

    #[test]
    fn a_control_character_in_a_name_is_escaped() {
        assert_eq!(Comm::new(b"a\x1bb").to_string(), "a\\x1bb");
    }

    #[test]
    fn environ_names_match_exactly() {
        assert_eq!(environ_var(b"HOME=/h\0CLAUDECODE=1\0"), Some("CLAUDECODE"));
        assert_eq!(environ_var(b"CLAUDECODE=\0"), None);
        assert_eq!(environ_var(b"CLAUDECODEX=1\0XCLAUDECODE=1\0"), None);
        assert_eq!(environ_var(b"X=CLAUDECODE=1\0"), None);
        assert_eq!(environ_var(b"OPENCODE=1"), Some("OPENCODE"));
        assert_eq!(environ_var(b""), None);
    }

    fn tree(
        procs: &[(u32, u32, &'static str, Option<&'static str>)],
    ) -> impl Fn(u32) -> Option<ProcInfo> {
        let map: HashMap<u32, ProcInfo> = procs
            .iter()
            .map(|&(pid, ppid, comm, var)| {
                (
                    pid,
                    ProcInfo {
                        ppid,
                        comm: Comm::new(comm.as_bytes()),
                        var,
                    },
                )
            })
            .collect();
        move |pid| map.get(&pid).copied()
    }

    #[test]
    fn the_walk_names_the_first_ancestor_with_a_variable() {
        let read = tree(&[
            (30, 20, "env", None),
            (20, 10, "sh", Some("CLAUDECODE")),
            (10, 1, "agent", Some("AGENT")),
            (1, 0, "init", None),
        ]);
        assert_eq!(
            walk(30, None, &read),
            Some(Agent::Ancestor {
                var: "CLAUDECODE",
                pid: 20,
                comm: Comm::new(b"sh"),
            })
        );
        assert_eq!(
            walk(30, None, &read).unwrap().to_string(),
            "CLAUDECODE is set in ancestor process 20 (sh)"
        );
    }

    #[test]
    fn the_walk_stops_at_the_stop_pid_and_at_init() {
        let read = tree(&[
            (30, 20, "env", None),
            (20, 10, "test", None),
            (10, 1, "agent", Some("CLAUDECODE")),
            (1, 0, "init", None),
        ]);
        assert_eq!(walk(30, Some(20), &read), None);
        assert!(walk(30, None, &read).is_some());
        let read = tree(&[(5, 1, "x", None), (1, 1, "init", None)]);
        assert_eq!(walk(5, None, &read), None);
        let read = tree(&[(1, 0, "init", Some("AGENT"))]);
        assert!(walk(1, None, &read).is_some());
    }

    /// A cycle or a missing process ends the walk.
    #[test]
    fn the_walk_is_bounded() {
        let read = tree(&[(7, 8, "a", None), (8, 7, "b", None)]);
        assert_eq!(walk(7, None, &read), None);
        let read = tree(&[(7, 99, "a", None)]);
        assert_eq!(walk(7, None, &read), None);
        let calls = std::cell::Cell::new(0usize);
        let counting = |pid: u32| {
            calls.set(calls.get() + 1);
            Some(ProcInfo {
                ppid: pid + 1,
                comm: Comm::new(b"p"),
                var: None,
            })
        };
        assert_eq!(walk(2, None, &counting), None);
        assert_eq!(calls.get(), MAX_ANCESTORS);
    }

    /// PLAN 8.3: the README lists every variable, so it cannot drift.
    #[test]
    fn the_readme_lists_every_variable() {
        let readme = include_str!("../README.md");
        for v in AGENT_VARS {
            assert!(readme.contains(&format!("`{v}`")), "README misses {v}");
        }
    }
}
