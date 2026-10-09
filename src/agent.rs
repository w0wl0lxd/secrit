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
#[cfg(any(target_os = "linux", test))]
const MAX_ENVIRON_BYTES: u64 = 4 << 20;

/// The size of the one buffer that the environment of an ancestor is read
/// into.
#[cfg(any(target_os = "linux", test))]
const ENVIRON_CHUNK: usize = 64 << 10;

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

/// One bit for each entry of [`AGENT_VARS`].
#[cfg(any(target_os = "linux", test))]
const ALL_AGENT_VARS: u32 = (1 << AGENT_VARS.len()) - 1;
#[cfg(any(target_os = "linux", test))]
const _: () = assert!(AGENT_VARS.len() < 32);

/// Finds the first agent variable (in [`AGENT_VARS`] order) that is set and
/// not empty in a `/proc/PID/environ` block (`NAME=value` entries, each
/// ended by a NUL) that comes in pieces. It keeps no byte of the block: only
/// the agent names that still match the current name, and the name length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
struct EnvironScan {
    state: ScanState,
    found: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(target_os = "linux", test))]
enum ScanState {
    /// In a name: the bits of the agent variables that the name matches so
    /// far, and the name length.
    Name { candidates: u32, len: usize },
    /// After `NAME=` for this index of [`AGENT_VARS`]: the next byte tells
    /// whether the value is empty.
    Value(usize),
    /// In an entry that cannot match, up to its NUL.
    Skip,
}

#[cfg(any(target_os = "linux", test))]
impl EnvironScan {
    const ENTRY_START: ScanState = ScanState::Name {
        candidates: ALL_AGENT_VARS,
        len: 0,
    };

    fn new() -> Self {
        Self {
            state: Self::ENTRY_START,
            found: None,
        }
    }

    fn feed(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state = match self.state {
                _ if b == 0 => Self::ENTRY_START,
                ScanState::Name { candidates, len } if b == b'=' => AGENT_VARS
                    .iter()
                    .enumerate()
                    .find(|&(i, var)| candidates & (1 << i) != 0 && var.len() == len)
                    .map_or(ScanState::Skip, |(i, _)| ScanState::Value(i)),
                ScanState::Name { candidates, len } => {
                    let candidates = AGENT_VARS
                        .iter()
                        .enumerate()
                        .filter(|&(i, var)| {
                            candidates & (1 << i) != 0 && var.as_bytes().get(len) == Some(&b)
                        })
                        .fold(0, |bits, (i, _)| bits | (1 << i));
                    if candidates == 0 {
                        ScanState::Skip
                    } else {
                        ScanState::Name {
                            candidates,
                            len: len + 1,
                        }
                    }
                }
                ScanState::Value(i) => {
                    self.found = Some(self.found.map_or(i, |f| f.min(i)));
                    ScanState::Skip
                }
                ScanState::Skip => ScanState::Skip,
            };
        }
    }

    fn finish(self) -> Option<&'static str> {
        self.found.and_then(|i| AGENT_VARS.get(i).copied())
    }
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
    let stat = std::fs::read(format!("/proc/{pid}/stat")).ok()?;
    let (comm, parent) = parse_stat(&stat)?;
    // A process that secrit cannot read has no variable.
    let var = std::fs::File::open(format!("/proc/{pid}/environ"))
        .and_then(read_environ_var)
        .ok()
        .flatten();
    Some(ProcInfo {
        ppid: parent,
        comm,
        var,
    })
}

/// The first agent variable in an environment block read from `reader`, at
/// most [`MAX_ENVIRON_BYTES`]. The environment of another process can hold
/// secrets of its own, so it goes through one fixed buffer that is wiped,
/// never a buffer that grows (and frees old copies).
#[cfg(any(target_os = "linux", test))]
fn read_environ_var(reader: impl std::io::Read) -> std::io::Result<Option<&'static str>> {
    let mut buf = zeroize::Zeroizing::new(vec![0u8; ENVIRON_CHUNK]);
    scan_environ(reader, &mut buf)
}

/// [`read_environ_var`] with the caller's buffer.
#[cfg(any(target_os = "linux", test))]
fn scan_environ(
    reader: impl std::io::Read,
    buf: &mut [u8],
) -> std::io::Result<Option<&'static str>> {
    use std::io::Read;
    let mut reader = reader.take(MAX_ENVIRON_BYTES);
    let mut scan = EnvironScan::new();
    loop {
        match reader.read(buf) {
            Ok(0) => return Ok(scan.finish()),
            Ok(n) => scan.feed(buf.get(..n).unwrap_or(buf)),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
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

    fn environ_var(environ: &[u8]) -> Option<&'static str> {
        let mut scan = EnvironScan::new();
        scan.feed(environ);
        scan.finish()
    }

    /// The scan in pieces of every size gives the same result as in one
    /// piece: a name, the `=` or the first value byte can be split across
    /// pieces.
    #[test]
    fn the_environ_scan_does_not_depend_on_the_chunks() {
        let cases: &[(&[u8], Option<&str>)] = &[
            (b"HOME=/h\0CLAUDECODE=1\0", Some("CLAUDECODE")),
            (b"CLAUDECODE=\0AGENT=\0", None),
            (b"CLAUDECODEX=1\0XCLAUDECODE=1\0CLAUDE=1\0", None),
            (b"X=CLAUDECODE=1\0=AGENT=1\0", None),
            (b"OPENCODE_CLIENT=x\0OPENCODE=1", Some("OPENCODE")),
            (b"COPILOT_CLI=1\0AI_AGENT=1\0", Some("AI_AGENT")),
            (b"AGENT=", None),
            (b"AGENT\0CLAUDECODE\0", None),
        ];
        for &(environ, want) in cases {
            for size in 1..=environ.len().max(1) {
                let mut scan = EnvironScan::new();
                for chunk in environ.chunks(size) {
                    scan.feed(chunk);
                }
                assert_eq!(scan.finish(), want, "{environ:?} in pieces of {size}");
                let mut buf = vec![0u8; size];
                assert_eq!(scan_environ(environ, &mut buf).unwrap(), want);
            }
        }
    }

    /// An entry longer than the buffer: a long name that starts like an
    /// agent name, a long value of an agent variable, and a long entry before
    /// an agent variable.
    #[test]
    fn an_environ_entry_can_be_longer_than_the_buffer() {
        let long = [b'x'; 100];
        let mut buf = [0u8; 4];
        let with = |parts: &[&[u8]]| parts.concat();
        let name = with(&[b"CLAUDECODE", &long, b"=1\0"]);
        assert_eq!(scan_environ(name.as_slice(), &mut buf).unwrap(), None);
        let value = with(&[b"AGENT=", &long, b"\0"]);
        assert_eq!(
            scan_environ(value.as_slice(), &mut buf).unwrap(),
            Some("AGENT")
        );
        let before = with(&[b"A=", &long, b"\0", b"GEMINI_CLI=1\0"]);
        assert_eq!(
            scan_environ(before.as_slice(), &mut buf).unwrap(),
            Some("GEMINI_CLI")
        );
    }

    /// The read stops at [`MAX_ENVIRON_BYTES`].
    #[test]
    fn the_environ_read_is_capped() {
        let entry = b"CLAUDECODE=1\0";
        let cap = usize::try_from(MAX_ENVIRON_BYTES).unwrap();
        let mut data = vec![0u8; cap - entry.len()];
        data.extend_from_slice(entry);
        assert_eq!(
            read_environ_var(data.as_slice()).unwrap(),
            Some("CLAUDECODE")
        );
        let mut over = vec![0u8; entry.len()];
        over.extend_from_slice(&data);
        assert_eq!(read_environ_var(over.as_slice()).unwrap(), None);
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

    /// A reader that records the address and the length of every buffer it
    /// is given.
    struct Recording<'a> {
        data: &'a [u8],
        bufs: Vec<(usize, usize)>,
    }

    impl std::io::Read for Recording<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.bufs.push((buf.as_ptr().addr(), buf.len()));
            let n = buf.len().min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    /// Review S1b-1: a buffer that grows frees its old copy without a wipe.
    /// The environment of an ancestor is read into one fixed buffer, so
    /// every read gets the same address and at most [`ENVIRON_CHUNK`] bytes.
    #[test]
    fn the_environ_read_uses_one_fixed_buffer() {
        let mut data = Vec::new();
        while data.len() < 3 * ENVIRON_CHUNK {
            data.extend_from_slice(b"SOME_SECRET=0123456789abcdef0123456789abcdef\0");
        }
        data.extend_from_slice(b"CLAUDECODE=1\0");
        let mut reader = Recording {
            data: &data,
            bufs: Vec::new(),
        };
        assert_eq!(read_environ_var(&mut reader).unwrap(), Some("CLAUDECODE"));
        let first = reader.bufs[0].0;
        for &(addr, len) in &reader.bufs {
            assert_eq!(addr, first, "a read used a second buffer");
            assert!(len <= ENVIRON_CHUNK, "a read of {len} bytes");
        }
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
