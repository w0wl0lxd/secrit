//! Bounded child runs (PLAN section 8.1, step 8; R1, R10).
//!
//! Every external program secrit starts (sops, age-keygen, git) runs here:
//! in its own process group, with a deadline, with capped stdout, and with
//! the whole group killed and reaped before [`run`] returns.
//!
//! The command of `secrit run` is different: [`supervise`] runs it in
//! secrit's own process group, with no deadline and no output cap, and
//! masks its output (v0.2 plan 7.1, step 5).

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::process::{
    Pid, Signal, WaitId, WaitIdOptions, getpid, kill_process, kill_process_group, waitid,
};
use zeroize::{Zeroize, Zeroizing};

use crate::mask::Masker;
use crate::signals;

/// The longest one child run may take. With an age key file, sops needs well
/// under a second; a run this long waits on something that will not come.
pub const TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(20);
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// [`TIMEOUT`], or a shorter one from the test hook.
#[must_use]
pub fn timeout() -> Duration {
    crate::testhook::child_timeout().unwrap_or(TIMEOUT)
}

/// What a finished child left.
#[derive(Debug)]
pub struct ChildOutput {
    pub status: ExitStatus,
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Zeroizing<Vec<u8>>,
}

/// Why a child run did not finish on its own. The messages hold no child
/// output, so a caller can show them as they are (PLAN 14).
#[derive(Debug, thiserror::Error)]
pub enum ChildError {
    #[error("could not run: {0}")]
    Io(io::Error),
    /// A deferred signal arrived.
    #[error("interrupted by a signal")]
    Interrupted,
    /// The child stopped: it read the terminal from a background group.
    #[error("stopped to read the terminal")]
    Stopped,
    #[error("did not finish in time")]
    Timeout,
    /// stdout passed its cap.
    #[error("printed too much")]
    Overflow,
}

impl From<io::Error> for ChildError {
    fn from(e: io::Error) -> Self {
        ChildError::Io(e)
    }
}

/// Run `cmd` in its own process group, feed `stdin`, and collect at most
/// `stdout_cap` bytes of stdout into a fixed buffer. Threads service the
/// pipes, so a large value or a chatty child cannot deadlock them. The main
/// thread polls the child until it exits, stops, overflows, times out or a
/// signal arrives. In every case the whole group is killed and the child is
/// reaped before this returns (R1, R10).
pub fn run(
    mut cmd: Command,
    stdin: Option<&[u8]>,
    stdout_cap: usize,
    timeout: Duration,
) -> Result<ChildOutput, ChildError> {
    // The child must be killed and reaped whatever arrives.
    let _critical = signals::Critical::enter();
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    if stdout_cap > 0 {
        cmd.stdout(Stdio::piped());
    }
    cmd.process_group(0);
    let mut child = cmd.spawn()?;
    let pid = Pid::from_child(&child);
    let child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();
    let overflow = AtomicBool::new(false);
    std::thread::scope(|s| {
        let writer = s.spawn(move || -> io::Result<()> {
            if let (Some(mut w), Some(data)) = (child_stdin, stdin) {
                match w.write_all(data) {
                    Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(e),
                    _ => {}
                }
            }
            Ok(())
        });
        let err_reader = s.spawn(move || {
            let mut buf = Zeroizing::new(Vec::with_capacity(MAX_STDERR_BYTES));
            if let Some(mut e) = child_stderr {
                let _ = (&mut e).take(MAX_STDERR_BYTES as u64).read_to_end(&mut buf);
                // Drain the rest, so the child never blocks on a full pipe.
                let _ = io::copy(&mut e, &mut io::sink());
            }
            buf
        });
        let overflow = &overflow;
        let out_reader = s.spawn(move || read_capped(child_stdout, stdout_cap, overflow));

        let waited = wait_child(pid, overflow, timeout);
        // The child is not reaped yet, so its pid still names its group. This
        // also ends any process it left behind holding a pipe open.
        let _ = kill_process_group(pid, Signal::KILL);
        let status = child.wait();
        let written = writer.join();
        let stderr = err_reader.join();
        let read = out_reader.join();
        waited?;
        let status = status?;
        written.map_err(|_| io::Error::other("stdin writer panicked"))??;
        let stderr = stderr.map_err(|_| io::Error::other("stderr reader panicked"))?;
        let (mut stdout, len) = read.map_err(|_| io::Error::other("stdout reader panicked"))??;
        if overflow.load(Ordering::SeqCst) {
            return Err(ChildError::Overflow);
        }
        stdout.truncate(len);
        Ok(ChildOutput {
            status,
            stdout,
            stderr,
        })
    })
}

/// Read at most `cap` bytes into a fixed buffer; set `overflow` and stop
/// when more arrive.
fn read_capped(
    pipe: Option<std::process::ChildStdout>,
    cap: usize,
    overflow: &AtomicBool,
) -> io::Result<(Zeroizing<Vec<u8>>, usize)> {
    let mut out = Zeroizing::new(vec![0u8; cap]);
    let mut len = 0;
    let Some(mut pipe) = pipe else {
        return Ok((out, 0));
    };
    loop {
        if len == cap {
            let mut probe = [0u8; 1];
            match pipe.read(&mut probe) {
                Ok(0) => break,
                Ok(_) => {
                    probe.zeroize();
                    overflow.store(true, Ordering::SeqCst);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
            continue;
        }
        match pipe.read(&mut out[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok((out, len))
}

/// Poll the child without reaping it (`WNOWAIT`), so its pid stays valid
/// for the group kill that follows.
fn wait_child(pid: Pid, overflow: &AtomicBool, timeout: Duration) -> Result<(), ChildError> {
    let deadline = Instant::now() + timeout;
    loop {
        let exited = match waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED
                | WaitIdOptions::STOPPED
                | WaitIdOptions::NOHANG
                | WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(st)) if st.stopped() => return Err(ChildError::Stopped),
            Ok(Some(_)) => true,
            Ok(None) | Err(Errno::INTR) => false,
            Err(e) => return Err(ChildError::Io(e.into())),
        };
        // Checked before an exit counts: a signal that arrives in the same
        // interval as the exit is not lost.
        if signals::pending() {
            return Err(ChildError::Interrupted);
        }
        if exited {
            return Ok(());
        }
        if overflow.load(Ordering::SeqCst) {
            return Err(ChildError::Overflow);
        }
        if Instant::now() >= deadline {
            return Err(ChildError::Timeout);
        }
        std::thread::sleep(POLL);
    }
}

/// How long the output of [`supervise`] stays idle before the masker
/// releases the bytes it holds (v0.2 plan 7.1, step 4).
pub const IDLE: Duration = Duration::from_millis(100);
/// How often [`supervise`] polls the command (v0.2 plan 7.1, step 5).
const SUPERVISE_POLL: Duration = Duration::from_millis(25);
const PUMP_BYTES: usize = 64 * 1024;

/// Run `cmd` for `secrit run` and mask its stdout and stderr (v0.2 plan
/// 7.1, step 5). The command inherits stdin and stays in secrit's process
/// group, the foreground group, so terminal signals reach both.
///
/// - INT and QUIT are recorded only: the command decides what they mean.
/// - TERM and HUP are forwarded to the command; secrit keeps waiting.
/// - TSTP does not stop secrit. When the command stops (Ctrl-Z), secrit
///   stops itself, so the shell sees the whole job stop. After `fg`
///   secrit sends CONT to the command and waits again. A stopped command
///   is never killed.
/// - No deadline and no output cap.
///
/// `handoff` is dropped right after the spawn: it holds secrit's copies of
/// the memfds, which only the command needs. `cmd` is dropped there too.
/// It holds the `--env` values, and std frees them without a wipe.
///
/// The pumps stop at the end of the output, or when the command has
/// exited and its output stays idle for [`IDLE`]. A process that the
/// command left behind and that writes later gets `EPIPE`.
pub fn supervise<H>(
    mut cmd: Command,
    maskers: [Masker; 2],
    handoff: H,
) -> Result<ExitStatus, ChildError> {
    let _critical = signals::Critical::enter();
    signals::record()?;
    let _ = signals::take();
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let spawned = cmd.spawn();
    drop(cmd);
    drop(handoff);
    let mut child = spawned?;
    let pid = Pid::from_child(&child);
    let out_pipe = child.stdout.take();
    let err_pipe = child.stderr.take();
    let exited = AtomicBool::new(false);
    let [out_masker, err_masker] = maskers;
    let result = std::thread::scope(|s| {
        let exited = &exited;
        let out = s.spawn(move || {
            let stdout = io::stdout();
            pump(out_pipe, stdout.as_fd(), out_masker, exited)
        });
        let err = s.spawn(move || {
            let stderr = io::stderr();
            pump(err_pipe, stderr.as_fd(), err_masker, exited)
        });
        let waited = wait_supervised(pid);
        if waited.is_err() {
            let _ = kill_process(pid, Signal::KILL);
        }
        exited.store(true, Ordering::SeqCst);
        // A write error (a closed stdout) only ends that pump; the command
        // then gets EPIPE, as in a pipeline.
        let _ = out.join();
        let _ = err.join();
        let status = child.wait();
        waited?;
        Ok(status?)
    });
    // A Ctrl-C that the command handled does not make secrit exit 130.
    signals::clear_pending();
    result
}

/// Poll the command until it exits. Forward TERM and HUP; follow a stop.
fn wait_supervised(pid: Pid) -> Result<(), ChildError> {
    loop {
        forward(pid);
        match waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED
                | WaitIdOptions::STOPPED
                | WaitIdOptions::NOHANG
                | WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(st)) if st.stopped() => {
                let _ = kill_process(getpid(), Signal::STOP);
                // Here again after a CONT, for example from `fg`.
                let _ = kill_process(pid, Signal::CONT);
            }
            Ok(Some(_)) => return Ok(()),
            Ok(None) | Err(Errno::INTR) => {}
            Err(e) => return Err(ChildError::Io(e.into())),
        }
        std::thread::sleep(SUPERVISE_POLL);
    }
}

/// Send TERM and HUP on to the command. INT, QUIT and TSTP reach it from
/// the terminal, or not at all.
fn forward(pid: Pid) {
    for sig in signals::take() {
        let signal = match sig {
            signal_hook::consts::SIGTERM => Signal::TERM,
            signal_hook::consts::SIGHUP => Signal::HUP,
            _ => continue,
        };
        let _ = kill_process(pid, signal);
    }
}

/// Copy `pipe` to `out` through `masker`. When the pipe stays idle for
/// [`IDLE`], release the held bytes (`flush_held`), so a prompt with no
/// newline is shown.
fn pump(
    pipe: Option<impl Read + AsFd>,
    out: BorrowedFd<'_>,
    mut masker: Masker,
    exited: &AtomicBool,
) -> io::Result<()> {
    let Some(mut pipe) = pipe else {
        return Ok(());
    };
    let idle = Timespec {
        tv_sec: 0,
        tv_nsec: IDLE.subsec_nanos().into(),
    };
    let mut buf = Zeroizing::new(vec![0u8; PUMP_BYTES]);
    loop {
        let mut fds = [PollFd::new(&pipe, PollFlags::IN)];
        match poll(&mut fds, Some(&idle)) {
            Ok(0) => {
                write_all(out, masker.flush_held())?;
                if exited.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            }
            Ok(_) => {}
            Err(Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let written = write_all(out, masker.feed(&buf[..n]));
                buf[..n].zeroize();
                written?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    write_all(out, masker.finish())
}

/// Write all of `data` to `out` with no buffer in between, so held bytes
/// leave at once and no copy stays in a std buffer.
fn write_all(out: BorrowedFd<'_>, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        match rustix::io::write(out, data) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => data = &data[n..],
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                // A non-blocking stdout: wait until it takes more.
                let mut fds = [PollFd::new(&out, PollFlags::OUT)];
                match poll(&mut fds, None) {
                    Ok(_) | Err(Errno::INTR) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        c
    }

    /// R1: a child that stops (as on a terminal read from a background
    /// group) is detected and killed, not waited on for ever.
    #[test]
    fn a_stopped_child_is_killed() {
        let started = Instant::now();
        let r = run(
            sh("kill -STOP $$; sleep 30"),
            None,
            0,
            Duration::from_secs(20),
        );
        assert!(matches!(r, Err(ChildError::Stopped)), "{r:?}", r = r.err());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// R1: a child that never finishes is killed at the deadline, together
    /// with a grandchild that holds its stderr open.
    #[test]
    fn a_slow_child_times_out() {
        let started = Instant::now();
        let r = run(
            sh("sleep 30 & sleep 30"),
            None,
            0,
            Duration::from_millis(200),
        );
        assert!(matches!(r, Err(ChildError::Timeout)), "{r:?}", r = r.err());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn output_is_capped_and_stdin_is_fed() {
        let mut c = sh("cat");
        c.stdout(Stdio::piped());
        let out = run(c, Some(b"abc"), 3, Duration::from_secs(20)).unwrap();
        assert!(out.status.success());
        assert_eq!(&out.stdout[..], b"abc");
        let r = run(sh("cat"), Some(b"abcd"), 3, Duration::from_secs(20));
        assert!(matches!(r, Err(ChildError::Overflow)), "{r:?}", r = r.err());
    }

    /// PLAN 14: the messages are fixed text, not the Debug form.
    #[test]
    fn errors_display_without_debug_text() {
        let all = [
            ChildError::Io(io::Error::from_raw_os_error(2)),
            ChildError::Interrupted,
            ChildError::Stopped,
            ChildError::Timeout,
            ChildError::Overflow,
        ];
        for e in all {
            let text = e.to_string();
            let debug = format!("{e:?}");
            assert_ne!(text, debug);
            for word in [
                "Io(",
                "Os {",
                "Interrupted",
                "Stopped",
                "Timeout",
                "Overflow",
            ] {
                assert!(!text.contains(word), "{text}");
            }
        }
        assert_eq!(ChildError::Timeout.to_string(), "did not finish in time");
    }
}
