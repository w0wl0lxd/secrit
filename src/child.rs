//! Bounded child runs (PLAN section 8.1, step 8; R1, R10).
//!
//! Every external program secrit starts (sops, age-keygen, git) runs here:
//! in its own process group, with a deadline, with capped stdout, and with
//! the whole group killed and reaped before [`run`] returns.

use std::io::{self, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
use zeroize::{Zeroize, Zeroizing};

use crate::signals;

/// The longest one child run may take. With an age key file, sops needs well
/// under a second; a run this long waits on something that will not come.
pub const TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(20);
const MAX_STDERR_BYTES: usize = 64 * 1024;

/// [`TIMEOUT`], or a shorter one from the test hook.
#[must_use]
pub fn timeout() -> Duration {
    #[cfg(feature = "test-hooks")]
    if let Some(ms) = std::env::var("SECRIT_TEST_CHILD_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return Duration::from_millis(ms);
    }
    TIMEOUT
}

/// What a finished child left.
#[derive(Debug)]
pub struct ChildOutput {
    pub status: ExitStatus,
    pub stdout: Zeroizing<Vec<u8>>,
    pub stderr: Zeroizing<Vec<u8>>,
}

/// Why a child run did not finish on its own.
#[derive(Debug)]
pub enum ChildError {
    Io(io::Error),
    /// A deferred signal arrived.
    Interrupted,
    /// The child stopped: it read the terminal from a background group.
    Stopped,
    Timeout,
    /// stdout passed its cap.
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
        match waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED
                | WaitIdOptions::STOPPED
                | WaitIdOptions::NOHANG
                | WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(st)) if st.stopped() => return Err(ChildError::Stopped),
            Ok(Some(_)) => return Ok(()),
            Ok(None) | Err(Errno::INTR) => {}
            Err(e) => return Err(ChildError::Io(e.into())),
        }
        if signals::pending() {
            return Err(ChildError::Interrupted);
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
}
