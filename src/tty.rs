//! The controlling terminal (PLAN sections 4.1, 4.2 and 7.1).
//!
//! secrit reads values from `/dev/tty` itself instead of through a prompt
//! crate, so that:
//!
//! - one no-echo session covers a whole multiline read (SEC-7);
//! - tab and other characters reach the content rules unchanged, and a
//!   control character fails instead of being dropped (SEC-5);
//! - every wait polls the deferred-signal flag, so INT, TERM, HUP and QUIT
//!   restore the terminal and exit 130 (SEC-13).
//!
//! A [`ModeGuard`] restores the original terminal settings when it drops.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;
use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};

use crate::signals;

/// How often a blocked wait checks the signal flag.
const POLL_NS: i64 = 100_000_000;

/// The longest line the Linux terminal driver keeps in canonical mode. It
/// silently drops the rest of a longer line, so a line that reaches this
/// length is refused instead of stored cut short.
pub const CANON_LINE_MAX: usize = 4095;

/// Open the controlling terminal for reading and writing.
pub fn open() -> io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
}

/// Write `text` to the terminal and flush it.
pub fn say(mut tty: &File, text: &str) -> io::Result<()> {
    tty.write_all(text.as_bytes())?;
    tty.flush()
}

/// Changed terminal settings, restored on drop.
#[derive(Debug)]
pub struct ModeGuard<'a> {
    tty: &'a File,
    orig: Termios,
    /// Dropped after the settings are restored.
    _critical: signals::Critical,
}

impl<'a> ModeGuard<'a> {
    /// Line mode with no echo. The newline is still echoed (`ECHONL`), so the
    /// cursor moves on, but no typed character is shown.
    pub fn no_echo(tty: &'a File) -> io::Result<Self> {
        let critical = signals::Critical::enter();
        let orig = tcgetattr(tty)?;
        let mut t = orig.clone();
        t.local_modes
            .remove(LocalModes::ECHO | LocalModes::ECHOE | LocalModes::ECHOK);
        t.local_modes
            .insert(LocalModes::ICANON | LocalModes::ECHONL);
        tcsetattr(tty, OptionalActions::Now, &t)?;
        Ok(Self {
            tty,
            orig,
            _critical: critical,
        })
    }

    /// Raw mode: one byte at a time, no echo, and Ctrl-C is a key press.
    pub fn raw(tty: &'a File) -> io::Result<Self> {
        let critical = signals::Critical::enter();
        let orig = tcgetattr(tty)?;
        let mut t = orig.clone();
        t.make_raw();
        tcsetattr(tty, OptionalActions::Now, &t)?;
        Ok(Self {
            tty,
            orig,
            _critical: critical,
        })
    }
}

impl Drop for ModeGuard<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.tty, OptionalActions::Now, &self.orig);
    }
}

/// Why a terminal or stdin read stopped early.
#[derive(Debug)]
pub enum ReadError {
    /// A deferred signal arrived.
    Interrupted,
    /// The input does not fit in the buffer.
    BufferFull,
    /// One line reached [`CANON_LINE_MAX`], so the terminal may have cut it.
    LineTooLong,
    Io(io::Error),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        ReadError::Io(e)
    }
}

/// How a line ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEnd {
    Newline,
    /// End of input (Ctrl-D on an empty line, or a hang-up).
    Eof,
}

/// Wait until `fd` is readable (or at its end). `Err(Interrupted)` when a
/// deferred signal arrives first.
pub fn wait_readable(fd: impl AsFd) -> Result<(), ReadError> {
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: POLL_NS,
    };
    let _critical = signals::Critical::enter();
    loop {
        if signals::pending() {
            return Err(ReadError::Interrupted);
        }
        let mut fds = [PollFd::new(&fd, PollFlags::IN)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(Errno::INTR) => {}
            Ok(_) => return Ok(()),
            Err(e) => return Err(ReadError::Io(e.into())),
        }
    }
}

/// Read one line into `buf[*len..]` and advance `*len`. The newline is not
/// kept. `buf` is never grown, so no partial copy is left in freed memory.
pub fn read_line(tty: &File, buf: &mut [u8], len: &mut usize) -> Result<LineEnd, ReadError> {
    let start = *len;
    loop {
        wait_readable(tty)?;
        if *len == buf.len() {
            return Err(ReadError::BufferFull);
        }
        match (&*tty).read(&mut buf[*len..]) {
            Ok(0) => return Ok(LineEnd::Eof),
            Ok(n) => {
                *len += n;
                if buf[*len - 1] == b'\n' {
                    *len -= 1;
                    if *len - start >= CANON_LINE_MAX {
                        return Err(ReadError::LineTooLong);
                    }
                    return Ok(LineEnd::Newline);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ReadError::Io(e)),
        }
    }
}

/// Wait for one key in raw mode. The caller holds a [`ModeGuard::raw`].
pub fn wait_key(tty: &File) -> Result<(), ReadError> {
    let mut byte = [0u8; 1];
    loop {
        wait_readable(tty)?;
        match (&*tty).read(&mut byte) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ReadError::Io(e)),
        }
    }
}
