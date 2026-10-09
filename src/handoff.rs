//! The `--file` hand-off of `secrit run` (v0.2 plan 7.1, step 2): each
//! value goes into a sealed memfd that the command inherits, and the
//! command gets `VAR=/dev/fd/N`. Linux only: rustix builds `memfd_create`
//! on Linux only.
//!
//! - Every memfd has the fixed name `secrit`, so `/proc/<pid>/fd` shows no
//!   secret name.
//! - No `CLOEXEC`: the command inherits the fd.
//! - `MFD_NOEXEC_SEAL`; on `EINVAL` (kernel before 6.3) `MFD_ALLOW_SEALING`.
//! - After the write: `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK |
//!   F_SEAL_SEAL`, checked with `F_GET_SEALS`, then a seek to 0.
//! - A reader that opens `/dev/fd/N` gets a new file description at offset
//!   0, so the path can be read more than once.
//!
//! Limits (README): a program that closes every fd above 2 (`sudo`) loses
//! the value; the fd and `VAR` pass to grandchildren; memfd pages can reach
//! swap (T7); a same-uid process can read `/proc/<pid>/fd/N` (T57).

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{
    MemfdFlags, SealFlags, SeekFrom, fcntl_add_seals, fcntl_get_seals, memfd_create, seek,
};
use rustix::io::{Errno, write};

/// The name of every memfd.
pub const NAME: &str = "secrit";

/// The seals that every memfd gets.
pub const SEALS: SealFlags = SealFlags::WRITE
    .union(SealFlags::GROW)
    .union(SealFlags::SHRINK)
    .union(SealFlags::SEAL);

/// A sealed memfd that holds one value.
#[derive(Debug)]
pub struct Sealed(OwnedFd);

impl Sealed {
    /// Write `value` into a new memfd and seal it.
    pub fn new(value: &[u8]) -> io::Result<Self> {
        let fd = match memfd_create(NAME, MemfdFlags::NOEXEC_SEAL) {
            Err(Errno::INVAL) => memfd_create(NAME, MemfdFlags::ALLOW_SEALING)?,
            created => created?,
        };
        let mut done = 0;
        while done < value.len() {
            match write(&fd, &value[done..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => done += n,
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        fcntl_add_seals(&fd, SEALS)?;
        if !fcntl_get_seals(&fd)?.contains(SEALS) {
            return Err(io::Error::other("the memfd seals did not take effect"));
        }
        seek(&fd, SeekFrom::Start(0))?;
        Ok(Self(fd))
    }

    /// `/dev/fd/N`, the path that the command opens.
    #[must_use]
    pub fn path(&self) -> String {
        format!("/dev/fd/{}", self.0.as_raw_fd())
    }
}

impl AsFd for Sealed {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::io::{FdFlags, fcntl_getfd};

    fn proc_path(sealed: &Sealed) -> String {
        format!("/proc/self/fd/{}", sealed.as_fd().as_raw_fd())
    }

    /// 7.1 step 2: every seal is set, the fd has no `CLOEXEC`, and the
    /// value reads in full twice.
    #[test]
    fn the_memfd_is_sealed_inheritable_and_rereadable() {
        let sealed = Sealed::new(b"hand-off-canary").unwrap();
        let seals = fcntl_get_seals(&sealed).unwrap();
        assert!(seals.contains(SEALS), "{seals:?}");
        assert!(!fcntl_getfd(&sealed).unwrap().contains(FdFlags::CLOEXEC));
        for _ in 0..2 {
            assert_eq!(
                std::fs::read(proc_path(&sealed)).unwrap(),
                b"hand-off-canary"
            );
        }
        assert!(sealed.path().starts_with("/dev/fd/"));
    }

    /// The fixed name hides the secret name in `/proc/<pid>/fd`.
    #[test]
    fn the_memfd_has_the_fixed_name() {
        let sealed = Sealed::new(b"x").unwrap();
        let link = std::fs::read_link(proc_path(&sealed)).unwrap();
        assert_eq!(link.to_string_lossy(), "/memfd:secrit (deleted)");
    }

    /// A write through a new open fails: the seals hold.
    #[test]
    fn a_write_is_refused() {
        use std::io::Write;
        let sealed = Sealed::new(b"value").unwrap();
        let opened = std::fs::OpenOptions::new()
            .append(true)
            .open(proc_path(&sealed));
        if let Ok(mut f) = opened {
            assert!(f.write_all(b"more").is_err());
        }
        assert_eq!(std::fs::read(proc_path(&sealed)).unwrap(), b"value");
    }
}
