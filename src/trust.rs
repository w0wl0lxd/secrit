//! Ownership and mode checks for files that steer secrit but are not the
//! store file: a configured `tools.sops` binary (SEC-10) and the `.sops.yaml`
//! that secrit passes to sops (SEC-12).
//!
//! The rule: after symlinks are followed, the file is a regular file owned by
//! this user or root, and neither the file nor its directory is writable by
//! group or others (a sticky directory is accepted). A Nix store path passes:
//! it is root-owned and read-only.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The uid that an unmapped owner shows as inside a user namespace.
const DEFAULT_OVERFLOW_UID: u32 = 65534;

fn overflow_uid() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/overflowuid")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(DEFAULT_OVERFLOW_UID)
}

/// Whether an owner `uid` with `mode` is a trusted Nix store entry: under
/// `/nix/store/`, writable by nobody, and owned by root. In a user namespace
/// (the Nix build sandbox) root is unmapped and shows as the overflow uid.
#[must_use]
pub fn nix_store_owner_ok(target: &Path, uid: u32, mode: u32, overflow: u32) -> bool {
    target.starts_with("/nix/store/") && mode & 0o222 == 0 && (uid == 0 || uid == overflow)
}

/// Whether `target` is a trusted Nix store entry (see [`nix_store_owner_ok`]).
#[must_use]
pub fn in_nix_store(target: &Path, meta: &Metadata) -> bool {
    nix_store_owner_ok(target, meta.uid(), meta.mode(), overflow_uid())
}

/// Whether the owner of `target` is this user, root, or the Nix store.
fn owner_ok(target: &Path, meta: &Metadata) -> bool {
    let uid = meta.uid();
    uid == rustix::process::getuid().as_raw() || uid == 0 || in_nix_store(target, meta)
}

/// Why a file is not trusted.
#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Unsafe(&'static str),
}

const STICKY: u32 = 0o1000;

/// Check `path` by the rule above. Returns the resolved target.
pub fn check_file(path: &Path) -> Result<PathBuf, TrustError> {
    let target = std::fs::canonicalize(path)?;
    let meta = std::fs::metadata(&target)?;
    if !meta.is_file() {
        return Err(TrustError::Unsafe("not a regular file"));
    }
    if !owner_ok(&target, &meta) {
        return Err(TrustError::Unsafe("owned by another user"));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(TrustError::Unsafe("writable by group or others"));
    }
    let dir = target
        .parent()
        .ok_or(TrustError::Unsafe("it has no parent directory"))?;
    let dmeta = std::fs::metadata(dir)?;
    if !owner_ok(dir, &dmeta) {
        return Err(TrustError::Unsafe("its directory is owned by another user"));
    }
    if dmeta.mode() & 0o022 != 0 && dmeta.mode() & STICKY == 0 {
        return Err(TrustError::Unsafe(
            "its directory is writable by group or others",
        ));
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn private_files_pass_and_shared_ones_fail() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f");
        std::fs::write(&f, "x").unwrap();
        chmod(&f, 0o644);
        chmod(d.path(), 0o755);
        assert!(check_file(&f).is_ok());

        chmod(&f, 0o664);
        assert!(matches!(check_file(&f), Err(TrustError::Unsafe(_))));
        chmod(&f, 0o644);

        chmod(d.path(), 0o775);
        assert!(matches!(check_file(&f), Err(TrustError::Unsafe(_))));
        chmod(d.path(), 0o1777);
        assert!(check_file(&f).is_ok());
        chmod(d.path(), 0o700);

        assert!(matches!(
            check_file(d.path()),
            Err(TrustError::Unsafe("not a regular file"))
        ));
        assert!(matches!(
            check_file(&d.path().join("missing")),
            Err(TrustError::Io(_))
        ));
    }

    /// A store path is trusted when root owns it, or when root shows as the
    /// overflow uid in a user namespace. It must be writable by nobody.
    #[test]
    fn nix_store_owners() {
        let p = Path::new("/nix/store/abc-sops/bin/sops");
        assert!(nix_store_owner_ok(p, 0, 0o555, 65534));
        assert!(nix_store_owner_ok(p, 65534, 0o555, 65534));
        assert!(!nix_store_owner_ok(p, 30001, 0o555, 65534));
        assert!(!nix_store_owner_ok(p, 65534, 0o755, 65534));
        let outside = Path::new("/tmp/nix/store/x");
        assert!(!nix_store_owner_ok(outside, 65534, 0o555, 65534));
    }

    #[test]
    fn a_symlink_is_judged_by_its_target() {
        let d = tempfile::tempdir().unwrap();
        let shared = d.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let f = shared.join("f");
        std::fs::write(&f, "x").unwrap();
        chmod(&f, 0o644);
        chmod(&shared, 0o777);
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&f, &link).unwrap();
        chmod(d.path(), 0o700);
        assert!(matches!(check_file(&link), Err(TrustError::Unsafe(_))));
        chmod(&shared, 0o700);
    }
}
