//! The `doctor` rows of a pass store (v0.2 plan 6.4). Read-only: they
//! create, change and decrypt nothing.

use std::os::unix::fs::MetadataExt;

use super::{GPG_ID_SIG, PassBackend, read_gpg_id};
use crate::backend::atomic::FileStore;
use crate::backend::{Backend, DoctorCtx};
use crate::cmd::shell_path;
use crate::git::find_root;
use crate::report::{Report, Status};

/// The oldest gpg with `--pinentry-mode` and `--list-only` as secrit uses
/// them.
const MIN_GPG: (u64, u64) = (2, 2);

pub(super) fn rows(r: &mut Report, b: &PassBackend, ctx: &DoctorCtx<'_>) {
    let name = |what: &str| format!("store {}: {what}", ctx.store);
    if ctx.tool_found && ctx.tool_version {
        match b.gpg_version() {
            Ok((major, minor, patch)) if (major, minor) >= MIN_GPG => {
                r.add(
                    "gpg version",
                    Status::Ok,
                    format!("{major}.{minor}.{patch}"),
                );
            }
            Ok((major, minor, patch)) => r.add(
                "gpg version",
                Status::Fail,
                format!(
                    "{major}.{minor}.{patch}; secrit needs {}.{} or newer",
                    MIN_GPG.0, MIN_GPG.1
                ),
            ),
            Err(e) => r.add("gpg version", Status::Fail, e.to_string()),
        }
    }

    match directory(b) {
        Ok(detail) => r.add(name("directory"), Status::Ok, detail),
        Err(e) => {
            r.add(name("directory"), Status::Fail, e);
            return;
        }
    }
    let (status, detail) = gnupg_home(b);
    r.add(name("GNUPGHOME"), status, detail);

    let gpg_id = match b.gpg_id(b.entries()) {
        Ok(p) => {
            r.add(name(".gpg-id"), Status::Ok, p.display().to_string());
            p
        }
        Err(e) => {
            r.add(name(".gpg-id"), Status::Fail, e.to_string());
            git_row(r, &name("git"), b);
            return;
        }
    };
    recipients_row(r, &name("recipients"), b, &gpg_id, ctx.tool_found);
    let sig = gpg_id.with_file_name(GPG_ID_SIG);
    if std::fs::symlink_metadata(&sig).is_ok() {
        r.add(
            name(".gpg-id.sig"),
            Status::Warn,
            format!(
                "{} exists: pass signs .gpg-id here, and secrit refuses every write until it can check the signature",
                sig.display()
            ),
        );
    }
    match b.list() {
        Ok(names) => r.add(name("entries"), Status::Ok, format!("{}", names.len())),
        Err(e) => r.add(name("entries"), Status::Fail, e.to_string()),
    }
    git_row(r, &name("git"), b);
}

/// The store directory, and the prefix directory when there is one.
fn directory(b: &PassBackend) -> Result<String, String> {
    b.check_root().map_err(|e| e.to_string())?;
    if !b.entries().exists() {
        return Ok(format!(
            "{} (created by the first store)",
            b.entries().display()
        ));
    }
    // The write-path checks of the entries directory, on a probe name.
    let probe = FileStore::new(
        b.entries().join(".secrit-doctor"),
        None,
        None,
        std::time::Duration::ZERO,
    )
    .map_err(|e| e.to_string())?;
    probe.check_dir().map_err(|e| e.to_string())?;
    Ok(b.entries().display().to_string())
}

fn gnupg_home(b: &PassBackend) -> (Status, String) {
    let home = b.gpg.gnupg_home();
    let shown = home.display();
    match std::fs::metadata(home) {
        Err(e) => (Status::Fail, format!("{shown}: {e}")),
        Ok(m) if !m.is_dir() => (Status::Fail, format!("{shown} is not a directory")),
        Ok(m) if m.uid() != rustix::process::getuid().as_raw() => {
            (Status::Fail, format!("{shown} is owned by another user"))
        }
        Ok(m) if m.mode() & 0o077 != 0 => (
            Status::Warn,
            format!(
                "{shown} has mode {:04o}; run 'chmod 700 {}'",
                m.mode() & 0o7777,
                shell_path(home)
            ),
        ),
        Ok(_) => (Status::Ok, shown.to_string()),
    }
}

fn recipients_row(
    r: &mut Report,
    check: &str,
    b: &PassBackend,
    gpg_id: &std::path::Path,
    have_gpg: bool,
) {
    let lines = match read_gpg_id(gpg_id) {
        Ok(l) => l,
        Err(e) => {
            r.add(check, Status::Fail, e.to_string());
            return;
        }
    };
    if !have_gpg {
        r.add(
            check,
            Status::Info,
            format!("{} (not checked: no gpg)", lines.join(", ")),
        );
        return;
    }
    let mut found = Vec::new();
    for line in &lines {
        match b.resolve_line(gpg_id, line, &b.target(None)) {
            Ok(k) => found.push(format!("{line} ({})", k.fpr)),
            Err(e) => {
                r.add(check, Status::Fail, e.to_string());
                return;
            }
        }
    }
    r.add(check, Status::Ok, found.join(", "));
}

fn git_row(r: &mut Report, check: &str, b: &PassBackend) {
    match find_root(b.entries()) {
        Some(root) => r.add(
            check,
            Status::Info,
            format!(
                "{} is a git repository; secrit never commits, so commit changes yourself",
                root.display()
            ),
        ),
        None => r.add(check, Status::Info, "not in a git repository"),
    }
}
