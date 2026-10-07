//! Read-only git queries for `doctor`, `init` and `wire` (PLAN F14). secrit
//! never runs a git command that changes a repository (PLAN N7).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::child;

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git not found on PATH")]
    NotFound,
    #[error("git {0} failed")]
    Failed(&'static str),
}

/// The repository that holds a path, and the git binary to ask.
#[derive(Debug)]
pub struct Repo {
    pub root: PathBuf,
    git: PathBuf,
    home: Option<OsString>,
}

/// The nearest ancestor of `dir` (or `dir` itself) that holds `.git`.
#[must_use]
pub fn find_root(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .find(|a| a.join(".git").exists())
        .map(Path::to_path_buf)
}

impl Repo {
    /// The repository that holds `dir`. `Ok(None)` when there is none.
    pub fn open(
        dir: &Path,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Option<Self>, GitError> {
        let Some(root) = find_root(dir) else {
            return Ok(None);
        };
        let path = env("PATH").unwrap_or_default();
        let absolute: Vec<PathBuf> = std::env::split_paths(&path)
            .filter(|d| d.is_absolute())
            .collect();
        let joined = std::env::join_paths(absolute).map_err(|_| GitError::NotFound)?;
        let git = which::which_in("git", Some(joined), "/").map_err(|_| GitError::NotFound)?;
        Ok(Some(Self {
            root,
            git,
            home: env("HOME"),
        }))
    }

    /// Whether the repository's own and global ignore rules match `path`.
    pub fn is_ignored(&self, path: &Path) -> Result<bool, GitError> {
        self.ask(
            "check-ignore",
            &["check-ignore", "-q", "--no-index", "--"],
            path,
        )
    }

    /// Whether `path` is in the index.
    pub fn is_tracked(&self, path: &Path) -> Result<bool, GitError> {
        self.ask("ls-files", &["ls-files", "--error-unmatch", "--"], path)
    }

    /// Whether the repository root has a `flake.nix`.
    #[must_use]
    pub fn is_flake(&self) -> bool {
        self.root.join("flake.nix").is_file()
    }

    /// `path` relative to the root, for printed commands.
    #[must_use]
    pub fn relative<'a>(&self, path: &'a Path) -> &'a Path {
        path.strip_prefix(&self.root).unwrap_or(path)
    }

    /// Run a query that answers with exit 0 (yes) or 1 (no).
    fn ask(&self, what: &'static str, args: &[&str], path: &Path) -> Result<bool, GitError> {
        let mut cmd = Command::new(&self.git);
        cmd.env_clear()
            .env("GIT_OPTIONAL_LOCKS", "0")
            .args(["-c", "core.fsmonitor=false", "-C"])
            .arg(&self.root)
            .args(args)
            .arg(self.relative(path))
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(h) = &self.home {
            cmd.env("HOME", h);
        }
        let out = child::run(cmd, None, 0, child::timeout()).map_err(|_| GitError::Failed(what))?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(GitError::Failed(what)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_is_the_nearest_dot_git() {
        let d = tempfile::tempdir().unwrap();
        let inner = d.path().join("a").join("b");
        std::fs::create_dir_all(&inner).unwrap();
        assert_eq!(find_root(&inner), None);
        std::fs::create_dir(d.path().join("a").join(".git")).unwrap();
        assert_eq!(find_root(&inner), Some(d.path().join("a")));
    }
}
