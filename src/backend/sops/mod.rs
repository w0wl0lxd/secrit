//! The sops backend (PLAN sections 6.2, 8.1 and 8.2; v0.2 plan 6.1).
//!
//! secrit never edits the store file in place: it edits a ciphertext copy
//! under a lock, validates the copy, and renames it over the original
//! (`backend/atomic.rs`). `runner.rs` runs sops, `format.rs` parses and
//! checks a store file, `edit.rs` is one `store` or `rm` on it, and
//! `doctor.rs` gives the `doctor` rows of a sops store.

mod doctor;
mod edit;
mod format;
mod runner;

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use self::edit::{Op, SopsEdit};
use self::format::{REGEX_RULES, SopsFormat, has_plaintext, has_recipients, non_string_kind};
use self::runner::{MAX_NEW_FILE_BYTES, Runner};
use super::atomic::{self, FileStore};
use super::{Backend, BackendError, DoctorCtx, Location, PutMode, Target, WriteReport};
use crate::config::{BackendKind, Env, SopsStore};
use crate::name::Name;
use crate::paths;
use crate::report::Report;
use crate::secret::SecretValue;

pub use self::runner::MIN_SOPS;
#[cfg(test)]
pub use self::runner::{NEED_SOPS, PROMPT_HINT};

#[derive(Debug)]
pub struct SopsBackend {
    store: FileStore,
    /// The store file as a [`Location`], for messages and errors.
    location: Location,
    format: SopsFormat,
    runner: Runner,
    age_key_file: Option<PathBuf>,
}

/// What `inspect` found in the store file. Holds names only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreFacts {
    /// Top-level entries outside `sops`.
    pub names: usize,
    /// Top-level names that hold a leaf that is not `ENC[...]`.
    pub plaintext: Vec<String>,
    /// The regex rules in the file's sops metadata.
    pub rules: Vec<&'static str>,
}

impl SopsBackend {
    /// `env` supplies `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME` and
    /// `XDG_RUNTIME_DIR`.
    pub fn new(
        store: &SopsStore,
        sops: PathBuf,
        lock_timeout: Duration,
        env: &Env,
    ) -> Result<Self, BackendError> {
        let backups = paths::abs_var(env, "XDG_STATE_HOME")
            .or_else(|| paths::abs_var(env, "HOME").map(|h| h.join(".local").join("state")))
            .map(|s| s.join("secrit").join("backups"));
        let file = FileStore::new(
            store.file.clone(),
            paths::abs_var(env, "XDG_RUNTIME_DIR"),
            backups.as_deref(),
            lock_timeout,
        )?;
        let sops_config = store
            .sops_config
            .clone()
            .or_else(|| nearest_sops_config(file.dir()));
        // sops's own default, made explicit because sops gets no real HOME.
        let age_key_file = store
            .age_key_file
            .clone()
            .or_else(|| paths::default_age_key_file(env));
        let runner = Runner::new(
            sops,
            sops_config,
            age_key_file.as_deref(),
            file.dir().to_path_buf(),
        );
        Ok(Self {
            location: Location::File(store.file.clone()),
            store: file,
            format: store_format(store),
            runner,
            age_key_file,
        })
    }

    /// The git sample and the `.gitignore` pattern of this store's temp
    /// copies.
    pub fn temp_ignore(&self) -> TempIgnore {
        TempIgnore::new(self.file(), self.format)
    }

    /// The version that `sops --version` reports.
    pub fn sops_version(&self) -> Result<(u64, u64, u64), BackendError> {
        self.runner.version()
    }

    /// [`Self::sops_version`], refused when it is older than [`MIN_SOPS`].
    pub fn checked_version(&self) -> Result<(u64, u64, u64), BackendError> {
        self.runner.checked_version()
    }

    pub fn file(&self) -> &Path {
        self.store.file()
    }

    pub fn dir(&self) -> &Path {
        self.store.dir()
    }

    pub fn sops(&self) -> &Path {
        self.runner.sops()
    }

    /// The `.sops.yaml` secrit passes to sops, if any.
    pub fn sops_config(&self) -> Option<&Path> {
        self.runner.sops_config()
    }

    /// The age key file sops gets as `SOPS_AGE_KEY_FILE`.
    pub fn age_key_file(&self) -> Option<&Path> {
        self.age_key_file.as_deref()
    }

    /// The trust rule for the `.sops.yaml` (SEC-12).
    pub fn check_sops_config(&self) -> Result<(), BackendError> {
        self.runner.check_sops_config()
    }

    /// The store file under the write-path checks, without decrypting.
    pub fn inspect(&self) -> Result<StoreFacts, BackendError> {
        let snap = self.store.read(true)?;
        self.format.refuse_other(&snap.bytes, self.file())?;
        let doc = self.format.parse(&snap.bytes, self.file())?;
        let rules = REGEX_RULES
            .iter()
            .copied()
            .filter(|k| {
                doc.meta
                    .get(*k)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            })
            .collect();
        let plaintext = doc
            .entries
            .iter()
            .filter(|(_, v)| has_plaintext(v))
            .map(|(k, _)| k.clone())
            .collect();
        Ok(StoreFacts {
            names: doc.entries.len(),
            plaintext,
            rules,
        })
    }

    /// Whether a creation rule of the `.sops.yaml` covers the store file:
    /// sops encrypts an empty document for it, and the output is dropped.
    pub fn rule_matches(&self) -> Result<bool, BackendError> {
        if self.sops_config().is_none() {
            return Ok(false);
        }
        let out = self
            .runner
            .encrypt_empty(self.format, self.file(), 0, self.target(None))?;
        if out.status.success() {
            return Ok(true);
        }
        if String::from_utf8_lossy(&out.stderr).contains("no matching creation rules") {
            return Ok(false);
        }
        Err(runner::failed("encrypt", self.target(None), &out, &[]))
    }

    /// Create the store file with no entries (PLAN section 4.6, step 4):
    /// sops encrypts the empty document under the `.sops.yaml` rule, and
    /// the store puts it in place without replacing a file.
    pub fn create_file(&self) -> Result<(), BackendError> {
        let file = self.file();
        self.store.create_new(self.format.temp_ext(), || {
            self.format.refuse_other_name(file)?;
            if self.sops_config().is_none() {
                return Err(BackendError::NoSopsConfig(file.to_path_buf()));
            }
            let out = self.runner.encrypt_empty(
                self.format,
                file,
                MAX_NEW_FILE_BYTES,
                self.target(None),
            )?;
            if !out.status.success() {
                return Err(runner::failed("encrypt", self.target(None), &out, &[]));
            }
            let doc = self.format.parse(&out.stdout, file)?;
            if !has_recipients(&doc.meta) {
                return Err(self.validation(None, "the new file has no recipients"));
            }
            Ok(out.stdout)
        })
    }

    /// The store file, and `name` when the step is about one.
    fn target(&self, name: Option<&Name>) -> Target {
        Target {
            location: self.location.clone(),
            name: name.cloned(),
        }
    }

    fn validation(&self, name: Option<&Name>, reason: impl Into<String>) -> BackendError {
        BackendError::Validation {
            target: self.target(name),
            reason: reason.into(),
        }
    }

    fn read_doc(&self) -> Result<(Vec<u8>, format::SopsDoc), BackendError> {
        let snap = self.store.read(false)?;
        let doc = self.format.parse(&snap.bytes, self.file())?;
        Ok((snap.bytes, doc))
    }

    fn exists_error(&self, name: &Name) -> BackendError {
        BackendError::Exists {
            name: name.clone(),
            location: self.location.clone(),
        }
    }

    fn missing_error(&self, name: &Name) -> BackendError {
        BackendError::Missing {
            name: name.clone(),
            location: self.location.clone(),
        }
    }

    fn write(&self, name: &Name, op: Op<'_>) -> Result<WriteReport, BackendError> {
        self.store.write(&SopsEdit {
            backend: self,
            name,
            op,
        })
    }
}

impl Backend for SopsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Sops
    }

    fn location(&self) -> &Location {
        &self.location
    }

    fn list(&self) -> Result<Vec<String>, BackendError> {
        let (_, doc) = self.read_doc()?;
        let mut names: Vec<String> = doc.entries.keys().cloned().collect();
        names.sort();
        Ok(names)
    }

    fn exists(&self, name: &Name) -> Result<bool, BackendError> {
        let (_, doc) = self.read_doc()?;
        Ok(doc.entries.contains_key(name.as_str()))
    }

    fn check_put(&self, name: &Name, mode: PutMode) -> Result<(), BackendError> {
        let (bytes, doc) = self.read_doc()?;
        self.format.refuse_other(&bytes, self.file())?;
        if mode == PutMode::CreateOnly && doc.entries.contains_key(name.as_str()) {
            return Err(self.exists_error(name));
        }
        self.check_cleartext_rules(name, &doc.meta)?;
        self.check_plaintext(name, &doc.entries)
    }

    fn check_remove(&self, name: &Name) -> Result<(), BackendError> {
        let (bytes, doc) = self.read_doc()?;
        self.format.refuse_other(&bytes, self.file())?;
        if !doc.entries.contains_key(name.as_str()) {
            return Err(self.missing_error(name));
        }
        self.check_plaintext(name, &doc.entries)
    }

    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError> {
        let (bytes, doc) = self.read_doc()?;
        for n in names {
            let entry = doc
                .entries
                .get(n.as_str())
                .ok_or_else(|| self.missing_error(n))?;
            if let Some(kind) = non_string_kind(entry) {
                return Err(BackendError::NotString {
                    name: n.to_string(),
                    kind,
                });
            }
        }
        // One decrypt per name: each value lands in its own fixed buffer,
        // and no JSON parser holds a copy (SEC-8).
        names
            .iter()
            .map(|n| {
                let value = self.runner.decrypt_one(
                    self.format,
                    &bytes,
                    n,
                    "decrypt",
                    self.target(Some(n)),
                    &[],
                )?;
                Ok((n.clone(), value))
            })
            .collect()
    }

    fn put(
        &self,
        name: &Name,
        value: &SecretValue,
        mode: PutMode,
    ) -> Result<WriteReport, BackendError> {
        self.write(name, Op::Put(value, mode))
    }

    fn remove(&self, name: &Name) -> Result<WriteReport, BackendError> {
        self.write(name, Op::Remove)
    }

    fn doctor(&self, report: &mut Report, ctx: &DoctorCtx<'_>) {
        doctor::rows(report, self, ctx);
    }
}

/// The format of a store's file. v0.2 starts with YAML only; S4 reads it
/// from the store config.
fn store_format(_store: &SopsStore) -> SopsFormat {
    SopsFormat::Yaml
}

/// How git sees the temp copies of one store. Both parts follow the
/// store's format, because a temp copy ends in the format's extension.
#[derive(Debug)]
pub struct TempIgnore {
    /// A temp copy name with a fixed random part, to ask git whether it
    /// ignores temp copies.
    pub sample: PathBuf,
    /// The `.gitignore` pattern that matches every temp copy.
    pub pattern: String,
}

impl TempIgnore {
    fn new(file: &Path, format: SopsFormat) -> Self {
        let ext = format.temp_ext();
        Self {
            sample: atomic::temp_sample(file, ext),
            pattern: atomic::temp_ignore(ext),
        }
    }

    /// The temp copies of `store`, from its config alone.
    pub fn of(store: &SopsStore) -> Self {
        Self::new(&store.file, store_format(store))
    }
}

fn nearest_sops_config(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .map(|a| a.join(".sops.yaml"))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::format::tests::{BASE, doc};
    use super::format::validate;
    use super::*;
    use crate::error::Exit;

    #[test]
    fn a_cleartext_entry_is_refused_before_the_value() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), &format!("{BASE}x_unencrypted: plain\n"));
        let z = Name::parse("z").unwrap();
        let a = Name::parse("a").unwrap();
        let e = b.check_put(&z, PutMode::CreateOnly).unwrap_err();
        assert!(
            e.to_string().contains("'x_unencrypted' is not encrypted"),
            "{e}"
        );
        assert!(!e.to_string().contains("plain"), "{e}");
        assert_eq!(e.exit(), Exit::Refused);
        let e = b.check_remove(&a).unwrap_err();
        assert!(e.to_string().contains("is not encrypted"), "{e}");
        assert_eq!(e.exit(), Exit::Refused);

        // NAME itself may be the cleartext entry: the write replaces or
        // removes it.
        let b = backend_for(tmp.path(), &format!("{BASE}e: plain\n"));
        let e_name = Name::parse("e").unwrap();
        assert!(b.check_put(&e_name, PutMode::Replace).is_ok());
        assert!(b.check_remove(&e_name).is_ok());
        let e = b.check_remove(&z).unwrap_err();
        assert!(matches!(e, BackendError::Missing { .. }), "{e}");
    }

    /// sops never encrypts an empty string, so an empty leaf holds no
    /// secret, the same as a null leaf.
    #[test]
    fn an_empty_string_leaf_is_not_plaintext() {
        assert!(!has_plaintext(&Value::String(String::new())));
        assert!(!has_plaintext(&Value::Null));
        let nested: Value = serde_json::from_str(r#"{"k": ["", null], "m": {"n": ""}}"#).unwrap();
        assert!(!has_plaintext(&nested));
        assert!(has_plaintext(&Value::String(" ".into())));

        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), &format!("{BASE}e: \"\"\n"));
        let z = Name::parse("z").unwrap();
        let a = Name::parse("a").unwrap();
        assert!(b.check_put(&z, PutMode::CreateOnly).is_ok());
        assert!(b.check_remove(&a).is_ok());
        assert!(b.inspect().unwrap().plaintext.is_empty());

        // The copy validation keeps the empty entry too.
        let orig = doc(&format!("{BASE}e: \"\"\n"));
        let copy = doc(&format!(
            "{BASE}e: \"\"\nz: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n"
        ));
        let v = SecretValue::new(b"v".to_vec());
        assert!(validate(&orig, &copy, &z, Op::Put(&v, PutMode::CreateOnly)).is_ok());
    }

    /// Whether the `.gitignore` glob `pattern` matches the file name `name`.
    /// Only `*` is special, and no `/` occurs.
    fn glob_matches(pattern: &str, name: &str) -> bool {
        let parts: Vec<&str> = pattern.split('*').collect();
        let (first, last) = (parts[0], parts[parts.len() - 1]);
        if !name.starts_with(first) || !name[first.len()..].ends_with(last) {
            return false;
        }
        let mut rest = &name[first.len()..name.len() - last.len()];
        for part in &parts[1..parts.len() - 1] {
            match rest.find(part) {
                Some(i) => rest = &rest[i + part.len()..],
                None => return false,
            }
        }
        true
    }

    /// The `.gitignore` pattern and the git sample come from the format of
    /// the store, so they match the temp copies that a write makes.
    #[test]
    fn the_temp_ignore_pattern_follows_the_format() {
        let file = Path::new("/s/main.yaml");
        for format in SopsFormat::ALL {
            let ext = format!(".{}", format.temp_ext());
            let temp = TempIgnore::new(file, format);
            let sample = temp.sample.file_name().unwrap().to_str().unwrap();
            assert_eq!(temp.sample.parent(), Some(Path::new("/s")));
            assert!(sample.ends_with(&ext), "{sample}");
            assert!(temp.pattern.ends_with(&ext), "{}", temp.pattern);
            assert!(glob_matches(&temp.pattern, sample), "{temp:?}");
            assert!(!glob_matches(&temp.pattern, "main.yaml"), "{temp:?}");
        }
        // v0.1 printed this pattern; YAML stores keep it.
        let yaml = TempIgnore::new(file, SopsFormat::Yaml);
        assert_eq!(yaml.pattern, ".*.secrit-*.yaml");

        // The store config and the backend give the same answer.
        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), BASE);
        let store = SopsStore {
            file: b.file().to_path_buf(),
            sops_config: None,
            age_key_file: None,
        };
        let (of_store, of_backend) = (TempIgnore::of(&store), b.temp_ignore());
        assert_eq!(of_store.sample, of_backend.sample);
        assert_eq!(of_store.pattern, of_backend.pattern);
    }

    fn backend_for(dir: &Path, yaml: &str) -> SopsBackend {
        let file = dir.join("main.yaml");
        std::fs::write(&file, yaml).unwrap();
        let store = SopsStore {
            file,
            sops_config: None,
            age_key_file: None,
        };
        SopsBackend::new(&store, "/nonexistent/sops".into(), Duration::ZERO, &|_| {
            None
        })
        .unwrap()
    }

    /// PLAN 4.1 step 1: `check_put` refuses before any value is read, with
    /// no sops run (the sops path here does not exist).
    #[test]
    fn check_put_refuses_without_a_value() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), BASE);
        let a = Name::parse("a").unwrap();
        let z = Name::parse("z").unwrap();
        let e = b.check_put(&a, PutMode::CreateOnly).unwrap_err();
        assert!(matches!(e, BackendError::Exists { .. }), "{e}");
        assert!(e.to_string().contains("main.yaml"), "{e}");
        assert!(b.check_put(&a, PutMode::Replace).is_ok());
        assert!(b.check_put(&z, PutMode::CreateOnly).is_ok());

        let regex = BASE.replace("  version:", "  unencrypted_regex: ^pub\n  version:");
        let b = backend_for(tmp.path(), &regex);
        let e = b.check_put(&z, PutMode::CreateOnly).unwrap_err();
        assert!(e.to_string().contains("unencrypted_regex"), "{e}");
        assert_eq!(e.exit(), Exit::Refused);

        let suffix = BASE.replace("  version:", "  unencrypted_suffix: _pub\n  version:");
        let b = backend_for(tmp.path(), &suffix);
        let e = b
            .check_put(&Name::parse("tok_pub").unwrap(), PutMode::Replace)
            .unwrap_err();
        assert!(e.to_string().contains("_pub"), "{e}");
        assert!(b.check_put(&z, PutMode::Replace).is_ok());
    }
}
