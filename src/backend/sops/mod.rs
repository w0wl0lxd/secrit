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

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use self::edit::{Op, SopsEdit};
use self::format::{
    REGEX_RULES, Slot, has_plaintext, has_recipients, leaf_names, leaves, lookup, non_string_kind,
    path_text,
};
use self::runner::{MAX_NEW_FILE_BYTES, Runner};
use super::atomic::{self, FileStore};
use super::{
    Backend, BackendError, Capabilities, DoctorCtx, Location, PutMode, Target, WireSource,
    WriteReport,
};
use crate::config::{BackendKind, Env, SopsStore};
use crate::name::Name;
use crate::paths;
use crate::report::Report;
use crate::secret::SecretValue;

pub use self::format::SopsFormat;
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
    /// The names that `ls` lists: the leaves outside `sops`.
    pub names: usize,
    /// The names of the leaves that are not `ENC[...]`.
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
        let format = SopsFormat::of_file(store.format, &store.file);
        let file = FileStore::new(
            store.file.clone(),
            paths::runtime_dir(env),
            paths::backup_dir(env).as_deref(),
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
            format,
            runner,
            age_key_file,
        })
    }

    /// The git sample and the `.gitignore` pattern of this store's temp
    /// copies.
    pub fn temp_ignore(&self) -> TempIgnore {
        TempIgnore::new(self.file(), self.format)
    }

    /// [`SopsFormat::refuse_other_name`] for the store file: `init` runs it
    /// before it makes any file.
    pub fn check_file_name(&self) -> Result<(), BackendError> {
        self.format.refuse_other_name(self.file())
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
        let doc = self.format.parse_to_write(&snap.bytes, self.file())?;
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
        let leaves = leaves(&doc.entries);
        let plaintext = leaves
            .iter()
            .filter(|(_, v)| has_plaintext(v))
            .map(|(p, _)| path_text(p))
            .collect();
        Ok(StoreFacts {
            names: leaves.len(),
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

    /// [`Self::read_doc`] for a write: a file in another format is refused
    /// (exit 3) before the parse can fail on it (v0.2 plan V14).
    fn read_doc_to_write(&self) -> Result<format::SopsDoc, BackendError> {
        let snap = self.store.read(false)?;
        self.format.parse_to_write(&snap.bytes, self.file())
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
            prune: Cell::new(None),
        })
    }
}

impl Backend for SopsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Sops
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            nested_names: self.format.nested_names(),
        }
    }

    fn location(&self) -> &Location {
        &self.location
    }

    /// Every leaf, as its key path (v0.2 plan 5.4). A file that another
    /// tool wrote with a nested map lists the leaves, not the map.
    fn list(&self) -> Result<Vec<String>, BackendError> {
        let (_, doc) = self.read_doc()?;
        Ok(leaf_names(&doc.entries))
    }

    fn exists(&self, name: &Name) -> Result<bool, BackendError> {
        let (_, doc) = self.read_doc()?;
        let path: Vec<&str> = name.segments().collect();
        Ok(matches!(lookup(&doc.entries, &path), Slot::Value(_)))
    }

    fn check_put(&self, name: &Name, mode: PutMode) -> Result<(), BackendError> {
        let doc = self.read_doc_to_write()?;
        let existed = self.check_path(name, &doc.entries, true)?;
        if mode == PutMode::CreateOnly && existed {
            return Err(self.exists_error(name));
        }
        self.check_cleartext_rules(name, &doc.meta)?;
        self.check_plaintext(name, &doc.entries)
    }

    fn check_remove(&self, name: &Name) -> Result<(), BackendError> {
        let doc = self.read_doc_to_write()?;
        if !self.check_path(name, &doc.entries, false)? {
            return Err(self.missing_error(name));
        }
        self.check_plaintext(name, &doc.entries)
    }

    fn get_many(&self, names: &[Name]) -> Result<Vec<(Name, SecretValue)>, BackendError> {
        let (bytes, doc) = self.read_doc()?;
        for n in names {
            let path: Vec<&str> = n.segments().collect();
            let Slot::Value(entry) = lookup(&doc.entries, &path) else {
                return Err(self.missing_error(n));
            };
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

    /// sops-nix reads a nested key from the `key` option, with the
    /// segments joined by `/` (v0.2 plan 5.7). It has no key option for a
    /// dotenv or an INI file: the secret is the whole decrypted file
    /// (sops-nix `sops-install-secrets`, read in the S6 lab).
    fn wire_source(&self, name: &Name) -> Option<WireSource> {
        let file = self.file().to_path_buf();
        let format = self.format;
        Some(if format.one_name_out() {
            WireSource::SopsFile {
                file,
                format,
                key: name.is_nested().then(|| name.clone()),
            }
        } else {
            WireSource::WholeSopsFile { file, format }
        })
    }
}

/// How git sees the temp copies of one store. The sample follows the
/// store's format, because a temp copy ends in the format's extension;
/// the pattern matches the temp copies of every format (v0.2 plan 6.1.5).
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
        Self {
            sample: atomic::temp_sample(file, format.temp_ext()),
            pattern: atomic::temp_ignore(),
        }
    }

    /// The temp copies of `store`, from its config alone.
    pub fn of(store: &SopsStore) -> Self {
        Self::new(&store.file, SopsFormat::of_file(store.format, &store.file))
    }
}

fn nearest_sops_config(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .map(|a| a.join(".sops.yaml"))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::format::tests::{BASE, DOTENV_BASE, INI_BASE, doc};
    use super::format::validate;
    use super::*;
    use crate::error::Exit;
    use crate::name::NameError;

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
            assert_eq!(temp.pattern, ".*.secrit-*");
            assert!(glob_matches(&temp.pattern, sample), "{temp:?}");
            assert!(!glob_matches(&temp.pattern, "main.yaml"), "{temp:?}");
            // The v0.1 pattern still matches the temp copies of a YAML
            // store, so `doctor` passes it for YAML only.
            let old = glob_matches(".*.secrit-*.yaml", sample);
            assert_eq!(old, format == SopsFormat::Yaml, "{sample}");
        }

        // The store config and the backend give the same answer.
        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), BASE);
        let store = SopsStore {
            file: b.file().to_path_buf(),
            format: None,
            sops_config: None,
            age_key_file: None,
        };
        let (of_store, of_backend) = (TempIgnore::of(&store), b.temp_ignore());
        assert_eq!(of_store.sample, of_backend.sample);
        assert_eq!(of_store.pattern, of_backend.pattern);

        // The sample of an INI store has the extension of its temp copies.
        let ini = SopsStore {
            file: tmp.path().join("main.ini"),
            ..store
        };
        let sample = TempIgnore::of(&ini).sample;
        assert_eq!(sample.extension().and_then(|e| e.to_str()), Some("ini"));
    }

    /// The format comes from the `format` key, else from the file name,
    /// and `wire` gets it with the store file.
    #[test]
    fn the_backend_takes_the_format_of_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let open = |name: &str, format| {
            let store = SopsStore {
                file: tmp.path().join(name),
                format,
                sops_config: None,
                age_key_file: None,
            };
            SopsBackend::new(&store, "/nonexistent/sops".into(), Duration::ZERO, &|_| {
                None
            })
        };
        let n = Name::parse("n").unwrap();
        for (name, explicit, want) in [
            ("s.yaml", None, SopsFormat::Yaml),
            ("s.json", None, SopsFormat::Json),
            ("s.sops", Some(SopsFormat::Json), SopsFormat::Json),
            ("s.env", Some(SopsFormat::Yaml), SopsFormat::Yaml),
        ] {
            let b = open(name, explicit).unwrap();
            assert_eq!(b.format, want, "{name}");
            let Some(WireSource::SopsFile { file, format, key }) = b.wire_source(&n) else {
                panic!("{name}: no sops file");
            };
            assert_eq!((file.as_path(), format), (b.file(), want), "{name}");
            assert_eq!(key, None, "{name}");
            assert!(b.capabilities().nested_names, "{name}");
        }
        // A dotenv store is flat, and sops-nix gives it out only whole.
        for (name, explicit) in [("s.env", None), ("s.txt", Some(SopsFormat::Dotenv))] {
            let b = open(name, explicit).unwrap();
            assert_eq!(b.format, SopsFormat::Dotenv, "{name}");
            assert!(!b.capabilities().nested_names, "{name}");
            let want = WireSource::WholeSopsFile {
                file: b.file().to_path_buf(),
                format: SopsFormat::Dotenv,
            };
            assert_eq!(b.wire_source(&n), Some(want), "{name}");
        }
        // An INI store takes `section/key`, and sops-nix gives it out only
        // whole.
        for (name, explicit) in [("s.ini", None), ("s.txt", Some(SopsFormat::Ini))] {
            let b = open(name, explicit).unwrap();
            assert_eq!(b.format, SopsFormat::Ini, "{name}");
            assert!(b.capabilities().nested_names, "{name}");
            let want = WireSource::WholeSopsFile {
                file: b.file().to_path_buf(),
                format: SopsFormat::Ini,
            };
            assert_eq!(b.wire_source(&n), Some(want), "{name}");
        }
    }

    /// v0.2 plan 5.4: an INI store takes a name of exactly two segments,
    /// `section/key`, each a variable name, and no name in the `sops`
    /// section. `check_put` refuses any other name with exit 3, with no
    /// sops run (the sops path here does not exist).
    #[test]
    fn an_ini_store_takes_section_and_key_names_only() {
        let tmp = tempfile::tempdir().unwrap();
        let b = store_file_for(tmp.path(), "main.ini", INI_BASE);
        assert_eq!(b.format, SopsFormat::Ini);
        assert_eq!(
            b.list().unwrap(),
            [
                "DEFAULT/bare",
                "empty",
                "s/EMPTY",
                "s/k",
                "s/longer_key_name"
            ]
        );
        for ok in ["s/new", "t/k", "DEFAULT/k", "empty/k", "SOPS/k"] {
            assert!(b.check_put(&name(ok), PutMode::CreateOnly).is_ok(), "{ok}");
        }
        assert!(b.check_put(&name("s/k"), PutMode::Replace).is_ok());
        for mode in [PutMode::CreateOnly, PutMode::Replace] {
            for bad in ["k", "top", "a/b/c", "s/k/deep", "a.b/k", "s/a-b", "s/0k"] {
                let e = b.check_put(&name(bad), mode).unwrap_err();
                assert!(
                    matches!(e, BackendError::Name(NameError::NotSectionKey)),
                    "{bad}: {e}"
                );
                assert!(e.to_string().contains("section/key"), "{e}");
                assert_eq!(e.exit(), Exit::Refused);
            }
            for bad in ["sops/k", "sops/mac"] {
                let e = b.check_put(&name(bad), mode).unwrap_err();
                assert!(
                    matches!(e, BackendError::Name(NameError::ReservedSection)),
                    "{bad}: {e}"
                );
                assert_eq!(e.exit(), Exit::Refused);
            }
        }
        // A section holds other names, so it is no name to write.
        let e = b.check_put(&name("s"), PutMode::Replace).unwrap_err();
        assert_eq!(e.exit(), Exit::Refused);
        // The file sets unencrypted_suffix = _pub in the `[sops]` section.
        // secrit tests each segment, as for a nested name of a YAML store.
        for bad in ["s/tok_pub", "app_pub/k"] {
            let e = b.check_put(&name(bad), PutMode::CreateOnly).unwrap_err();
            assert!(
                matches!(e, BackendError::Name(NameError::UnencryptedSuffix { .. })),
                "{bad}: {e}"
            );
        }
        // A metadata line is not an entry, so it is no name to remove.
        let e = b.check_remove(&name("sops/mac")).unwrap_err();
        assert_eq!(e.exit(), Exit::Failed, "{e}");
        assert!(b.check_remove(&name("s/k")).is_ok());
    }

    /// v0.2 plan 5.4 and T58: a dotenv store takes a variable name with
    /// no `sops_` prefix. `check_put` refuses any other name with exit 3,
    /// with no sops run (the sops path here does not exist). The suffix
    /// rule of the flat metadata applies too.
    #[test]
    fn a_dotenv_store_takes_variable_names_only() {
        let tmp = tempfile::tempdir().unwrap();
        let b = store_file_for(tmp.path(), "main.env", DOTENV_BASE);
        assert_eq!(b.format, SopsFormat::Dotenv);
        assert_eq!(b.list().unwrap(), ["A", "EMPTY"]);
        for ok in ["TOKEN", "b2_C", "SOPS_X", "xsops_y"] {
            assert!(b.check_put(&name(ok), PutMode::CreateOnly).is_ok(), "{ok}");
        }
        for mode in [PutMode::CreateOnly, PutMode::Replace] {
            for bad in ["sops_x", "sops_mac", "sops_age__list_0__map_enc"] {
                let e = b.check_put(&name(bad), mode).unwrap_err();
                assert!(
                    matches!(e, BackendError::Name(NameError::MetadataPrefix)),
                    "{bad}: {e}"
                );
                assert!(e.to_string().contains("metadata"), "{e}");
                assert_eq!(e.exit(), Exit::Refused);
            }
            for bad in ["a.b", "a-b", "0a", "a/b"] {
                let e = b.check_put(&name(bad), mode).unwrap_err();
                assert!(
                    matches!(e, BackendError::Name(NameError::NotVariable)),
                    "{bad}: {e}"
                );
                assert_eq!(e.exit(), Exit::Refused);
            }
        }
        // The name `sops` stays reserved, as in every sops format.
        let e = b.check_put(&name("sops"), PutMode::CreateOnly).unwrap_err();
        assert!(matches!(e, BackendError::Name(NameError::Reserved)), "{e}");
        // The file sets unencrypted_suffix = _pub in a flat metadata line.
        let e = b
            .check_put(&name("tok_pub"), PutMode::CreateOnly)
            .unwrap_err();
        assert!(
            matches!(e, BackendError::Name(NameError::UnencryptedSuffix { .. })),
            "{e}"
        );
        // A metadata line is not an entry, so it is no name to remove.
        let e = b.check_remove(&name("sops_mac")).unwrap_err();
        assert!(matches!(e, BackendError::Missing { .. }), "{e}");
        assert!(b.check_remove(&name("A")).is_ok());
        let e = b.check_put(&name("A"), PutMode::CreateOnly).unwrap_err();
        assert!(matches!(e, BackendError::Exists { .. }), "{e}");
        assert!(b.inspect().unwrap().plaintext.is_empty());

        // A YAML store has no such rule.
        let yaml = backend_for(tmp.path(), BASE);
        for ok in ["sops_x", "a.b", "0a"] {
            assert!(
                yaml.check_put(&name(ok), PutMode::CreateOnly).is_ok(),
                "{ok}"
            );
        }
    }

    fn backend_for(dir: &Path, yaml: &str) -> SopsBackend {
        store_file_for(dir, "main.yaml", yaml)
    }

    /// A backend for the store file `file_name` in `dir` with the content
    /// `text`. The format comes from the file name.
    fn store_file_for(dir: &Path, file_name: &str, text: &str) -> SopsBackend {
        let file = dir.join(file_name);
        std::fs::write(&file, text).unwrap();
        let store = SopsStore {
            file,
            format: None,
            sops_config: None,
            age_key_file: None,
        };
        SopsBackend::new(&store, "/nonexistent/sops".into(), Duration::ZERO, &|_| {
            None
        })
        .unwrap()
    }

    const ENC: &str = "ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]";

    fn name(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    /// v0.2 plan 5.4: the reserved `sops` key is the first segment only,
    /// and the suffix rules apply to every segment, as sops applies them
    /// (S5 lab). All refusals exit 3 with no sops run.
    #[test]
    fn the_sops_name_rules_apply_to_each_segment() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), BASE);
        for ok in ["app/sops", "x/y/z", "sops.x", "q/sops"] {
            assert!(b.check_put(&name(ok), PutMode::CreateOnly).is_ok(), "{ok}");
        }
        for bad in ["sops", "sops/x"] {
            let e = b.check_put(&name(bad), PutMode::CreateOnly).unwrap_err();
            assert!(
                matches!(e, BackendError::Name(NameError::Reserved)),
                "{bad}: {e}"
            );
            assert_eq!(e.exit(), Exit::Refused);
        }
        for bad in ["x_unencrypted", "p_unencrypted/k", "q/b_unencrypted/c"] {
            let e = b.check_put(&name(bad), PutMode::CreateOnly).unwrap_err();
            assert!(
                matches!(e, BackendError::Name(NameError::UnencryptedSuffix { .. })),
                "{bad}: {e}"
            );
            assert_eq!(e.exit(), Exit::Refused);
        }

        let suffix = BASE.replace("  version:", "  unencrypted_suffix: _pub\n  version:");
        let b = backend_for(tmp.path(), &suffix);
        let e = b
            .check_put(&name("x_pub/k"), PutMode::CreateOnly)
            .unwrap_err();
        assert!(e.to_string().contains("_pub"), "{e}");
        assert!(b.check_put(&name("x/k"), PutMode::CreateOnly).is_ok());

        // sops encrypts a leaf when any key on its path ends with the
        // encrypted_suffix.
        let enc = BASE.replace("  version:", "  encrypted_suffix: _enc\n  version:");
        let b = backend_for(tmp.path(), &enc);
        for ok in ["g_enc/k", "g/k_enc", "x_enc"] {
            assert!(b.check_put(&name(ok), PutMode::CreateOnly).is_ok(), "{ok}");
        }
        let e = b.check_put(&name("g/k"), PutMode::CreateOnly).unwrap_err();
        assert!(
            matches!(
                e,
                BackendError::Name(NameError::MissingEncryptedSuffix { .. })
            ),
            "{e}"
        );
    }

    /// T49: a path through a value that is not a map is refused before any
    /// input, and so is a write or a remove of a name that holds others.
    #[test]
    fn a_key_path_never_turns_a_value_into_a_map() {
        let tmp = tempfile::tempdir().unwrap();
        let b = backend_for(tmp.path(), &format!("{BASE}m:\n  n: {ENC}\n"));
        for (bad, mode) in [
            ("a/b", PutMode::CreateOnly),
            ("a/b/c", PutMode::Replace),
            ("m/n/o", PutMode::CreateOnly),
        ] {
            let e = b.check_put(&name(bad), mode).unwrap_err();
            assert!(matches!(e, BackendError::KeyPath { .. }), "{bad}: {e}");
            assert!(e.to_string().contains("not a map"), "{bad}: {e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        for mode in [PutMode::CreateOnly, PutMode::Replace] {
            let e = b.check_put(&name("m"), mode).unwrap_err();
            assert!(
                e.to_string().contains("holds other names under 'm/'"),
                "{e}"
            );
            assert_eq!(e.exit(), Exit::Refused);
        }
        let e = b.check_remove(&name("m")).unwrap_err();
        assert!(matches!(e, BackendError::KeyPath { .. }), "{e}");
        assert_eq!(e.exit(), Exit::Refused);

        // A nested name that exists, and one that does not.
        let e = b.check_put(&name("m/n"), PutMode::CreateOnly).unwrap_err();
        assert!(matches!(e, BackendError::Exists { .. }), "{e}");
        assert!(b.check_put(&name("m/n"), PutMode::Replace).is_ok());
        assert!(b.check_put(&name("m/x"), PutMode::CreateOnly).is_ok());
        assert!(b.check_remove(&name("m/n")).is_ok());
        assert!(b.exists(&name("m/n")).unwrap());
        // Under a string, a name does not exist for `rm`.
        let e = b.check_remove(&name("a/b")).unwrap_err();
        assert!(matches!(e, BackendError::Missing { .. }), "{e}");
        assert_eq!(b.list().unwrap(), ["a", "m/n"]);
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
