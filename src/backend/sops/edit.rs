//! One `store` or `rm` on a sops file, as a [`FileEdit`] for the write
//! protocol in `backend/atomic.rs`, and the checks that run before it.
//!
//! A name is a key path (v0.2 plan 5.4). sops 3.13.3, checked in the S5
//! lab: `set` creates missing parent maps, and replaces a string leaf on
//! the path with a map, silently (T49); `unset` leaves an empty parent
//! map. So secrit refuses a path through a value that is not a map before
//! any input, and `rm` prunes the ancestors that it left empty with a
//! second `unset` on the same copy (6.1.2).

use std::cell::Cell;
use std::path::Path;

use serde_json::{Map, Value};

use super::SopsBackend;
use super::format::{
    REGEX_RULES, Slot, SopsDoc, has_plaintext, is_branch, leaves, lookup, path_text, prune_depth,
    validate,
};
use crate::backend::atomic::FileEdit;
use crate::backend::{BackendError, PutMode};
use crate::display::escape;
use crate::name::{DEFAULT_UNENCRYPTED_SUFFIX, Name, NameError, RESERVED};
use crate::secret::SecretValue;

#[derive(Debug, Clone, Copy)]
pub enum Op<'a> {
    Put(&'a SecretValue, PutMode),
    Remove,
}

/// `op` on `name` in the store file of `backend`.
#[derive(Debug)]
pub struct SopsEdit<'a> {
    pub backend: &'a SopsBackend,
    pub name: &'a Name,
    pub op: Op<'a>,
    /// For a remove: the segments of the ancestor that the remove leaves
    /// empty, from the precheck of the original.
    pub prune: Cell<Option<usize>>,
}

impl FileEdit for SopsEdit<'_> {
    type Doc = SopsDoc;

    fn temp_ext(&self) -> &'static str {
        self.backend.format.temp_ext()
    }

    fn precheck(&self, original: &[u8]) -> Result<(SopsDoc, bool), BackendError> {
        let b = self.backend;
        b.format.refuse_other(original, b.store.file())?;
        let doc = b.format.parse(original, b.store.file())?;
        let put = matches!(self.op, Op::Put(..));
        let existed = b.check_path(self.name, &doc.entries, put)?;
        match self.op {
            Op::Put(_, PutMode::CreateOnly) if existed => {
                return Err(b.exists_error(self.name));
            }
            Op::Remove if !existed => return Err(b.missing_error(self.name)),
            Op::Put(..) => b.check_cleartext_rules(self.name, &doc.meta)?,
            Op::Remove => {
                let path: Vec<&str> = self.name.segments().collect();
                self.prune.set(prune_depth(&doc.entries, &path));
            }
        }
        Ok((doc, existed))
    }

    fn apply(&self, tmp: &Path) -> Result<(), BackendError> {
        let b = self.backend;
        let target = b.target(Some(self.name));
        match self.op {
            Op::Put(value, _) => b.runner.set(b.format, tmp, self.name, value, target),
            Op::Remove => {
                b.runner.unset(b.format, tmp, self.name, target.clone())?;
                match self.prune.get().and_then(|depth| self.name.prefix(depth)) {
                    Some(ancestor) => b.runner.unset(b.format, tmp, &ancestor, target),
                    None => Ok(()),
                }
            }
        }
    }

    fn parse(&self, copy: &[u8], path: &Path) -> Result<SopsDoc, BackendError> {
        self.backend.format.parse(copy, path)
    }

    fn validate(&self, original: &SopsDoc, copy: &SopsDoc) -> Result<(), BackendError> {
        validate(original, copy, self.name, self.op)
            .map_err(|reason| self.backend.validation(Some(self.name), reason))
    }

    fn readback(&self, copy: &[u8]) -> Result<(), BackendError> {
        match self.op {
            Op::Put(value, _) => self.backend.readback(copy, self.name, value),
            Op::Remove => Ok(()),
        }
    }
}

impl SopsBackend {
    /// The key path of `name` in `entries`: `true` when it holds a value.
    /// A name that holds other names is refused: a write or a remove of it
    /// would replace or drop them all. For a put (`put`), a path through a
    /// value that is not a map is refused too (T49); for a remove, that
    /// name does not exist. Must not decrypt.
    pub(super) fn check_path(
        &self,
        name: &Name,
        entries: &Map<String, Value>,
        put: bool,
    ) -> Result<bool, BackendError> {
        let path: Vec<&str> = name.segments().collect();
        match lookup(entries, &path) {
            Slot::Missing => Ok(false),
            Slot::Blocked { .. } if !put => Ok(false),
            Slot::Value(v) if is_branch(v) => Err(self.key_path_error(
                name,
                format!("it holds other names under '{name}/'; secrit writes and removes one value at a time"),
            )),
            Slot::Value(_) => Ok(true),
            Slot::Blocked { depth, kind } => Err(self.key_path_error(
                name,
                format!(
                    "'{}' holds a {kind}, not a map, and secrit never turns a value into a map",
                    escape(&path_text(&path[..depth]))
                ),
            )),
        }
    }

    fn key_path_error(&self, name: &Name, reason: String) -> BackendError {
        BackendError::KeyPath {
            name: name.clone(),
            location: self.location.clone(),
            reason,
        }
    }

    /// Refuse a file that already holds a cleartext leaf other than NAME
    /// (written by another tool, or kept by sops under `unencrypted_suffix`).
    /// The copy validation refuses such a file after the write (PLAN 8.1,
    /// step 9); this check runs first, so nobody types a value for nothing.
    pub(super) fn check_plaintext(
        &self,
        name: &Name,
        entries: &Map<String, Value>,
    ) -> Result<(), BackendError> {
        let path: Vec<&str> = name.segments().collect();
        match leaves(entries)
            .into_iter()
            .find(|(p, v)| *p != path && has_plaintext(v))
        {
            Some((p, _)) => Err(BackendError::CleartextRule {
                path: self.store.file().to_path_buf(),
                reason: format!(
                    "entry '{}' is not encrypted, and secrit never writes a file with a cleartext entry; encrypt it or remove it with sops first",
                    escape(&path_text(&p))
                ),
            }),
            None => Ok(()),
        }
    }

    /// Refuse a name that sops would store in cleartext under the file's own
    /// rules (the metadata in its `sops` block, which `sops set` applies),
    /// or that the format reserves (v0.2 plan 5.4, 6.1.3). sops tests the
    /// suffix rules on each key of the path (sops 3.13.3, checked in the
    /// S5 lab): a leaf is cleartext when any key on its path ends with
    /// `unencrypted_suffix`, and encrypted under `encrypted_suffix` only
    /// when a key on its path ends with it.
    pub(super) fn check_cleartext_rules(
        &self,
        name: &Name,
        meta: &Map<String, Value>,
    ) -> Result<(), BackendError> {
        // Only the top-level `sops` key is metadata: `app/sops` is a name.
        if name.segments().next() == Some(RESERVED) {
            return Err(NameError::Reserved.into());
        }
        let rule = |k: &str| {
            meta.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        };
        for &key in REGEX_RULES {
            if rule(key).is_some() {
                return Err(BackendError::CleartextRule {
                    path: self.store.file().to_path_buf(),
                    reason: format!(
                        "the file sets {key}, and secrit v0.1 does not evaluate sops regex rules"
                    ),
                });
            }
        }
        // The sops default suffix is refused too, as in v0.1, whatever the
        // file sets.
        for sfx in [Some(DEFAULT_UNENCRYPTED_SUFFIX), rule("unencrypted_suffix")]
            .into_iter()
            .flatten()
        {
            if name.segments().any(|s| s.ends_with(sfx)) {
                return Err(NameError::UnencryptedSuffix {
                    name: name.to_string(),
                    suffix: escape(sfx).into_owned(),
                }
                .into());
            }
        }
        if let Some(sfx) = rule("encrypted_suffix")
            && !name.segments().any(|s| s.ends_with(sfx))
        {
            return Err(NameError::MissingEncryptedSuffix {
                name: name.to_string(),
                suffix: escape(sfx).into_owned(),
            }
            .into());
        }
        Ok(())
    }

    /// Decrypt `name` from the validated copy bytes and compare it in
    /// constant time.
    fn readback(&self, copy: &[u8], name: &Name, value: &SecretValue) -> Result<(), BackendError> {
        let json = value
            .to_json_string()
            .map_err(|_| self.validation(Some(name), "the value is not UTF-8"))?;
        let inner = &json[1..json.len() - 1];
        let got = self.runner.decrypt_one(
            self.format,
            copy,
            name,
            "readback decrypt",
            self.target(Some(name)),
            &[value.expose(), inner],
        )?;
        if !value.ct_eq(got.expose()) {
            return Err(self.validation(
                Some(name),
                "the value read back from the new file differs from the input",
            ));
        }
        Ok(())
    }
}
