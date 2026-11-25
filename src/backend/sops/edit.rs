//! One `store` or `rm` on a sops file, as a [`FileEdit`] for the write
//! protocol in `backend/atomic.rs`, and the checks that run before it.

use std::path::Path;

use serde_json::{Map, Value};

use super::SopsBackend;
use super::format::{REGEX_RULES, SopsDoc, has_plaintext, validate};
use crate::backend::atomic::FileEdit;
use crate::backend::{BackendError, PutMode};
use crate::display::escape;
use crate::name::{Name, NameError};
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
        let existed = doc.entries.contains_key(self.name.as_str());
        match self.op {
            Op::Put(_, PutMode::CreateOnly) if existed => {
                return Err(b.exists_error(self.name));
            }
            Op::Remove if !existed => return Err(b.missing_error(self.name)),
            Op::Put(..) => b.check_cleartext_rules(self.name, &doc.meta)?,
            Op::Remove => {}
        }
        Ok((doc, existed))
    }

    fn apply(&self, tmp: &Path) -> Result<(), BackendError> {
        let b = self.backend;
        let target = b.target(Some(self.name));
        match self.op {
            Op::Put(value, _) => b.runner.set(b.format, tmp, self.name, value, target),
            Op::Remove => b.runner.unset(b.format, tmp, self.name, target),
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
    /// Refuse a file that already holds a cleartext entry other than NAME
    /// (written by another tool, or kept by sops under `unencrypted_suffix`).
    /// The copy validation refuses such a file after the write (PLAN 8.1,
    /// step 9); this check runs first, so nobody types a value for nothing.
    pub(super) fn check_plaintext(
        &self,
        name: &Name,
        entries: &Map<String, Value>,
    ) -> Result<(), BackendError> {
        match entries
            .iter()
            .find(|(k, v)| k.as_str() != name.as_str() && has_plaintext(v))
        {
            Some((k, _)) => Err(BackendError::CleartextRule {
                path: self.store.file().to_path_buf(),
                reason: format!(
                    "entry '{}' is not encrypted, and secrit never writes a file with a cleartext entry; encrypt it or remove it with sops first",
                    escape(k)
                ),
            }),
            None => Ok(()),
        }
    }

    /// Refuse a name that sops would store in cleartext under the file's own
    /// rules (the metadata in its `sops` block, which `sops set` applies).
    pub(super) fn check_cleartext_rules(
        &self,
        name: &Name,
        meta: &Map<String, Value>,
    ) -> Result<(), BackendError> {
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
        if let Some(sfx) = rule("unencrypted_suffix")
            && name.as_str().ends_with(sfx)
        {
            return Err(NameError::UnencryptedSuffix {
                name: name.to_string(),
                suffix: escape(sfx).into_owned(),
            }
            .into());
        }
        if let Some(sfx) = rule("encrypted_suffix")
            && !name.as_str().ends_with(sfx)
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
