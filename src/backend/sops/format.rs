//! The store file format (v0.2 plan 5.5 and 6.1.2): how secrit parses a
//! sops file and checks the copy that sops wrote. v0.2 starts with YAML
//! only; S4 adds JSON.

use std::path::Path;

use serde::de::IgnoredAny;
use serde_json::{Map, Value};

use super::edit::Op;
use crate::backend::{BackendError, Location};
use crate::display::escape;
use crate::name::Name;

/// The recipient keys of the sops metadata.
const KEY_TYPES: &[&str] = &[
    "age",
    "pgp",
    "kms",
    "gcp_kms",
    "azure_kv",
    "hc_vault",
    "hckms",
    "key_groups",
];
/// The sops regex rules that leave some entries in cleartext. secrit v0.1
/// does not evaluate them, so it does not write a file that sets one. The
/// suffix rules are enforced by the name check instead.
pub const REGEX_RULES: &[&str] = &["unencrypted_regex", "encrypted_regex"];
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// The file name endings that sops reads as another format than YAML.
const NON_YAML_ENDINGS: [&str; 3] = [".json", ".env", ".ini"];

/// The format of a sops store file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SopsFormat {
    Yaml,
}

/// A parsed sops file: the entries, and the sops metadata apart.
#[derive(Debug)]
pub struct SopsDoc {
    pub entries: Map<String, Value>,
    pub meta: Map<String, Value>,
}

impl SopsFormat {
    /// The sops `--input-type` and `--output-type` of the store file.
    pub fn input_type(self) -> &'static str {
        match self {
            SopsFormat::Yaml => "yaml",
        }
    }

    /// The extension of a temp copy, so sops reads it in this format.
    pub fn temp_ext(self) -> &'static str {
        match self {
            SopsFormat::Yaml => "yaml",
        }
    }

    /// What sops encrypts for a new store file with no entries.
    pub fn empty_doc(self) -> &'static [u8] {
        match self {
            SopsFormat::Yaml => b"{}\n",
        }
    }

    /// What the store file must be, for [`BackendError::Parse`].
    fn what(self) -> &'static str {
        match self {
            SopsFormat::Yaml => "sops YAML file",
        }
    }

    pub fn parse(self, bytes: &[u8], path: &Path) -> Result<SopsDoc, BackendError> {
        let parse_err = |what: &str| BackendError::Parse {
            location: Location::File(path.to_path_buf()),
            format: self.what(),
            what: what.into(),
        };
        // The parser's own message can quote file content; it is not shown.
        let value: Value =
            serde_saphyr::from_slice(bytes).map_err(|_| parse_err("invalid YAML"))?;
        let Value::Object(mut entries) = value else {
            return Err(parse_err("the top level is not a mapping"));
        };
        let Some(Value::Object(meta)) = entries.remove("sops") else {
            return Err(parse_err("there is no sops metadata block"));
        };
        if !meta
            .get("mac")
            .and_then(Value::as_str)
            .is_some_and(|m| m.starts_with("ENC["))
        {
            return Err(parse_err("the sops block has no MAC"));
        }
        Ok(SopsDoc { entries, meta })
    }

    /// v0.1 runs `sops set` and `unset` with `--output-type yaml`, so a
    /// write turns a JSON store into YAML, which a consumer that reads it as
    /// JSON cannot parse (v0.2 plan, V14). The write path refuses such a
    /// file before it reads a value. A YAML file in flow style also parses
    /// as JSON; sops never writes one. A leading UTF-8 BOM does not hide a
    /// JSON file.
    pub fn refuse_other(self, bytes: &[u8], path: &Path) -> Result<(), BackendError> {
        self.refuse_other_name(path)?;
        let body = bytes
            .strip_prefix(UTF8_BOM)
            .unwrap_or(bytes)
            .trim_ascii_start();
        let object =
            body.first() == Some(&b'{') && serde_json::from_slice::<IgnoredAny>(body).is_ok();
        if object {
            return Err(BackendError::Unsafe {
                path: path.to_path_buf(),
                reason: "it is a sops JSON file; secrit v0.1 writes YAML stores only, \
                         and a write would rewrite it as YAML"
                    .into(),
            });
        }
        Ok(())
    }

    /// sops picks the format from the file name, so a YAML store file must
    /// not have a name that sops reads as JSON, dotenv or INI.
    pub fn refuse_other_name(self, path: &Path) -> Result<(), BackendError> {
        let others: &[&str] = match self {
            SopsFormat::Yaml => &NON_YAML_ENDINGS,
        };
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        match others.iter().find(|e| file_name.ends_with(*e)) {
            Some(ending) => Err(BackendError::Unsafe {
                path: path.to_path_buf(),
                reason: format!(
                    "sops does not read a {ending} file as YAML; \
                     secrit v0.1 writes YAML stores only"
                ),
            }),
            None => Ok(()),
        }
    }
}

pub fn has_recipients(meta: &Map<String, Value>) -> bool {
    KEY_TYPES.iter().any(|k| {
        meta.get(*k)
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
    })
}

/// Whether `v` holds a leaf that sops did not encrypt. sops never encrypts
/// an empty string or a null; such a leaf holds no secret.
pub fn has_plaintext(v: &Value) -> bool {
    match v {
        Value::String(s) => !s.is_empty() && !s.starts_with("ENC["),
        Value::Bool(_) | Value::Number(_) => true,
        Value::Null => false,
        Value::Array(a) => a.iter().any(has_plaintext),
        Value::Object(m) => m.values().any(has_plaintext),
    }
}

/// The kind of a ciphertext entry that does not decrypt to a string, from
/// the type tag sops writes into each `ENC[...]` value.
pub fn non_string_kind(entry: &Value) -> Option<&'static str> {
    match entry {
        Value::String(s) if !s.starts_with("ENC[") || s.ends_with(",type:str]") => None,
        Value::String(s) if s.ends_with(",type:int]") || s.ends_with(",type:float]") => {
            Some("number")
        }
        Value::String(s) if s.ends_with(",type:bool]") => Some("boolean"),
        Value::String(_) => Some("value of another type"),
        Value::Bool(_) => Some("boolean"),
        Value::Number(_) => Some("number"),
        Value::Null => Some("null"),
        Value::Array(_) => Some("list"),
        Value::Object(_) => Some("map"),
    }
}

/// The metadata that a `set` or `unset` must not change.
fn stable_meta(meta: &Map<String, Value>) -> Map<String, Value> {
    let mut m = meta.clone();
    for k in ["mac", "lastmodified", "version"] {
        m.remove(k);
    }
    m
}

/// PLAN section 8.1, step 9 (the structural part; the readback is separate).
/// The error is the reason; the caller adds the file and the name.
pub fn validate(orig: &SopsDoc, copy: &SopsDoc, name: &Name, op: Op<'_>) -> Result<(), String> {
    let fail = |m: String| Err(m);
    if !has_recipients(&copy.meta) {
        return fail("the new file has no recipients".into());
    }
    if stable_meta(&orig.meta) != stable_meta(&copy.meta) {
        return fail("the recipients or the sops settings changed".into());
    }
    for (k, v) in &orig.entries {
        if k != name.as_str() && copy.entries.get(k) != Some(v) {
            return fail(format!("entry '{}' changed or vanished", escape(k)));
        }
    }
    if let Some(k) = copy
        .entries
        .keys()
        .find(|k| k.as_str() != name.as_str() && !orig.entries.contains_key(*k))
    {
        return fail(format!("an unexpected entry '{}' appeared", escape(k)));
    }
    // No leaf of the new file is cleartext, not even an entry that was
    // cleartext before: secrit never writes such a file (PLAN 8.1, step 9).
    if let Some((k, _)) = copy.entries.iter().find(|(_, v)| has_plaintext(v)) {
        return fail(format!("entry '{}' is not encrypted", escape(k)));
    }
    match op {
        Op::Put(..) => match copy.entries.get(name.as_str()) {
            Some(Value::String(s))
                if s.starts_with("ENC[AES256_GCM,") && s.ends_with(",type:str]") =>
            {
                Ok(())
            }
            _ => fail(format!("'{name}' is not stored as an encrypted string")),
        },
        Op::Remove if copy.entries.contains_key(name.as_str()) => {
            fail(format!("'{name}' is still present"))
        }
        Op::Remove => Ok(()),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::backend::PutMode;
    use crate::error::Exit;
    use crate::secret::SecretValue;

    pub const BASE: &str = "a: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\nsops:\n  age:\n    - recipient: age1x\n      enc: blob\n  mac: ENC[AES256_GCM,data:m,type:str]\n  lastmodified: '1'\n  version: 3.13.3\n";

    pub fn doc(yaml: &str) -> SopsDoc {
        SopsFormat::Yaml
            .parse(yaml.as_bytes(), Path::new("/t.yaml"))
            .unwrap()
    }

    #[test]
    fn entry_kinds_come_from_the_ciphertext_tag() {
        let s = |v: &str| Value::String(v.into());
        assert_eq!(non_string_kind(&s("ENC[AES256_GCM,data:x,type:str]")), None);
        assert_eq!(non_string_kind(&s("cleartext")), None);
        assert_eq!(
            non_string_kind(&s("ENC[AES256_GCM,data:x,type:int]")),
            Some("number")
        );
        assert_eq!(
            non_string_kind(&s("ENC[AES256_GCM,data:x,type:bool]")),
            Some("boolean")
        );
        assert_eq!(non_string_kind(&serde_json::json!({"a": 1})), Some("map"));
        assert_eq!(non_string_kind(&serde_json::json!([1])), Some("list"));
    }

    #[test]
    fn parse_doc_requires_a_sops_block() {
        let parse = |b: &[u8]| SopsFormat::Yaml.parse(b, Path::new("/t"));
        assert!(parse(b"a: b\n").is_err());
        assert!(parse(b"- a\n").is_err());
        assert!(parse(b"sops:\n  age: []\n").is_err());
        assert_eq!(doc(BASE).entries.len(), 1);
    }

    #[test]
    fn a_store_that_is_not_yaml_is_refused() {
        let yaml = Path::new("/s/main.yaml");
        let f = SopsFormat::Yaml;
        assert!(f.refuse_other(BASE.as_bytes(), yaml).is_ok());
        let json = br#"{"a": "ENC[x]", "sops": {"mac": "ENC[m]"}}"#;
        let bom = b"\xEF\xBB\xBF{\"a\": \"ENC[x]\"}";
        let bom_space = b"\xEF\xBB\xBF \n {}";
        for bytes in [&json[..], b"\n  {}\n", &bom[..], &bom_space[..]] {
            let e = f.refuse_other(bytes, yaml).unwrap_err();
            assert!(e.to_string().contains("sops JSON file"), "{e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        // Flow-style YAML that is not JSON stays allowed, with a BOM too.
        assert!(f.refuse_other(b"{a: b}\n", yaml).is_ok());
        assert!(f.refuse_other(b"\xEF\xBB\xBF{a: b}\n", yaml).is_ok());
        let mut bom_yaml = b"\xEF\xBB\xBF".to_vec();
        bom_yaml.extend_from_slice(BASE.as_bytes());
        assert!(f.refuse_other(&bom_yaml, yaml).is_ok());
        for name in ["main.json", "MAIN.JSON", ".env", "a.env", "a.ini"] {
            let path = Path::new("/s").join(name);
            let e = f.refuse_other(BASE.as_bytes(), &path).unwrap_err();
            assert!(e.to_string().contains("YAML stores only"), "{name}: {e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        assert!(f.refuse_other_name(Path::new("/s/a.env.yaml")).is_ok());
    }

    #[test]
    fn validate_catches_tampering() {
        let orig = doc(BASE);
        let n = Name::parse("b").unwrap();
        let v = SecretValue::new(b"v".to_vec());
        let put = Op::Put(&v, PutMode::CreateOnly);
        let good = doc(
            &format!("{BASE}b: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n")
                .replace("mac: ENC[AES256_GCM,data:m", "mac: ENC[AES256_GCM,data:NEW"),
        );
        assert!(validate(&orig, &good, &n, put).is_ok());

        let cleartext = doc(&format!("{BASE}b: v\n"));
        assert!(validate(&orig, &cleartext, &n, put).is_err());

        let as_int = doc(&format!(
            "{BASE}b: ENC[AES256_GCM,data:q,iv:w,tag:e,type:int]\n"
        ));
        assert!(validate(&orig, &as_int, &n, put).is_err());

        let new_recipient = doc(
            &format!("{BASE}b: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n")
                .replace("recipient: age1x", "recipient: age1other"),
        );
        assert!(validate(&orig, &new_recipient, &n, put).is_err());

        let other_changed = doc(
            &format!("{BASE}b: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n")
                .replace("data:x", "data:CHANGED"),
        );
        assert!(validate(&orig, &other_changed, &n, put).is_err());

        let removed = doc(&BASE.replace("a: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n", ""));
        let a = Name::parse("a").unwrap();
        assert!(validate(&orig, &removed, &a, Op::Remove).is_ok());
        assert!(validate(&orig, &orig, &a, Op::Remove).is_err());

        // A cleartext leaf that was already in the file fails too (A-3),
        // and the reason names the entry, never its value.
        let orig_x = doc(&format!("{BASE}x: cleartext\n"));
        let copy_x = doc(&format!(
            "{BASE}x: cleartext\nb: ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\n"
        ));
        let reason = validate(&orig_x, &copy_x, &n, put).unwrap_err();
        assert!(reason.contains("'x' is not encrypted"), "{reason}");
        assert!(!reason.contains("cleartext"), "{reason}");
        let nested_yaml = format!("{BASE}x:\n  k: [1]\n");
        let nested = doc(&nested_yaml);
        let nested_removed =
            doc(&nested_yaml.replace("a: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n", ""));
        let reason = validate(&nested, &nested_removed, &a, Op::Remove).unwrap_err();
        assert!(reason.contains("'x' is not encrypted"), "{reason}");
    }
}
