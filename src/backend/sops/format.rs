//! The store file format (v0.2 plan 5.5, 5.8 and 6.1.2): how secrit picks
//! the format of a sops file, parses it, and checks the copy that sops
//! wrote.

use std::fmt;
use std::path::Path;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

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

/// The file name endings that sops reads as YAML.
const YAML_ENDINGS: [&str; 2] = [".yaml", ".yml"];
/// The file name ending that sops reads as JSON.
const JSON_ENDING: &str = ".json";
/// The file name endings that sops reads as a format that secrit does not
/// support yet, with that format's name (v0.2 plan S6 and S6b).
const UNSUPPORTED_ENDINGS: [(&str, &str); 2] = [(".env", "dotenv"), (".ini", "INI")];

/// The format of a sops store file: the `format` key of a sops store
/// (v0.2 plan 5.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum SopsFormat {
    /// A sops YAML file
    Yaml,
    /// A sops JSON file
    Json,
}

/// A parsed sops file: the entries, and the sops metadata apart.
#[derive(Debug)]
pub struct SopsDoc {
    pub entries: Map<String, Value>,
    pub meta: Map<String, Value>,
}

impl SopsFormat {
    /// Every format: for the tests that must cover each one, and for the
    /// temp copies that `doctor` lists.
    pub const ALL: [SopsFormat; 2] = [SopsFormat::Yaml, SopsFormat::Json];

    /// The format of the store `file`: `explicit` (the `format` key), else
    /// the one that sops picks from the file name. A `.json` name means
    /// JSON, and any other name means YAML, as in v0.1. A name that sops
    /// reads as dotenv or INI is refused until secrit supports that format
    /// (v0.2 plan 5.8).
    pub fn of_file(explicit: Option<SopsFormat>, file: &Path) -> Result<Self, BackendError> {
        if let Some(format) = explicit {
            return Ok(format);
        }
        let name = lower_file_name(file);
        if name.ends_with(JSON_ENDING) {
            return Ok(SopsFormat::Json);
        }
        match UNSUPPORTED_ENDINGS.iter().find(|(e, _)| name.ends_with(e)) {
            Some((ending, format)) => Err(BackendError::Unsafe {
                path: file.to_path_buf(),
                reason: format!(
                    "sops reads a {ending} file as {format}, and secrit does not support the {format} format yet"
                ),
            }),
            None => Ok(SopsFormat::Yaml),
        }
    }

    /// The value of the `format` key, and the `format` of a sops-nix
    /// secret.
    pub fn name(self) -> &'static str {
        match self {
            SopsFormat::Yaml => "yaml",
            SopsFormat::Json => "json",
        }
    }

    /// The sops `--input-type` and `--output-type` of the store file.
    pub fn input_type(self) -> &'static str {
        self.name()
    }

    /// The extension of a temp copy, so sops reads it in this format.
    pub fn temp_ext(self) -> &'static str {
        self.name()
    }

    /// Whether `ext` is the temp copy extension of any format. A change of
    /// the `format` key changes the extension, so a stale temp copy can
    /// have the extension of another format.
    pub fn is_temp_ext(ext: &std::ffi::OsStr) -> bool {
        Self::ALL.iter().any(|f| ext == f.temp_ext())
    }

    /// What sops encrypts for a new store file with no entries: the JSON
    /// input of `sops encrypt`, whatever the output format.
    pub fn empty_doc(self) -> &'static [u8] {
        match self {
            SopsFormat::Yaml | SopsFormat::Json => b"{}\n",
        }
    }

    /// The format in messages.
    fn label(self) -> &'static str {
        match self {
            SopsFormat::Yaml => "YAML",
            SopsFormat::Json => "JSON",
        }
    }

    /// What the store file must be, for [`BackendError::Parse`].
    fn what(self) -> &'static str {
        match self {
            SopsFormat::Yaml => "sops YAML file",
            SopsFormat::Json => "sops JSON file",
        }
    }

    /// The file name endings that sops reads as another format.
    fn other_endings(self) -> Vec<&'static str> {
        let own: &[&str] = match self {
            SopsFormat::Yaml => &[JSON_ENDING],
            SopsFormat::Json => &YAML_ENDINGS,
        };
        own.iter()
            .copied()
            .chain(UNSUPPORTED_ENDINGS.iter().map(|(e, _)| *e))
            .collect()
    }

    pub fn parse(self, bytes: &[u8], path: &Path) -> Result<SopsDoc, BackendError> {
        let parse_err = |what: &str| BackendError::Parse {
            location: Location::File(path.to_path_buf()),
            format: self.what(),
            what: what.into(),
        };
        // The parser's own message can quote file content; it is not shown.
        let value: Value = match self {
            SopsFormat::Yaml => {
                serde_saphyr::from_slice(bytes).map_err(|_| parse_err("invalid YAML"))?
            }
            SopsFormat::Json => strict_json(bytes).map_err(parse_err)?,
        };
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

    /// Every sops run names the store's format, so a write would rewrite a
    /// file of another format in the store's format (v0.2 plan V14, T50).
    /// The write path refuses such a file before it reads a value. A YAML
    /// store refuses a JSON file: a YAML file in flow style also parses as
    /// JSON, but sops never writes one, and a leading UTF-8 BOM does not
    /// hide a JSON file. A JSON store refuses a file that is not strict
    /// JSON.
    pub fn refuse_other(self, bytes: &[u8], path: &Path) -> Result<(), BackendError> {
        self.refuse_other_name(path)?;
        let other = match self {
            SopsFormat::Yaml => {
                let body = bytes
                    .strip_prefix(UTF8_BOM)
                    .unwrap_or(bytes)
                    .trim_ascii_start();
                let object = body.first() == Some(&b'{')
                    && serde_json::from_slice::<IgnoredAny>(body).is_ok();
                object.then_some("it is a sops JSON file")
            }
            SopsFormat::Json => strict_json(bytes)
                .is_err()
                .then_some("it is not a sops JSON file"),
        };
        match other {
            Some(what) => Err(BackendError::Unsafe {
                path: path.to_path_buf(),
                reason: format!(
                    "{what}, and the store's format is {}; a write would rewrite it as {}. \
                     Set the store's format key to the format of the file",
                    self.name(),
                    self.label()
                ),
            }),
            None => Ok(()),
        }
    }

    /// sops picks the format from the file name, so a store file must not
    /// have a name that sops reads as another format: a `sops edit` of it
    /// would rewrite it in that format.
    pub fn refuse_other_name(self, path: &Path) -> Result<(), BackendError> {
        let file_name = lower_file_name(path);
        match self
            .other_endings()
            .into_iter()
            .find(|e| file_name.ends_with(e))
        {
            Some(ending) => Err(BackendError::Unsafe {
                path: path.to_path_buf(),
                reason: format!(
                    "sops does not read a {ending} file as {}, and the store's format is {}",
                    self.label(),
                    self.name()
                ),
            }),
            None => Ok(()),
        }
    }
}

/// The file name of `path` in lower case, for the ending checks.
fn lower_file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// `bytes` as strict JSON (v0.2 plan 6.1.2): one value, no byte order mark,
/// and no key twice in one object, because a repeated key would hide an
/// entry from the copy validation. The error is fixed text: a parser
/// message can quote file content.
fn strict_json(bytes: &[u8]) -> Result<Value, &'static str> {
    serde_json::from_slice::<IgnoredAny>(bytes).map_err(|_| "invalid JSON")?;
    serde_json::from_slice::<StrictValue>(bytes)
        .map(|v| v.0)
        .map_err(|_| "a key appears twice in one object")
}

/// A JSON value that refuses a repeated key in an object.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(StrictValue)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictValue(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut m = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if m.contains_key(&k) {
                return Err(de::Error::custom("a key appears twice"));
            }
            let StrictValue(v) = map.next_value()?;
            m.insert(k, v);
        }
        Ok(Value::Object(m))
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
    fn a_yaml_store_refuses_another_format() {
        let yaml = Path::new("/s/main.yaml");
        let f = SopsFormat::Yaml;
        assert!(f.refuse_other(BASE.as_bytes(), yaml).is_ok());
        let json = br#"{"a": "ENC[x]", "sops": {"mac": "ENC[m]"}}"#;
        let bom = b"\xEF\xBB\xBF{\"a\": \"ENC[x]\"}";
        let bom_space = b"\xEF\xBB\xBF \n {}";
        for bytes in [&json[..], b"\n  {}\n", &bom[..], &bom_space[..]] {
            let e = f.refuse_other(bytes, yaml).unwrap_err();
            assert!(e.to_string().contains("it is a sops JSON file"), "{e}");
            assert!(e.to_string().contains("format is yaml"), "{e}");
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
            assert!(e.to_string().contains("as YAML"), "{name}: {e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        assert!(f.refuse_other_name(Path::new("/s/a.env.yaml")).is_ok());
    }

    pub const JSON_BASE: &str = r#"{
	"a": "ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]",
	"sops": {
		"age": [{"recipient": "age1x", "enc": "blob"}],
		"mac": "ENC[AES256_GCM,data:m,type:str]",
		"lastmodified": "1",
		"version": "3.13.3"
	}
}
"#;

    /// T50: a JSON store parses with `serde_json`, strictly, and refuses a
    /// file that is not strict JSON or that has a name sops reads as
    /// another format.
    #[test]
    fn a_json_store_is_strict_json() {
        let f = SopsFormat::Json;
        let path = Path::new("/s/main.json");
        let doc = f.parse(JSON_BASE.as_bytes(), path).unwrap();
        assert_eq!(doc.entries.len(), 1);
        assert!(doc.meta.contains_key("age"));
        assert!(f.refuse_other(JSON_BASE.as_bytes(), path).is_ok());

        // The YAML form of the same file, a byte order mark, trailing
        // text and a repeated key are refused, and the parse error quotes
        // no file content.
        let dup = JSON_BASE.replace(
            "\t\"sops\"",
            "\t\"a\": \"ENC[AES256_GCM,data:secret-ish,type:str]\",\n\t\"sops\"",
        );
        let nested_dup = JSON_BASE.replace("\"lastmodified\"", "\"mac\": \"x\", \"lastmodified\"");
        let mut bom = b"\xEF\xBB\xBF".to_vec();
        bom.extend_from_slice(JSON_BASE.as_bytes());
        let trailing = format!("{JSON_BASE}x");
        for (bytes, want) in [
            (BASE.as_bytes(), "invalid JSON"),
            (&bom[..], "invalid JSON"),
            (trailing.as_bytes(), "invalid JSON"),
            (dup.as_bytes(), "a key appears twice"),
            (nested_dup.as_bytes(), "a key appears twice"),
        ] {
            let e = f.parse(bytes, path).unwrap_err();
            let text = e.to_string();
            assert!(text.contains("as a sops JSON file"), "{text}");
            assert!(text.contains(want), "{text}");
            assert!(
                !text.contains("secret-ish") && !text.contains("ENC["),
                "{text}"
            );
            let e = f.refuse_other(bytes, path).unwrap_err();
            assert!(e.to_string().contains("it is not a sops JSON file"), "{e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        for name in ["s.yaml", "S.YML", "s.env", "s.ini"] {
            let e = f
                .refuse_other(JSON_BASE.as_bytes(), &Path::new("/s").join(name))
                .unwrap_err();
            assert!(e.to_string().contains("as JSON"), "{name}: {e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        assert!(f.refuse_other_name(Path::new("/s/secrets")).is_ok());
        assert!(f.refuse_other_name(Path::new("/s/a.yaml.json")).is_ok());
    }

    /// v0.2 plan 5.8: the `format` key wins; with none, `.json` means JSON,
    /// `.env` and `.ini` are refused, and any other name means YAML.
    #[test]
    fn the_format_comes_from_the_key_or_the_file_name() {
        let of = |explicit, name: &str| SopsFormat::of_file(explicit, &Path::new("/s").join(name));
        for (name, want) in [
            ("main.yaml", SopsFormat::Yaml),
            ("main.yml", SopsFormat::Yaml),
            ("secrets", SopsFormat::Yaml),
            ("main.txt", SopsFormat::Yaml),
            ("main.json", SopsFormat::Json),
            ("MAIN.JSON", SopsFormat::Json),
        ] {
            assert_eq!(of(None, name).unwrap(), want, "{name}");
        }
        for (name, said) in [("a.env", "dotenv"), (".env", "dotenv"), ("a.INI", "INI")] {
            let e = of(None, name).unwrap_err();
            assert!(e.to_string().contains(said), "{name}: {e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        for format in SopsFormat::ALL {
            for name in ["main.yaml", "main.json", "a.env", "secrets"] {
                assert_eq!(of(Some(format), name).unwrap(), format, "{name}");
            }
        }
        assert_eq!(SopsFormat::Json.input_type(), "json");
        assert_eq!(SopsFormat::Json.temp_ext(), "json");
        assert_eq!(SopsFormat::Yaml.name(), "yaml");
    }

    /// The copy validation of 6.1.2 holds for a JSON store too.
    #[test]
    fn validate_catches_tampering_in_json() {
        let path = Path::new("/s/main.json");
        let parse = |s: &str| SopsFormat::Json.parse(s.as_bytes(), path).unwrap();
        let orig = parse(JSON_BASE);
        let b = Name::parse("b").unwrap();
        let v = SecretValue::new(b"v".to_vec());
        let put = Op::Put(&v, PutMode::CreateOnly);
        let with_b = |b_value: &str| {
            JSON_BASE.replace("\t\"sops\"", &format!("\t\"b\": {b_value},\n\t\"sops\""))
        };
        let good = parse(&with_b("\"ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\""));
        assert!(validate(&orig, &good, &b, put).is_ok());
        for bad in [
            with_b("\"v\""),
            with_b("\"ENC[AES256_GCM,data:q,iv:w,tag:e,type:int]\""),
            with_b("5"),
            with_b("\"ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\"").replace("data:x", "data:Y"),
            with_b("\"ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]\"").replace("age1x", "age1y"),
        ] {
            assert!(validate(&orig, &parse(&bad), &b, put).is_err(), "{bad}");
        }
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
