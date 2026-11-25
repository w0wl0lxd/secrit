//! The store file format (v0.2 plan 5.5, 5.8 and 6.1.2): how secrit picks
//! the format of a sops file, parses it, and checks the copy that sops
//! wrote.

use std::collections::BTreeMap;
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
        // The parser's own message can quote file content; it is not shown.
        let value: Value = match self {
            SopsFormat::Yaml => serde_saphyr::from_slice(bytes)
                .map_err(|_| self.parse_error(path, "invalid YAML"))?,
            SopsFormat::Json => strict_json(bytes).map_err(|what| self.parse_error(path, what))?,
        };
        self.doc(value, path)
    }

    /// A [`BackendError::Parse`] of the store file at `path`.
    fn parse_error(self, path: &Path, what: &str) -> BackendError {
        BackendError::Parse {
            location: Location::File(path.to_path_buf()),
            format: self.what(),
            what: what.into(),
        }
    }

    /// The entries and the sops metadata of a parsed file.
    fn doc(self, value: Value, path: &Path) -> Result<SopsDoc, BackendError> {
        let parse_err = |what: &str| self.parse_error(path, what);
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

    /// [`Self::parse`] for the write path. Every sops run names the
    /// store's format, so a write would rewrite a file of another format in
    /// the store's format (v0.2 plan V14, T50). The write path refuses such
    /// a file (exit 3) before it reads a value, and before the parse can
    /// fail on it. A YAML store refuses a JSON file: a YAML file in flow
    /// style also parses as JSON, but sops never writes one, and a leading
    /// UTF-8 BOM does not hide a JSON file. A JSON store refuses a file
    /// that is not strict JSON, and parses the file only once.
    pub fn parse_to_write(self, bytes: &[u8], path: &Path) -> Result<SopsDoc, BackendError> {
        self.refuse_other_name(path)?;
        match self {
            SopsFormat::Yaml => {
                let body = bytes
                    .strip_prefix(UTF8_BOM)
                    .unwrap_or(bytes)
                    .trim_ascii_start();
                if body.first() == Some(&b'{') && serde_json::from_slice::<IgnoredAny>(body).is_ok()
                {
                    return Err(self.other_format(path, "it is a sops JSON file"));
                }
                self.parse(bytes, path)
            }
            SopsFormat::Json => {
                let value = strict_json(bytes)
                    .map_err(|_| self.other_format(path, "it is not a sops JSON file"))?;
                self.doc(value, path)
            }
        }
    }

    /// The refusal of a file that `what` says is in another format.
    fn other_format(self, path: &Path, what: &str) -> BackendError {
        BackendError::Unsafe {
            path: path.to_path_buf(),
            reason: format!(
                "{what}, and the store's format is {}; a write would rewrite it as {}. \
                 Set the store's format key to the format of the file",
                self.name(),
                self.label()
            ),
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
/// entry from the copy validation. One pass: the only data error that
/// [`StrictVisitor`] makes is a repeated key, and every other error is a
/// syntax or end-of-input error. The error is fixed text: a parser message
/// can quote file content.
fn strict_json(bytes: &[u8]) -> Result<Value, &'static str> {
    serde_json::from_slice::<StrictValue>(bytes)
        .map(|v| v.0)
        .map_err(|e| {
            if e.is_data() {
                "a key appears twice in one object"
            } else {
                "invalid JSON"
            }
        })
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

/// What a key path addresses in the entries of a store file.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Slot<'a> {
    /// The path holds this value.
    Value(&'a Value),
    /// The path is not in the file. Every ancestor that is present is a map.
    Missing,
    /// The ancestor of the first `depth` segments holds a value that is not
    /// a map, so the path cannot exist under it.
    Blocked { depth: usize, kind: &'static str },
}

/// The value at `path` in `entries`.
pub fn lookup<'a>(entries: &'a Map<String, Value>, path: &[&str]) -> Slot<'a> {
    let mut map = entries;
    for (i, segment) in path.iter().enumerate() {
        let Some(v) = map.get(*segment) else {
            return Slot::Missing;
        };
        if i + 1 == path.len() {
            return Slot::Value(v);
        }
        match v {
            Value::Object(m) => map = m,
            other => {
                return Slot::Blocked {
                    depth: i + 1,
                    kind: kind_of(other),
                };
            }
        }
    }
    Slot::Missing
}

/// The kind of a value in messages.
pub fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Null => "null",
        Value::Array(_) => "list",
        Value::Object(_) => "map",
    }
}

/// Whether `v` is a map that holds at least one key: a path with names
/// under it, not a value.
pub fn is_branch(v: &Value) -> bool {
    v.as_object().is_some_and(|m| !m.is_empty())
}

/// Every leaf of `entries` with its key path, in key order. A leaf is a
/// value that is not a map, or a map with no keys.
pub fn leaves(entries: &Map<String, Value>) -> Vec<(Vec<&str>, &Value)> {
    fn walk<'a>(
        map: &'a Map<String, Value>,
        path: &mut Vec<&'a str>,
        out: &mut Vec<(Vec<&'a str>, &'a Value)>,
    ) {
        for (k, v) in map {
            path.push(k);
            match v {
                Value::Object(m) if !m.is_empty() => walk(m, path, out),
                _ => out.push((path.clone(), v)),
            }
            path.pop();
        }
    }
    let mut out = Vec::new();
    walk(entries, &mut Vec::new(), &mut out);
    out
}

/// A key path as a name in messages and in `ls`: its keys joined by `/`.
pub fn path_text(path: &[&str]) -> String {
    path.join("/")
}

/// The names that `ls` prints: the path of every leaf (v0.2 plan 5.4).
pub fn leaf_names(entries: &Map<String, Value>) -> Vec<String> {
    let mut names: Vec<String> = leaves(entries).iter().map(|(p, _)| path_text(p)).collect();
    names.sort();
    names
}

/// Put `value` at `path`, and create each missing ancestor as a map.
/// `Err(depth)` when the ancestor of the first `depth` segments is not a
/// map; `entries` may then hold new empty maps.
fn put_at(entries: &mut Map<String, Value>, path: &[&str], value: Value) -> Result<(), usize> {
    let Some((last, parents)) = path.split_last() else {
        return Ok(());
    };
    let mut map = entries;
    for (i, segment) in parents.iter().enumerate() {
        let next = map
            .entry((*segment).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        match next {
            Value::Object(m) => map = m,
            _ => return Err(i + 1),
        }
    }
    map.insert((*last).to_owned(), value);
    Ok(())
}

/// Remove the value at `path`, and every ancestor map that the removal
/// left empty. `false` when there was no value at `path`.
fn remove_at(entries: &mut Map<String, Value>, path: &[&str]) -> bool {
    match path {
        [] => false,
        [last] => entries.remove(*last).is_some(),
        [first, rest @ ..] => {
            let Some(Value::Object(child)) = entries.get_mut(*first) else {
                return false;
            };
            let removed = remove_at(child, rest);
            if removed && child.is_empty() {
                entries.remove(*first);
            }
            removed
        }
    }
}

/// The ancestor that a remove of `path` leaves empty and prunes, as its
/// number of segments: the shallowest one whose maps hold only the path
/// down to the target (v0.2 plan 6.1.2). `None` when the parent keeps
/// another key, or for a top-level name.
pub fn prune_depth(entries: &Map<String, Value>, path: &[&str]) -> Option<usize> {
    let mut root = None;
    // From the parent up: an ancestor is left empty when it holds one key,
    // and that key is the target or an ancestor that is left empty.
    for depth in (1..path.len()).rev() {
        match lookup(entries, &path[..depth]) {
            Slot::Value(Value::Object(m)) if m.len() == 1 => root = Some(depth),
            _ => break,
        }
    }
    root
}

/// The first difference of `copy` from `want`, as the reason of a failed
/// check. Every leaf is compared as parsed: the raw `ENC[...]` strings.
fn first_difference(want: &Map<String, Value>, copy: &Map<String, Value>) -> Option<String> {
    let copy_leaves: BTreeMap<Vec<&str>, &Value> = leaves(copy).into_iter().collect();
    let want_leaves: BTreeMap<Vec<&str>, &Value> = leaves(want).into_iter().collect();
    let text = |p: &[&str]| escape(&path_text(p)).into_owned();
    if let Some((p, _)) = want_leaves
        .iter()
        .find(|(p, v)| copy_leaves.get(*p) != Some(*v))
    {
        return Some(format!("entry '{}' changed or vanished", text(p)));
    }
    copy_leaves
        .keys()
        .find(|p| !want_leaves.contains_key(*p))
        .map(|p| format!("an unexpected entry '{}' appeared", text(p)))
}

/// Whether `v` is the ciphertext of a string that sops wrote.
fn is_encrypted_string(v: &Value) -> bool {
    matches!(v, Value::String(s) if s.starts_with("ENC[AES256_GCM,") && s.ends_with(",type:str]"))
}

/// PLAN section 8.1, step 9, on the tree of v0.2 plan 6.1.2 (the
/// structural part; the readback is separate). The copy must equal the
/// original with only the target changed: for a put, the target is an
/// encrypted string and only its missing ancestors are new maps; for a
/// remove, the target is gone with the ancestors that it left empty.
/// Every other leaf is byte-equal. The error is the reason; the caller
/// adds the file and the name.
pub fn validate(orig: &SopsDoc, copy: &SopsDoc, name: &Name, op: Op<'_>) -> Result<(), String> {
    let path: Vec<&str> = name.segments().collect();
    if !has_recipients(&copy.meta) {
        return Err("the new file has no recipients".into());
    }
    if stable_meta(&orig.meta) != stable_meta(&copy.meta) {
        return Err("the recipients or the sops settings changed".into());
    }
    let ancestor = |depth: usize| escape(&path_text(&path[..depth])).into_owned();
    let mut want = orig.entries.clone();
    match op {
        Op::Put(..) => {
            if let Slot::Value(v) = lookup(&orig.entries, &path)
                && is_branch(v)
            {
                return Err(format!("'{name}' holds other names in the original file"));
            }
            let target = match lookup(&copy.entries, &path) {
                Slot::Value(v) if is_encrypted_string(v) => v.clone(),
                _ => return Err(format!("'{name}' is not stored as an encrypted string")),
            };
            put_at(&mut want, &path, target).map_err(|depth| {
                format!("'{}' in the original file is not a map", ancestor(depth))
            })?;
        }
        Op::Remove => {
            match lookup(&orig.entries, &path) {
                Slot::Value(v) if !is_branch(v) => {}
                _ => return Err(format!("'{name}' is not a value in the original file")),
            }
            if let Slot::Value(_) = lookup(&copy.entries, &path) {
                return Err(format!("'{name}' is still present"));
            }
            remove_at(&mut want, &path);
        }
    }
    if let Some(reason) = first_difference(&want, &copy.entries) {
        return Err(reason);
    }
    // No leaf of the new file is cleartext, not even an entry that was
    // cleartext before: secrit never writes such a file (PLAN 8.1, step 9).
    if let Some((p, _)) = leaves(&copy.entries)
        .into_iter()
        .find(|(_, v)| has_plaintext(v))
    {
        return Err(format!(
            "entry '{}' is not encrypted",
            escape(&path_text(&p))
        ));
    }
    Ok(())
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

    /// The refusal of a write: the error of [`SopsFormat::parse_to_write`]
    /// when it is not a parse error.
    fn refusal(f: SopsFormat, bytes: &[u8], path: &Path) -> Result<(), BackendError> {
        match f.parse_to_write(bytes, path) {
            Err(e @ BackendError::Unsafe { .. }) => Err(e),
            _ => Ok(()),
        }
    }

    /// The write path parses a file in the store's format to the same
    /// document as the read path, and a file that the read path cannot
    /// parse gives the same parse error.
    #[test]
    fn parse_to_write_reads_the_same_doc_as_parse() {
        for (f, text, path) in [
            (SopsFormat::Yaml, BASE, "/s/main.yaml"),
            (SopsFormat::Json, JSON_BASE, "/s/main.json"),
        ] {
            let path = Path::new(path);
            let read = f.parse(text.as_bytes(), path).unwrap();
            let write = f.parse_to_write(text.as_bytes(), path).unwrap();
            assert_eq!(read.entries, write.entries);
            assert_eq!(read.meta, write.meta);
        }
        let path = Path::new("/s/main.json");
        let e = SopsFormat::Json
            .parse_to_write(b"{\"a\": \"ENC[x]\"}", path)
            .unwrap_err();
        assert!(e.to_string().contains("no sops metadata block"), "{e}");
        assert_eq!(e.exit(), Exit::Failed);
    }

    #[test]
    fn a_yaml_store_refuses_another_format() {
        let yaml = Path::new("/s/main.yaml");
        let f = SopsFormat::Yaml;
        assert!(refusal(f, BASE.as_bytes(), yaml).is_ok());
        let json = br#"{"a": "ENC[x]", "sops": {"mac": "ENC[m]"}}"#;
        let bom = b"\xEF\xBB\xBF{\"a\": \"ENC[x]\"}";
        let bom_space = b"\xEF\xBB\xBF \n {}";
        for bytes in [&json[..], b"\n  {}\n", &bom[..], &bom_space[..]] {
            let e = refusal(f, bytes, yaml).unwrap_err();
            assert!(e.to_string().contains("it is a sops JSON file"), "{e}");
            assert!(e.to_string().contains("format is yaml"), "{e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        // Flow-style YAML that is not JSON stays allowed, with a BOM too.
        assert!(refusal(f, b"{a: b}\n", yaml).is_ok());
        assert!(refusal(f, b"\xEF\xBB\xBF{a: b}\n", yaml).is_ok());
        let mut bom_yaml = b"\xEF\xBB\xBF".to_vec();
        bom_yaml.extend_from_slice(BASE.as_bytes());
        assert!(refusal(f, &bom_yaml, yaml).is_ok());
        for name in ["main.json", "MAIN.JSON", ".env", "a.env", "a.ini"] {
            let path = Path::new("/s").join(name);
            let e = refusal(f, BASE.as_bytes(), &path).unwrap_err();
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
        assert!(refusal(f, JSON_BASE.as_bytes(), path).is_ok());

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
            let e = refusal(f, bytes, path).unwrap_err();
            assert!(e.to_string().contains("it is not a sops JSON file"), "{e}");
            assert_eq!(e.exit(), Exit::Refused);
        }
        for name in ["s.yaml", "S.YML", "s.env", "s.ini"] {
            let e = refusal(f, JSON_BASE.as_bytes(), &Path::new("/s").join(name)).unwrap_err();
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
        // The reason names the leaf by its key path (v0.2 plan 5.4).
        assert!(reason.contains("'x/k' is not encrypted"), "{reason}");
    }

    const ENC: &str = "ENC[AES256_GCM,data:q,iv:w,tag:e,type:str]";

    fn name(s: &str) -> Name {
        Name::parse(s).unwrap()
    }

    /// A YAML doc with the entries `body` (indented YAML) on top of the
    /// metadata of [`BASE`] and no top-level `a`.
    fn tree(body: &str) -> SopsDoc {
        let meta = BASE.replace("a: ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]\n", "");
        doc(&format!("{body}{meta}"))
    }

    /// `ls` lists every leaf by its key path, and an empty map too.
    #[test]
    fn leaves_are_listed_by_key_path() {
        let d = tree(&format!(
            "z: {ENC}\na:\n  b:\n    c: {ENC}\n  d: {ENC}\ne: {{}}\nl: [1]\n"
        ));
        assert_eq!(leaf_names(&d.entries), ["a/b/c", "a/d", "e", "l", "z"]);
    }

    #[test]
    fn lookup_follows_maps_only() {
        let d = tree(&format!("a:\n  b: {ENC}\ns: {ENC}\n"));
        let at = |p: &[&str]| lookup(&d.entries, p);
        assert!(matches!(at(&["a", "b"]), Slot::Value(Value::String(_))));
        assert!(matches!(at(&["a"]), Slot::Value(Value::Object(_))));
        assert_eq!(at(&["a", "x"]), Slot::Missing);
        assert_eq!(at(&["q", "r"]), Slot::Missing);
        assert_eq!(
            at(&["s", "x", "y"]),
            Slot::Blocked {
                depth: 1,
                kind: "string"
            }
        );
        assert_eq!(
            at(&["a", "b", "c"]),
            Slot::Blocked {
                depth: 2,
                kind: "string"
            }
        );
    }

    /// `rm` prunes the ancestors that it leaves empty, and no other map.
    #[test]
    fn the_prune_depth_is_the_shallowest_ancestor_left_empty() {
        let d = tree(&format!(
            "a:\n  b:\n    c: {ENC}\nk:\n  l:\n    m: {ENC}\n  n: {ENC}\ntop: {ENC}\n"
        ));
        let depth = |p: &[&str]| prune_depth(&d.entries, p);
        assert_eq!(depth(&["a", "b", "c"]), Some(1));
        assert_eq!(depth(&["k", "l", "m"]), Some(2));
        assert_eq!(depth(&["k", "n"]), None);
        assert_eq!(depth(&["top"]), None);
    }

    /// v0.2 plan 6.1.2: a nested put may create only the missing ancestors,
    /// every other leaf stays byte-equal, and a leaf never becomes a map.
    #[test]
    fn validate_checks_the_tree_of_a_nested_put() {
        let v = SecretValue::new(b"v".to_vec());
        let put = Op::Put(&v, PutMode::CreateOnly);
        let abc = name("a/b/c");
        let orig = tree(&format!("z: {ENC}\n"));
        let good = tree(&format!("z: {ENC}\na:\n  b:\n    c: {ENC}\n"));
        assert!(validate(&orig, &good, &abc, put).is_ok());

        // Into a map that exists, beside a sibling.
        let orig_a = tree(&format!("a:\n  d: {ENC}\n"));
        let good_a = tree(&format!("a:\n  d: {ENC}\n  b:\n    c: {ENC}\n"));
        assert!(validate(&orig_a, &good_a, &abc, put).is_ok());

        for (copy, want) in [
            // The sibling changed.
            (
                tree(&format!(
                    "a:\n  d: ENC[AES256_GCM,data:Y,type:str]\n  b:\n    c: {ENC}\n"
                )),
                "entry 'a/d' changed or vanished",
            ),
            // The sibling vanished.
            (
                tree(&format!("a:\n  b:\n    c: {ENC}\n")),
                "entry 'a/d' changed or vanished",
            ),
            // A map appeared beside the target.
            (
                tree(&format!(
                    "a:\n  d: {ENC}\n  b:\n    c: {ENC}\n    x: {{}}\n"
                )),
                "an unexpected entry 'a/b/x' appeared",
            ),
            // The target is not an encrypted string.
            (
                tree(&format!("a:\n  d: {ENC}\n  b:\n    c: plain\n")),
                "'a/b/c' is not stored as an encrypted string",
            ),
            (
                tree(&format!("a:\n  d: {ENC}\n  b:\n    c:\n      x: {ENC}\n")),
                "'a/b/c' is not stored as an encrypted string",
            ),
        ] {
            let reason = validate(&orig_a, &copy, &abc, put).unwrap_err();
            assert!(reason.contains(want), "{want}: {reason}");
        }

        // T49: sops turns the string `a` into a map; the copy fails.
        let ab = name("a/b");
        let orig_s = tree(&format!("a: {ENC}\n"));
        let turned = tree(&format!("a:\n  b: {ENC}\n"));
        let reason = validate(&orig_s, &turned, &ab, put).unwrap_err();
        assert!(
            reason.contains("'a' in the original file is not a map"),
            "{reason}"
        );

        // A put over a name that holds other names fails too.
        let a = name("a");
        let flat = tree(&format!("a: {ENC}\n"));
        let reason = validate(&orig_a, &flat, &a, put).unwrap_err();
        assert!(reason.contains("holds other names"), "{reason}");
    }

    /// v0.2 plan 6.1.2: a nested remove drops the target and the ancestors
    /// that it left empty, and nothing else.
    #[test]
    fn validate_checks_the_tree_of_a_nested_remove() {
        let abc = name("a/b/c");
        let orig = tree(&format!("a:\n  b:\n    c: {ENC}\nz: {ENC}\n"));
        let pruned = tree(&format!("z: {ENC}\n"));
        assert!(validate(&orig, &pruned, &abc, Op::Remove).is_ok());
        let unpruned = tree(&format!("a:\n  b: {{}}\nz: {ENC}\n"));
        let reason = validate(&orig, &unpruned, &abc, Op::Remove).unwrap_err();
        assert!(reason.contains("unexpected entry 'a/b'"), "{reason}");
        let still = validate(&orig, &orig, &abc, Op::Remove).unwrap_err();
        assert!(still.contains("'a/b/c' is still present"), "{still}");

        // A sibling keeps its parent.
        let orig_d = tree(&format!("a:\n  b:\n    c: {ENC}\n  d: {ENC}\n"));
        let kept = tree(&format!("a:\n  d: {ENC}\n"));
        assert!(validate(&orig_d, &kept, &abc, Op::Remove).is_ok());
        let too_much = tree("x: ''\n");
        let reason = validate(&orig_d, &too_much, &abc, Op::Remove).unwrap_err();
        assert!(
            reason.contains("entry 'a/d' changed or vanished"),
            "{reason}"
        );

        // An empty map that was there before stays.
        let orig_e = tree(&format!("a:\n  b:\n    c: {ENC}\n  e: {{}}\n"));
        let kept_e = tree("a:\n  e: {}\n");
        assert!(validate(&orig_e, &kept_e, &abc, Op::Remove).is_ok());
        let lost_e = tree("z: ''\n");
        assert!(validate(&orig_e, &lost_e, &abc, Op::Remove).is_err());

        // A remove of a name that holds other names fails.
        let a = name("a");
        let reason = validate(&orig, &pruned, &a, Op::Remove).unwrap_err();
        assert!(reason.contains("is not a value"), "{reason}");
    }
}
