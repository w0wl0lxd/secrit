//! The conformance suite (v0.2 plan 10.1) on a sops YAML store, a sops
//! JSON store and a sops dotenv store, with the real sops and age-keygen
//! in a temp directory only, and the checks that only sops has.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::fixture::{Fixture, SopsDotenvFixture, SopsFixture, SopsJsonFixture};
use common::{TestEnv, code, run_cmd, stderr};
use serde_json::Value;

crate::conformance_suite!(common::fixture::SopsFixture);

/// The same cases on a sops JSON store (v0.2 plan S4).
mod json {
    crate::conformance_suite!(crate::common::fixture::SopsJsonFixture);
}

/// The same cases on a sops dotenv store (v0.2 plan S6).
mod dotenv {
    crate::conformance_suite!(crate::common::fixture::SopsDotenvFixture);
}

/// T1: `store` and `store --replace` give sops the value with
/// `set --value-stdin`.
#[test]
fn sops_set_reads_the_value_on_stdin() {
    let f = SopsFixture::new();
    let log = f.dirs().root.path().join("argv.log");
    f.log_tool_argv(&log);
    let out = f.dirs().store_value("n", b"v1");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = f.dirs().run(["store", "n", "--replace"], Some(b"v2"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));

    let logged = std::fs::read_to_string(&log).unwrap();
    let count = |arg: &str| logged.lines().filter(|l| *l == arg).count();
    assert_eq!(count("set"), 2, "{logged}");
    assert_eq!(count("--value-stdin"), 2, "{logged}");
}

/// The store file as a JSON object that holds a `sops` block. Panics when
/// it is not strict JSON.
fn json_object(path: &Path) -> serde_json::Map<String, Value> {
    let bytes = std::fs::read(path).unwrap();
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(m)) if m.contains_key("sops") => m,
        _ => panic!("{} is not a sops JSON file", path.display()),
    }
}

/// T50 (v0.2 plan 6.1.2): every write keeps a JSON store JSON, and sops
/// with `--input-type json` decrypts it. The temp copies end in `.json`,
/// and every sops run names the JSON type.
#[test]
fn a_json_store_stays_json() {
    let f = SopsJsonFixture::new();
    let env = f.env();
    assert!(env.store_file.ends_with("main.json"));
    let log = env.root.path().join("argv.log");
    f.log_tool_argv(&log);

    let steps: [(&[&str], Option<&[u8]>); 4] = [
        (&["store", "a"], Some(b"value-a")),
        (&["store", "b"], Some(b"value-b")),
        (&["store", "a", "--replace"], Some(b"value-a2")),
        (&["rm", "b", "--yes"], None),
    ];
    for (args, stdin) in steps {
        let out = env.run(args, stdin);
        assert_eq!(code(&out), 0, "{args:?}: {}", stderr(&out));
        json_object(&env.store_file);
    }
    let names: Vec<String> = json_object(&env.store_file)
        .into_iter()
        .map(|(k, _)| k)
        .filter(|k| k != "sops")
        .collect();
    assert_eq!(names, ["a"]);
    // TestEnv::decrypt runs sops with --input-type json.
    env.assert_value("a", "value-a2");
    assert_eq!(env.ls(), ["a"]);
    assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());

    let logged = std::fs::read_to_string(&log).unwrap();
    let args: Vec<&str> = logged.lines().collect();
    let types: Vec<&str> = args
        .windows(2)
        .filter(|w| w[0] == "--input-type" || w[0] == "--output-type")
        .map(|w| w[1])
        .collect();
    assert!(!types.is_empty(), "{logged}");
    assert!(types.iter().all(|t| *t == "json"), "{logged}");
    for line in args.iter().filter(|a| a.contains(".secrit-")) {
        assert!(
            Path::new(line).extension().is_some_and(|e| e == "json"),
            "{line}"
        );
    }
}

/// A YAML store stays YAML after each write, as in v0.1: the file is not
/// JSON, and an explicit `format = "yaml"` changes nothing.
#[test]
fn a_yaml_store_is_unchanged() {
    let f = SopsFixture::new();
    let env = f.env();
    for extra in ["", "format = \"yaml\"\n"] {
        env.write_config(extra);
        let name = if extra.is_empty() { "a" } else { "b" };
        let out = env.store_value(name, b"value");
        assert_eq!(code(&out), 0, "{extra}: {}", stderr(&out));
        let bytes = env.store_bytes();
        assert!(
            serde_json::from_slice::<Value>(&bytes).is_err(),
            "the YAML store became JSON"
        );
        assert!(String::from_utf8(bytes).unwrap().contains("\nsops:\n"));
        env.assert_value(name, "value");
    }
    assert_eq!(env.ls(), ["a", "b"]);
}

/// The `format` key picks the format of a file whose name does not: with
/// `format = "json"` a JSON store named `main.sops` works; with no
/// `format`, secrit reads the name as YAML and refuses the JSON content
/// (the S0 guard) with exit 3, the file unchanged.
#[test]
fn the_format_key_picks_the_format() {
    let mut env = TestEnv::with_format("json");
    std::fs::write(
        &env.sops_config,
        format!(
            "creation_rules:\n  - path_regex: secrets/main\\.sops$\n    age: {}\n",
            env.recipients.join(",")
        ),
    )
    .unwrap();
    env.store_file = env.store_dir.join("main.sops");
    env.create_store(&env.store_file);
    env.write_config("");
    let before = env.store_bytes();
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("sops JSON file"), "{}", stderr(&out));
    assert_eq!(env.store_bytes(), before);

    env.write_config("format = \"json\"\n");
    let out = env.store_value("n", b"v");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    json_object(&env.store_file);
    env.assert_value("n", "v");
    assert_eq!(env.ls(), ["n"]);
}

/// `wire` names the store's format in the sops-nix stanza.
#[test]
fn wire_prints_the_store_format() {
    let json = SopsJsonFixture::new();
    let yaml = SopsFixture::new();
    for (env, want) in [(json.env(), "json"), (yaml.env(), "yaml")] {
        assert_eq!(code(&env.store_value("n", b"v")), 0);
        let out = env.run(["wire", "n", "--owner", "u"], None);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(
            text.contains(&format!("  format = \"{want}\";\n")),
            "{text}"
        );
        assert!(
            text.contains(&format!("main.{want}")),
            "the stanza names the store file: {text}"
        );
    }
}

/// `secrit init` with a new config, key and store file under `dir` of the
/// temp root: the output, and the config, the key file and the store file.
fn init_at(
    env: &TestEnv,
    dir: &str,
    file: &str,
    extra: &[&str],
) -> (Output, PathBuf, PathBuf, PathBuf) {
    let base = env.root.path().join(dir);
    let config = base.join("config.toml");
    let key = base.join("keys.txt");
    let file = base.join("repo").join("secrets").join(file);
    let mut c = env.cmd();
    c.env("SECRIT_CONFIG", &config);
    let mut args = vec![
        "init".to_owned(),
        "--sops-file".to_owned(),
        file.display().to_string(),
        "--age-key".to_owned(),
        key.display().to_string(),
        "--write-sops-config".to_owned(),
    ];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    (run_cmd(c, args, None), config, key, file)
}

/// `init --format json` creates a JSON store and writes `format = "json"`
/// into the config. A `.json` file name gives a JSON store with no
/// `format` key. `--format json` for a file that sops reads as YAML is
/// refused with exit 3 before any file is made.
#[test]
fn init_format_json_creates_a_json_store() {
    let env = TestEnv::new();
    let init = |dir: &str, file: &str, extra: &[&str]| init_at(&env, dir, file, extra);

    for (dir, file, extra, key_line) in [
        ("flag", "s.json", &["--format", "json"][..], true),
        ("name", "s.json", &[][..], false),
    ] {
        let (out, config, _, file) = init(dir, file, extra);
        assert_eq!(code(&out), 0, "{dir}: {}", stderr(&out));
        json_object(&file);
        let text = std::fs::read_to_string(&config).unwrap();
        assert_eq!(text.contains("format = \"json\""), key_line, "{text}");

        let mut c = env.cmd();
        c.env("SECRIT_CONFIG", &config);
        let out = run_cmd(c, ["store", "n"], Some(b"v"));
        assert_eq!(code(&out), 0, "{dir}: {}", stderr(&out));
        json_object(&file);
    }

    let (out, config, key, file) = init("refused", "s.yaml", &["--format", "json"]);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains(".yaml"), "{}", stderr(&out));
    assert!(!file.exists() && !config.exists() && !key.exists());
}

/// The value at the key path `path` of the decrypted store, or `None`.
fn nested(env: &TestEnv, path: &[&str]) -> Option<Value> {
    let mut v = Value::Object(env.decrypt());
    for key in path {
        v = v.as_object()?.get(*key)?.clone();
    }
    Some(v)
}

/// `sops decrypt --extract` of the key path `expr` in the test process,
/// with the store's own input type: what sops-nix does for a nested key
/// (v0.2 plan S5 acceptance). Never printed.
fn sops_extract(env: &TestEnv, expr: &str) -> Vec<u8> {
    let out = env
        .sops_cmd()
        .args(["decrypt", "--input-type", env.format, "--extract", expr])
        .arg(&env.store_file)
        .output()
        .unwrap();
    assert!(out.status.success(), "sops --extract {expr} failed");
    out.stdout
}

/// `get NAME --stdout` into a private file under `script`, so agent
/// detection sees a terminal. The name and the paths reach the shell as
/// variables.
fn get_stdout(env: &TestEnv, name: &str) -> (std::process::Output, Vec<u8>) {
    let dest = env.root.path().join("get.out");
    let _ = std::fs::remove_file(&dest);
    let bin = std::ffi::OsStr::new(common::BIN);
    let envs = [
        ("GET_BIN", bin),
        ("GET_NAME", std::ffi::OsStr::new(name)),
        ("GET_OUT", dest.as_os_str()),
    ];
    let inner = "umask 077; exec \"$GET_BIN\" get \"$GET_NAME\" --stdout > \"$GET_OUT\"";
    let out = env.under_script_env(inner, &envs);
    (out, std::fs::read(&dest).unwrap_or_default())
}

/// v0.2 plan S5 on one format: `store a/b/c` writes a nested key that
/// `ls` lists as `a/b/c`, `get` reads back, and sops `--extract` with
/// `["a"]["b"]["c"]` decrypts, as sops-nix does.
fn nested_names_round_trip_on(env: &TestEnv) {
    for (name, value) in [("a/b/c", "v-abc"), ("a/d", "v-ad"), ("top", "v-top")] {
        let out = env.store_value(name, value.as_bytes());
        assert_eq!(code(&out), 0, "{name}: {}", stderr(&out));
        assert!(stderr(&out).contains(&format!("stored {name} in main")));
    }
    assert_eq!(env.ls(), ["a/b/c", "a/d", "top"]);
    let json = env.run(["ls", "--json"], None);
    assert_eq!(
        String::from_utf8(json.stdout).unwrap().trim(),
        r#"["a/b/c","a/d","top"]"#
    );
    assert!(
        nested(env, &["a", "b", "c"]) == Some(Value::String("v-abc".into())),
        "a/b/c is not a nested string"
    );
    assert_eq!(sops_extract(env, r#"["a"]["b"]["c"]"#), b"v-abc");
    assert_eq!(sops_extract(env, r#"["a"]["d"]"#), b"v-ad");

    let (out, got) = get_stdout(env, "a/b/c");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(got == b"v-abc", "get --stdout bytes differ");

    // Create-only and replace work on a nested name.
    let out = env.store_value("a/b/c", b"other");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("'a/b/c' already exists"),
        "{}",
        stderr(&out)
    );
    let out = env.run(["store", "a/b/c", "--replace"], Some(b"v-abc2"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(sops_extract(env, r#"["a"]["b"]["c"]"#), b"v-abc2");
    assert_eq!(sops_extract(env, r#"["a"]["d"]"#), b"v-ad");
}

#[test]
fn nested_names_round_trip() {
    nested_names_round_trip_on(SopsFixture::new().env());
}

/// The same on a JSON store, which stays strict JSON.
#[test]
fn nested_names_round_trip_json() {
    let f = SopsJsonFixture::new();
    nested_names_round_trip_on(f.env());
    json_object(&f.env().store_file);
}

/// T49 (v0.2 plan 6.1.2): `store a/b` when `a` holds a string exits 3
/// before it reads a value, and the file is unchanged. sops itself would
/// turn `a` into a map (S5 lab). A name that holds other names is refused
/// for `store --replace` and `rm` too.
#[test]
fn a_nested_store_never_turns_a_value_into_a_map() {
    let yaml = SopsFixture::new();
    let json = SopsJsonFixture::new();
    for env in [yaml.env(), json.env()] {
        assert_eq!(code(&env.store_value("a", b"leaf")), 0);
        assert_eq!(code(&env.store_value("m/n", b"inner")), 0);
        let before = env.store_bytes();
        for args in [
            &["store", "a/b"][..],
            &["store", "a/b/c", "--replace"],
            &["store", "m", "--replace"],
            &["store", "m"],
            &["rm", "m", "--yes"],
        ] {
            let out = env.run(args, Some(b"canary-49"));
            assert_eq!(code(&out), 3, "{args:?}: {}", stderr(&out));
            common::assert_absent(&out, "canary-49");
            assert_eq!(env.store_bytes(), before, "{args:?} changed the file");
        }
        let out = env.store_value("a/b", b"v");
        assert!(
            stderr(&out).contains("'a' holds a string, not a map"),
            "{}",
            stderr(&out)
        );
        assert_eq!(env.ls(), ["a", "m/n"]);
        env.assert_value("a", "leaf");
        assert_eq!(env.backups(), Vec::<std::path::PathBuf>::new());
    }
}

/// v0.2 plan 6.1.2: `rm a/b/c` removes the key and prunes the maps that
/// it left empty, with a second `unset` on the same copy; a map that
/// keeps another key stays.
#[test]
fn rm_of_a_nested_name_prunes_empty_maps() {
    let yaml = SopsFixture::new();
    let json = SopsJsonFixture::new();
    for env in [yaml.env(), json.env()] {
        for (name, value) in [("a/b/c", "1"), ("x/y/z", "2"), ("x/w", "3")] {
            assert_eq!(code(&env.store_value(name, value.as_bytes())), 0, "{name}");
        }
        let out = env.run(["rm", "a/b/c", "--yes"], None);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        assert!(stderr(&out).contains("removed a/b/c"));
        assert_eq!(nested(env, &["a"]), None, "the empty maps a and a/b stay");
        let out = env.run(["rm", "x/y/z", "--yes"], None);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        assert_eq!(nested(env, &["x", "y"]), None, "the empty map x/y stays");
        assert_eq!(nested(env, &["x", "w"]), Some(Value::String("3".into())));
        assert_eq!(env.ls(), ["x/w"]);
        let out = env.run(["rm", "x/w", "--yes"], None);
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        assert_eq!(env.ls(), Vec::<String>::new());
        assert_eq!(env.decrypt().len(), 0, "a map stayed in the file");
        assert_eq!(env.temp_files(), Vec::<std::path::PathBuf>::new());
        if env.format == "json" {
            json_object(&env.store_file);
        }
    }
}

/// `wire a/b/c` names the key path in the sops-nix stanza, and `--format
/// env` maps `/` to `_`.
#[test]
fn wire_prints_the_key_of_a_nested_name() {
    let f = SopsFixture::new();
    let env = f.env();
    assert_eq!(code(&env.store_value("a/b/c", b"v")), 0);
    let out = env.run(["wire", "a/b/c", "--owner", "u"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = String::from_utf8(out.stdout.clone()).unwrap();
    assert!(text.starts_with("sops.secrets.\"a/b/c\" = {\n"), "{text}");
    assert!(text.contains("  key = \"a/b/c\";\n"), "{text}");
    assert!(
        !stderr(&out).contains("not in the store yet"),
        "{}",
        stderr(&out)
    );

    let out = env.run(["wire", "a/b/c", "--format", "env"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "A_B_C_FILE=/run/secrets/a/b/c\n"
    );
    let out = env.run(["wire", "top", "--owner", "u"], None);
    assert!(!String::from_utf8(out.stdout).unwrap().contains("key ="));
}

/// v0.2 plan S5 risk: a v0.1 file that another tool wrote with a nested
/// map now lists its leaves, not the map's name. A leaf is a name that
/// `get` reads and `rm` removes.
#[test]
fn ls_lists_the_leaves_of_a_nested_map() {
    let f = SopsFixture::new();
    let env = f.env();
    env.create_store_with(
        &env.store_file,
        &[],
        br#"{"svc": {"db": {"pass": "p1"}, "key": "k1"}, "flat": "f1"}"#,
    );
    assert_eq!(env.ls(), ["flat", "svc/db/pass", "svc/key"]);
    let (out, got) = get_stdout(env, "svc/db/pass");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(got == b"p1", "get --stdout bytes differ");
    let (out, got) = get_stdout(env, "svc");
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("holds a map"));
    assert!(got.is_empty());
    let out = env.run(["rm", "svc/db/pass", "--yes"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(env.ls(), ["flat", "svc/key"]);
}

/// The name grammar of v0.2 plan 5.4 at the command line: each segment
/// follows the v0.1 grammar, and the refusal comes before any input.
#[test]
fn bad_key_paths_are_refused() {
    let f = SopsFixture::new();
    let env = f.env();
    let nine = ["s"; 9].join("/");
    for name in ["a//b", "/a", "a/", "a/.b", "a/b c", nine.as_str(), "sops/x"] {
        let out = env.store_value(name, b"canary-54");
        assert_eq!(code(&out), 3, "{name}: {}", stderr(&out));
        common::assert_absent(&out, "canary-54");
    }
    assert_eq!(code(&env.store_value("app/sops", b"v")), 0);
    assert_eq!(env.ls(), ["app/sops"]);
}

/// The lines of a dotenv store file as sops splits them: the entries and
/// the `sops_` metadata lines, each as key and raw value.
fn dotenv_lines(env: &TestEnv) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let text = String::from_utf8(env.store_bytes()).unwrap();
    let (mut entries, mut meta) = (BTreeMap::new(), BTreeMap::new());
    for line in text.split('\n') {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .expect("a line of the dotenv store has no '='");
        let map = if key.starts_with("sops_") {
            &mut meta
        } else {
            &mut entries
        };
        let old = map.insert(key.to_owned(), value.to_owned());
        assert!(old.is_none(), "{key} is in the dotenv store twice");
    }
    (entries, meta)
}

/// The metadata lines that a write must not change.
fn stable_lines(meta: &BTreeMap<String, String>) -> BTreeMap<&str, &str> {
    meta.iter()
        .filter(|(k, _)| !["sops_mac", "sops_lastmodified"].contains(&k.as_str()))
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// The 14 tricky strings of V11 (v0.2 plan 6.1.1), as the S6 lab ran them
/// through sops 3.13.3.
const TRICKY: [&str; 14] = [
    "line1\nline2",
    "crlf\r\nend",
    "# hash",
    "semi;colon",
    "\"double\"",
    "'single'",
    "\"\"\"triple\"\"\"",
    "back\\slash",
    "trailing\\",
    " lead and trail ",
    "a=b=c",
    "tab\there",
    "\u{fc}n\u{ef}c\u{f6}d\u{e9} \u{2713} \u{65e5}\u{672c}",
    "$HOME `id` $(id)",
];

/// v0.2 plan S6 and V11: each tricky string comes back byte-exact from a
/// dotenv store, through sops and through `get`. After each `store`, the
/// line of every other entry is byte-identical, and so is every metadata
/// line except the MAC and the time.
#[test]
fn a_dotenv_store_round_trips_the_tricky_strings() {
    let f = SopsDotenvFixture::new();
    let env = f.env();
    assert!(env.store_file.ends_with("main.env"));
    let (mut entries, mut meta) = dotenv_lines(env);
    assert!(entries.is_empty(), "a new dotenv store has an entry");
    for (i, value) in TRICKY.iter().enumerate() {
        let name = format!("T{i}");
        let out = env.run(["store", name.as_str(), "--raw"], Some(value.as_bytes()));
        assert_eq!(code(&out), 0, "{name}: {}", stderr(&out));
        let (now, now_meta) = dotenv_lines(env);
        let line = now.get(&name).expect("the stored name has no line");
        assert!(
            line.starts_with("ENC[AES256_GCM,") && line.ends_with(",type:str]"),
            "{name} is not an encrypted string"
        );
        assert_eq!(now.len(), entries.len() + 1, "{name}");
        for (k, v) in &entries {
            assert!(now.get(k) == Some(v), "the line of {k} changed with {name}");
        }
        assert!(
            stable_lines(&now_meta) == stable_lines(&meta),
            "a metadata line changed with {name}"
        );
        (entries, meta) = (now, now_meta);
    }

    let all = env.decrypt();
    assert_eq!(all.len(), TRICKY.len());
    for (i, value) in TRICKY.iter().enumerate() {
        let name = format!("T{i}");
        assert!(
            all.get(&name) == Some(&Value::String((*value).to_owned())),
            "{name} differs in the decrypted store"
        );
        assert!(
            sops_extract(env, &format!("[\"{name}\"]")) == value.as_bytes(),
            "{name} differs through sops --extract"
        );
        let (out, got) = get_stdout(env, &name);
        assert_eq!(code(&out), 0, "{name}: {}", stderr(&out));
        assert!(
            got == value.as_bytes(),
            "{name} differs through get --stdout"
        );
    }
    assert_eq!(env.ls().len(), TRICKY.len());
    assert_eq!(env.temp_files(), Vec::<PathBuf>::new());
}

/// v0.2 plan 5.4 and T58: a dotenv store takes a variable name with no
/// `sops_` prefix. Any other name exits 3 before a value is read, and the
/// file is unchanged. sops itself accepts `a.b` and `bad key` (S6 lab).
#[test]
fn a_dotenv_store_refuses_a_name_outside_its_grammar() {
    let f = SopsDotenvFixture::new();
    let env = f.env();
    assert_eq!(code(&env.store_value("KEEP", b"kept")), 0);
    let before = env.store_bytes();
    for (name, said) in [
        ("sops_x", "metadata"),
        ("sops_mac", "metadata"),
        ("a.b", "variable name"),
        ("a-b", "variable name"),
        ("0a", "variable name"),
        ("a/b", "nested names"),
    ] {
        for replace in [false, true] {
            let mut args = vec!["store", name];
            if replace {
                args.push("--replace");
            }
            let out = env.run(args, Some(b"canary-58"));
            assert_eq!(code(&out), 3, "{name}: {}", stderr(&out));
            assert!(stderr(&out).contains(said), "{name}: {}", stderr(&out));
            common::assert_absent(&out, "canary-58");
            assert_eq!(env.store_bytes(), before, "{name} changed the file");
        }
    }
    assert_eq!(env.ls(), ["KEEP"]);
    env.assert_value("KEEP", "kept");
    assert_eq!(env.backups(), Vec::<PathBuf>::new());
    assert_eq!(env.temp_files(), Vec::<PathBuf>::new());
}

/// v0.2 plan 6.1.2: the flat metadata of a dotenv store names both
/// recipients, and `store`, `store --replace` and `rm` change no metadata
/// line except the MAC and the time. A file with its own
/// `unencrypted_suffix` keeps that rule: secrit reads it from the flat
/// line and refuses a name that sops would leave in cleartext.
#[test]
fn a_dotenv_store_keeps_its_metadata() {
    let f = SopsDotenvFixture::new();
    let env = f.env();
    let (_, meta) = dotenv_lines(env);
    let mut in_file: Vec<&String> = (0..2)
        .map(|i| &meta[&format!("sops_age__list_{i}__map_recipient")])
        .collect();
    in_file.sort();
    let mut want: Vec<&String> = env.recipients.iter().collect();
    want.sort();
    assert_eq!(in_file, want);

    let steps: [(&[&str], Option<&[u8]>); 4] = [
        (&["store", "A"], Some(b"value-a")),
        (&["store", "B"], Some(b"value-b")),
        (&["store", "A", "--replace"], Some(b"value-a2")),
        (&["rm", "B", "--yes"], None),
    ];
    for (args, stdin) in steps {
        let out = env.run(args, stdin);
        assert_eq!(code(&out), 0, "{args:?}: {}", stderr(&out));
        let (_, now) = dotenv_lines(env);
        assert!(
            stable_lines(&now) == stable_lines(&meta),
            "{args:?} changed a metadata line"
        );
        assert!(now.contains_key("sops_mac") && now.contains_key("sops_lastmodified"));
    }
    assert_eq!(env.ls(), ["A"]);
    env.assert_value("A", "value-a2");
    assert_eq!(env.temp_files(), Vec::<PathBuf>::new());

    env.create_store_with(
        &env.store_file,
        &["--unencrypted-suffix", "_pub"],
        br#"{"KEEP": "kept"}"#,
    );
    let (_, meta) = dotenv_lines(env);
    assert_eq!(meta["sops_unencrypted_suffix"], "_pub");
    let before = env.store_bytes();
    let out = env.store_value("TOKEN_pub", b"canary-61");
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("_pub"), "{}", stderr(&out));
    common::assert_absent(&out, "canary-61");
    assert_eq!(env.store_bytes(), before);
    let out = env.store_value("TOKEN", b"value");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(env.ls(), ["KEEP", "TOKEN"]);
    env.assert_value("KEEP", "kept");
}

/// v0.2 plan S6 acceptance: `sops exec-env` on the file that secrit wrote
/// exports each value to a program.
#[test]
fn sops_exec_env_exports_the_stored_values() {
    let f = SopsDotenvFixture::new();
    let env = f.env();
    assert_eq!(code(&env.store_value("API_TOKEN", b"exec env value 1")), 0);
    assert_eq!(code(&env.store_value("OTHER", b"second=value")), 0);
    let dest = env.root.path().join("exec-env.out");
    let out = env
        .sops_cmd()
        .arg("exec-env")
        .arg(&env.store_file)
        .arg("printf '%s|%s' \"$API_TOKEN\" \"$OTHER\" > \"$SECRIT_TEST_OUT\"")
        .env("SECRIT_TEST_OUT", &dest)
        .output()
        .unwrap();
    assert!(out.status.success(), "sops exec-env failed");
    assert!(
        std::fs::read(&dest).unwrap() == b"exec env value 1|second=value",
        "the exported values differ from the stored values"
    );
}

/// A dotenv store refuses a store file that is not dotenv lines (T50, as
/// for JSON): `store` and `rm` exit 3 before a value is read, and the file
/// is unchanged. Here the file is a sops YAML file.
#[test]
fn a_dotenv_store_refuses_a_file_of_another_format() {
    let f = SopsDotenvFixture::new();
    let env = f.env();
    let yaml = SopsFixture::new();
    assert_eq!(code(&yaml.env().store_value("old", b"v")), 0);
    std::fs::write(&env.store_file, yaml.env().store_bytes()).unwrap();
    let before = env.store_bytes();
    for args in [
        &["store", "N"][..],
        &["store", "N", "--replace"],
        &["rm", "old", "--yes"],
    ] {
        let out = env.run(args, Some(b"canary-50"));
        assert_eq!(code(&out), 3, "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("it is not a sops dotenv file"),
            "{args:?}: {}",
            stderr(&out)
        );
        common::assert_absent(&out, "canary-50");
        assert_eq!(env.store_bytes(), before, "{args:?} changed the file");
    }
    let out = env.run(["ls"], None);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("sops dotenv file"),
        "{}",
        stderr(&out)
    );
    assert_eq!(env.temp_files(), Vec::<PathBuf>::new());
}

/// sops-nix gives a dotenv file to a consumer only as one whole file, so
/// `wire` refuses a dotenv store with exit 3 and names `sops exec-env`,
/// and `store` prints no `wire` hint for it.
#[test]
fn wire_refuses_a_dotenv_store() {
    let f = SopsDotenvFixture::new();
    let env = f.env();
    env.write_config("wire_hint = true\n");
    let out = env.store_value("TOKEN", b"v");
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(!stderr(&out).contains("secrit wire"), "{}", stderr(&out));
    for args in [
        &["wire", "TOKEN", "--owner", "u"][..],
        &["wire", "TOKEN", "--format", "env"],
    ] {
        let out = env.run(args, None);
        let err = stderr(&out);
        assert_eq!(code(&out), 3, "{args:?}: {err}");
        assert!(out.stdout.is_empty(), "{args:?} printed a stanza");
        assert!(err.contains("one whole file"), "{err}");
        assert!(err.contains("sops exec-env"), "{err}");
        assert!(err.contains("main.env"), "{err}");
    }
}

/// `init` creates a dotenv store for `--format dotenv` or a `.env` file
/// name: sops encrypts an empty document to a file of metadata lines (S6
/// lab). The config gets `format = "dotenv"` only for the flag. `--format
/// dotenv` for a file that sops reads as YAML exits 3 before any file is
/// made.
#[test]
fn init_creates_a_dotenv_store() {
    let env = TestEnv::new();
    for (dir, file, extra, key_line) in [
        ("flag", "app.env", &["--format", "dotenv"][..], true),
        ("name", ".env", &[][..], false),
    ] {
        let (out, config, _, file) = init_at(&env, dir, file, extra);
        assert_eq!(code(&out), 0, "{dir}: {}", stderr(&out));
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            text.lines().all(|l| l.starts_with("sops_")),
            "{dir}: a new dotenv store holds a line that is not metadata"
        );
        assert!(text.contains("sops_mac=ENC["), "{dir}: no MAC line");
        let config_text = std::fs::read_to_string(&config).unwrap();
        assert_eq!(
            config_text.contains("format = \"dotenv\""),
            key_line,
            "{config_text}"
        );
        assert!(stderr(&out).contains("sops exec-env"), "{}", stderr(&out));
        assert!(!stderr(&out).contains("secrit wire"), "{}", stderr(&out));

        let run = |args: &[&str], stdin: Option<&[u8]>| {
            let mut c = env.cmd();
            c.env("SECRIT_CONFIG", &config);
            run_cmd(c, args, stdin)
        };
        let out = run(&["store", "TOKEN"], Some(b"v"));
        assert_eq!(code(&out), 0, "{dir}: {}", stderr(&out));
        let out = run(&["ls"], None);
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "TOKEN\n", "{dir}");
    }

    let (out, config, key, file) = init_at(&env, "refused", "s.yaml", &["--format", "dotenv"]);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains(".yaml"), "{}", stderr(&out));
    assert!(!file.exists() && !config.exists() && !key.exists());
}

/// sops keeps an empty dotenv value in clear (`E=`), as it does in YAML.
/// Such a line holds no secret, so `store` and `rm` accept the file and
/// the line stays.
#[test]
fn an_empty_dotenv_value_does_not_block_a_write() {
    let f = SopsDotenvFixture::new();
    let env = f.env();
    env.create_store_with(&env.store_file, &[], br#"{"E": "", "B": "x"}"#);
    let (entries, _) = dotenv_lines(env);
    assert_eq!(entries["E"], "", "sops encrypted the empty value");
    assert!(entries["B"].starts_with("ENC["), "sops did not encrypt B");

    let out = env.store_value("C", b"new value");
    assert_eq!(code(&out), 0, "store: {}", stderr(&out));
    env.assert_value("C", "new value");
    let out = env.run(["rm", "--yes", "B"], None);
    assert_eq!(code(&out), 0, "rm: {}", stderr(&out));
    let (entries, _) = dotenv_lines(env);
    assert_eq!(entries["E"], "");
    assert_eq!(env.ls(), ["C", "E"]);
    env.assert_value("E", "");
}
