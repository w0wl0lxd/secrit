//! The conformance suite (v0.2 plan 10.1) on a sops YAML store and a sops
//! JSON store, with the real sops and age-keygen in a temp directory only,
//! and the checks that only sops has.

mod common;

use std::path::Path;

use common::fixture::{Fixture, SopsFixture, SopsJsonFixture};
use common::{TestEnv, code, run_cmd, stderr};
use serde_json::Value;

crate::conformance_suite!(common::fixture::SopsFixture);

/// The same cases on a sops JSON store (v0.2 plan S4).
mod json {
    crate::conformance_suite!(crate::common::fixture::SopsJsonFixture);
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

/// `init --format json` creates a JSON store and writes `format = "json"`
/// into the config. A `.json` file name gives a JSON store with no
/// `format` key. `--format json` for a file that sops reads as YAML is
/// refused with exit 3 before any file is made.
#[test]
fn init_format_json_creates_a_json_store() {
    let env = TestEnv::new();
    let init = |dir: &str, file: &str, extra: &[&str]| {
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
    };

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
