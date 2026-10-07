//! Integration tests for `doctor`, `wire` and `init` (PLAN 4.6-4.8): the real
//! secrit binary, sops, age-keygen and git, in a temp directory only.

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime};

use common::{TestEnv, code, run_cmd, stderr};
use serde_json::Value;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// secrit with git on its PATH.
fn with_git(env: &TestEnv) -> Command {
    let mut c = env.cmd();
    let dirs: Vec<PathBuf> = [&env.sops, &env.age_keygen, &common::git()]
        .iter()
        .filter_map(|p| p.parent().map(Path::to_path_buf))
        .collect();
    c.env("PATH", std::env::join_paths(dirs).unwrap());
    c
}

fn git(env: &TestEnv, repo: &Path, args: &[&str]) {
    let st = Command::new(common::git())
        .env_clear()
        .env("HOME", &env.home)
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success(), "git {args:?} failed");
}

/// The rows of `doctor --json`, as (check, status).
fn rows(out: &Output) -> Vec<(String, String)> {
    let v: Value = serde_json::from_slice(&out.stdout).expect("doctor --json output");
    v.as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["check"].as_str().unwrap().to_owned(),
                r["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

fn status_of<'a>(rows: &'a [(String, String)], check: &str) -> Vec<&'a str> {
    rows.iter()
        .filter(|(c, _)| c == check)
        .map(|(_, s)| s.as_str())
        .collect()
}

#[test]
fn doctor_passes_on_a_good_setup() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("one", b"v1\n")), 0);
    let out = env.run(["doctor", "--json"], None);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    let r = rows(&out);
    for check in [
        "config",
        "sops",
        "sops version",
        "age key exposure",
        "store main: age key",
        "store main: directory",
        "store main: file",
        "store main: plaintext",
        "store main: .sops.yaml",
        "store main: temp files",
        "store main: backups",
    ] {
        assert_eq!(status_of(&r, check), ["ok"], "{check}: {r:?}");
    }
    assert!(!r.iter().any(|(_, s)| s == "fail"), "{r:?}");
    // sops writes `unencrypted_suffix: _unencrypted` into every file; the
    // name check covers it, so it is not a warning.
    assert!(
        status_of(&r, "store main: cleartext rules").is_empty(),
        "{r:?}"
    );
    let plain = env.run(["doctor"], None);
    assert_eq!(code(&plain), 0);
    assert!(
        stdout(&plain).contains("ok    store main: file: "),
        "{}",
        stdout(&plain)
    );
    assert!(stdout(&plain).contains("(1 names)"), "{}", stdout(&plain));
}

#[test]
fn doctor_reports_each_problem() {
    let env = TestEnv::new();
    std::fs::set_permissions(&env.key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    // A cleartext leaf in the store file. The MAC no longer matches, but
    // doctor never decrypts.
    let text = String::from_utf8(env.store_bytes()).unwrap();
    std::fs::write(&env.store_file, format!("leaked: in-clear\n{text}")).unwrap();
    let stale = env.store_dir.join(".main.yaml.secrit-00aa.yaml");
    std::fs::write(&stale, "x").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(7200))
        .unwrap();
    std::fs::write(env.store_dir.join("main.yaml.secrit-bak.1"), "x").unwrap();
    let mut cmd = env.cmd();
    cmd.env("SOPS_AGE_KEY", "AGE-SECRET-KEY-NOT-A-REAL-ONE");
    let out = run_cmd(cmd, ["doctor", "--json"], None);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("check(s) failed"), "{}", stderr(&out));
    let r = rows(&out);
    assert_eq!(status_of(&r, "store main: age key"), ["fail"], "{r:?}");
    assert_eq!(status_of(&r, "store main: plaintext"), ["fail"], "{r:?}");
    assert_eq!(status_of(&r, "age key exposure"), ["warn"], "{r:?}");
    assert_eq!(
        status_of(&r, "store main: temp files"),
        ["warn", "warn"],
        "{r:?}"
    );
    let all = stdout(&out);
    assert!(all.contains("leaked"), "the row names the key: {all}");
    assert!(!all.contains("in-clear"), "a value reached the output");
    assert!(!all.contains("NOT-A-REAL-ONE"), "a key reached the output");
    assert!(!stderr(&out).contains("NOT-A-REAL-ONE"));
}

#[test]
fn doctor_warns_on_a_regex_rule() {
    let env = TestEnv::new();
    std::fs::write(
        &env.sops_config,
        format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    encrypted_regex: ^data$\n    age: {}\n",
            env.recipients.join(",")
        ),
    )
    .unwrap();
    std::fs::remove_file(&env.store_file).unwrap();
    env.create_store(&env.store_file);
    let out = env.run(["doctor", "--json"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let r = rows(&out);
    assert_eq!(
        status_of(&r, "store main: cleartext rules"),
        ["warn"],
        "{r:?}"
    );
}

#[test]
fn doctor_without_a_config_fails_with_a_hint() {
    let env = TestEnv::new();
    std::fs::remove_file(&env.config_file).unwrap();
    let out = env.run(["doctor"], None);
    assert_eq!(code(&out), 1);
    assert!(
        stdout(&out).contains("fail  config: no config file"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("secrit init"), "{}", stdout(&out));
}

#[test]
fn doctor_checks_the_git_repository() {
    let env = TestEnv::new();
    let repo = env.store_dir.parent().unwrap().to_path_buf();
    git(&env, &repo, &["init", "-q"]);
    std::fs::write(repo.join("flake.nix"), "{ outputs = _: { }; }\n").unwrap();
    let out = run_cmd(with_git(&env), ["doctor", "--json"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let r = rows(&out);
    assert_eq!(status_of(&r, "store main: git ignore"), ["warn"], "{r:?}");
    assert_eq!(status_of(&r, "store main: git"), ["warn"], "{r:?}");

    std::fs::write(repo.join(".gitignore"), ".*.secrit-*.yaml\n").unwrap();
    git(&env, &repo, &["add", "secrets/main.yaml"]);
    let out = run_cmd(with_git(&env), ["doctor", "--json"], None);
    let r = rows(&out);
    assert_eq!(status_of(&r, "store main: git ignore"), ["ok"], "{r:?}");
    assert_eq!(status_of(&r, "store main: git"), ["ok"], "{r:?}");
}

#[test]
fn wire_prints_the_stanza_and_the_commands() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("gh-token", b"v\n")), 0);
    let out = env.run(["wire", "gh-token", "--owner", "alice"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let want = format!(
        "sops.secrets.\"gh-token\" = {{\n  sopsFile = {}; # absolute; pure flake evaluation needs a path inside the flake\n  format = \"yaml\";\n  owner = \"alice\";\n}};\n",
        env.store_file.display()
    );
    assert_eq!(stdout(&out), want);
    assert!(!stderr(&out).contains("nixos-rebuild"), "{}", stderr(&out));

    let flake = env.store_dir.parent().unwrap().to_path_buf();
    env.write_config(&format!(
        "\n[nix]\nflake = \"{}\"\nhost = \"box\"\n",
        flake.display()
    ));
    let repo = &flake;
    git(&env, repo, &["init", "-q"]);
    let mut cmd = with_git(&env);
    cmd.env("USER", "bob");
    let out = run_cmd(cmd, ["wire", "gh-token"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("  sopsFile = ./secrets/main.yaml; # relative to "),
        "{}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("owner = \"bob\";"),
        "{}",
        stdout(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains(&format!(
            "then run: git -C {} add secrets/main.yaml",
            repo.display()
        )),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "then run: sudo nixos-rebuild switch --flake {}#box",
            flake.display()
        )),
        "{err}"
    );
}

#[test]
fn store_prints_the_wire_hint_when_asked() {
    let env = TestEnv::new();
    let out = env.store_value("plain", b"v\n");
    assert!(!stderr(&out).contains("secrit wire"), "{}", stderr(&out));
    env.write_config("wire_hint = true");
    let out = env.store_value("hinted", b"v\n");
    assert_eq!(code(&out), 0);
    assert!(
        stderr(&out).contains("run 'secrit wire hinted' to expose it at /run/secrets/hinted"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn wire_checks_its_input() {
    let env = TestEnv::new();
    let out = env.run(["wire", "absent", "--owner", "alice"], None);
    assert_eq!(code(&out), 0);
    assert!(stderr(&out).contains("absent is not in the store yet"));
    let out = env.run(["wire", "n", "--owner", "a\";x"], None);
    assert_eq!(code(&out), 2);
    assert!(stdout(&out).is_empty());
    let out = env.run(["wire", "n"], None);
    assert_eq!(code(&out), 2, "no USER: {}", stderr(&out));
    assert!(stderr(&out).contains("pass --owner"));
    let out = env.run(["wire", "gh.token", "--format", "env"], None);
    assert_eq!(stdout(&out), "GH_TOKEN_FILE=/run/secrets/gh.token\n");
    let out = env.run(["wire", "bad/name", "--owner", "a"], None);
    assert_eq!(code(&out), 3);
}

/// A secrit command for a machine with no config, key or store yet.
struct Fresh {
    config: PathBuf,
    key: PathBuf,
    file: PathBuf,
}

impl Fresh {
    fn new(env: &TestEnv, name: &str) -> Self {
        let dir = env.root.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            config: dir.join("cfg").join("config.toml"),
            key: dir.join("age").join("keys.txt"),
            file: dir.join("repo").join("secrets").join("s.yaml"),
        }
    }

    fn run(&self, env: &TestEnv, args: &[&str]) -> Output {
        let mut c = with_git(env);
        c.env("SECRIT_CONFIG", &self.config);
        let mut all = vec![
            "init".to_owned(),
            "--sops-file".to_owned(),
            self.file.display().to_string(),
            "--age-key".to_owned(),
            self.key.display().to_string(),
        ];
        all.extend(args.iter().map(|s| (*s).to_owned()));
        run_cmd(c, all, None)
    }

    fn secrit(&self, env: &TestEnv, args: &[&str], stdin: Option<&[u8]>) -> Output {
        let mut c = env.cmd();
        c.env("SECRIT_CONFIG", &self.config);
        run_cmd(c, args, stdin)
    }
}

#[test]
fn init_sets_up_a_fresh_machine_once() {
    let env = TestEnv::new();
    let f = Fresh::new(&env, "fresh");

    let dry = f.run(&env, &["--write-sops-config", "--dry-run"]);
    assert_eq!(code(&dry), 0, "{}", stderr(&dry));
    assert!(stderr(&dry).contains("would: create the age key"));
    assert!(!f.key.exists() && !f.file.exists() && !f.config.exists());

    let out = f.run(&env, &["--write-sops-config"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("back up"), "{}", stderr(&out));
    for p in [&f.key, &f.config] {
        assert_eq!(std::fs::metadata(p).unwrap().mode() & 0o777, 0o600, "{p:?}");
    }
    let rule = f.file.parent().unwrap().join(".sops.yaml");
    assert!(
        std::fs::read_to_string(&rule)
            .unwrap()
            .contains("path_regex: '(^|/)s\\.yaml$'")
    );
    assert!(f.file.is_file());
    let config = std::fs::read_to_string(&f.config).unwrap();
    assert!(config.contains("default_store = \"main\""), "{config}");
    assert!(config.contains(&format!("file = \"{}\"", f.file.display())));

    // The new setup works end to end.
    let out = f.secrit(&env, &["store", "first"], Some(b"value\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = f.secrit(&env, &["ls"], None);
    assert_eq!(stdout(&out), "first\n");

    // A second run changes nothing.
    let before: Vec<Vec<u8>> = [&f.key, &f.file, &f.config, &rule]
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    let again = f.run(&env, &["--write-sops-config"]);
    assert_eq!(code(&again), 0, "{}", stderr(&again));
    assert!(stderr(&again).contains("exists; unchanged"));
    let after: Vec<Vec<u8>> = [&f.key, &f.file, &f.config, &rule]
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    assert!(before == after, "a second init changed a file");
}

#[test]
fn init_never_edits_a_sops_config() {
    let env = TestEnv::new();
    let f = Fresh::new(&env, "norule");
    let out = f.run(&env, &[]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stdout(&out).starts_with("creation_rules:\n"),
        "{}",
        stdout(&out)
    );
    assert!(stderr(&out).contains("--write-sops-config"));
    assert!(f.key.is_file(), "the key step runs first");
    assert!(!f.file.exists());

    let repo = f.file.parent().unwrap().parent().unwrap();
    std::fs::create_dir_all(repo).unwrap();
    let other = format!(
        "creation_rules:\n  - path_regex: other\\.yaml$\n    age: {}\n",
        env.recipients[0]
    );
    std::fs::write(repo.join(".sops.yaml"), &other).unwrap();
    let out = f.run(&env, &["--write-sops-config"]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("has no creation rule"),
        "{}",
        stderr(&out)
    );
    assert!(stdout(&out).contains("path_regex: '(^|/)secrets/s\\.yaml$'"));
    assert_eq!(
        std::fs::read_to_string(repo.join(".sops.yaml")).unwrap(),
        other
    );
    assert!(!f.file.exists());
    assert!(!f.config.exists());
}

#[test]
fn init_in_a_repository_prints_the_git_steps() {
    let env = TestEnv::new();
    let f = Fresh::new(&env, "inrepo");
    let repo = f.file.parent().unwrap().parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&repo).unwrap();
    git(&env, &repo, &["init", "-q"]);
    let out = f.run(&env, &["--write-sops-config"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        repo.join(".sops.yaml").is_file(),
        "the rule goes to the repository root"
    );
    let err = stderr(&out);
    assert!(err.contains("next: ignore temp copies"), "{err}");
    assert!(
        err.contains(&format!(
            "next: git -C {} add secrets/s.yaml",
            repo.display()
        )),
        "{err}"
    );
}
