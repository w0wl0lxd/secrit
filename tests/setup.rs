//! Integration tests for `doctor`, `wire` and `init` (PLAN 4.6-4.8): the real
//! secrit binary, sops, age-keygen and git, in a temp directory only.

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use common::{TestEnv, bin, code, run_cmd, stderr};
use serde_json::Value;

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A program that writes its pid to `pid_file` and then hangs. With `-o
/// PATH` it first creates PATH empty, as age-keygen does before it writes
/// the key.
fn hanging(env: &TestEnv, name: &str, pid_file: &Path) -> PathBuf {
    env.script(
        name,
        &format!(
            "[ \"$1\" = -o ] && : > \"$2\"\necho $$ > '{}'\nexec '{}' 30",
            pid_file.display(),
            bin("sleep").display()
        ),
    )
}

/// Run `cmd` with `args`, wait until `pid_file` names the hanging child,
/// send TERM to secrit, and return what secrit left.
fn term_while_waiting(mut cmd: Command, args: &[&str], pid_file: &Path) -> Output {
    let child = cmd
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !std::fs::read_to_string(pid_file).is_ok_and(|s| s.ends_with('\n')) {
        assert!(Instant::now() < deadline, "the hanging child never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    let hung = std::fs::read_to_string(pid_file).unwrap().trim().to_owned();
    let st = Command::new(bin("kill"))
        .args(["-s", "TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
    let out = child.wait_with_output().unwrap();
    assert!(
        !Path::new(&format!("/proc/{hung}")).exists(),
        "the child outlived secrit"
    );
    out
}

/// secrit with a git on its PATH that hangs, and a `.git` above the store.
fn with_hanging_git(env: &TestEnv, pid_file: &Path) -> Command {
    let dir = env.root.path().join("fake-git");
    std::fs::create_dir_all(&dir).unwrap();
    let git = hanging(env, "git-hang", pid_file);
    std::fs::rename(&git, dir.join("git")).unwrap();
    std::fs::create_dir_all(env.store_dir.parent().unwrap().join(".git")).unwrap();
    let mut c = env.cmd();
    let dirs: Vec<PathBuf> = [&env.sops, &env.age_keygen]
        .iter()
        .filter_map(|p| p.parent().map(Path::to_path_buf))
        .chain([dir])
        .collect();
    c.env("PATH", std::env::join_paths(dirs).unwrap());
    c
}

/// Finding 1: a signal while doctor waits for sops or git exits 130 and
/// prints no rows, instead of rows that blame the stopped child.
#[test]
fn a_signal_stops_doctor_with_130() {
    let env = TestEnv::new();
    let pid_file = env.root.path().join("sops.pid");
    let sops = hanging(&env, "sops-hang", &pid_file);
    env.write_config_with(&sops, "");
    let out = term_while_waiting(env.cmd(), &["doctor", "--json"], &pid_file);
    assert_eq!(code(&out), 130, "{}{}", stdout(&out), stderr(&out));
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    assert!(stderr(&out).contains("interrupted"), "{}", stderr(&out));

    let env = TestEnv::new();
    let pid_file = env.root.path().join("git.pid");
    let cmd = with_hanging_git(&env, &pid_file);
    let out = term_while_waiting(cmd, &["doctor"], &pid_file);
    assert_eq!(code(&out), 130, "{}{}", stdout(&out), stderr(&out));
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));
}

/// Finding 1: the same for the git queries of wire and init.
#[test]
fn a_signal_during_git_stops_wire_and_init_with_130() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("n", b"v\n")), 0);
    let pid_file = env.root.path().join("git.pid");
    let cmd = with_hanging_git(&env, &pid_file);
    let out = term_while_waiting(cmd, &["wire", "n", "--owner", "a"], &pid_file);
    assert_eq!(code(&out), 130, "{}", stderr(&out));
    assert!(!stderr(&out).contains("then run"), "{}", stderr(&out));

    std::fs::remove_file(&pid_file).unwrap();
    let cmd = with_hanging_git(&env, &pid_file);
    let out = term_while_waiting(cmd, &["init"], &pid_file);
    assert_eq!(code(&out), 130, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("run 'secrit init' again"), "{err}");
    assert!(!err.contains("nothing was changed"), "{err}");
}

/// Findings 2 and 3: a signal while age-keygen writes the new key leaves no
/// file at the key path and no temp directory, and says that init can be
/// run again. A rerun then makes the key. An empty key file is refused.
#[test]
fn an_interrupted_keygen_leaves_no_key() {
    let env = TestEnv::new();
    let key = env.root.path().join("newkey").join("keys.txt");
    let file = env.store_dir.join("fresh.yaml");
    let pid_file = env.root.path().join("keygen.pid");
    let keygen = hanging(&env, "keygen-hang", &pid_file);
    let config = |keygen: &Path| {
        let text = format!(
            "default_store = \"main\"\n\n[stores.main]\nbackend = \"sops\"\nfile = \"{}\"\nage_key_file = \"{}\"\n\n[tools]\nsops = \"{}\"\nage_keygen = \"{}\"\n",
            file.display(),
            key.display(),
            env.sops.display(),
            keygen.display()
        );
        std::fs::write(&env.config_file, text).unwrap();
    };
    config(&keygen);
    let out = term_while_waiting(env.cmd(), &["init"], &pid_file);
    assert_eq!(code(&out), 130, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("run 'secrit init' again"), "{err}");
    assert!(!err.contains("nothing was changed"), "{err}");
    assert!(!key.exists(), "an empty key was left at the key path");
    let left: Vec<_> = std::fs::read_dir(key.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "the temp directory was left: {left:?}");

    config(&env.age_keygen);
    let out = env.run(["init"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(std::fs::metadata(&key).unwrap().len() > 0);
    assert_eq!(std::fs::metadata(&key).unwrap().mode() & 0o777, 0o600);
    assert!(file.is_file());

    std::fs::write(&key, "").unwrap();
    let out = env.run(["init"], None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("is empty"), "{}", stderr(&out));
}

/// Finding 5: a flag that names another file than the configured store is
/// refused before any step, so init makes no file the config does not use.
#[test]
fn init_refuses_a_flag_that_differs_from_the_config() {
    let env = TestEnv::new();
    let other = env.store_dir.join("other.yaml");
    let out = env.run(
        [
            "init",
            "--sops-file",
            other.to_str().unwrap(),
            "--write-sops-config",
        ],
        None,
    );
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("--sops-file"), "{}", stderr(&out));
    assert!(
        !other.exists(),
        "init created a file the config does not use"
    );

    let key = env.root.path().join("keys").join("other.txt");
    let out = env.run(["init", "--age-key", key.to_str().unwrap()], None);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("--age-key"), "{}", stderr(&out));
    assert!(!key.exists());

    let same = env.store_file.to_str().unwrap();
    let out = env.run(["init", "--sops-file", same], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("exists; unchanged"),
        "{}",
        stderr(&out)
    );
}

/// Finding 4 (refuted): a new `.sops.yaml` outside the store file's tree
/// gets a rule with the absolute path, and sops matches it, so init and
/// the first write succeed.
#[test]
fn init_with_a_sops_config_elsewhere_works() {
    let env = TestEnv::new();
    let f = Fresh::new(&env, "apart");
    let rules = env
        .root
        .path()
        .join("apart")
        .join("rules")
        .join(".sops.yaml");
    let out = f.run(
        &env,
        &[
            "--sops-config",
            rules.to_str().unwrap(),
            "--write-sops-config",
        ],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = std::fs::read_to_string(&rules).unwrap();
    assert!(text.contains("path_regex: '(^|/)/"), "{text}");
    assert!(f.file.is_file());
    let out = f.secrit(&env, &["store", "first"], Some(b"value\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = f.secrit(&env, &["ls"], None);
    assert_eq!(stdout(&out), "first\n");
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

/// The sops version row shows once, however many sops stores the config
/// names.
#[test]
fn doctor_checks_the_sops_version_once() {
    let env = TestEnv::new();
    let second = env.store_dir.join("second.yaml");
    env.create_store(&second);
    let text = format!(
        "{}\n[stores.second]\nbackend = \"sops\"\nfile = \"{}\"\nage_key_file = \"{}\"\n",
        std::fs::read_to_string(&env.config_file).unwrap(),
        second.display(),
        env.key_file.display()
    );
    std::fs::write(&env.config_file, text).unwrap();
    let out = env.run(["doctor", "--json"], None);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    let r = rows(&out);
    assert_eq!(status_of(&r, "sops version"), ["ok"], "{r:?}");
    assert_eq!(status_of(&r, "store second: file"), ["ok"], "{r:?}");
    assert_eq!(status_of(&r, "store main: file"), ["ok"], "{r:?}");
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

/// v0.2 plan 6.1.5: the temp copies of a JSON store end in `.json`, so the
/// v0.1 line `.*.secrit-*.yaml` does not ignore them. `doctor` warns and
/// names the line for every format, `.*.secrit-*`; with it, the row is ok.
/// A JSON store passes every other `doctor` check.
#[test]
fn doctor_checks_the_ignore_line_of_a_json_store() {
    let env = TestEnv::with_format("json");
    assert_eq!(code(&env.store_value("n", b"v")), 0);
    let repo = env.store_dir.parent().unwrap().to_path_buf();
    git(&env, &repo, &["init", "-q"]);
    std::fs::write(repo.join(".gitignore"), ".*.secrit-*.yaml\n").unwrap();
    git(&env, &repo, &["add", "secrets/main.json"]);
    let out = run_cmd(with_git(&env), ["doctor"], None);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    assert!(
        stdout(&out).contains(&format!(
            "warn  store main: git ignore: {} does not ignore temp copies; add '.*.secrit-*' to its .gitignore",
            repo.display()
        )),
        "{}",
        stdout(&out)
    );
    assert!(!stdout(&out).contains("fail"), "{}", stdout(&out));

    std::fs::write(repo.join(".gitignore"), ".*.secrit-*\n").unwrap();
    let out = run_cmd(with_git(&env), ["doctor", "--json"], None);
    let r = rows(&out);
    assert_eq!(status_of(&r, "store main: git ignore"), ["ok"], "{r:?}");
    assert_eq!(status_of(&r, "store main: file"), ["ok"], "{r:?}");
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
    // A-6 and B-4: the ignore line and the spell-checker reminder.
    let ignore_line = format!(
        "then run: echo '.*.secrit-*' >> {}\n",
        repo.join(".gitignore").display()
    );
    assert!(err.contains(&ignore_line), "{err}");
    assert!(
        err.contains(&format!(
            "then: if a pre-commit spell checker (such as typos) runs in {}, exclude secrets/main.yaml from it; ciphertext can fail it",
            repo.display()
        )),
        "{err}"
    );

    std::fs::write(repo.join(".gitignore"), ".*.secrit-*.yaml\n").unwrap();
    git(&env, repo, &["add", ".gitignore", "secrets/main.yaml"]);
    let mut cmd = with_git(&env);
    cmd.env("USER", "bob");
    let out = run_cmd(cmd, ["wire", "gh-token"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(!err.contains("then run: echo"), "{err}");
    assert!(!err.contains("git -C"), "{err}");
    assert!(!err.contains("spell checker"), "{err}");
    assert!(err.contains("then run: sudo nixos-rebuild"), "{err}");
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

    // A second run changes nothing, not even a key mode the user set (T23).
    std::fs::set_permissions(&f.key, std::fs::Permissions::from_mode(0o400)).unwrap();
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
    assert_eq!(std::fs::metadata(&f.key).unwrap().mode() & 0o7777, 0o400);
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
    assert!(
        err.contains(&format!(
            "next: ignore temp copies: echo '.*.secrit-*' >> {}\n",
            repo.join(".gitignore").display()
        )),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "next: git -C {} add secrets/s.yaml\n",
            repo.display()
        )),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "next: if a pre-commit spell checker (such as typos) runs in {}, exclude secrets/s.yaml from it; ciphertext can fail it\n",
            repo.display()
        )),
        "{err}"
    );
}

/// B-1: with a config that does not name the store, init prints only the
/// store's table. Appended to the config as told, it loads.
#[test]
fn init_prints_a_section_that_loads() {
    let env = TestEnv::new();
    let other = env.store_dir.join("other.yaml");
    let out = env.run(
        [
            "init",
            "--store",
            "other",
            "--sops-file",
            other.to_str().unwrap(),
            "--age-key",
            env.key_file.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(other.is_file(), "init creates the store file");
    let section = stdout(&out);
    assert!(section.starts_with("[stores.other]\n"), "{section}");
    assert!(!section.contains("default_store"), "{section}");
    let mut config = std::fs::read_to_string(&env.config_file).unwrap();
    config.push('\n');
    config.push_str(&section);
    std::fs::write(&env.config_file, config).unwrap();
    assert_eq!(code(&env.store_value("n", b"v\n")), 0);
    let out = env.run(["ls", "--store", "other"], None);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    let out = env.run(["store", "--store", "other", "x"], Some(b"v\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert_eq!(env.ls(), ["n"], "the default store is still main");
}

/// C-3 and D-4 (T23): init keeps a key that the user made, with its bytes
/// and its mode, and makes no other file next to it.
#[test]
fn init_keeps_an_existing_key() {
    let env = TestEnv::new();
    let f = Fresh::new(&env, "ownkey");
    std::fs::create_dir_all(f.key.parent().unwrap()).unwrap();
    let st = Command::new(&env.age_keygen)
        .env_clear()
        .arg("-o")
        .arg(&f.key)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    std::fs::set_permissions(&f.key, std::fs::Permissions::from_mode(0o400)).unwrap();
    let bytes = std::fs::read(&f.key).unwrap();

    let out = f.run(&env, &["--write-sops-config"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("exists; unchanged"), "{err}");
    assert!(!err.contains("back up"), "{err}");
    assert_eq!(std::fs::read(&f.key).unwrap(), bytes);
    assert_eq!(std::fs::metadata(&f.key).unwrap().mode() & 0o7777, 0o400);
    let names: Vec<_> = std::fs::read_dir(f.key.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, [std::ffi::OsString::from("keys.txt")]);
    assert!(f.file.is_file());
}

/// D-3: `secrit init --sops-file ...` with no `--age-key` and no
/// `SECRIT_CONFIG` uses the default paths under `XDG_CONFIG_HOME`.
#[test]
fn init_uses_the_default_paths_on_an_empty_home() {
    let env = TestEnv::new();
    let home = env.root.path().join("empty-home");
    let xdg = home.join(".config");
    std::fs::create_dir_all(&home).unwrap();
    let file = env
        .root
        .path()
        .join("fresh")
        .join("repo")
        .join("secrets")
        .join("s.yaml");
    let cmd = || {
        let mut c = with_git(&env);
        c.env_remove("SECRIT_CONFIG")
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &xdg);
        c
    };
    let init = || {
        run_cmd(
            cmd(),
            [
                "init",
                "--sops-file",
                file.to_str().unwrap(),
                "--write-sops-config",
            ],
            None,
        )
    };
    let out = init();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let key = xdg.join("sops").join("age").join("keys.txt");
    let config = xdg.join("secrit").join("config.toml");
    for p in [&key, &config] {
        assert_eq!(std::fs::metadata(p).unwrap().mode() & 0o777, 0o600, "{p:?}");
    }
    assert!(file.is_file());
    assert!(file.parent().unwrap().join(".sops.yaml").is_file());
    assert!(
        !stderr(&out).contains("using config"),
        "no variable picked the config: {}",
        stderr(&out)
    );

    let out = run_cmd(cmd(), ["store", "first"], Some(b"value\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let out = run_cmd(cmd(), ["ls"], None);
    assert_eq!(stdout(&out), "first\n", "{}", stderr(&out));

    let before: Vec<Vec<u8>> = [&key, &config, &file]
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    let again = init();
    assert_eq!(code(&again), 0, "{}", stderr(&again));
    let after: Vec<Vec<u8>> = [&key, &config, &file]
        .iter()
        .map(|p| std::fs::read(p).unwrap())
        .collect();
    assert!(before == after, "a second init changed a file");
}

/// `doctor --json` and its rows.
fn doctor_rows(env: &TestEnv) -> (Output, Vec<(String, String)>) {
    let out = env.run(["doctor", "--json"], None);
    let r = rows(&out);
    (out, r)
}

/// B-3 and D-5: the directory, file, .sops.yaml, backups and sops checks of
/// PLAN 4.7 each fail on their own broken item, and doctor exits 1. No value
/// reaches the output. `doctor_reports_each_problem` covers the age key,
/// plaintext, temp file and cleartext rule rows.
#[test]
fn doctor_fails_each_store_check() {
    let mode = |p: &Path, m: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    };
    let expect_fail = |env: &TestEnv, check: &str, what: &str| {
        let (out, r) = doctor_rows(env);
        assert_eq!(code(&out), 1, "{what}: {}{}", stdout(&out), stderr(&out));
        assert!(
            status_of(&r, check).contains(&"fail"),
            "{what}: {check}: {r:?}"
        );
        assert!(!stdout(&out).contains("secret-value"), "{what}");
        assert!(!stderr(&out).contains("secret-value"), "{what}");
    };
    let fresh = || {
        let env = TestEnv::new();
        assert_eq!(code(&env.store_value("n", b"secret-value\n")), 0);
        env
    };

    let env = fresh();
    mode(&env.store_dir, 0o775);
    expect_fail(&env, "store main: directory", "group-writable directory");
    mode(&env.store_dir, 0o755);

    let env = fresh();
    let real = env.root.path().join("real.yaml");
    std::fs::rename(&env.store_file, &real).unwrap();
    std::os::unix::fs::symlink(&real, &env.store_file).unwrap();
    expect_fail(&env, "store main: file", "symlinked store file");

    let env = fresh();
    std::fs::hard_link(&env.store_file, env.root.path().join("link.yaml")).unwrap();
    expect_fail(&env, "store main: file", "hard-linked store file");

    let env = fresh();
    mode(&env.store_file, 0o666);
    expect_fail(&env, "store main: file", "store file mode 0666");

    let env = fresh();
    std::fs::write(&env.store_file, "a: b\n").unwrap();
    expect_fail(&env, "store main: file", "not sops YAML");

    let env = fresh();
    std::fs::remove_file(&env.store_file).unwrap();
    expect_fail(&env, "store main: file", "missing store file");

    let env = fresh();
    mode(&env.sops_config, 0o666);
    expect_fail(&env, "store main: .sops.yaml", ".sops.yaml mode 0666");

    // The first store made a backup directory only on a replace.
    let env = fresh();
    assert_eq!(
        code(&env.run(["store", "--replace", "n"], Some(b"secret-value2\n"))),
        0
    );
    let dirs: Vec<PathBuf> = std::fs::read_dir(env.backup_root())
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(dirs.len(), 1);
    mode(&dirs[0], 0o755);
    expect_fail(&env, "store main: backups", "backup directory mode 0755");
    mode(&dirs[0], 0o700);
    let moved = env.root.path().join("moved-backups");
    std::fs::rename(&dirs[0], &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &dirs[0]).unwrap();
    expect_fail(&env, "store main: backups", "symlinked backup directory");

    let env = fresh();
    let old = env.script(
        "sops-old",
        "for a in \"$@\"; do [ \"$a\" = --version ] && { echo 'sops 3.10.0'; exit 0; }; done\nexit 1",
    );
    env.write_config_with(&old, "");
    expect_fail(&env, "sops version", "sops 3.10");

    let env = fresh();
    env.write_config_with(&env.root.path().join("no-such-sops"), "");
    expect_fail(&env, "sops", "missing configured sops");
}

/// v0.2 plan S3: the sops module split moves the store rows out of the
/// doctor command and changes no row. This pins every row of a full setup
/// (a value, a backup, a git repository with a flake) in order. The
/// hardening rows depend on the host, so the test drops them. The status of
/// the agent and tool rows depends on the host and the build, so the test
/// compares only their names.
#[test]
fn doctor_rows_keep_their_order() {
    let env = TestEnv::new();
    assert_eq!(code(&env.store_value("one", b"v1\n")), 0);
    let out = env.run(["store", "--replace", "one"], Some(b"v2\n"));
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let repo = env.store_dir.parent().unwrap().to_path_buf();
    git(&env, &repo, &["init", "-q"]);
    std::fs::write(repo.join("flake.nix"), "{ outputs = _: { }; }\n").unwrap();
    std::fs::write(repo.join(".gitignore"), ".*.secrit-*.yaml\n").unwrap();
    git(&env, &repo, &["add", "secrets/main.yaml"]);
    let out = run_cmd(with_git(&env), ["doctor", "--json"], None);
    assert_eq!(code(&out), 0, "{}{}", stdout(&out), stderr(&out));
    let host_dependent = ["agent", "sops", "age-keygen"];
    let got: Vec<(String, String)> = rows(&out)
        .into_iter()
        .filter(|(c, _)| c != "hardening")
        .map(|(c, s)| {
            let s = if host_dependent.contains(&c.as_str()) {
                "*".to_owned()
            } else {
                s
            };
            (c, s)
        })
        .collect();
    let want = [
        ("agent", "*"),
        ("age key exposure", "ok"),
        ("config", "ok"),
        ("sops", "*"),
        ("age-keygen", "*"),
        ("sops version", "ok"),
        ("store main: age key", "ok"),
        ("store main: directory", "ok"),
        ("store main: file", "ok"),
        ("store main: plaintext", "ok"),
        ("store main: .sops.yaml", "ok"),
        ("store main: temp files", "ok"),
        ("store main: backups", "ok"),
        ("store main: git ignore", "ok"),
        ("store main: git", "ok"),
    ]
    .map(|(c, s)| (c.to_owned(), s.to_owned()));
    assert_eq!(got, want, "{}", stdout(&out));
}
