//! The conformance suite (v0.2 plan 10.1) on a Secret Service store, and
//! the checks that only this backend has (v0.2 plan 6.3, S10). Each test
//! runs its own session bus and gnome-keyring; see
//! `common/fixture_secret_service.rs`.

#![cfg(target_os = "linux")]

mod common;

use std::io::Write;
use std::process::{Command, Output, Stdio};

use common::conformance::get_to_file;
use common::fixture::Fixture;
use common::fixture_secret_service::SecretServiceFixture;
use common::{assert_absent, code, no_tty, run_cmd, stderr};

crate::conformance_suite!(common::fixture_secret_service::SecretServiceFixture);

fn fixture() -> SecretServiceFixture {
    SecretServiceFixture::new()
}

fn ok(out: &Output) {
    assert_eq!(code(out), 0, "{}", stderr(out));
}

/// `secret-tool lookup secrit-name NAME` reads a value that secrit wrote,
/// and secrit reads an item that `secret-tool store` wrote with the secrit
/// attributes (v0.2 plan 6.3).
#[test]
fn secret_tool_reads_what_secrit_wrote() {
    let f = fixture();
    ok(&f.dirs().store_value("n", b"interop-value"));
    assert!(
        f.lookup(&["secrit-name", "n"]).as_deref() == Some(&b"interop-value"[..]),
        "secret-tool read another value"
    );
    assert_eq!(f.item_count("n"), 1);

    f.tool_store("m", b"from-tool");
    assert_eq!(f.dirs().ls(), ["m", "n"]);
    let (out, got) = get_to_file(&f, false, "m");
    ok(&out);
    assert!(got == b"from-tool", "get read another value");
}

/// Two stores share one collection, and each sees only its own items.
#[test]
fn stores_do_not_see_each_other() {
    let f = fixture();
    ok(&f.dirs().store_value("n", b"main-value"));
    let section = "backend = \"secret-service\"\n\n[stores.other]\nbackend = \"secret-service\"\n";
    f.dirs().write_store_config(section, "", 120);
    let out = f.dirs().run(["--store", "other", "ls"], None);
    ok(&out);
    assert!(out.stdout.is_empty(), "the other store lists names");
    ok(&f
        .dirs()
        .run(["--store", "other", "store", "n"], Some(b"other-value")));
    assert_eq!(f.dirs().ls(), ["n"]);
    assert!(
        f.read_back("n").as_deref() == Some(&b"main-value"[..]),
        "the main store value changed"
    );
    assert_eq!(f.item_count("n"), 1);
}

/// T32: 20 parallel `store` of one name make one item; the other 19 exit
/// 3 and change nothing.
#[test]
fn parallel_create_only_makes_one_item() {
    let f = fixture();
    let children: Vec<_> = (0..20)
        .map(|i| {
            let mut c = f.dirs().cmd();
            c.args(["store", "n"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = c.spawn().unwrap();
            let value = format!("writer-{i}");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(value.as_bytes())
                .unwrap();
            child
        })
        .collect();
    let outs: Vec<Output> = children
        .into_iter()
        .map(|c| c.wait_with_output().unwrap())
        .collect();
    let codes: Vec<i32> = outs.iter().map(code).collect();
    assert_eq!(codes.iter().filter(|c| **c == 0).count(), 1, "{codes:?}");
    assert_eq!(codes.iter().filter(|c| **c == 3).count(), 19, "{codes:?}");
    for out in outs.iter().filter(|o| code(o) == 3) {
        assert!(stderr(out).contains("already exists"), "{}", stderr(out));
    }
    assert_eq!(f.item_count("n"), 1);
    assert_eq!(f.names(), ["n"]);
}

/// T33: a locked collection is refused with `Locked` for every value and
/// write operation, and nothing changes. `ls` still works while the daemon
/// shows the attributes.
#[test]
fn a_locked_collection_is_refused() {
    let f = fixture();
    ok(&f.dirs().store_value("n", b"locked-canary-41e9"));
    f.lock_values();
    let locked = |out: &Output| {
        assert_eq!(code(out), 3, "{}", stderr(out));
        assert!(stderr(out).contains("is locked"), "{}", stderr(out));
        assert_absent(out, "locked-canary-41e9");
    };
    locked(&f.dirs().store_value("m", b"v"));
    locked(
        &f.dirs()
            .run(["store", "n", "--replace", "--yes"], Some(b"v")),
    );
    locked(&f.dirs().run(["rm", "n", "--yes"], None));
    let (out, got) = get_to_file(&f, false, "n");
    assert_eq!(code(&out), 3, "{}", String::from_utf8_lossy(&out.stdout));
    assert!(String::from_utf8_lossy(&out.stdout).contains("is locked"));
    assert!(got.is_empty());
    assert_eq!(f.dirs().ls(), ["n"]);
    assert_eq!(f.item_count("n"), 1);
}

/// T33: after a restart with the keyring locked on disk, gnome-keyring
/// shows only hashed attributes. `ls` cannot know the names, so it is
/// refused with `Locked` and lists nothing.
#[test]
fn ls_on_a_keyring_locked_on_disk_is_refused() {
    let mut f = fixture();
    ok(&f.dirs().store_value("n", b"v"));
    f.restart_locked();
    let out = f.dirs().run(["ls"], None);
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("is locked"), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

/// Q30: with `unlock = "prompt"`, an agent still gets the refusal: only
/// the owner at a terminal may cause an unlock prompt.
#[test]
fn unlock_prompt_is_refused_for_agents() {
    let f = fixture();
    f.dirs().write_store_config(
        "backend = \"secret-service\"\nunlock = \"prompt\"\n",
        "",
        120,
    );
    ok(&f.dirs().store_value("n", b"v"));
    f.lock_values();
    let mut cmd = f.dirs().cmd();
    cmd.env("CLAUDECODE", "1");
    let out = run_cmd(cmd, ["store", "m"], Some(b"v"));
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(stderr(&out).contains("is locked"), "{}", stderr(&out));
    // No terminal counts as an agent too.
    let mut cmd = no_tty(&f.dirs().cmd());
    cmd.args(["store", "m"]);
    let out = run_cmd(cmd, std::iter::empty::<&str>(), Some(b"v"));
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert_eq!(f.names(), ["n"]);
}

/// T31: only `unix:path=<absolute>` passes, the socket must be in a
/// private directory, and with the variable unset secrit uses
/// `$XDG_RUNTIME_DIR/bus`.
#[test]
fn the_bus_address_is_checked() {
    let f = fixture();
    ok(&f.dirs().store_value("n", b"v"));
    let refused = |addr: &std::ffi::OsStr, why: &str| {
        let mut cmd = f.dirs().cmd();
        cmd.env("DBUS_SESSION_BUS_ADDRESS", addr);
        let out = run_cmd(cmd, ["ls"], None);
        assert_eq!(code(&out), 3, "{}", stderr(&out));
        let err = stderr(&out);
        assert!(err.contains("refusing the D-Bus session bus"), "{err}");
        assert!(err.contains(why), "{err}");
    };
    refused("tcp:host=127.0.0.1,port=9".as_ref(), "only a unix:path=");
    refused("unix:abstract=/tmp/dbus-x".as_ref(), "only a unix:path=");

    // A socket of this user in a sticky, world-writable directory.
    let shared = f.dirs().root.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(
        &shared,
        std::os::unix::fs::PermissionsExt::from_mode(0o1777),
    )
    .unwrap();
    let sock = shared.join("bus");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let mut addr = std::ffi::OsString::from("unix:path=");
    addr.push(&sock);
    refused(&addr, "writable by group or others");

    // A symlink to the real socket.
    let link = f.dirs().runtime.join("link");
    std::os::unix::fs::symlink(&f.bus, &link).unwrap();
    let mut addr = std::ffi::OsString::from("unix:path=");
    addr.push(&link);
    refused(&addr, "not a socket");

    // Unset: $XDG_RUNTIME_DIR/bus, which is the fixture bus.
    let mut cmd = f.dirs().cmd();
    cmd.env_remove("DBUS_SESSION_BUS_ADDRESS");
    let out = run_cmd(cmd, ["ls"], None);
    ok(&out);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "n");
}

/// T55: `rm` says that no backup is kept and that the daemon may keep the
/// old value in its own files.
#[test]
fn rm_says_no_backup_is_kept() {
    let f = fixture();
    ok(&f.dirs().store_value("n", b"v"));
    let out = f.dirs().run(["rm", "n", "--yes"], None);
    ok(&out);
    let err = stderr(&out);
    assert!(err.contains("no backup; the old value is gone"), "{err}");
    assert!(err.contains("the daemon may keep the old value"), "{err}");
    assert_eq!(f.read_back("n"), None);
    let out = f.dirs().run(["rm", "n", "--yes"], None);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(stderr(&out).contains("does not exist"));
}

/// The doctor rows of v0.2 plan 6.3, and the same-uid reader note (T29).
/// No store uses sops, so a missing sops is a warning only.
#[test]
fn doctor_shows_the_daemon_rows() {
    let f = fixture();
    ok(&f.dirs().store_value("n", b"doctor-canary-0b3f"));
    let out = f.dirs().run(["doctor"], None);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    ok(&out);
    for row in [
        "ok    store main: bus: ",
        "ok    store main: daemon: the session bus answers",
        "ok    store main: session: encrypted (DH) session",
        "ok    store main: collection: Secret Service collection 'default' (secrit-store=main) is unlocked",
        "ok    store main: items: 1 secrit item(s)",
        "info  store main: readers: any process of this user",
    ] {
        assert!(text.contains(row), "missing {row:?} in:\n{text}");
    }
    assert!(!text.contains("fail"), "{text}");
    assert_absent(&out, "doctor-canary-0b3f");

    f.lock_values();
    let out = f.dirs().run(["doctor"], None);
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(code(&out), 1, "{text}");
    assert!(text.contains("fail  store main: collection: "), "{text}");
}

/// `init --backend secret-service` checks the daemon and the collection,
/// writes the config, and refuses the sops flags.
#[test]
fn init_writes_a_secret_service_config() {
    let f = fixture();
    let d = f.dirs();
    std::fs::remove_file(&d.config_file).unwrap();
    let out = d.run(
        [
            "init",
            "--backend",
            "secret-service",
            "--sops-file",
            "x.yaml",
        ],
        None,
    );
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("--sops-file apply only to a sops store"));
    assert!(!d.config_file.exists());

    let out = d.run(["init", "--backend", "secret-service"], None);
    ok(&out);
    assert!(stderr(&out).contains("is reachable and unlocked (0 secrit items)"));
    let text = std::fs::read_to_string(&d.config_file).unwrap();
    assert!(text.contains("backend = \"secret-service\""), "{text}");
    assert!(text.contains("collection = \"default\""), "{text}");
    assert!(!text.contains("file"), "{text}");
    ok(&d.store_value("n", b"v"));
    assert_eq!(f.names(), ["n"]);

    // A second run changes nothing.
    let out = d.run(["init"], None);
    ok(&out);
    assert!(
        stderr(&out).contains("exists; unchanged"),
        "{}",
        stderr(&out)
    );
    let out = d.run(["init", "--backend", "sops"], None);
    assert_eq!(code(&out), 2, "{}", stderr(&out));
    assert!(stderr(&out).contains("with backend secret-service"));
}

/// R13: a signal while a D-Bus call is blocked exits 130 through the
/// normal error path, so the lock is released and the next write works.
#[cfg(feature = "test-hooks")]
#[test]
fn a_signal_during_a_blocked_call_exits_130() {
    let f = fixture();
    let d = f.dirs();
    let mut cmd = d.cmd();
    cmd.env("SECRIT_TEST_HOOK", "after-lock=pause")
        .env("SECRIT_TEST_HOOK_DIR", d.hook_dir())
        .args(["store", "n"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"v").unwrap();
    d.wait_for_hook(1);
    // The daemon stops answering; secrit's next D-Bus call blocks.
    f.signal_keyring("STOP");
    std::fs::write(d.hook_dir().join("go"), b"").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let st = Command::new(common::bin("kill"))
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
    let out = child.wait_with_output().unwrap();
    f.signal_keyring("CONT");
    assert_eq!(code(&out), 130, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("interrupted by a signal during Secret Service write"),
        "{}",
        stderr(&out)
    );
    // The lock is free: a second store does not wait for it.
    let started = std::time::Instant::now();
    let out = d.store_value("m", b"v");
    ok(&out);
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
}

/// T55, Q37: `store --replace` on a free name asks nothing. When another
/// program creates the name before the write, secrit refuses (exit 3) under
/// its lock and keeps the other item: nobody confirmed a replace.
#[cfg(feature = "test-hooks")]
#[test]
fn an_unconfirmed_replace_keeps_an_item_made_meanwhile() {
    let f = fixture();
    let d = f.dirs();
    let mut cmd = d.cmd();
    cmd.env("SECRIT_TEST_HOOK", "after-lock=pause")
        .env("SECRIT_TEST_HOOK_DIR", d.hook_dir())
        .args(["store", "n", "--replace"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"mine").unwrap();
    d.wait_for_hook(1);
    f.tool_store("n", b"theirs");
    std::fs::write(d.hook_dir().join("go"), b"").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 3, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("appeared while secrit waited; nothing was replaced"),
        "{}",
        stderr(&out)
    );
    assert_eq!(f.item_count("n"), 1);
    assert!(
        f.read_back("n").as_deref() == Some(&b"theirs"[..]),
        "the other item changed"
    );

    // `--yes` confirms the replace before secrit looks, so it replaces.
    let out = d.run(["store", "n", "--replace", "--yes"], Some(b"mine"));
    ok(&out);
    assert!(f.read_back("n").as_deref() == Some(&b"mine"[..]));
    assert_eq!(f.item_count("n"), 1);
}

/// v0.2 plan 5.7: `wire` needs a sops file, so on a Secret Service store
/// it prints nothing and exits 3 for every format. `store` prints no
/// `/run/secrets` hint, and the config refuses `wire_hint`.
#[test]
fn wire_is_refused_on_a_secret_service_store() {
    let f = fixture();
    f.dirs()
        .write_store_config("backend = \"secret-service\"\nwire_hint = true\n", "", 120);
    let out = f.dirs().run(["ls"], None);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out)
            .contains("config key stores.main.wire_hint does not apply to backend secret-service"),
        "{}",
        stderr(&out)
    );
    f.dirs()
        .write_store_config("backend = \"secret-service\"\n", "", 120);
    let out = f.dirs().store_value("n", b"v");
    ok(&out);
    assert!(!stderr(&out).contains("/run/secrets"), "{}", stderr(&out));
    for format in ["nix", "env"] {
        let out = f.dirs().run(["wire", "n", "--format", format], None);
        assert_eq!(code(&out), 3, "{}", stderr(&out));
        assert!(out.stdout.is_empty(), "wire printed a stanza");
        assert!(
            stderr(&out).contains("uses the secret-service backend, and wire needs a sops store"),
            "{}",
            stderr(&out)
        );
    }
}
