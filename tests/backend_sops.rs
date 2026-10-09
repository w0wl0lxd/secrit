//! The conformance suite (v0.2 plan 10.1) on a sops YAML store, with the
//! real sops and age-keygen in a temp directory only, and the checks that
//! only sops has.

mod common;

use common::fixture::{Fixture, SopsFixture};
use common::{code, stderr};

crate::conformance_suite!(common::fixture::SopsFixture);

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
