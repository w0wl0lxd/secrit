//! The conformance suite (v0.2 plan 10.1) on a sops YAML store, with the
//! real sops and age-keygen in a temp directory only.

mod common;

crate::conformance_suite!(common::fixture::SopsFixture);
