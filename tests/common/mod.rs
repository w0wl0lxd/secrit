//! Test harness (PLAN section 15.1, v0.2 plan 10.1).
//!
//! - `env`: the temp directories, the secrit command and the pty helpers.
//!   Its items are re-exported here, so a test file uses `common::TestEnv`.
//! - `fixture`: the `Fixture` trait, one implementation per backend.
//! - `conformance`: the cases that every backend passes, and the
//!   `conformance_suite!` macro that makes one test per case.

#![allow(dead_code)]

pub mod conformance;
pub mod env;
pub mod fixture;

// backend_sops.rs reaches env through the fixture only.
#[allow(unused_imports)]
pub use env::*;
