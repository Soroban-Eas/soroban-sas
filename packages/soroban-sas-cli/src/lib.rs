//! Library facade for `soroban-sas-cli`.
//!
//! Exposes pure parsing modules so they can be used as dependencies by fuzz
//! harnesses and integration tests without pulling in the full CLI binary
//! entrypoint.
//!
//! Only the pure, side-effect-free parsing modules are re-exported here.
//! Modules that perform I/O, spawn threads, or depend on the binary's
//! command-line infrastructure remain private to the binary entry point
//! (`main.rs`).
#![allow(dead_code)]
pub mod bulk;
pub mod io_safety;
pub mod json_schema;
