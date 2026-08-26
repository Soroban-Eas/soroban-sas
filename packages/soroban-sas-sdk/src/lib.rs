#![allow(clippy::new_without_default)]
#![allow(unexpected_cfgs)]
//! Soroban SAS SDK
//!
//! This library provides strong types, builder patterns, and RPC integration
//! for interacting with the Soroban Attestation Service (SAS).

pub mod account;
pub mod client;
pub mod schema_builder;

pub fn init() {}
pub mod attestation_builder;
pub mod batch;
pub mod rpc;
pub mod signature;
pub mod simulate;
pub mod transaction;

pub mod errors;
pub mod events;
pub use schema_builder::SchemaBuilder;
#[cfg(test)]
mod test;
