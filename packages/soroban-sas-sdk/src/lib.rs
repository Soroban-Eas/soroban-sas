#![allow(clippy::new_without_default)]
#![allow(unexpected_cfgs)]
//! Soroban SAS SDK
//!
//! This library provides strong types, builder patterns, and RPC integration
//! for interacting with the Soroban Attestation Service (SAS).

pub mod account;
pub mod attestation_builder;
pub mod batch;
pub mod client;
pub mod delegation;
pub mod limits;
pub mod rpc;
pub mod schema_builder;
pub mod sequence;
pub mod signature;
pub mod simulate;
pub mod strkey;
pub mod transaction;

pub mod chaos;
pub mod errors;
pub mod events;
pub mod schema_macro;
pub use attestation_builder::AttestationRequestBuilder;
pub use rpc::{RateLimitPolicy, RpcBackend};
pub use schema_builder::SchemaBuilder;
pub use schema_macro::SchemaType;
pub use simulate::{
    build_invoke_transaction, build_simulate_transaction_xdr, decode_result, encode_arg,
    sign_transaction, unsigned_envelope_xdr, validate_simulated_transaction,
};
#[cfg(test)]
mod test;
