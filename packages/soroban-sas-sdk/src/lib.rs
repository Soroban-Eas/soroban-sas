#![allow(clippy::new_without_default)]
#![allow(unexpected_cfgs)]
//! Soroban SAS SDK
//!
//! This library provides strong types, builder patterns, and RPC integration
//! for interacting with the Soroban Attestation Service (SAS).

extern crate self as soroban_sas_sdk;

pub mod account;
pub mod attestation;
pub mod attestation_builder;
pub mod auth;
pub mod batch;
#[cfg(not(target_arch = "wasm32"))]
pub mod client;
pub mod delegation;
pub mod limits;
#[cfg(not(target_arch = "wasm32"))]
pub mod retry;
pub mod rpc;
pub mod schema_builder;
pub mod sequence;
pub mod signature;
pub mod simulate;
#[cfg(not(target_arch = "wasm32"))]
pub mod stream;
pub mod strkey;
pub mod transaction;
pub mod transaction_signer;
#[cfg(not(target_arch = "wasm32"))]
pub mod transaction_submitter;
#[cfg(not(target_arch = "wasm32"))]
pub use retry::{ExponentialBackoff, RetryPolicy, RpcErrorKind};
#[cfg(not(target_arch = "wasm32"))]
pub use transaction_submitter::{
    FeeBumpSigner, FeeBumpStrategy, FeeBumpTransactionEnvelope, PendingTransaction, SubmitError,
    SubmitResponse, TransactionStatus, TransactionSubmitter,
};

#[cfg(not(target_arch = "wasm32"))]
pub mod chaos;
pub mod errors;
pub mod events;
pub mod schema_macro;
#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
mod wasm_http;
pub use attestation_builder::AttestationRequestBuilder;
pub use auth::AuthEntryBuilder;
pub use rpc::{RateLimitPolicy, RpcBackend};
pub use schema_builder::SchemaBuilder;
pub use schema_macro::SchemaType;
pub use simulate::{
    build_invoke_transaction, build_simulate_transaction_xdr, sign_transaction,
    unsigned_envelope_xdr, validate_simulated_transaction,
};
// The typed `encode_arg`/`decode_result` helpers round-trip values through the
// host `Val` bridge, which only exists on native targets. Edge runtimes get
// the pure-XDR `decode_scval` helper instead (#553).
#[cfg(target_arch = "wasm32")]
pub use simulate::decode_scval;
#[cfg(not(target_arch = "wasm32"))]
pub use simulate::{decode_result, encode_arg};

pub use soroban_sas_schema_macro::derive_schema;
#[cfg(not(target_arch = "wasm32"))]
pub use stream::{AttestationEvent, EventFilter, EventStream, EventSubscription, StreamEnvelope};
#[cfg(not(target_arch = "wasm32"))]
pub mod mock;
#[cfg(not(target_arch = "wasm32"))]
pub use mock::{IndexerClientTrait, MockCall, MockSASClient, SASClientTrait};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod test;
