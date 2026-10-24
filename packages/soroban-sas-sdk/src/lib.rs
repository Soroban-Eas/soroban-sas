#![allow(clippy::new_without_default)]
#![allow(unexpected_cfgs)]
//! Soroban SAS SDK
//!
//! This library provides strong types, builder patterns, and RPC integration
//! for interacting with the Soroban Attestation Service (SAS).

extern crate self as soroban_sas_sdk;

pub mod account;
pub mod attestation_builder;
pub mod auth;
pub mod batch;
pub mod client;
pub mod delegation;
pub mod limits;
pub mod retry;
pub mod rpc;
pub mod schema_builder;
pub mod sequence;
pub mod signature;
pub mod simulate;
pub mod stream;
pub mod strkey;
pub mod transaction;
pub mod transaction_signer;
pub mod transaction_submitter;
pub use retry::{ExponentialBackoff, RetryPolicy, RpcErrorKind};
pub use transaction_submitter::{
    FeeBumpSigner, FeeBumpStrategy, FeeBumpTransactionEnvelope, PendingTransaction, SubmitError,
    SubmitResponse, TransactionStatus, TransactionSubmitter,
};

pub mod chaos;
pub mod errors;
pub mod events;
pub mod schema_macro;
pub use attestation_builder::AttestationRequestBuilder;
pub use auth::AuthEntryBuilder;
pub use rpc::{RateLimitPolicy, RpcBackend};
pub use schema_builder::SchemaBuilder;
pub use schema_macro::SchemaType;
pub use simulate::{
    build_invoke_transaction, build_simulate_transaction_xdr, decode_result, encode_arg,
    sign_transaction, unsigned_envelope_xdr, validate_simulated_transaction,
};
pub use soroban_sas_schema_macro::derive_schema;
pub use stream::{AttestationEvent, EventFilter, EventStream, EventSubscription, StreamEnvelope};
pub mod mock;
pub use mock::{IndexerClientTrait, MockCall, MockSASClient, SASClientTrait};
#[cfg(test)]
mod test;
