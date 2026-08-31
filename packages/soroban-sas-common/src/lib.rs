#![allow(unexpected_cfgs)]
#![no_std]
pub mod errors;
pub mod events;
pub mod macros;
pub mod merkle;
pub mod signature;
pub mod typed_data;
pub mod validation;

pub use errors::*;
pub use events::*;
pub use merkle::*;
pub use signature::*;
pub use typed_data::*;
pub use validation::*;

use soroban_sdk::{contracttype, Address, Bytes, String};

/// Approximate number of ledgers in one year at five seconds per ledger.
pub const LEDGERS_IN_ONE_YEAR: u32 = 6_307_200;

/// Maximum byte length of `Attestation.data` accepted on-chain.
///
/// Large payloads increase hashing, XDR encoding, event emission, storage,
/// and cross-contract invocation costs. A bounded ceiling keeps these within
/// the measured Soroban budget envelope and prevents unpredictable budget
/// exhaustion or ledger-entry size violations. The value is chosen to be
/// well within Soroban limits while accommodating typical attestation
/// payloads. (#157)
pub const MAX_ATTESTATION_DATA_BYTES: u32 = 10_000;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UID(pub soroban_sdk::BytesN<32>);

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaRecord {
    pub uid: UID,
    pub resolver: Address,
    pub revocable: bool,
    pub schema: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)] // Optimize storage serialization
pub struct Attestation {
    pub uid: UID,
    pub schema_uid: UID,
    pub time: u64,
    pub expiration_time: u64,
    pub revocation_time: u64,
    pub ref_uid: UID,
    pub recipient: Address,
    pub attester: Address,
    pub revocable: bool,
    pub data: Bytes,
}

#[cfg(test)]
mod test;
