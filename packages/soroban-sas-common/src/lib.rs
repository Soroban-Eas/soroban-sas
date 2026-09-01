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

use soroban_sdk::{contracttype, Address, Bytes, Env, String};
use soroban_sdk::{contracttype, Address, Bytes, BytesN, String};

/// Approximate number of ledgers in one year at five seconds per ledger.
pub const LEDGERS_IN_ONE_YEAR: u32 = 6_307_200;

/// TTL threshold, in ledgers, below which instance storage should be
/// renewed. Instance storage holds a contract's core configuration (e.g.
/// SAS's admin, schema registry, and indexer bindings): unlike persistent
/// entries, if it is allowed to expire the entire contract becomes
/// unusable, since even reading the configuration needed to renew it is no
/// longer possible. Chosen well above `INSTANCE_EXTEND_TO_LEDGERS` so
/// ordinary read/write traffic renews it long before expiry risk, without
/// requiring a bump on every single call.
pub const INSTANCE_TTL_THRESHOLD_LEDGERS: u32 = 500_000;

/// Number of ledgers instance storage is extended to whenever it is
/// renewed, once remaining TTL falls below
/// `INSTANCE_TTL_THRESHOLD_LEDGERS`. Set to one year, matching the
/// persistent-storage retention window (`LEDGERS_IN_ONE_YEAR`) used
/// elsewhere, so configuration and the data it governs expire on
/// comparable horizons.
pub const INSTANCE_EXTEND_TO_LEDGERS: u32 = LEDGERS_IN_ONE_YEAR;

/// Renews the calling contract's instance storage TTL using the shared
/// `INSTANCE_TTL_THRESHOLD_LEDGERS`/`INSTANCE_EXTEND_TO_LEDGERS` policy.
///
/// Call this from `init` (so configuration starts with a full TTL) and
/// from admin and commonly used public entry points (so ordinary traffic
/// keeps the TTL renewed without any single call being responsible for
/// it). Cheap to call on every invocation: `extend_ttl` is a no-op unless
/// the entry's remaining TTL has actually fallen below the threshold.
pub fn extend_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD_LEDGERS, INSTANCE_EXTEND_TO_LEDGERS);
}
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

/// A delegated-verification key registered for an attester via
/// `SAS::register_attester_key`/`rotate_attester_key`/`revoke_attester_key`.
///
/// `version` starts at `1` on first registration and increases by one on
/// every rotation or post-revocation re-registration, so consumers can
/// order key changes for the same attester. A `revoked` record is kept
/// (not deleted) so a stale signature made under it fails closed rather
/// than falling through to "no record found".
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttesterKeyRecord {
    pub public_key: BytesN<32>,
    pub version: u32,
    pub revoked: bool,
}

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
