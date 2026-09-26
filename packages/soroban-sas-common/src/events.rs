//! Standardized event topics and payloads emitted by the SAS contracts.
//!
//! Off-chain indexing services (e.g. The Graph, Soroban Zephyr) subscribe to
//! these topics to build fast, queryable materialized views of the
//! attestation graph without reading contract storage.

use crate::UID;
use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Symbol};

/// First topic of every `AttestationIssued` event.
pub const ATTESTED: Symbol = symbol_short!("ATTESTED");
/// First topic of every `AttestationRevoked` event.
pub const REVOKED: Symbol = symbol_short!("REVOKED");
/// First topic of every `SchemaRegistered` event.
pub const REGISTERED: Symbol = symbol_short!("REGISTER");
/// First topic of every `AttesterKeyRegistered` event.
pub const ATTESTER_KEY_REGISTERED: Symbol = symbol_short!("ATTKREG");
/// First topic of every `AttesterKeyRotated` event.
pub const ATTESTER_KEY_ROTATED: Symbol = symbol_short!("ATTKROT");
/// First topic of every `AttesterKeyRevoked` event.
pub const ATTESTER_KEY_REVOKED: Symbol = symbol_short!("ATTKREV");
/// First topic of every `IndexerUpdated` event.
pub const INDEXER_UPDATED: Symbol = symbol_short!("IDXUPD");
/// First topic of every `SchemaFeeUpdated` event.
pub const SCHEMA_FEE_UPDATED: Symbol = symbol_short!("FEEUPD");
/// First topic of every `TreasuryUpdated` event.
pub const TREASURY_UPDATED: Symbol = symbol_short!("TRSUPD");
/// First topic of every `ContractUpgraded` event.
pub const CONTRACT_UPGRADED: Symbol = symbol_short!("UPGRADED");
/// First topic of every `SchemaDelegateAdded` event.
pub const SCHEMA_DELEGATE_ADDED: Symbol = symbol_short!("DELADD");
/// First topic of every `SchemaDelegateRemoved` event.
pub const SCHEMA_DELEGATE_REMOVED: Symbol = symbol_short!("DELREM");
/// First topic of every `AdminTransferProposed` event.
pub const ADMIN_TRANSFER_PROPOSED: Symbol = symbol_short!("ADMPROP");
/// First topic of every `AdminTransferCompleted` event.
pub const ADMIN_TRANSFER_COMPLETED: Symbol = symbol_short!("ADMCOMP");
/// First topic of every `SchemaOwnershipTransferred` event.
pub const SCHEMA_OWNERSHIP_TRANSFERRED: Symbol = symbol_short!("SCHOWN");
/// First topic of every `BatchAttested` event.
pub const BATCH_ATTESTED: Symbol = symbol_short!("BATCHATT");
/// First topic of every `BatchRevoked` event.
pub const BATCH_REVOKED: Symbol = symbol_short!("BATCHREV");
/// First topic of every `SchemaDeprecated` event.
pub const SCHEMA_DEPRECATED: Symbol = symbol_short!("SCHDEP");

/// Payload of the `SchemaRegistered` event.
///
/// Published with topics `(REGISTERED, schema_uid)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaRegisteredEvent {
    pub schema_uid: UID,
    pub owner: Address,
}

/// Payload of the `AttestationIssued` event.
///
/// Published with topics `(ATTESTED, schema_uid, attester)` so indexers can
/// filter by schema or attester without decoding the payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationIssuedEvent {
    pub uid: UID,
    pub schema_uid: UID,
    pub attester: Address,
    pub recipient: Address,
}

/// Payload of the `AttestationRevoked` event.
///
/// Published with topics `(REVOKED, uid)`. `timestamp` is the ledger
/// timestamp recorded as the attestation's revocation time.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationRevokedEvent {
    pub uid: UID,
    pub timestamp: u64,
}

/// Payload of the `AttesterKeyRegistered` event.
///
/// Published with topics `(ATTESTER_KEY_REGISTERED, attester)` the first
/// time a delegated-verification key is registered for `attester`, and
/// again if a key is re-registered after a prior one was revoked.
/// `version` starts at `1` and increases by one on every subsequent
/// registration or rotation for the same attester, so off-chain consumers
/// can order key changes without relying on ledger sequence alone.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttesterKeyRegisteredEvent {
    pub attester: Address,
    pub public_key: BytesN<32>,
    pub version: u32,
}

/// Payload of the `AttesterKeyRotated` event.
///
/// Published with topics `(ATTESTER_KEY_ROTATED, attester)` when an
/// already-registered, non-revoked key is replaced with a new one.
/// `old_public_key` and `new_public_key` let an off-chain monitor
/// reconstruct the full key history; `new_version` is the incremented
/// version now in effect.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttesterKeyRotatedEvent {
    pub attester: Address,
    pub old_public_key: BytesN<32>,
    pub new_public_key: BytesN<32>,
    pub new_version: u32,
}

/// Payload of the `AttesterKeyRevoked` event.
///
/// Published with topics `(ATTESTER_KEY_REVOKED, attester)`. Once revoked,
/// `public_key` no longer validates any delegated operation for
/// `attester`, even though the record is retained (rather than deleted)
/// so `version` continues to increase on any future re-registration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttesterKeyRevokedEvent {
    pub attester: Address,
    pub public_key: BytesN<32>,
    pub version: u32,
}
/// `Option<Address>`-equivalent for contract event payloads.
///
/// `#[contracttype]`'s generated `Option<T>` conversion requires a
/// host-independent `From<T> for ScVal`, which `Address` does not provide
/// (unlike primitives such as `i128`) — at this pinned SDK version that
/// surfaces as a compile error specifically under the `testutils` cfg
/// (`cargo test`, `cargo clippy --all-targets`). A plain enum sidesteps it:
/// enum-with-data conversions go through a different, unaffected codegen
/// path.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreviousAddress {
    None,
    Some(Address),
}

impl From<Option<Address>> for PreviousAddress {
    fn from(value: Option<Address>) -> Self {
        match value {
            Some(address) => PreviousAddress::Some(address),
            None => PreviousAddress::None,
        }
    }
}

/// Payload of the `IndexerUpdated` event.
///
/// Published with topics `(INDEXER_UPDATED, authorizer)` on a successful
/// `SAS::set_indexer`. `old_indexer` is `PreviousAddress::None` the first
/// time an indexer is bound. `authorizer` is the address that authorized the
/// change (SAS's admin), included directly in the payload — not just implied
/// by `require_auth` — so an off-chain monitor can attribute the change
/// without cross-referencing a separate admin-lookup call.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexerUpdatedEvent {
    pub old_indexer: PreviousAddress,
    pub new_indexer: Address,
    pub authorizer: Address,
}

/// Payload of the `SchemaFeeUpdated` event.
///
/// Published with topics `(SCHEMA_FEE_UPDATED, authorizer)` on a
/// successful `SchemaRegistry::set_fee`. `old_fee_token`/`old_fee_amount`
/// are `PreviousAddress::None`/`None` the first time a fee is set. The
/// token and amount are split into separate fields (rather than an
/// `Option<(Address, i128)>` pair) because `Option<Address>` fails to
/// compile under `testutils` — see [`PreviousAddress`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaFeeUpdatedEvent {
    pub old_fee_token: PreviousAddress,
    pub old_fee_amount: Option<i128>,
    pub new_fee_token: Address,
    pub new_fee_amount: i128,
    pub authorizer: Address,
}

/// Payload of the `TreasuryUpdated` event.
///
/// Published with topics `(TREASURY_UPDATED, authorizer)` on a successful
/// `SchemaRegistry::set_treasury`. `old_treasury` is `PreviousAddress::None`
/// the first time a treasury address is set.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreasuryUpdatedEvent {
    pub old_treasury: PreviousAddress,
    pub new_treasury: Address,
    pub authorizer: Address,
}

/// Payload of the `ContractUpgraded` event.
///
/// Published with topics `(CONTRACT_UPGRADED, authorizer)` on a successful
/// contract upgrade immediately before the WASM swap is requested. Soroban
/// does not let a running contract read its installed WASM hash. Producers
/// therefore document how the first upgrade represents an unavailable legacy
/// hash and track successful target hashes for subsequent events.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractUpgradedEvent {
    pub old_wasm_hash: BytesN<32>,
    pub new_wasm_hash: BytesN<32>,
    pub authorizer: Address,
}

/// Payload of the `SchemaDelegateAdded` event.
///
/// Published with topics `(SCHEMA_DELEGATE_ADDED, schema_uid)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaDelegateAddedEvent {
    pub schema_uid: UID,
    pub delegate: Address,
    pub authorizer: Address,
}

/// Payload of the `SchemaDelegateRemoved` event.
///
/// Published with topics `(SCHEMA_DELEGATE_REMOVED, schema_uid)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaDelegateRemovedEvent {
    pub schema_uid: UID,
    pub delegate: Address,
    pub authorizer: Address,
}

/// Payload of the `AdminTransferProposed` event.
///
/// Published with topics `(ADMIN_TRANSFER_PROPOSED, current_admin)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferProposedEvent {
    pub current_admin: Address,
    pub proposed_admin: Address,
}
pub type AdminTransferProposed = AdminTransferProposedEvent;

/// Payload of the `AdminTransferCompleted` event.
///
/// Published with topics `(ADMIN_TRANSFER_COMPLETED, old_admin)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferCompletedEvent {
    pub old_admin: Address,
    pub new_admin: Address,
}
pub type AdminTransferCompleted = AdminTransferCompletedEvent;

/// Payload of the `SchemaOwnershipTransferred` event.
///
/// Published with topics `(SCHEMA_OWNERSHIP_TRANSFERRED, schema_uid)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaOwnershipTransferredEvent {
    pub schema_uid: UID,
    pub old_owner: Address,
    pub new_owner: Address,
}
pub type SchemaOwnershipTransferred = SchemaOwnershipTransferredEvent;

/// Payload of the `BatchAttested` event.
///
/// Published with topics `(BATCH_ATTESTED,)` as the **last** event of a
/// successful `SAS::multi_attest` call — after every per-item
/// `AttestationIssued` event, so consumers see the batch's members before
/// its summary. Not emitted at all if the batch call reverts (#213): a
/// summary always describes a batch that was fully committed, never a
/// partial one.
///
/// `count` is the number of attestations issued by the call;
/// `attester_count` is the number of *distinct* attester addresses among
/// them (an attester issuing three attestations in one batch counts once).
/// This distinguishes one batch call from several independent calls when an
/// indexer restarts from an earlier ledger, and avoids the need to
/// heuristically group sequential per-item events by schema/attester to
/// answer "how many attestations did this transaction issue".
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchAttestedEvent {
    pub count: u32,
    pub attester_count: u32,
}

/// Payload of the `SchemaDeprecated` event.
///
/// Published with topics `(SCHEMA_DEPRECATED, schema_uid)` when
/// `SchemaRegistry::deprecate` transitions a schema from active to
/// deprecated. Not republished on an idempotent repeat call, so consumers
/// can treat this event as the single, authoritative deprecation moment.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaDeprecatedEvent {
    pub schema_uid: UID,
    pub deprecated_by: Address,
}

/// Payload of the `BatchRevoked` event.
///
/// Published with topics `(BATCH_REVOKED,)` as the **last** event of a
/// successful `SAS::multi_revoke` call, after every per-item
/// `AttestationRevoked` event — the revocation counterpart to
/// `BatchAttestedEvent`; see its doc comment for the field semantics and
/// ordering/failure guarantees, which are identical here.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRevokedEvent {
    pub count: u32,
    pub attester_count: u32,
}

/// First topic of a SAS `FeeConfigUpdated` event.
pub const FEECFG_UPDATED: Symbol = symbol_short!("FEECFGUPD");

/// Fee policy after an authorized `set_fee` or `clear_fee` storage write.
/// Published with topics `(FEECFG_UPDATED, authorizer)`.
/// Optional addresses use the SDK 20-compatible encoding described by
/// [`PreviousAddress`]; amounts use native `Option<i128>`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeeConfigUpdatedEvent {
    pub old_token: PreviousAddress,
    pub old_amount: Option<i128>,
    pub new_token: PreviousAddress,
    pub new_amount: Option<i128>,
    pub authorizer: Address,
}
