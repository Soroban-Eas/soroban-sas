use soroban_sdk::{symbol_short, Symbol};

pub const REGISTRY_ADMIN: Symbol = symbol_short!("ADMIN");
pub const SCHEMA_COUNT: Symbol = symbol_short!("COUNT");
pub const SCHEMA_FEE: Symbol = symbol_short!("FEE");
pub const TREASURY: Symbol = symbol_short!("TREASURY");
pub const DEPRECATED: Symbol = symbol_short!("DEPRECATE");
/// Maps a schema UID to the address that registered it. Kept separately from
/// `SchemaRecord` so the record's serialized contract type remains stable.
pub const SCHEMA_CREATOR: Symbol = symbol_short!("CREATOR");
/// The WASM hash currently installed for this contract. Soroban does not
/// expose a way to read a contract's own installed hash from within its
/// own execution, so `commit_upgrade` tracks it here itself, letting
/// `ContractUpgradedEvent` report the hash being replaced. A missing entry
/// means "unknown" (the first upgrade on a legacy/genesis deployment) and is
/// reported as an all-zero hash.
pub const CURRENT_WASM_HASH: Symbol = symbol_short!("WASMHASH");
/// Monotonically increasing registry version. Used to gate upgrades and
/// drive storage-migration checks. v1 is the genesis deployment.
pub const REGISTRY_VERSION: Symbol = symbol_short!("VERSION");
/// First topic of the versioned registry `UPGRADE` event, published with
/// topics `(UPGRADE, old_version, new_version)` and data
/// `(old_version, new_version, wasm_hash)` on every successful upgrade.
/// `commit_upgrade` publishes this alongside the standardized
/// `ContractUpgraded` event (`soroban_sas_common::events::CONTRACT_UPGRADED`),
/// so consumers can follow activations either by version or by WASM hash.
/// For v2 the validation is `new_version == old_version + 1` and the hash
/// must be non-zero; unknown future versions are rejected.
pub const UPGRADE_EVENT: Symbol = symbol_short!("UPGRADE");
/// Storage key for schema delegate allow-lists.
/// Stored under `(AUTHORIZED_DELEGATES, schema_uid, delegate_address) -> bool`.
pub const AUTHORIZED_DELEGATES: Symbol = symbol_short!("DELEGATES");

/// Storage key for a schema's multi-signature owner set (#288).
/// Stored under `(SCHEMA_OWNERS, schema_uid) -> OwnerSet`.
pub const SCHEMA_OWNERS: Symbol = symbol_short!("OWNERS");

/// Storage key for the in-flight multi-signature ownership transfer.
/// Stored under `(PENDING_OWNERSHIP, schema_uid) -> PendingOwnershipTransfer`
/// and removed as soon as the transfer is executed, cancelled, or invalidated
/// by a reconfiguration of the owner set.
pub const PENDING_OWNERSHIP: Symbol = symbol_short!("PENDOWN");

/// First topic of the `(SCHEMA_OWNER_SET_UPDATED, uid)` event published when a
/// schema's multi-signature owner set is configured or replaced. Data is
/// `(authorizer, OwnerSet)`.
pub const SCHEMA_OWNER_SET_UPDATED: Symbol = symbol_short!("OWNSETUP");

/// First topic of the `(SCHEMA_OWNER_PROPOSED, uid)` event published when a
/// multi-signature ownership transfer collects its first approval. Data is
/// `(proposer, PendingOwnershipTransfer)`.
pub const SCHEMA_OWNER_PROPOSED: Symbol = symbol_short!("OWNPROP");

/// First topic of the `(SCHEMA_OWNER_APPROVED, uid)` event published for every
/// additional approval collected on an in-flight transfer. Data is
/// `(approver, approval_count)`.
pub const SCHEMA_OWNER_APPROVED: Symbol = symbol_short!("OWNAPPR");

/// First topic of the `(SCHEMA_OWNER_TRANSFER_CANCELLED, uid)` event published
/// when an in-flight multi-signature ownership transfer is abandoned. Data is
/// the cancelling owner.
pub const SCHEMA_OWNER_TRANSFER_CANCELLED: Symbol = symbol_short!("OWNCANC");

/// Hard ceiling on the size of a single multi-signature owner set. Bounds the
/// cost of every approval scan so a hostile configuration cannot make owner
/// checks unbounded.
pub const MAX_OWNER_SET: u32 = 10;
