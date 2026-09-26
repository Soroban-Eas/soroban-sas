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
