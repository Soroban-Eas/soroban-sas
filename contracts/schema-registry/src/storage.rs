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
/// own execution, so `upgrade` tracks it here itself, purely so
/// `ContractUpgradedEvent` can report the hash being replaced.
pub const CURRENT_WASM_HASH: Symbol = symbol_short!("WASMHASH");
/// Monotonically increasing registry version. Used to gate upgrades and
/// drive storage-migration checks. v1 is the genesis deployment.
pub const REGISTRY_VERSION: Symbol = symbol_short!("VERSION");
/// Persisted allow-list gate for tested WASM hashes could be added here.
/// For v2 the validation is `new_version == old_version + 1` and the hash
/// must be non-zero and not the current WASM's hash; unknown future
/// versions are rejected.
pub const UPGRADE_EVENT: Symbol = symbol_short!("UPGRADE");
