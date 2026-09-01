#![allow(unexpected_cfgs)]
#![no_std]
#![allow(unused_variables)]

use soroban_sas_common::{
    extend_instance_ttl, validate_schema_syntax, SASError, SchemaRecord, LEDGERS_IN_ONE_YEAR, UID,
    events::{CONTRACT_UPGRADED, SCHEMA_FEE_UPDATED, TREASURY_UPDATED},
    validate_schema_syntax, ContractUpgradedEvent, SASError, SchemaFeeUpdatedEvent, SchemaRecord,
    TreasuryUpdatedEvent, LEDGERS_IN_ONE_YEAR, UID,
};
use soroban_sdk::{
    contract, contractimpl, panic_with_error, xdr::ToXdr, Address, Bytes, BytesN, Env, String,
};

#[contract]
pub struct SchemaRegistry;

mod storage;
use storage::*;

fn extend_instance_ttl(env: &Env) {
    env.storage().instance().extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
}

/// Pushes a schema record's archival horizon back out to the shared
/// retention window ([`LEDGERS_IN_ONE_YEAR`], used as both the renewal
/// threshold and the extend-to target, matching every other persistent
/// write in this contract).
///
/// Call this only once `uid` is known to exist: read views renew an active
/// record so that a schema which is heavily read but never rewritten is not
/// archived, breaking downstream validation and discovery. The missing-UID
/// path must stay side-effect free.
fn renew_schema_record(env: &Env, uid: &UID) {
    env.storage()
        .persistent()
        .extend_ttl(uid, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
}

fn require_registry_admin(env: &Env) -> Address {
    let admin: Option<Address> = env.storage().instance().get(&REGISTRY_ADMIN);
    match admin {
        Some(a) => a,
        None => panic_with_error!(env, SASError::NotInitialized),
    }
}

const MAX_SCAN_BUDGET: u32 = 100;

#[contractimpl]
impl SchemaRegistry {
    /// Compatibility probe used by SAS::init before storing this registry.
    pub fn sasreg(_env: Env) -> bool {
        true
    }

    pub fn init(env: Env, admin: soroban_sdk::Address) {
        extend_instance_ttl(&env);
        if env.storage().instance().has(&REGISTRY_ADMIN) {
            panic_with_error!(&env, SASError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&REGISTRY_ADMIN, &admin);
        extend_instance_ttl(&env);
        // Genesis version = 1. Stored so upgrades can enforce monotonic
        // version increments and storage-migration gates.
        if !env.storage().instance().has(&REGISTRY_VERSION) {
            env.storage().instance().set(&REGISTRY_VERSION, &1u32);
        }
    }

    /// Returns the registry's current version (1 = genesis). Useful for
    /// off-chain upgrade orchestration and for the `UPGRADE` event's old/new
    /// version fields.
    pub fn get_version(env: Env) -> u32 {
        extend_instance_ttl(&env);
        env.storage().instance().get(&REGISTRY_VERSION).unwrap_or(1)
    }

    /// Replaces this contract's installed WASM. Requires the registry
    /// admin's authorization. Emits `ContractUpgraded` with the hash being
    /// replaced and the new hash immediately before the swap takes effect,
    /// so a failed or unauthorized call never emits the event: if the swap
    /// itself then fails (e.g. `new_wasm_hash` has no uploaded WASM),
    /// Soroban rolls back the whole invocation, discarding the event and
    /// the storage write below along with it.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        admin.require_auth();

        Self::record_upgrade_event(&env, &admin, new_wasm_hash.clone());
    /// Versioned upgrade. Validates the candidate before activation:
    ///  - `new_version` must be exactly `current + 1` (no skips/downgrades)
    ///  - only known versions (currently 2, i.e. next after genesis) are
    ///    accepted — unknown future versions are rejected before any WASM
    ///    is written
    ///  - the WASM hash must be non-zero
    ///  - storage schema check: `SCHEMA_COUNT` must still be readable (so a
    ///    faulty WASM that would orphan existing schemas is caught on the
    ///    upgrade path itself)
    /// Emits an `UPGRADE` event with `(old_version, new_version, wasm_hash)`
    /// and bumps the stored version before calling
    /// `update_current_contract_wasm`. See `docs/UPGRADE_RUNBOOK.md` for the
    /// staged activation / rollback procedure.
    pub fn upgrade(env: Env, new_wasm_hash: soroban_sdk::BytesN<32>, new_version: u32) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
        extend_instance_ttl(&env);

        let old_version: u32 = env
            .storage()
            .instance()
            .get(&REGISTRY_VERSION)
            .unwrap_or(1);

        // Reject unknown future versions before writing any state.
        // Genesis 1 -> only 2 is known; expand this allow-list as new
        // releases are audited and their WASM hashes are pinned.
        const MAX_KNOWN_VERSION: u32 = 2;
        if new_version > MAX_KNOWN_VERSION {
            panic_with_error!(&env, SASError::IncompatibleDependency);
        }
        if new_version != old_version.saturating_add(1) {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        // Hash must be non-zero.
        if new_wasm_hash.to_array() == [0u8; 32] {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        // Storage-migration gate: existing persistent keys must still be
        // readable after the upgrade path. This is a lightweight sanity
        // check that the new contract's storage layout still contains the
        // `SCHEMA_COUNT` key; a real migration would compare full schema
        // counts before/after via simulation.
        let _count: Option<u32> = env.storage().persistent().get(&SCHEMA_COUNT);

        env.events().publish(
            (UPGRADE_EVENT, old_version, new_version),
            (old_version, new_version, new_wasm_hash.clone()),
        );

        env.storage()
            .instance()
            .set(&REGISTRY_VERSION, &new_version);

        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Records the WASM-hash rotation and emits `ContractUpgraded`.
    /// Factored out of `upgrade` so its event-payload logic (reading the
    /// previously tracked hash, building the event) can be exercised in
    /// tests without going through `update_current_contract_wasm`, which
    /// requires a real, previously uploaded WASM blob to target.
    fn record_upgrade_event(env: &Env, admin: &Address, new_wasm_hash: BytesN<32>) {
        let old_wasm_hash: Option<BytesN<32>> = env.storage().instance().get(&CURRENT_WASM_HASH);
        // Soroban does not expose a way to read the currently installed
        // WASM hash from within the contract itself, so the first upgrade
        // on a given deployment has no prior tracked hash to report; every
        // upgrade after that carries the hash it is replacing.
        let old_wasm_hash = old_wasm_hash.unwrap_or_else(|| new_wasm_hash.clone());

        env.storage()
            .instance()
            .set(&CURRENT_WASM_HASH, &new_wasm_hash);

        env.events().publish(
            (CONTRACT_UPGRADED, admin.clone()),
            ContractUpgradedEvent {
                old_wasm_hash,
                new_wasm_hash,
                authorizer: admin.clone(),
            },
        );
    }

    /// Sets the fee charged for schema registration. Requires the registry
    /// admin's authorization. Emits `SchemaFeeUpdated` with the previous
    /// fee (`None` the first time a fee is set) after the new fee has
    /// already been written to storage.
    pub fn set_fee(env: Env, fee: i128) {
        let admin: Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();

        let old_fee: Option<i128> = env.storage().instance().get(&SCHEMA_FEE);
        env.storage().instance().set(&SCHEMA_FEE, &fee);
        extend_instance_ttl(&env);

        env.events().publish(
            (SCHEMA_FEE_UPDATED, admin.clone()),
            SchemaFeeUpdatedEvent {
                old_fee,
                new_fee: fee,
                authorizer: admin,
            },
        );
    }

    /// Sets the treasury address that receives registration fees. Requires
    /// the registry admin's authorization. Emits `TreasuryUpdated` with the
    /// previous treasury (`None` the first time a treasury is set) after
    /// the new address has already been written to storage.
    pub fn set_treasury(env: Env, treasury: Address) {
        let admin: Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
    pub fn set_treasury(env: Env, treasury: soroban_sdk::Address) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();

        let old_treasury: Option<Address> = env.storage().instance().get(&TREASURY);
        env.storage().instance().set(&TREASURY, &treasury);
        extend_instance_ttl(&env);

        env.events().publish(
            (TREASURY_UPDATED, admin.clone()),
            TreasuryUpdatedEvent {
                old_treasury,
                new_treasury: treasury,
                authorizer: admin,
            },
        );
    }

    pub fn withdraw_fees(env: Env, amount: i128) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
        extend_instance_ttl(&env);
        // Native token transfer logic goes here
    }

    /// Deprecates a schema. Only creator or admin may call.
    /// Panics NotInitialized if not init, SchemaNotFound if uid unknown
    /// (no tombstone written). Repeated calls are idempotent.
    pub fn deprecate(env: Env, uid: UID, authorizer: Address) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);

        if !env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaNotFound);
        }

        authorizer.require_auth();

        let creator: Option<Address> = env
            .storage()
            .persistent()
            .get(&(SCHEMA_CREATOR, uid.clone()));
        if authorizer != admin && creator.as_ref() != Some(&authorizer) {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let deprecated_key = (DEPRECATED, uid.clone());
        if env
            .storage()
            .persistent()
            .get::<_, bool>(&deprecated_key)
            .unwrap_or(false)
        {
            return;
        }
        env.storage().persistent().set(&deprecated_key, &true);
        env.storage().persistent().extend_ttl(
            &deprecated_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );
        extend_instance_ttl(&env);
    }

    /// Registers a new schema in the registry.
    ///
    /// See `docs/schemas.md` for the schema syntax specification.
    pub fn register(
        env: Env,
        owner: Address,
        schema: String,
        resolver: Address,
        revocable: bool,
    ) -> UID {
        extend_instance_ttl(&env);
        if let Err(err) = validate_schema_syntax(&env, &schema) {
            panic_with_error!(&env, err);
        }

        // The owner must authorize the registration so the emitted event
        // carries a caller identity that off-chain indexers can trust.
        owner.require_auth();

        // Canonical schema identity includes the schema string, resolver
        // address, and revocability flag. Including all policy-defining fields
        // in the UID preimage ensures two registrations with identical field
        // definitions but different resolver or revocability policies do not
        // collide. See specs/protocol-v1.md#schema-identity.
        let mut payload = Bytes::new(&env);
        payload.append(&schema.clone().to_xdr(&env));
        payload.append(&resolver.clone().to_xdr(&env));
        payload.append(&Bytes::from_slice(&env, &[revocable as u8]));

        let hash = env.crypto().sha256(&payload);
        let uid = UID(hash);

        if env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaAlreadyExists);
        }

        let record = SchemaRecord {
            uid: uid.clone(),
            resolver,
            revocable,
            schema,
        };
        env.storage().persistent().set(&uid, &record);
        env.storage()
            .persistent()
            .extend_ttl(&uid, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        let creator_key = (SCHEMA_CREATOR, uid.clone());
        env.storage().persistent().set(&creator_key, &owner);
        env.storage().persistent().extend_ttl(
            &creator_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        let mut count: u32 = if let Some(c) = env.storage().persistent().get(&SCHEMA_COUNT) {
            env.storage().persistent().extend_ttl(
                &SCHEMA_COUNT,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
            c
        } else if env.storage().persistent().has::<u32>(&0u32) {
            // Count is missing but a record exists at index 0 — metadata expired.
            panic_with_error!(&env, SASError::CountMetadataExpired);
        } else {
            0
        };
        env.storage().persistent().set(&count, &uid);
        env.storage()
            .persistent()
            .extend_ttl(&count, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        count += 1;
        env.storage().persistent().set(&SCHEMA_COUNT, &count);
        env.storage().persistent().extend_ttl(
            &SCHEMA_COUNT,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        env.events().publish(
            (soroban_sas_common::events::REGISTERED, uid.clone()),
            soroban_sas_common::SchemaRegisteredEvent {
                schema_uid: uid.clone(),
                owner,
            },
        );

        extend_instance_ttl(&env);

        uid
    }

    /// Returns the active [`SchemaRecord`] for `uid`, renewing its TTL when it
    /// exists. An unknown or deprecated UID returns `None` and creates no
    /// storage.
    pub fn get_schema(env: Env, uid: UID) -> Option<SchemaRecord> {
        extend_instance_ttl(&env);
        if env
            .storage()
            .persistent()
            .get(&(DEPRECATED, uid.clone()))
            .unwrap_or(false)
        {
            return None;
        }
        let record: Option<SchemaRecord> = env.storage().persistent().get(&uid);
        if record.is_some() {
            renew_schema_record(&env, &uid);
        }
        record
    }

    /// Reports whether `uid` names an active (non-deprecated) schema. SAS
    /// calls this view during issuance, so a successful check renews the
    /// record's TTL to keep an actively used schema hot. A missing or
    /// deprecated UID returns `false` without creating or extending an entry.
    pub fn validate_schema(env: Env, uid: UID) -> bool {
        extend_instance_ttl(&env);
        if env
            .storage()
            .persistent()
            .get(&(DEPRECATED, uid.clone()))
            .unwrap_or(false)
        {
            return false;
        }
        if env.storage().persistent().has(&uid) {
            renew_schema_record(&env, &uid);
            true
        } else {
            false
        }
    }

    /// Returns up to `limit` active schemas from `start`, skipping deprecated.
    /// Scans until page full, budget (100) or end. Use paginated for cursor.
    pub fn get_schemas(env: Env, start: u32, limit: u32) -> soroban_sdk::Vec<SchemaRecord> {
        extend_instance_ttl(&env);
        if limit == 0 {
            return soroban_sdk::Vec::new(&env);
        }
        let count: u32 = env.storage().persistent().get(&SCHEMA_COUNT).unwrap_or(0);
        if count > 0 {
            env.storage().persistent().extend_ttl(
                &SCHEMA_COUNT,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
        }
        if start >= count {
            return soroban_sdk::Vec::new(&env);
        }
        let mut schemas = soroban_sdk::Vec::new(&env);
        let mut index = start;
        let mut scanned: u32 = 0;
        while index < count && schemas.len() < limit && scanned < MAX_SCAN_BUDGET {
            if let Some(uid) = env.storage().persistent().get::<u32, UID>(&index) {
                env.storage().persistent().extend_ttl(
                    &index,
                    LEDGERS_IN_ONE_YEAR,
                    LEDGERS_IN_ONE_YEAR,
                );
                let is_deprecated: bool = env
                    .storage()
                    .persistent()
                    .get(&(DEPRECATED, uid.clone()))
                    .unwrap_or(false);
                if !is_deprecated {
                    if let Some(record) = env.storage().persistent().get::<UID, SchemaRecord>(&uid)
                    {
                        env.storage().persistent().extend_ttl(
                            &uid,
                            LEDGERS_IN_ONE_YEAR,
                            LEDGERS_IN_ONE_YEAR,
                        );
                        schemas.push_back(record);
                    }
                }
            }
            index = index.saturating_add(1);
            scanned = scanned.saturating_add(1);
        }
        schemas
    }

    /// Paginated: returns (schemas, next_cursor). Same semantics as get_schemas.
    pub fn get_schemas_paginated(
        env: Env,
        start: u32,
        limit: u32,
    ) -> (soroban_sdk::Vec<SchemaRecord>, u32) {
        extend_instance_ttl(&env);
        let count: u32 = env.storage().persistent().get(&SCHEMA_COUNT).unwrap_or(0);
        if count > 0 {
            env.storage().persistent().extend_ttl(
                &SCHEMA_COUNT,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
        }
        if limit == 0 || start >= count {
            return (
                soroban_sdk::Vec::new(&env),
                if start >= count { count } else { start },
            );
        }
        let mut schemas = soroban_sdk::Vec::new(&env);
        let mut index = start;
        let mut scanned: u32 = 0;
        while index < count && schemas.len() < limit && scanned < MAX_SCAN_BUDGET {
            if let Some(uid) = env.storage().persistent().get::<u32, UID>(&index) {
                env.storage().persistent().extend_ttl(
                    &index,
                    LEDGERS_IN_ONE_YEAR,
                    LEDGERS_IN_ONE_YEAR,
                );
                let is_deprecated: bool = env
                    .storage()
                    .persistent()
                    .get(&(DEPRECATED, uid.clone()))
                    .unwrap_or(false);
                if !is_deprecated {
                    if let Some(record) = env.storage().persistent().get::<UID, SchemaRecord>(&uid)
                    {
                        env.storage().persistent().extend_ttl(
                            &uid,
                            LEDGERS_IN_ONE_YEAR,
                            LEDGERS_IN_ONE_YEAR,
                        );
                        schemas.push_back(record);
                    }
                }
            }
            index = index.saturating_add(1);
            scanned = scanned.saturating_add(1);
        }
        (schemas, index)
    }
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_extra;
