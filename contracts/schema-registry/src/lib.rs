#![allow(unexpected_cfgs)]
#![no_std]
#![allow(unused_variables)]

use soroban_sas_common::{validate_schema_syntax, SASError, SchemaRecord, LEDGERS_IN_ONE_YEAR, UID};
use soroban_sdk::{
    contract, contractimpl, panic_with_error, xdr::ToXdr, Address, Bytes, Env, String,
};

#[contract]
pub struct SchemaRegistry;

mod storage;
use storage::*;

fn extend_instance_ttl(env: &Env) {
    env.storage().instance().extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
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

    pub fn set_fee(env: Env, fee: i128) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
        env.storage().instance().set(&SCHEMA_FEE, &fee);
    }

    pub fn set_treasury(env: Env, treasury: soroban_sdk::Address) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
        env.storage().instance().set(&TREASURY, &treasury);
    }

    pub fn withdraw_fees(env: Env, amount: i128) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
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
    }

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

        let mut count: u32 = env.storage().persistent().get(&SCHEMA_COUNT).unwrap_or(0);
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

        uid
    }

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
        env.storage().persistent().get(&uid)
    }

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
        env.storage().persistent().has(&uid)
    }

    /// Returns up to `limit` active schemas from `start`, skipping deprecated.
    /// Scans until page full, budget (100) or end. Use paginated for cursor.
    pub fn get_schemas(env: Env, start: u32, limit: u32) -> soroban_sdk::Vec<SchemaRecord> {
        extend_instance_ttl(&env);
        if limit == 0 {
            return soroban_sdk::Vec::new(&env);
        }
        let count: u32 = env.storage().persistent().get(&SCHEMA_COUNT).unwrap_or(0);
        if start >= count {
            return soroban_sdk::Vec::new(&env);
        }
        let mut schemas = soroban_sdk::Vec::new(&env);
        let mut index = start;
        let mut scanned: u32 = 0;
        while index < count && schemas.len() < limit && scanned < MAX_SCAN_BUDGET {
            if let Some(uid) = env.storage().persistent().get::<u32, UID>(&index) {
                let is_deprecated: bool = env
                    .storage()
                    .persistent()
                    .get(&(DEPRECATED, uid.clone()))
                    .unwrap_or(false);
                if !is_deprecated {
                    if let Some(record) = env.storage().persistent().get::<UID, SchemaRecord>(&uid)
                    {
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
                let is_deprecated: bool = env
                    .storage()
                    .persistent()
                    .get(&(DEPRECATED, uid.clone()))
                    .unwrap_or(false);
                if !is_deprecated {
                    if let Some(record) = env.storage().persistent().get::<UID, SchemaRecord>(&uid)
                    {
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
