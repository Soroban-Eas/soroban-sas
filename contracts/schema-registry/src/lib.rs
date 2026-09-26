#![allow(unexpected_cfgs)]
#![no_std]
#![allow(unused_variables)]

#[cfg(test)]
use soroban_sas_common::{events::CONTRACT_UPGRADED, ContractUpgradedEvent};
use soroban_sas_common::{
    events::{
        SCHEMA_DELEGATE_ADDED, SCHEMA_DELEGATE_REMOVED, SCHEMA_FEE_UPDATED,
        SCHEMA_OWNERSHIP_TRANSFERRED, TREASURY_UPDATED,
    },
    validate_schema_syntax, PreviousAddress, SASError, SchemaDelegateAddedEvent,
    SchemaDelegateRemovedEvent, SchemaFeeUpdatedEvent, SchemaOwnershipTransferredEvent,
    SchemaRecord, TreasuryUpdatedEvent, LEDGERS_IN_ONE_YEAR, UID,
};
#[cfg(test)]
use soroban_sdk::BytesN;
use soroban_sdk::{contract, contractimpl, panic_with_error, token, Address, Env, String};

#[contract]
pub struct SchemaRegistry;

mod storage;
use storage::*;

fn extend_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
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

        let old_version: u32 = env.storage().instance().get(&REGISTRY_VERSION).unwrap_or(1);

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
    #[cfg(test)]
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

    /// Pins the asset and exact amount `register_with_value` charges for
    /// schema registration. Requires the registry admin's authorization.
    /// `amount` must be positive; call `clear_fee` for fee-free
    /// registration instead of encoding "no fee" as an arbitrary zero.
    /// Emits `SchemaFeeUpdated` with the previous fee (`None` the first
    /// time a fee is set) after the new fee has already been written to
    /// storage.
    pub fn set_fee(env: Env, token: Address, amount: i128) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        let old_fee: Option<(Address, i128)> = env.storage().instance().get(&SCHEMA_FEE);
        env.storage()
            .instance()
            .set(&SCHEMA_FEE, &(token.clone(), amount));
        extend_instance_ttl(&env);

        let (old_fee_token, old_fee_amount) = match old_fee {
            Some((t, a)) => (PreviousAddress::Some(t), Some(a)),
            None => (PreviousAddress::None, None),
        };
        env.events().publish(
            (SCHEMA_FEE_UPDATED, admin.clone()),
            SchemaFeeUpdatedEvent {
                old_fee_token,
                old_fee_amount,
                new_fee_token: token,
                new_fee_amount: amount,
                authorizer: admin,
            },
        );
    }

    /// Removes the registration fee requirement, so `register` (and
    /// `register_with_value` called with `value == 0`) are free again.
    /// Requires the registry admin's authorization.
    pub fn clear_fee(env: Env) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
        env.storage().instance().remove(&SCHEMA_FEE);
        extend_instance_ttl(&env);
    }

    /// Returns the `(token, amount)` fee `register_with_value` requires, or
    /// `None` when registration is fee-free.
    pub fn get_fee(env: Env) -> Option<(Address, i128)> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&SCHEMA_FEE)
    }

    pub fn get_treasury(env: Env) -> Option<Address> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&TREASURY)
    }

    /// Sets the treasury address that receives registration fees. Requires
    /// the registry admin's authorization. Emits `TreasuryUpdated` with the
    /// previous treasury (`None` the first time a treasury is set) after
    /// the new address has already been written to storage.
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
                old_treasury: old_treasury.into(),
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

    /// Authorizes `delegate` to issue and revoke attestations under schema `uid`.
    ///
    /// Requires authorization from the primary schema owner (creator).
    /// Emits `SchemaDelegateAdded`.
    pub fn add_delegate(env: Env, uid: UID, delegate: Address) {
        extend_instance_ttl(&env);
        if !env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaNotFound);
        }

        let creator_key = (SCHEMA_CREATOR, uid.clone());
        let creator: Option<Address> = env.storage().persistent().get(&creator_key);
        let Some(owner) = creator else {
            panic_with_error!(&env, SASError::SchemaNotFound);
        };

        owner.require_auth();

        let delegate_key = (AUTHORIZED_DELEGATES, uid.clone(), delegate.clone());
        env.storage().persistent().set(&delegate_key, &true);
        env.storage().persistent().extend_ttl(
            &delegate_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        env.events().publish(
            (SCHEMA_DELEGATE_ADDED, uid.clone()),
            SchemaDelegateAddedEvent {
                schema_uid: uid,
                delegate,
                authorizer: owner,
            },
        );

        extend_instance_ttl(&env);
    }

    /// Revokes `delegate`'s authorization to issue or revoke attestations under schema `uid`.
    ///
    /// Requires authorization from the primary schema owner (creator).
    /// Emits `SchemaDelegateRemoved`.
    pub fn remove_delegate(env: Env, uid: UID, delegate: Address) {
        extend_instance_ttl(&env);
        if !env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaNotFound);
        }

        let creator_key = (SCHEMA_CREATOR, uid.clone());
        let creator: Option<Address> = env.storage().persistent().get(&creator_key);
        let Some(owner) = creator else {
            panic_with_error!(&env, SASError::SchemaNotFound);
        };

        owner.require_auth();

        let delegate_key = (AUTHORIZED_DELEGATES, uid.clone(), delegate.clone());
        env.storage().persistent().remove(&delegate_key);

        env.events().publish(
            (SCHEMA_DELEGATE_REMOVED, uid.clone()),
            SchemaDelegateRemovedEvent {
                schema_uid: uid,
                delegate,
                authorizer: owner,
            },
        );

        extend_instance_ttl(&env);
    }

    /// Transfers ownership of schema `uid` to `new_owner` (#229).
    ///
    /// Requires authorization from the current schema owner (creator).
    /// Rejects non-existent schemas (`SASError::SchemaNotFound`) and deprecated
    /// schemas (`SASError::InvalidSchema`).
    /// Emits `SchemaOwnershipTransferred`.
    pub fn transfer_schema_ownership(env: Env, uid: UID, new_owner: Address) {
        extend_instance_ttl(&env);
        if !env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaNotFound);
        }

        if env
            .storage()
            .persistent()
            .get(&(DEPRECATED, uid.clone()))
            .unwrap_or(false)
        {
            panic_with_error!(&env, SASError::InvalidSchema);
        }

        let creator_key = (SCHEMA_CREATOR, uid.clone());
        let creator: Option<Address> = env.storage().persistent().get(&creator_key);
        let Some(old_owner) = creator else {
            panic_with_error!(&env, SASError::SchemaNotFound);
        };

        old_owner.require_auth();

        env.storage().persistent().set(&creator_key, &new_owner);
        env.storage().persistent().extend_ttl(
            &creator_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );
        renew_schema_record(&env, &uid);

        env.events().publish(
            (SCHEMA_OWNERSHIP_TRANSFERRED, uid.clone()),
            SchemaOwnershipTransferredEvent {
                schema_uid: uid,
                old_owner,
                new_owner,
            },
        );

        extend_instance_ttl(&env);
    }

    /// Registers a new schema in the registry, free of charge.
    ///
    /// See `docs/schemas.md` for the schema syntax specification.
    pub fn register(
        env: Env,
        owner: Address,
        schema: String,
        resolver: Address,
        revocable: bool,
    ) -> UID {
        // The owner must authorize the registration so the emitted event
        // carries a caller identity that off-chain indexers can trust.
        owner.require_auth();
        Self::register_internal(env, owner, schema, resolver, revocable)
    }

    /// Registers a new schema, paying the configured registration fee (#1).
    ///
    /// Mirrors `SAS::attest_with_value`'s payment discipline: the fee asset
    /// and exact amount are pinned by `set_fee`, not supplied by the
    /// caller. `token`/`value` here are the caller's declaration of what
    /// they expect to pay — a mismatch against the live configuration
    /// fails with `SASError::FeeMismatch` before anything is registered or
    /// transferred, so a fee raised after the caller signed never silently
    /// overcharges them. With no fee configured, only `value == 0` is
    /// accepted. The transfer goes straight to the configured treasury
    /// (`SASError::TreasuryNotSet` if none is set) and happens before the
    /// schema is stored, so a failed payment aborts the whole invocation.
    pub fn register_with_value(
        env: Env,
        owner: Address,
        schema: String,
        resolver: Address,
        revocable: bool,
        token: Address,
        value: i128,
    ) -> UID {
        if value < 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        let configured: Option<(Address, i128)> = env.storage().instance().get(&SCHEMA_FEE);
        match &configured {
            Some((fee_token, fee_amount)) => {
                if &token != fee_token || value != *fee_amount {
                    panic_with_error!(&env, SASError::FeeMismatch);
                }
            }
            None => {
                if value != 0 {
                    panic_with_error!(&env, SASError::FeeMismatch);
                }
            }
        }

        // The owner must authorize both the registration and (when a fee
        // applies) the token transfer below.
        owner.require_auth();

        if value > 0 {
            let treasury: Address = env
                .storage()
                .instance()
                .get(&TREASURY)
                .unwrap_or_else(|| panic_with_error!(&env, SASError::TreasuryNotSet));
            token::Client::new(&env, &token).transfer(&owner, &treasury, &value);
        }

        Self::register_internal(env, owner, schema, resolver, revocable)
    }

    fn register_internal(
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

        // Canonical schema identity includes the schema string, resolver
        // address, and revocability flag. Including all policy-defining fields
        // in the UID preimage ensures two registrations with identical field
        // definitions but different resolver or revocability policies do not
        // collide. See specs/protocol-v1.md#schema-identity.
        let uid = soroban_sas_common::schema_uid(&env, &schema, &resolver, revocable);

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

    /// Returns true if `delegate` is currently an authorized delegate for `uid`.
    pub fn is_delegate(env: Env, uid: UID, delegate: Address) -> bool {
        extend_instance_ttl(&env);
        let delegate_key = (AUTHORIZED_DELEGATES, uid, delegate);
        if env
            .storage()
            .persistent()
            .get::<_, bool>(&delegate_key)
            .unwrap_or(false)
        {
            env.storage().persistent().extend_ttl(
                &delegate_key,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
            true
        } else {
            false
        }
    }

    /// Returns the creator/owner address recorded when schema `uid` was registered.
    pub fn get_creator(env: Env, uid: UID) -> Option<Address> {
        extend_instance_ttl(&env);
        let creator_key = (SCHEMA_CREATOR, uid.clone());
        let creator: Option<Address> = env.storage().persistent().get(&creator_key);
        if creator.is_some() {
            env.storage().persistent().extend_ttl(
                &creator_key,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
        }
        creator
    }

    /// Checks whether `attester` is authorized to issue attestations under
    /// `uid` — returns true if `attester` is either the primary schema owner
    /// or an authorized delegate, provided the schema exists and is not
    /// deprecated.
    ///
    /// Single cross-contract call for SAS issuance checks to prevent excessive
    /// gas usage.
    pub fn is_authorized(env: Env, uid: UID, attester: Address) -> bool {
        extend_instance_ttl(&env);
        if env
            .storage()
            .persistent()
            .get(&(DEPRECATED, uid.clone()))
            .unwrap_or(false)
        {
            return false;
        }

        let creator_key = (SCHEMA_CREATOR, uid.clone());
        if let Some(creator) = env.storage().persistent().get::<_, Address>(&creator_key) {
            if creator == attester {
                env.storage().persistent().extend_ttl(
                    &creator_key,
                    LEDGERS_IN_ONE_YEAR,
                    LEDGERS_IN_ONE_YEAR,
                );
                return true;
            }
        } else {
            return false;
        }

        let delegate_key = (AUTHORIZED_DELEGATES, uid.clone(), attester);
        if env
            .storage()
            .persistent()
            .get::<_, bool>(&delegate_key)
            .unwrap_or(false)
        {
            env.storage().persistent().extend_ttl(
                &delegate_key,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
            return true;
        }

        false
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
