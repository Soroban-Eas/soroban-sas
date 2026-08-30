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
        env.storage().instance().set(&REGISTRY_ADMIN, &admin);
    }

    pub fn upgrade(env: Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
        extend_instance_ttl(&env);
        let admin: soroban_sdk::Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    pub fn set_fee(env: Env, fee: i128) {
        extend_instance_ttl(&env);
        let admin: soroban_sdk::Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        admin.require_auth();
        env.storage().instance().set(&SCHEMA_FEE, &fee);
    }

    pub fn set_treasury(env: Env, treasury: soroban_sdk::Address) {
        extend_instance_ttl(&env);
        let admin: soroban_sdk::Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        admin.require_auth();
        env.storage().instance().set(&TREASURY, &treasury);
    }

    pub fn withdraw_fees(env: Env, amount: i128) {
        extend_instance_ttl(&env);
        let admin: soroban_sdk::Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        admin.require_auth();
        // Native token transfer logic goes here
    }

    /// Deprecates a schema. Only its original registrant or the registry
    /// administrator may authorize this operation.
    pub fn deprecate(env: Env, uid: UID, authorizer: Address) {
        extend_instance_ttl(&env);
        authorizer.require_auth();

        let admin: Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        let creator: Option<Address> = env
            .storage()
            .persistent()
            .get(&(SCHEMA_CREATOR, uid.clone()));
        // Schemas registered before creator tracking was introduced have no
        // mapping. The registry admin remains able to deprecate those legacy
        // records; new records also permit their creator.
        if authorizer != admin && creator.as_ref() != Some(&authorizer) {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let deprecated_key = (DEPRECATED, uid);
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

        let mut payload = Bytes::new(&env);
        payload.append(&schema.clone().to_xdr(&env));

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

    pub fn get_schemas(env: Env, start: u32, limit: u32) -> soroban_sdk::Vec<SchemaRecord> {
        extend_instance_ttl(&env);
        let mut schemas = soroban_sdk::Vec::new(&env);
        let count: u32 = env.storage().persistent().get(&SCHEMA_COUNT).unwrap_or(0);

        let end = if start + limit > count {
            count
        } else {
            start + limit
        };
        for i in start..end {
            if let Some(uid) = env.storage().persistent().get::<u32, UID>(&i) {
                if let Some(record) = env.storage().persistent().get(&uid) {
                    schemas.push_back(record);
                }
            }
        }
        schemas
    }
}

#[cfg(test)]
mod test;
