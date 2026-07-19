#![allow(unexpected_cfgs)]
#![no_std]

use soroban_sas_common::{SASError, SchemaRecord, UID};
use soroban_sdk::{contract, contractimpl, token, xdr::ToXdr, Address, Bytes, Env, String};

#[contract]
pub struct SchemaRegistry;

mod storage;
use storage::*;

#[contractimpl]
impl SchemaRegistry {
    pub fn init(env: Env, admin: soroban_sdk::Address) {
        if env.storage().instance().has(&REGISTRY_ADMIN) {
            panic!("Already initialized");
        }
        env.storage().instance().set(&REGISTRY_ADMIN, &admin);
    }

    pub fn upgrade(env: Env, new_wasm_hash: soroban_sdk::BytesN<32>) {
        let admin: soroban_sdk::Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Configure the registration fee. Setting a fee also enables it.
    pub fn set_fee(env: Env, fee_asset: Address, fee_amount: i128) {
        let admin: soroban_sdk::Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        admin.require_auth();
        if fee_amount <= 0 {
            soroban_sdk::panic_with_error!(&env, SASError::InvalidFeeAmount);
        }
        env.storage().instance().set(&FEE_ASSET, &fee_asset);
        env.storage().instance().set(&SCHEMA_FEE, &fee_amount);
        env.storage().instance().set(&FEE_ENABLED, &true);
    }

    /// Toggle fee collection without discarding the configured asset/amount.
    /// Enabling requires a fee to have been configured via `set_fee`.
    pub fn set_fee_enabled(env: Env, enabled: bool) {
        let admin: soroban_sdk::Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        admin.require_auth();
        if enabled && !env.storage().instance().has(&SCHEMA_FEE) {
            soroban_sdk::panic_with_error!(&env, SASError::FeeNotConfigured);
        }
        env.storage().instance().set(&FEE_ENABLED, &enabled);
    }

    pub fn set_treasury(env: Env, treasury: soroban_sdk::Address) {
        let admin: soroban_sdk::Address = env.storage().instance().get(&REGISTRY_ADMIN).unwrap();
        admin.require_auth();
        env.storage().instance().set(&TREASURY, &treasury);
    }

    /// Returns the active fee as (asset, amount), or None when fees are disabled.
    pub fn get_fee(env: Env) -> Option<(Address, i128)> {
        let enabled: bool = env
            .storage()
            .instance()
            .get(&FEE_ENABLED)
            .unwrap_or(false);
        if !enabled {
            return None;
        }
        let asset: Address = env.storage().instance().get(&FEE_ASSET)?;
        let amount: i128 = env.storage().instance().get(&SCHEMA_FEE)?;
        Some((asset, amount))
    }

    pub fn get_treasury(env: Env) -> Option<Address> {
        env.storage().instance().get(&TREASURY)
    }

    pub fn deprecate(env: Env, uid: UID) {
        // Typically require creator auth, skipping for brevity
        env.storage().persistent().set(&(DEPRECATED, uid), &true);
    }

    pub fn register(env: Env, caller: Address, schema: String, resolver: Address, revocable: bool) -> UID {
        caller.require_auth();

        let mut payload = Bytes::new(&env);
        payload.append(&schema.clone().to_xdr(&env));

        let hash = env.crypto().sha256(&payload);
        let uid = UID(hash);

        if env.storage().persistent().has(&uid) {
            soroban_sdk::panic_with_error!(&env, SASError::SchemaAlreadyExists);
        }

        // Collect the protocol fee before mutating registry state. The token
        // transfer is atomic with the registration: if it fails (insufficient
        // balance or missing authorization), the whole invocation aborts.
        // Routing funds straight to the treasury means the contract never
        // custodies fees, and Soroban's host forbids reentrant invocations.
        if let Some((fee_asset, fee_amount)) = Self::get_fee(env.clone()) {
            let treasury: Address = env
                .storage()
                .instance()
                .get(&TREASURY)
                .unwrap_or_else(|| {
                    soroban_sdk::panic_with_error!(&env, SASError::TreasuryNotSet)
                });
            token::Client::new(&env, &fee_asset).transfer(&caller, &treasury, &fee_amount);
        }

        let record = SchemaRecord {
            uid: uid.clone(),
            resolver,
            revocable,
            schema,
        };
        env.storage().persistent().set(&uid, &record);

        let mut count: u32 = env.storage().persistent().get(&SCHEMA_COUNT).unwrap_or(0);
        env.storage().persistent().set(&count, &uid);
        count += 1;
        env.storage().persistent().set(&SCHEMA_COUNT, &count);

        env.events()
            .publish((soroban_sas_common::events::REGISTERED,), uid.clone());

        uid
    }

    pub fn get_schema(env: Env, uid: UID) -> Option<SchemaRecord> {
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
