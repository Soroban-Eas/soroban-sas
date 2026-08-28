#![allow(unexpected_cfgs)]
#![no_std]
use soroban_sas_common::{SASError, LEDGERS_IN_ONE_YEAR, UID};
use soroban_sdk::{contract, contractimpl, panic_with_error, symbol_short, Address, Env, Symbol};

// v1.0.0 Indexer logic frozen

#[contract]
pub struct Indexer;

/// Address allowed to administer this indexer instance.
pub const INDEXER_ADMIN: Symbol = symbol_short!("ADMIN");
/// Address of the SAS contract whose attestations this indexer mirrors.
pub const SAS_CONTRACT: Symbol = symbol_short!("SAS");
const MAX_CHUNK_SIZE: u32 = 100;
const RECIPIENT_TOTAL: Symbol = symbol_short!("RCOUNT");
const SCHEMA_TOTAL: Symbol = symbol_short!("SCOUNT");
const ATTESTER_TOTAL: Symbol = symbol_short!("ACOUNT");
const SAS_INTERFACE_VERSION: Symbol = symbol_short!("SASV1");

fn index_address_uid(env: &Env, key: &Address, uid: &UID, total_key: Symbol) {
    let count_key = (total_key, key.clone());
    let mut total: u32 = env.storage().instance().get(&count_key).unwrap_or(0);
    let mut chunk_index = total / MAX_CHUNK_SIZE;
    let mut chunk: soroban_sdk::Vec<UID> = env
        .storage()
        .persistent()
        .get(&(key.clone(), chunk_index))
        .unwrap_or_else(|| soroban_sdk::Vec::new(env));
    if chunk.len() >= MAX_CHUNK_SIZE {
        chunk_index += 1;
        chunk = env
            .storage()
            .persistent()
            .get(&(key.clone(), chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(env));
    }
    chunk.push_back(uid.clone());
    let storage_key = (key.clone(), chunk_index);
    env.storage().persistent().set(&storage_key, &chunk);
    env.storage().persistent().extend_ttl(
        &storage_key,
        LEDGERS_IN_ONE_YEAR,
        LEDGERS_IN_ONE_YEAR,
    );

    total += 1;
    env.storage().instance().set(&count_key, &total);
}

fn index_uid_uid(env: &Env, key: &UID, uid: &UID, total_key: Symbol) {
    let count_key = (total_key, key.clone());
    let mut total: u32 = env.storage().instance().get(&count_key).unwrap_or(0);
    let mut chunk_index = total / MAX_CHUNK_SIZE;
    let mut chunk: soroban_sdk::Vec<UID> = env
        .storage()
        .persistent()
        .get(&(key.clone(), chunk_index))
        .unwrap_or_else(|| soroban_sdk::Vec::new(env));
    if chunk.len() >= MAX_CHUNK_SIZE {
        chunk_index += 1;
        chunk = env
            .storage()
            .persistent()
            .get(&(key.clone(), chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(env));
    }
    chunk.push_back(uid.clone());
    let storage_key = (key.clone(), chunk_index);
    env.storage().persistent().set(&storage_key, &chunk);
    env.storage().persistent().extend_ttl(
        &storage_key,
        LEDGERS_IN_ONE_YEAR,
        LEDGERS_IN_ONE_YEAR,
    );

    total += 1;
    env.storage().instance().set(&count_key, &total);
}

#[contractimpl]
impl Indexer {
    /// Compatibility probe used by Indexer::init to prove the supplied
    /// address is an SAS v1 contract rather than merely a contract address.
    pub fn sasv1(_env: Env) -> bool {
        true
    }

    /// Binds this indexer to an `admin` and to the `sas` contract whose
    /// attestations it indexes. Callable exactly once; a second call panics
    /// with `SASError::AlreadyInitialized`.
    pub fn init(env: Env, admin: Address, sas: Address) {
        if env.storage().instance().has(&INDEXER_ADMIN) {
            panic_with_error!(&env, SASError::AlreadyInitialized);
        }
        let compatible: bool = env
            .try_invoke_contract(&sas, &SAS_INTERFACE_VERSION, soroban_sdk::vec![&env])
            .unwrap_or(false);
        if !compatible {
            panic_with_error!(&env, SASError::IncompatibleDependency);
        }
        env.storage().instance().set(&INDEXER_ADMIN, &admin);
        env.storage().instance().set(&SAS_CONTRACT, &sas);
    }

    /// Returns the admin address recorded by `init`, if the indexer has been
    /// initialized.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&INDEXER_ADMIN)
    }

    /// Returns the SAS contract address this indexer is bound to, if the
    /// indexer has been initialized.
    pub fn get_sas(env: Env) -> Option<Address> {
        env.storage().instance().get(&SAS_CONTRACT)
    }

    pub fn index_attestation(
        env: Env,
        uid: UID,
        recipient: Address,
        schema_uid: UID,
        attester: Address,
    ) {
        index_address_uid(&env, &recipient, &uid, RECIPIENT_TOTAL);
        index_uid_uid(&env, &schema_uid, &uid, SCHEMA_TOTAL);
        index_address_uid(&env, &attester, &uid, ATTESTER_TOTAL);
    }

    pub fn get_attestations_by_recipient(env: Env, recipient: Address) -> soroban_sdk::Vec<UID> {
        let chunk_index = 0u32;
        env.storage()
            .persistent()
            .get(&(recipient, chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    pub fn get_attestations_by_schema(env: Env, schema_uid: UID) -> soroban_sdk::Vec<UID> {
        let chunk_index = 0u32;
        env.storage()
            .persistent()
            .get(&(schema_uid, chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    pub fn get_attestations_by_attester(env: Env, attester: Address) -> soroban_sdk::Vec<UID> {
        let chunk_index = 0u32;
        env.storage()
            .persistent()
            .get(&(attester, chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    pub fn get_atts_by_recipient_paginated(
        env: Env,
        recipient: Address,
        cursor: u32,
        limit: u32,
    ) -> soroban_sdk::Vec<UID> {
        if limit == 0 {
            return soroban_sdk::Vec::new(&env);
        }

        let total_key = (RECIPIENT_TOTAL, recipient.clone());
        let total: u32 = env.storage().instance().get(&total_key).unwrap_or(0);
        if cursor >= total {
            return soroban_sdk::Vec::new(&env);
        }

        let end = core::cmp::min(total, cursor.saturating_add(limit));
        let mut index = cursor;
        let mut uids = soroban_sdk::Vec::new(&env);

        while index < end {
            let chunk_index = index / MAX_CHUNK_SIZE;
            let chunk_offset = index % MAX_CHUNK_SIZE;
            let Some(chunk): Option<soroban_sdk::Vec<UID>> = env
                .storage()
                .persistent()
                .get(&(recipient.clone(), chunk_index))
            else {
                break;
            };

            if chunk_offset >= chunk.len() {
                index = (chunk_index + 1) * MAX_CHUNK_SIZE;
                continue;
            }

            let available = chunk.len() - chunk_offset;
            let remaining = end - index;
            let take = if remaining < available {
                remaining
            } else {
                available
            };

            for offset in 0..take {
                if let Some(uid) = chunk.get(chunk_offset + offset) {
                    uids.push_back(uid);
                }
            }
            index += take;
        }

        uids
    }
}

#[cfg(test)]
mod test;
