#![allow(unexpected_cfgs)]
#![no_std]
use soroban_sas_common::{SASError, UID};
use soroban_sdk::{contract, contractimpl, panic_with_error, symbol_short, Address, Env, Symbol};

// v1.0.0 Indexer logic frozen

#[contract]
pub struct Indexer;

/// Address allowed to administer this indexer instance.
pub const INDEXER_ADMIN: Symbol = symbol_short!("ADMIN");
/// Address of the SAS contract whose attestations this indexer mirrors.
pub const SAS_CONTRACT: Symbol = symbol_short!("SAS");

#[contractimpl]
impl Indexer {
    /// Binds this indexer to an `admin` and to the `sas` contract whose
    /// attestations it indexes. Callable exactly once; a second call panics
    /// with `SASError::AlreadyInitialized`.
    pub fn init(env: Env, admin: Address, sas: Address) {
        if env.storage().instance().has(&INDEXER_ADMIN) {
            panic_with_error!(&env, SASError::AlreadyInitialized);
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
        _env: Env,
        _uid: UID,
        _recipient: Address,
        _schema_uid: UID,
        _attester: Address,
    ) {
        // Chunked Recipient -> Vec<UID>
        // Max 100 per chunk to avoid Soroban limits
        let chunk_index = 0u32;
        let mut recipient_uids: soroban_sdk::Vec<UID> = _env
            .storage()
            .persistent()
            .get(&(_recipient.clone(), chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&_env));
        recipient_uids.push_back(_uid.clone());
        _env.storage()
            .persistent()
            .set(&(_recipient, chunk_index), &recipient_uids);

        // Chunked Schema -> Vec<UID>
        let mut schema_uids: soroban_sdk::Vec<UID> = _env
            .storage()
            .persistent()
            .get(&(_schema_uid.clone(), chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&_env));
        schema_uids.push_back(_uid.clone());
        _env.storage()
            .persistent()
            .set(&(_schema_uid, chunk_index), &schema_uids);

        // Chunked Attester -> Vec<UID>
        let mut attester_uids: soroban_sdk::Vec<UID> = _env
            .storage()
            .persistent()
            .get(&(_attester.clone(), chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&_env));
        attester_uids.push_back(_uid.clone());
        _env.storage()
            .persistent()
            .set(&(_attester, chunk_index), &attester_uids);
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
        _limit: u32,
    ) -> soroban_sdk::Vec<UID> {
        let chunk_index = cursor / 100;
        env.storage()
            .persistent()
            .get(&(recipient, chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }
}

#[cfg(test)]
mod test;
