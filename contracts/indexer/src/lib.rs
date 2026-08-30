#![allow(unexpected_cfgs)]
#![no_std]
use soroban_sas_common::{SASError, LEDGERS_IN_ONE_YEAR, UID};
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, symbol_short, Address, Env, Symbol,
};

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
/// Persistent key prefix for a UID's [`IndexStatus`]: `(STATUS_KEY, uid)`.
const STATUS_KEY: Symbol = symbol_short!("IDXSTAT");
/// Persistent key prefix for a UID's idempotency record: `(INDEXED_KEY, uid)`
/// stores the `(recipient, schema_uid, attester)` triple the UID was first
/// indexed with. Its presence marks the UID as already indexed and pins the
/// metadata a retry must match.
const INDEXED_KEY: Symbol = symbol_short!("INDEXED");

/// The `(recipient, schema_uid, attester)` triple a UID was first indexed
/// with. A later `index_attestation` for the same UID must supply an
/// identical triple (idempotent retry) or it is rejected. Stored as a plain
/// tuple rather than a `#[contracttype]` struct so no `arbitrary`/testutils
/// bound is imposed on `UID` in downstream test builds.
type IndexRecord = (Address, UID, Address);

/// Lifecycle state the indexer tracks per attestation UID so filtered
/// queries can hide revoked / replaced entries without deleting history.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexStatus {
    Active,
    Revoked,
    Replaced,
}

fn extend_instance_ttl(env: &Env) {
    env.storage().instance().extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
}

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
    extend_instance_ttl(env);
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
    extend_instance_ttl(env);
}

/// Records a non-default lifecycle state for `uid`. Only `Revoked` /
/// `Replaced` are ever persisted — an unindexed or freshly indexed UID has
/// no status entry, which [`is_active`] and [`Indexer::get_attestation_status`]
/// both read as active. Invoked by the SAS `handle_revoke` / `handle_replace`
/// callbacks (added separately).
#[allow(dead_code)]
fn set_index_status(env: &Env, uid: &UID, status: IndexStatus) {
    let key = (STATUS_KEY, uid.clone());
    env.storage().persistent().set(&key, &status);
    env.storage()
        .persistent()
        .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
}

fn is_active(env: &Env, uid: &UID) -> bool {
    // No status entry means legacy `Active` (issued before status tracking).
    matches!(
        env.storage()
            .persistent()
            .get::<_, IndexStatus>(&(STATUS_KEY, uid.clone())),
        Some(IndexStatus::Active) | None
    )
}

fn collect_filtered(
    env: &Env,
    total: u32,
    mut get_chunk: impl FnMut(u32) -> Option<soroban_sdk::Vec<UID>>,
    include_revoked: bool,
) -> soroban_sdk::Vec<UID> {
    let mut out = soroban_sdk::Vec::new(env);
    let mut index = 0u32;
    while index < total {
        let chunk_index = index / MAX_CHUNK_SIZE;
        let chunk_offset = index % MAX_CHUNK_SIZE;
        let Some(chunk) = get_chunk(chunk_index) else {
            break;
        };
        if chunk_offset >= chunk.len() {
            index = (chunk_index + 1) * MAX_CHUNK_SIZE;
            continue;
        }
        let available = chunk.len() - chunk_offset;
        let remaining = total - index;
        let take = core::cmp::min(available, remaining);
        for offset in 0..take {
            if let Some(uid) = chunk.get(chunk_offset + offset) {
                if include_revoked || is_active(env, &uid) {
                    out.push_back(uid);
                }
            }
        }
        index += take;
    }
    out
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
        extend_instance_ttl(&env);
        if env.storage().instance().has(&INDEXER_ADMIN) {
            panic_with_error!(&env, SASError::AlreadyInitialized);
        }
        let compatible: bool = env
            .try_invoke_contract::<bool, soroban_sdk::Error>(&sas, &SAS_INTERFACE_VERSION, soroban_sdk::vec![&env])
            .unwrap_or(Ok(false)).unwrap_or(false);
        if !compatible {
            panic_with_error!(&env, SASError::IncompatibleDependency);
        }
        env.storage().instance().set(&INDEXER_ADMIN, &admin);
        env.storage().instance().set(&SAS_CONTRACT, &sas);
        extend_instance_ttl(&env);
    }

    /// Returns the admin address recorded by `init`, if the indexer has been
    /// initialized.
    pub fn get_admin(env: Env) -> Option<Address> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&INDEXER_ADMIN)
    }

    /// Returns the SAS contract address this indexer is bound to, if the
    /// indexer has been initialized.
    pub fn get_sas(env: Env) -> Option<Address> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&SAS_CONTRACT)
    }

    /// Records `uid` in the recipient, schema, and attester indexes.
    ///
    /// Idempotent: a repeated call with the **same**
    /// `(recipient, schema_uid, attester)` triple is a no-op (it only
    /// renews TTLs), so a retried cross-contract call or a migration replay
    /// can't duplicate query results or inflate storage. A repeated call
    /// for the same `uid` with a **different** triple is rejected with
    /// `SASError::DuplicateAttestation`.
    pub fn index_attestation(
        env: Env,
        uid: UID,
        recipient: Address,
        schema_uid: UID,
        attester: Address,
    ) {
        extend_instance_ttl(&env);

        let record: IndexRecord = (recipient.clone(), schema_uid.clone(), attester.clone());
        let record_key = (INDEXED_KEY, uid.clone());
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<_, IndexRecord>(&record_key)
        {
            if existing != record {
                panic_with_error!(&env, SASError::DuplicateAttestation);
            }
            // Identical retry: renew the idempotency record's TTL and return
            // without touching the append-only indexes.
            env.storage().persistent().extend_ttl(
                &record_key,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
            extend_instance_ttl(&env);
            return;
        }

        env.storage().persistent().set(&record_key, &record);
        env.storage().persistent().extend_ttl(
            &record_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        index_address_uid(&env, &recipient, &uid, RECIPIENT_TOTAL);
        index_uid_uid(&env, &schema_uid, &uid, SCHEMA_TOTAL);
        index_address_uid(&env, &attester, &uid, ATTESTER_TOTAL);
        extend_instance_ttl(&env);
    }

    /// Returns the recorded [`IndexStatus`] for `uid`, or `None` when the
    /// UID was never indexed (or was indexed before status tracking existed).
    pub fn get_attestation_status(env: Env, uid: UID) -> Option<IndexStatus> {
        extend_instance_ttl(&env);
        env.storage().persistent().get(&(STATUS_KEY, uid))
    }

    pub fn get_attestations_by_recipient(env: Env, recipient: Address) -> soroban_sdk::Vec<UID> {
        extend_instance_ttl(&env);
        let chunk_index = 0u32;
        env.storage()
            .persistent()
            .get(&(recipient, chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    pub fn get_attestations_by_schema(env: Env, schema_uid: UID) -> soroban_sdk::Vec<UID> {
        extend_instance_ttl(&env);
        let chunk_index = 0u32;
        env.storage()
            .persistent()
            .get(&(schema_uid, chunk_index))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    pub fn get_attestations_by_attester(env: Env, attester: Address) -> soroban_sdk::Vec<UID> {
        extend_instance_ttl(&env);
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
        extend_instance_ttl(&env);
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

    /// Filtered variants: `include_revoked == true` returns the full
    /// auditable history (active + revoked + replaced); `false` returns
    /// only `Active` UIDs. Replacement UIDs remain `Active`; their
    /// predecessors become `Replaced` and are filtered out in active-only
    /// mode but still appear in historical mode via the forward/reverse
    /// links (`get_replacement` / `get_replaces`).

    pub fn get_recipient_filtered(
        env: Env,
        recipient: Address,
        include_revoked: bool,
    ) -> soroban_sdk::Vec<UID> {
        let total: u32 = env
            .storage()
            .instance()
            .get(&(RECIPIENT_TOTAL, recipient.clone()))
            .unwrap_or(0);
        collect_filtered(&env, total, |chunk_index| {
            env.storage()
                .persistent()
                .get(&(recipient.clone(), chunk_index))
        }, include_revoked)
    }

    pub fn get_schema_filtered(
        env: Env,
        schema_uid: UID,
        include_revoked: bool,
    ) -> soroban_sdk::Vec<UID> {
        let total: u32 = env
            .storage()
            .instance()
            .get(&(SCHEMA_TOTAL, schema_uid.clone()))
            .unwrap_or(0);
        collect_filtered(&env, total, |chunk_index| {
            env.storage()
                .persistent()
                .get(&(schema_uid.clone(), chunk_index))
        }, include_revoked)
    }

    pub fn get_attester_filtered(
        env: Env,
        attester: Address,
        include_revoked: bool,
    ) -> soroban_sdk::Vec<UID> {
        let total: u32 = env
            .storage()
            .instance()
            .get(&(ATTESTER_TOTAL, attester.clone()))
            .unwrap_or(0);
        collect_filtered(&env, total, |chunk_index| {
            env.storage()
                .persistent()
                .get(&(attester.clone(), chunk_index))
        }, include_revoked)
    }

    /// Paginated active-only view: walks the underlying chunks and
    /// skips revoked/replaced UIDs until `limit` active entries are
    /// collected or the total is exhausted. `cursor` is a raw offset
    /// into the historical index (so callers can resume with
    /// `cursor + returned.len()` only when also advancing over skipped
    /// entries, or use `cursor + limit` for historical pagination).
    pub fn get_recipient_paginated_filtered(
        env: Env,
        recipient: Address,
        cursor: u32,
        limit: u32,
        include_revoked: bool,
    ) -> soroban_sdk::Vec<UID> {
        if limit == 0 {
            return soroban_sdk::Vec::new(&env);
        }
        let total: u32 = env
            .storage()
            .instance()
            .get(&(RECIPIENT_TOTAL, recipient.clone()))
            .unwrap_or(0);
        if cursor >= total {
            return soroban_sdk::Vec::new(&env);
        }
        let mut out = soroban_sdk::Vec::new(&env);
        let mut index = cursor;
        while index < total && out.len() < limit {
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
            if let Some(uid) = chunk.get(chunk_offset) {
                if include_revoked || is_active(&env, &uid) {
                    out.push_back(uid);
                    if out.len() >= limit {
                        break;
                    }
                }
            }
            index += 1;
        }
        out
    }
}

#[cfg(test)]
mod test;
