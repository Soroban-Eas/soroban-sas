//! Shared deterministic/fuzz oracle for both chunk-writing helpers.
extern crate std;
use super::*;
use soroban_sdk::{
    xdr::{Hash, ScAddress},
    Bytes, BytesN, TryFromVal,
};
use std::collections::BTreeMap;
use std::vec::Vec;

/// Limits host memory and work per fuzz input while crossing three boundaries.
pub const MAX_INSERTIONS: usize = 400;

/// Insert a bounded sequence into recipient and schema indexes. A position
/// salt makes each UID unique even when libFuzzer repeats an input record.
/// Check exact order/multiplicity, stored counts, and physical chunk sizes.
pub fn check_chunking(pairs: &[([u8; 4], [u8; 32])]) {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.budget().reset_unlimited();
    let id = env.register_contract(None, Indexer);
    let mut expected: BTreeMap<[u8; 4], Vec<UID>> = BTreeMap::new();
    // Also exercise reads with no insertions.
    expected.insert([0; 4], Vec::new());
    env.as_contract(&id, || {
        for (position, (key, raw_uid)) in pairs.iter().take(MAX_INSERTIONS).enumerate() {
            let mut input = Bytes::from_slice(&env, raw_uid);
            input.append(&Bytes::from_slice(&env, &(position as u32).to_be_bytes()));
            let uid = UID(env.crypto().sha256(&input).into());
            let (recipient, schema) = keys(&env, key);
            index_address_uid(&env, &recipient, &uid, RECIPIENT_TOTAL);
            index_uid_uid(&env, &schema, &uid, SCHEMA_TOTAL);
            let entries = expected.entry(*key).or_default();
            entries.push(uid);
            if matches!(entries.len(), 99 | 100 | 101 | 200 | 201 | 300 | 301) {
                check_key(&env, key, entries);
            }
        }
        for (key, entries) in &expected {
            check_key(&env, key, entries);
        }
    });
}

fn keys(env: &Env, key: &[u8; 4]) -> (Address, UID) {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(key);
    let recipient = Address::try_from_val(env, &ScAddress::Contract(Hash(bytes))).unwrap();
    (recipient, UID(BytesN::from_array(env, &bytes)))
}

fn check_key(env: &Env, key: &[u8; 4], expected: &[UID]) {
    let (recipient, schema) = keys(env, key);
    let count = expected.len() as u32;
    assert_eq!(
        index_total(env, &(RECIPIENT_TOTAL, recipient.clone())),
        count
    );
    assert_eq!(index_total(env, &(SCHEMA_TOTAL, schema.clone())), count);
    let recipients: Vec<_> = Indexer::get_attestations_by_recipient(env.clone(), recipient.clone())
        .iter()
        .collect();
    let schemas: Vec<_> = Indexer::get_attestations_by_schema(env.clone(), schema.clone())
        .iter()
        .collect();
    assert_eq!(recipients.as_slice(), expected);
    assert_eq!(schemas.as_slice(), expected);
    for chunk_index in 0..count.div_ceil(MAX_CHUNK_SIZE) {
        let size = (count - chunk_index * MAX_CHUNK_SIZE).min(MAX_CHUNK_SIZE);
        let recipient_chunk: soroban_sdk::Vec<UID> = env
            .storage()
            .persistent()
            .get(&(recipient.clone(), chunk_index))
            .unwrap();
        let schema_chunk: soroban_sdk::Vec<UID> = env
            .storage()
            .persistent()
            .get(&(schema.clone(), chunk_index))
            .unwrap();
        assert_eq!(recipient_chunk.len(), size);
        assert_eq!(schema_chunk.len(), size);
    }
}
