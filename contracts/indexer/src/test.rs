use super::*;
use soroban_sas_common::UID;
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Env};

mod mock {
    use super::*;
    #[contract]
    pub struct MockSas;
    #[contractimpl]
    impl MockSas {
        pub fn SASV1(_env: Env) -> bool { true }
    }
}

#[test]
fn test_init_records_admin_and_sas_binding() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let admin = Address::generate(&env);
    let sas = env.register_contract(None, mock::MockSas);

    assert_eq!(client.get_admin(), None);
    client.init(&admin, &sas);

    assert_eq!(client.get_admin(), Some(admin.clone()));
    assert_eq!(client.get_sas(), Some(sas.clone()));
}

#[test]
fn test_init_twice_is_rejected() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let admin = Address::generate(&env);
    let sas = env.register_contract(None, mock::MockSas);
    client.init(&admin, &sas);

    let res = client.try_init(&admin, &sas);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::AlreadyInitialized.into()))
    );
}

#[test]
fn test_index_single_attestation() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    client.index_attestation(&uid, &recipient, &schema_uid, &attester);
}

/*
#[test]
fn test_chunked_storage_limits() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[3u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    // Simulate exceeding a chunk limit
    for i in 0..150u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));
        client.index_attestation(&uid, &recipient, &schema_uid, &attester);
    }
}
*/

#[test]
fn test_reindexing_identical_metadata_is_a_no_op() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    // Same call three times — a retried cross-contract call / migration replay.
    client.index_attestation(&uid, &recipient, &schema_uid, &attester);
    client.index_attestation(&uid, &recipient, &schema_uid, &attester);
    client.index_attestation(&uid, &recipient, &schema_uid, &attester);

    assert_eq!(client.get_attestations_by_recipient(&recipient).len(), 1);
    assert_eq!(client.get_attestations_by_schema(&schema_uid).len(), 1);
    assert_eq!(client.get_attestations_by_attester(&attester).len(), 1);
}

#[test]
fn test_reusing_a_uid_with_a_different_recipient_is_rejected() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let attester = Address::generate(&env);

    client.index_attestation(&uid, &Address::generate(&env), &schema_uid, &attester);
    let res = client.try_index_attestation(&uid, &Address::generate(&env), &schema_uid, &attester);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::DuplicateAttestation.into()))
    );
}

#[test]
fn test_reusing_a_uid_with_a_different_schema_or_attester_is_rejected() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_a = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let schema_b = UID(soroban_sdk::BytesN::from_array(&env, &[3u8; 32]));
    let recipient = Address::generate(&env);
    let attester_a = Address::generate(&env);
    let attester_b = Address::generate(&env);

    client.index_attestation(&uid, &recipient, &schema_a, &attester_a);

    let wrong_schema = client.try_index_attestation(&uid, &recipient, &schema_b, &attester_a);
    assert_eq!(
        wrong_schema,
        Err(Ok(soroban_sas_common::SASError::DuplicateAttestation.into()))
    );

    let wrong_attester = client.try_index_attestation(&uid, &recipient, &schema_a, &attester_b);
    assert_eq!(
        wrong_attester,
        Err(Ok(soroban_sas_common::SASError::DuplicateAttestation.into()))
    );

    // The original entry is untouched by the rejected retries.
    assert_eq!(client.get_attestations_by_recipient(&recipient).len(), 1);
}

#[test]
fn test_get_attestation_status_defaults_to_none_until_a_callback_sets_it() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    assert_eq!(client.get_attestation_status(&uid), None);
    client.index_attestation(&uid, &recipient, &schema_uid, &attester);
    // A freshly indexed UID has no explicit status entry; `None` is read as
    // active by the filtered queries.
    assert_eq!(client.get_attestation_status(&uid), None);
}

#[test]
fn test_reverse_lookup() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[4u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[10u8; 32]));
    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[11u8; 32]));

    client.index_attestation(&uid1, &recipient, &schema_uid, &attester);
    client.index_attestation(&uid2, &recipient, &schema_uid, &attester);

    let recipient_uids = client.get_attestations_by_recipient(&recipient);
    assert_eq!(recipient_uids.len(), 2);

    let schema_uids = client.get_attestations_by_schema(&schema_uid);
    assert_eq!(schema_uids.len(), 2);
}

#[test]
fn test_attester_indexing_large_datasets() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[5u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    for i in 0..50u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));
        client.index_attestation(&uid, &recipient, &schema_uid, &attester);
    }

    let attester_uids = client.get_attestations_by_attester(&attester);
    assert_eq!(attester_uids.len(), 50);
}

#[test]
fn test_cursor_pagination_large_datasets() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[6u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    for i in 0..101u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));
        client.index_attestation(&uid, &recipient, &schema_uid, &attester);
    }

    let chunk0: soroban_sdk::Vec<UID> = env.as_contract(&indexer_id, || {
        env.storage()
            .persistent()
            .get(&(recipient.clone(), 0u32))
            .unwrap()
    });
    let chunk1: soroban_sdk::Vec<UID> = env.as_contract(&indexer_id, || {
        env.storage()
            .persistent()
            .get(&(recipient.clone(), 1u32))
            .unwrap()
    });

    assert_eq!(chunk0.len(), 100);
    assert_eq!(chunk1.len(), 1);

    let paginated = client.get_atts_by_recipient_paginated(&recipient, &0, &10);
    assert_eq!(paginated.len(), 10);
}

#[test]
fn test_instance_ttl_renewed_by_trusted_write_and_read() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let admin = Address::generate(&env);
    let sas = env.register_contract(None, mock::MockSas);
    client.init(&admin, &sas);

    // Verify initial binding readable
    assert_eq!(client.get_admin(), Some(admin.clone()));
    assert_eq!(client.get_sas(), Some(sas.clone()));

    // Simulate half-year passage then trusted write renews instance TTL
    env.ledger().with_mut(|li| {
        li.sequence_number += soroban_sas_common::LEDGERS_IN_ONE_YEAR / 2;
    });
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[77u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[78u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    client.index_attestation(&uid, &recipient, &schema_uid, &attester);

    // Advance another half-year + 100 beyond original TTL; without renewal this would have expired
    env.ledger().with_mut(|li| {
        li.sequence_number += soroban_sas_common::LEDGERS_IN_ONE_YEAR / 2 + 100;
    });
    // Trusted write renewed TTL, so admin/sas must still be readable
    assert_eq!(client.get_admin(), Some(admin.clone()));
    assert_eq!(client.get_sas(), Some(sas.clone()));
    // Persistent chunk must still be readable
    let by_recipient = client.get_attestations_by_recipient(&recipient);
    assert_eq!(by_recipient.len(), 1);
}

#[test]
fn test_read_only_renews_instance_without_mutating_chunks() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let admin = Address::generate(&env);
    let sas = env.register_contract(None, mock::MockSas);
    client.init(&admin, &sas);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[88u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[89u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    client.index_attestation(&uid, &recipient, &schema_uid, &attester);

    // Capture chunk before read-only renewal
    let chunk_before: soroban_sdk::Vec<UID> = env.as_contract(&indexer_id, || {
        env.storage()
            .persistent()
            .get(&(recipient.clone(), 0u32))
            .unwrap()
    });

    // Advance half year, then perform read-only calls that should renew instance TTL
    env.ledger().with_mut(|li| {
        li.sequence_number += soroban_sas_common::LEDGERS_IN_ONE_YEAR / 2;
    });
    // These reads renew instance but must not mutate persistent chunks
    let _ = client.get_admin();
    let _ = client.get_sas();
    let _ = client.get_attestations_by_recipient(&recipient);
    let _ = client.get_attestations_by_schema(&schema_uid);
    let _ = client.get_attestations_by_attester(&attester);
    let _ = client.get_atts_by_recipient_paginated(&recipient, &0, &10);

    let chunk_after: soroban_sdk::Vec<UID> = env.as_contract(&indexer_id, || {
        env.storage()
            .persistent()
            .get(&(recipient.clone(), 0u32))
            .unwrap()
    });
    assert_eq!(chunk_before, chunk_after);

    // Advance beyond original TTL, still readable due to read renewal
    env.ledger().with_mut(|li| {
        li.sequence_number += soroban_sas_common::LEDGERS_IN_ONE_YEAR / 2 + 100;
    });
    assert_eq!(client.get_admin(), Some(admin));
    assert_eq!(chunk_after.len(), 1);
}

/// `live_until_ledger` recorded for one persistent contract-data entry, or
/// `None` when no such entry exists.
///
/// The SDK 20 test host neither exposes `get_ttl` nor evicts entries whose TTL
/// has lapsed, so advancing the ledger and re-reading proves nothing about
/// archival. Reading the ledger snapshot is the only way to observe a TTL
/// extension directly.
fn chunk_live_until<K>(env: &Env, chunk_key: &K) -> Option<u32>
where
    K: soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
{
    use soroban_sdk::xdr::{ContractDataDurability, LedgerKey, ScVal};
    use soroban_sdk::TryFromVal;

    let target = ScVal::try_from_val(env, &chunk_key.into_val(env)).unwrap();
    env.to_ledger_snapshot()
        .ledger_entries
        .iter()
        .find_map(|(key, (_, live_until))| match &**key {
            LedgerKey::ContractData(data)
                if data.durability == ContractDataDurability::Persistent && data.key == target =>
            {
                *live_until
            }
            _ => None,
        })
}

/// Issue #78: every lookup dimension rolls over at `MAX_CHUNK_SIZE`, and the
/// complete-read APIs walk all of the chunks rather than returning chunk 0.
#[test]
fn test_all_dimensions_chunk_at_max_and_complete_reads_walk_every_chunk() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    // Each `index_attestation` is its own transaction on-chain, with its own
    // budget; the test host accumulates them into one. Reset so building a
    // 101-entry fixture cannot exhaust the budget the assertions need.
    env.budget().reset_unlimited();

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[7u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    let total = MAX_CHUNK_SIZE + 1;
    for i in 0..total {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_be_bytes());
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));
        client.index_attestation(&uid, &recipient, &schema_uid, &attester);
    }

    // 100/1 split in the underlying chunks, for all three dimensions.
    env.as_contract(&indexer_id, || {
        for (dimension, chunk0, chunk1) in [
            (
                "recipient",
                env.storage()
                    .persistent()
                    .get::<_, soroban_sdk::Vec<UID>>(&(recipient.clone(), 0u32)),
                env.storage()
                    .persistent()
                    .get::<_, soroban_sdk::Vec<UID>>(&(recipient.clone(), 1u32)),
            ),
            (
                "schema",
                env.storage()
                    .persistent()
                    .get::<_, soroban_sdk::Vec<UID>>(&(schema_uid.clone(), 0u32)),
                env.storage()
                    .persistent()
                    .get::<_, soroban_sdk::Vec<UID>>(&(schema_uid.clone(), 1u32)),
            ),
            (
                "attester",
                env.storage()
                    .persistent()
                    .get::<_, soroban_sdk::Vec<UID>>(&(attester.clone(), 0u32)),
                env.storage()
                    .persistent()
                    .get::<_, soroban_sdk::Vec<UID>>(&(attester.clone(), 1u32)),
            ),
        ] {
            assert_eq!(chunk0.map(|c| c.len()), Some(MAX_CHUNK_SIZE), "{dimension}");
            assert_eq!(chunk1.map(|c| c.len()), Some(1), "{dimension}");
        }
    });

    // The complete reads see past chunk 0.
    assert_eq!(
        client.get_attestations_by_recipient(&recipient).len(),
        total
    );
    assert_eq!(client.get_attestations_by_schema(&schema_uid).len(), total);
    assert_eq!(client.get_attestations_by_attester(&attester).len(), total);

    // Order is preserved across the chunk boundary: the last UID indexed is
    // the last one returned.
    let mut last_bytes = [0u8; 32];
    last_bytes[0..4].copy_from_slice(&(total - 1).to_be_bytes());
    let last_uid = UID(soroban_sdk::BytesN::from_array(&env, &last_bytes));
    let by_recipient = client.get_attestations_by_recipient(&recipient);
    assert_eq!(by_recipient.last(), Some(last_uid.clone()));
    assert_eq!(
        client.get_attestations_by_attester(&attester).last(),
        Some(last_uid)
    );

    // Filtered and paginated views agree with the complete read.
    assert_eq!(
        client.get_recipient_filtered(&recipient, &true).len(),
        total
    );
    assert_eq!(client.get_schema_filtered(&schema_uid, &true).len(), total);
    assert_eq!(client.get_attester_filtered(&attester, &true).len(), total);
    assert_eq!(
        client
            .get_atts_by_recipient_paginated(&recipient, &MAX_CHUNK_SIZE, &10)
            .len(),
        1
    );
}

/// Issue #79: reading a recipient index renews the TTL of the chunks it
/// touches, so a hot-but-static index is not archived out from under callers.
#[test]
fn test_recipient_read_preserves_hot_index_ttl() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[11u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[12u8; 32]));
    client.index_attestation(&uid, &recipient, &schema_uid, &attester);

    let chunk_key = (recipient.clone(), 0u32);
    let at_write = chunk_live_until(&env, &chunk_key).expect("chunk written");

    // Let half the retention window elapse without any write to the index.
    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    assert_eq!(chunk_live_until(&env, &chunk_key), Some(at_write));

    // A complete read pushes the archival horizon back out to a full year.
    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    assert_eq!(client.get_attestations_by_recipient(&recipient).len(), 1);
    assert_eq!(chunk_live_until(&env, &chunk_key), Some(expected));

    // So does a paginated read.
    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    assert_eq!(
        client
            .get_atts_by_recipient_paginated(&recipient, &0, &10)
            .len(),
        1
    );
    assert_eq!(chunk_live_until(&env, &chunk_key), Some(expected));
}

/// Issue #79: a lookup key with no chunks reads as empty. The read must not
/// trap and must not materialize the chunk it failed to find.
#[test]
fn test_read_of_missing_chunk_is_empty_and_creates_no_storage() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let unknown_recipient = Address::generate(&env);
    let unknown_schema = UID(soroban_sdk::BytesN::from_array(&env, &[13u8; 32]));
    let unknown_attester = Address::generate(&env);

    assert_eq!(
        client
            .get_attestations_by_recipient(&unknown_recipient)
            .len(),
        0
    );
    assert_eq!(client.get_attestations_by_schema(&unknown_schema).len(), 0);
    assert_eq!(
        client.get_attestations_by_attester(&unknown_attester).len(),
        0
    );
    assert_eq!(
        client
            .get_atts_by_recipient_paginated(&unknown_recipient, &0, &10)
            .len(),
        0
    );
    assert_eq!(
        client
            .get_recipient_filtered(&unknown_recipient, &true)
            .len(),
        0
    );

    env.as_contract(&indexer_id, || {
        assert!(!env
            .storage()
            .persistent()
            .has(&(unknown_recipient.clone(), 0u32)));
        assert!(!env
            .storage()
            .persistent()
            .has(&(unknown_schema.clone(), 0u32)));
        assert!(!env
            .storage()
            .persistent()
            .has(&(unknown_attester.clone(), 0u32)));
    });
    assert_eq!(chunk_live_until(&env, &(unknown_recipient, 0u32)), None);
}

/// The active-only paginator advances one entry at a time so it can skip
/// filtered-out UIDs. That makes it the one read path that has to cross a
/// chunk boundary mid-scan, so it is exercised with a whole chunk filtered
/// out.
#[test]
fn test_filtered_pagination_skips_a_full_chunk_of_revoked_uids() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    // Each `index_attestation` is its own transaction on-chain, with its own
    // budget; the test host accumulates them into one. Reset so building a
    // 101-entry fixture cannot exhaust the budget the assertions need.
    env.budget().reset_unlimited();

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[14u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    let total = MAX_CHUNK_SIZE + 1;
    let uid_at = |i: u32| {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_be_bytes());
        UID(soroban_sdk::BytesN::from_array(&env, &bytes))
    };
    for i in 0..total {
        client.index_attestation(&uid_at(i), &recipient, &schema_uid, &attester);
    }

    // Revoke everything in chunk 0, leaving only the single UID in chunk 1.
    env.as_contract(&indexer_id, || {
        for i in 0..MAX_CHUNK_SIZE {
            set_index_status(&env, &uid_at(i), IndexStatus::Revoked);
        }
    });

    // The active-only scan walks past all 100 revoked entries and returns the
    // one live UID from the next chunk.
    let active = client.get_recipient_paginated_filtered(&recipient, &0, &5, &false);
    assert_eq!(active.len(), 1);
    assert_eq!(active.first(), Some(uid_at(MAX_CHUNK_SIZE)));
    assert_eq!(client.get_recipient_filtered(&recipient, &false).len(), 1);

    // The historical view is unaffected by status.
    let historical = client.get_recipient_paginated_filtered(&recipient, &0, &5, &true);
    assert_eq!(historical.len(), 5);
    assert_eq!(historical.first(), Some(uid_at(0)));
    assert_eq!(
        client.get_recipient_filtered(&recipient, &true).len(),
        total
    );

    // A cursor landing inside the second chunk still resolves.
    let tail = client.get_recipient_paginated_filtered(&recipient, &MAX_CHUNK_SIZE, &5, &false);
    assert_eq!(tail.len(), 1);
}
