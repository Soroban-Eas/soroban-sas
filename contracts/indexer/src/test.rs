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
