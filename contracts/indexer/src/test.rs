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
fn test_revocation_updates_status_and_filtered_query() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[4u8; 32]));
    let attester = Address::generate(&env);

    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[10u8; 32]));
    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[11u8; 32]));
    client.index_attestation(&uid1, &recipient, &schema_uid, &attester);
    client.index_attestation(&uid2, &recipient, &schema_uid, &attester);

    // Revoke uid1 via callback
    client.handle_revoke(&uid1);

    assert_eq!(client.get_attestation_status(&uid1), Some(IndexStatus::Revoked));
    assert_eq!(client.get_attestation_status(&uid2), Some(IndexStatus::Active));

    // Historical includes both, active-only excludes revoked
    let historical = client.get_recipient_filtered(&recipient, &true);
    assert_eq!(historical.len(), 2);
    let active = client.get_recipient_filtered(&recipient, &false);
    assert_eq!(active.len(), 1);
    assert_eq!(active.get(0).unwrap(), uid2);

    // Schema and attester filtered also respect status
    let schema_active = client.get_schema_filtered(&schema_uid, &false);
    assert_eq!(schema_active.len(), 1);
    let attester_active = client.get_attester_filtered(&attester, &false);
    assert_eq!(attester_active.len(), 1);
}

#[test]
fn test_replacement_links_old_and_new_without_deleting_history() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[4u8; 32]));
    let attester = Address::generate(&env);

    let old_uid = UID(soroban_sdk::BytesN::from_array(&env, &[20u8; 32]));
    let new_uid = UID(soroban_sdk::BytesN::from_array(&env, &[21u8; 32]));
    client.index_attestation(&old_uid, &recipient, &schema_uid, &attester);
    // Replacement indexes new and marks old as Replaced
    client.index_attestation(&new_uid, &recipient, &schema_uid, &attester);
    client.handle_replace(&old_uid, &new_uid);

    assert_eq!(client.get_attestation_status(&old_uid), Some(IndexStatus::Replaced));
    assert_eq!(client.get_replacement(&old_uid), Some(new_uid.clone()));
    assert_eq!(client.get_replaces(&new_uid), Some(old_uid.clone()));

    // Historical returns both, active returns only new
    let historical = client.get_recipient_filtered(&recipient, &true);
    assert_eq!(historical.len(), 2);
    assert!(historical.contains(&old_uid));
    assert!(historical.contains(&new_uid));

    let active = client.get_recipient_filtered(&recipient, &false);
    assert_eq!(active.len(), 1);
    assert_eq!(active.get(0).unwrap(), new_uid);
}

#[test]
fn test_paginated_filtered_skips_revoked() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[4u8; 32]));
    let attester = Address::generate(&env);

    for i in 0..5u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));
        client.index_attestation(&uid, &recipient, &schema_uid, &attester);
        if i % 2 == 0 {
            client.handle_revoke(&uid);
        }
    }
    // 5 total, 3 revoked (0,2,4), 2 active (1,3)
    let active = client.get_recipient_filtered(&recipient, &false);
    assert_eq!(active.len(), 2);

    let paginated = client.get_recipient_paginated_filtered(&recipient, &0, &10, &false);
    assert_eq!(paginated.len(), 2);

    // Limit 1 returns one active; cursor walk should eventually collect both.
    let page1 = client.get_recipient_paginated_filtered(&recipient, &0, &1, &false);
    assert_eq!(page1.len(), 1);
}

#[test]
fn test_batch_revocation_via_callbacks() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);
    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[6u8; 32]));
    let attester = Address::generate(&env);
    let mut uids = soroban_sdk::Vec::new(&env);
    for i in 0..10u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i + 50;
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));
        client.index_attestation(&uid, &recipient, &schema_uid, &attester);
        uids.push_back(uid);
    }
    // Simulate batch revoke
    for uid in uids.iter() {
        client.handle_revoke(&uid);
    }
    let active = client.get_recipient_filtered(&recipient, &false);
    assert_eq!(active.len(), 0);
    let historical = client.get_recipient_filtered(&recipient, &true);
    assert_eq!(historical.len(), 10);
}
