extern crate alloc;
use super::*;
use soroban_sas_common::{ContractUpgradedEvent, SASError, INSTANCE_EXTEND_TO_LEDGERS, UID};
use soroban_sdk::{
    contract, contractimpl, symbol_short, testutils::Address as _, testutils::Events as _, BytesN,
    Env, IntoVal,
};

mod mock {
    use super::*;
    #[contract]
    pub struct MockSas;
    #[contractimpl]
    impl MockSas {
        pub fn sasv1(_env: Env) -> bool {
            true
        }


        /// Mirrors the real SAS contract's cross-contract call into the
        /// indexer, so tests can prove the indexer accepts writes that
        /// originate from the bound SAS contract's own execution context.
        pub fn relay_index(
            env: Env,
            indexer: Address,
            uid: UID,
            recipient: Address,
            schema_uid: UID,
            attester: Address,
            expiration_time: u64,
        ) {
            env.storage()
                .instance()
                .extend_ttl(INSTANCE_EXTEND_TO_LEDGERS, INSTANCE_EXTEND_TO_LEDGERS);
            env.invoke_contract::<()>(
                &indexer,
                &Symbol::new(&env, "index_attestation"),
                soroban_sdk::vec![
                    &env,
                    uid.into_val(&env),
                    recipient.into_val(&env),
                    schema_uid.into_val(&env),
                    attester.into_val(&env),
                    expiration_time.into_val(&env),
                ],
            );
        }
    }
}

mod mock_attacker {
    use super::*;
    #[contract]
    pub struct MockAttacker;
    #[contractimpl]
    impl MockAttacker {
        /// A contract with no special relationship to the indexer, used to
        /// prove an arbitrary caller cannot poison the index.
        pub fn relay_index(
            env: Env,
            indexer: Address,
            uid: UID,
            recipient: Address,
            schema_uid: UID,
            attester: Address,

            expiration_time: u64,
        ) {
            env.invoke_contract::<()>(
                &indexer,
                &Symbol::new(&env, "index_attestation"),
                soroban_sdk::vec![
                    &env,
                    uid.into_val(&env),
                    recipient.into_val(&env),
                    schema_uid.into_val(&env),
                    attester.into_val(&env),
                    expiration_time.into_val(&env),
                ],
            );
        }
    }
}

/// Registers an indexer bound to a freshly registered `mock::MockSas`, and
/// returns `(indexer_id, indexer_client, sas_id)`.
fn setup_indexed(env: &Env) -> (Address, IndexerClient<'_>, Address) {
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(env, &indexer_id);
    let admin = Address::generate(env);
    let sas = env.register_contract(None, mock::MockSas);
    env.as_contract(&sas, || {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_EXTEND_TO_LEDGERS, INSTANCE_EXTEND_TO_LEDGERS);
    });
    env.mock_all_auths();
    client.init(&admin, &sas);
    (indexer_id, client, sas)
}

#[test]
fn test_init_records_admin_and_sas_binding() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let admin = Address::generate(&env);
    let sas = env.register_contract(None, mock::MockSas);

    assert_eq!(client.get_admin(), None);
    env.mock_all_auths();
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
    env.mock_all_auths();
    client.init(&admin, &sas);

    let res = client.try_init(&admin, &sas);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::AlreadyInitialized.into()))
    );
}

fn setup_upgrade_indexer(env: &Env) -> (Address, Address, Address) {
    let indexer = env.register_contract(None, Indexer);
    let admin = Address::generate(env);
    let sas = env.register_contract(None, mock::MockSas);
    env.mock_all_auths();
    IndexerClient::new(env, &indexer).init(&admin, &sas);
    (indexer, admin, sas)
}

#[test]
fn test_upgrade_version_genesis_and_legacy_default() {
    let env = Env::default();
    let (indexer, _admin, _sas) = setup_upgrade_indexer(&env);
    let client = IndexerClient::new(&env, &indexer);
    assert_eq!(client.get_version(), 1);

    env.as_contract(&indexer, || {
        env.storage().instance().remove(&INDEXER_VERSION);
    });
    assert_eq!(client.get_version(), 1);
}

#[test]
fn test_init_does_not_overwrite_existing_upgrade_version() {
    let env = Env::default();
    let indexer = env.register_contract(None, Indexer);
    env.as_contract(&indexer, || {
        env.storage().instance().set(&INDEXER_VERSION, &2u32);
    });
    let admin = Address::generate(&env);
    let sas = env.register_contract(None, mock::MockSas);
    env.mock_all_auths();
    let client = IndexerClient::new(&env, &indexer);
    client.init(&admin, &sas);
    assert_eq!(client.get_version(), 2);
}

#[test]
fn test_upgrade_preparation_moves_one_to_two_emits_event_and_preserves_bindings() {
    let env = Env::default();
    let (indexer, admin, sas) = setup_upgrade_indexer(&env);
    let client = IndexerClient::new(&env, &indexer);
    let new_hash = BytesN::from_array(&env, &[7u8; 32]);

    env.as_contract(&indexer, || {
        let validated_admin = validate_upgrade(&env, &new_hash, 2).unwrap();
        commit_upgrade(&env, &validated_admin, &new_hash, 2);
    });

    assert_eq!(client.get_version(), 2);
    assert_eq!(client.get_admin(), Some(admin.clone()));
    assert_eq!(client.get_sas(), Some(sas));
    let expected = ContractUpgradedEvent {
        old_wasm_hash: BytesN::from_array(&env, &[0u8; 32]),
        new_wasm_hash: new_hash,
        authorizer: admin.clone(),
    };
    let all = env.events().all();
    assert_eq!(
        all.slice(all.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                indexer,
                (symbol_short!("UPGRADED"), admin).into_val(&env),
                expected.into_val(&env),
            )
        ]
    );
}

#[test]
fn test_upgrade_validation_rejects_skip_current_zero_and_unknown_version_without_mutation() {
    let env = Env::default();
    let (indexer, _admin, _sas) = setup_upgrade_indexer(&env);
    let client = IndexerClient::new(&env, &indexer);
    let hash = BytesN::from_array(&env, &[8u8; 32]);
    let zero = BytesN::from_array(&env, &[0u8; 32]);
    let events_before = env.events().all().len();

    let (current, downgrade, zero_result, unknown, skipped) = env.as_contract(&indexer, || {
        let current = validate_upgrade(&env, &hash, 1);
        let zero_result = validate_upgrade(&env, &zero, 2);
        let unknown = validate_upgrade(&env, &hash, MAX_KNOWN_VERSION + 1);
        env.storage().instance().set(&INDEXER_VERSION, &2u32);
        let downgrade = validate_upgrade(&env, &hash, 1);
        // With MAX_KNOWN_VERSION=2, create a lower stored version so a skip
        // can be tested independently from the unknown-version guard.
        env.storage().instance().set(&INDEXER_VERSION, &0u32);
        let skipped = validate_upgrade(&env, &hash, 2);
        env.storage().instance().set(&INDEXER_VERSION, &1u32);
        (current, downgrade, zero_result, unknown, skipped)
    });

    assert_eq!(current, Err(SASError::InvalidValue));
    assert_eq!(downgrade, Err(SASError::InvalidValue));
    assert_eq!(zero_result, Err(SASError::InvalidValue));
    assert_eq!(unknown, Err(SASError::IncompatibleDependency));
    assert_eq!(skipped, Err(SASError::InvalidValue));
    assert_eq!(client.get_version(), 1);
    assert_eq!(env.events().all().len(), events_before);
}

#[test]
fn test_upgrade_requires_admin_auth_and_emits_no_success_event() {
    let env = Env::default();
    let (indexer, _admin, _sas) = setup_upgrade_indexer(&env);
    let client = IndexerClient::new(&env, &indexer);
    env.set_auths(&[]);
    let events_before = env.events().all().len();

    let result = client.try_upgrade(&BytesN::from_array(&env, &[9u8; 32]), &2);
    assert!(result.is_err());
    assert_eq!(client.get_version(), 1);
    assert_eq!(env.events().all().len(), events_before);
}

#[test]
fn test_upgrade_rejects_missing_layout_without_mutation_or_event() {
    let env = Env::default();
    let (indexer, _admin, _sas) = setup_upgrade_indexer(&env);
    let client = IndexerClient::new(&env, &indexer);
    env.as_contract(&indexer, || {
        env.storage().instance().remove(&SAS_CONTRACT);
    });
    let events_before = env.events().all().len();
    let result = client.try_upgrade(&BytesN::from_array(&env, &[10u8; 32]), &2);

    assert_eq!(result, Err(Ok(SASError::IncompatibleDependency.into())));
    assert_eq!(client.get_version(), 1);
    assert_eq!(env.events().all().len(), events_before);
}

#[test]
fn test_upgrade_event_uses_a_previously_tracked_hash() {
    let env = Env::default();
    let (indexer, admin, _sas) = setup_upgrade_indexer(&env);
    let old_hash = BytesN::from_array(&env, &[12u8; 32]);
    let new_hash = BytesN::from_array(&env, &[13u8; 32]);

    env.as_contract(&indexer, || {
        env.storage().instance().set(&CURRENT_WASM_HASH, &old_hash);
        commit_upgrade(&env, &admin, &new_hash, 2);
    });

    let expected = ContractUpgradedEvent {
        old_wasm_hash: old_hash,
        new_wasm_hash: new_hash,
        authorizer: admin.clone(),
    };
    let all = env.events().all();
    assert_eq!(
        all.slice(all.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                indexer,
                (symbol_short!("UPGRADED"), admin).into_val(&env),
                expected.into_val(&env),
            )
        ]
    );
}

#[test]
fn test_failed_wasm_swap_rolls_back_version_and_tracked_hash() {
    let env = Env::default();
    let (indexer, _admin, _sas) = setup_upgrade_indexer(&env);
    let client = IndexerClient::new(&env, &indexer);
    let missing_hash = BytesN::from_array(&env, &[11u8; 32]);

    assert!(client.try_upgrade(&missing_hash, &2).is_err());
    assert_eq!(client.get_version(), 1);
    let tracked: Option<BytesN<32>> = env.as_contract(&indexer, || {
        env.storage().instance().get(&CURRENT_WASM_HASH)
    });
    assert_eq!(tracked, None);
}

#[test]
fn test_index_single_attestation() {
    let env = Env::default();
    let (indexer_id, _client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);
}

#[test]
fn reverse_pages_match_forward_history_across_chunk_boundaries() {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.budget().reset_unlimited();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    let schema = UID(BytesN::from_array(&env, &[3; 32]));
    assert!(client
        .get_atts_by_recipient_reverse(&recipient, &None, &10)
        .uids
        .is_empty());
    for n in 0..201u32 {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&n.to_be_bytes());
        let uid = UID(BytesN::from_array(&env, &raw));
        sas_client.relay_index(&indexer_id, &uid, &recipient, &schema, &attester, &0);
    }
    let forward = client.get_attestations_by_recipient(&recipient);
    for dimension in 0..3 {
        let mut cursor = None;
        let mut reverse = soroban_sdk::Vec::new(&env);
        loop {
            let page = match dimension {
                0 => client.get_atts_by_recipient_reverse(&recipient, &cursor, &37),
                1 => client.get_atts_by_schema_reverse(&schema, &cursor, &37),
                _ => client.get_atts_by_attester_reverse(&attester, &cursor, &37),
            };
            assert!(page.uids.len() <= 37);
            for uid in page.uids {
                reverse.push_back(uid);
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(reverse.len(), forward.len());
        for i in 0..forward.len() {
            assert_eq!(reverse.get(i), forward.get(forward.len() - 1 - i));
        }
    }
    assert!(client
        .get_atts_by_recipient_reverse(&recipient, &None, &0)
        .uids
        .is_empty());
    assert!(client
        .get_atts_by_recipient_reverse(&recipient, &Some(201), &10)
        .uids
        .is_empty());
    let exact_chunk = client.get_atts_by_recipient_reverse(&recipient, &Some(99), &100);
    assert_eq!(exact_chunk.uids.len(), 100);
    assert_eq!(exact_chunk.next_cursor, None);

    // Both pages touch one chunk despite the 201-item history. This budget
    // comparison guards against accidentally scanning from the head.
    env.budget().reset_unlimited();
    assert_eq!(
        client
            .get_atts_by_recipient_reverse(&recipient, &Some(199), &20)
            .uids
            .len(),
        20
    );
    let tail_cost = env.budget().cpu_instruction_cost();
    env.budget().reset_unlimited();
    assert_eq!(
        client
            .get_atts_by_recipient_reverse(&recipient, &Some(19), &20)
            .uids
            .len(),
        20
    );
    let head_cost = env.budget().cpu_instruction_cost();
    assert!(
        tail_cost < head_cost.saturating_mul(3),
        "tail={tail_cost}, head={head_cost}"
    );
}

/// Issue #450: `get_atts_by_*_recent` returns the newest `limit` entries,
/// newest first, deriving its start from the tail counter and walking
/// backward across chunk boundaries; it must agree with the reverse pages
/// and with reversing the forward history.
#[test]
fn recent_reads_return_newest_first_and_agree_with_reverse_pages() {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.budget().reset_unlimited();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    let schema = UID(BytesN::from_array(&env, &[21; 32]));

    let total = MAX_CHUNK_SIZE + 25; // 125: chunk 1 holds only 25 UIDs.
    let uid_at = |i: u32| {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&i.to_be_bytes());
        UID(BytesN::from_array(&env, &raw))
    };

    // A zero limit and an empty history are empty pages, never errors.
    assert!(client
        .get_atts_by_recipient_recent(&recipient, &0)
        .is_empty());
    assert_eq!(client.get_count_by_recipient(&recipient), 0);

    for i in 0..total {
        sas_client.relay_index(&indexer_id, &uid_at(i), &recipient, &schema, &attester, &0);
    }

    // Unfiltered recent is newest-first and matches the reverse reader.
    let recent = client.get_atts_by_recipient_recent(&recipient, &10);
    assert_eq!(recent.len(), 10);
    assert_eq!(recent.first(), Some(uid_at(total - 1)));
    assert_eq!(recent.last(), Some(uid_at(total - 10)));
    assert_eq!(
        recent,
        client
            .get_atts_by_recipient_reverse(&recipient, &None, &10)
            .uids
    );

    // A 30-entry page spans the boundary: 25 from chunk 1 then 5 from chunk 0.
    let spanning = client.get_atts_by_recipient_recent(&recipient, &30);
    assert_eq!(spanning.len(), 30);
    for i in 0..spanning.len() {
        assert_eq!(spanning.get(i), Some(uid_at(total - 1 - i)));
    }

    // Asking for more than exists returns everything, still descending.
    let all = client.get_atts_by_recipient_recent(&recipient, &(total + 50));
    assert_eq!(all.len(), total);
    assert_eq!(all.first(), Some(uid_at(total - 1)));
    assert_eq!(all.last(), Some(uid_at(0)));

    // Schema and attester variants share the same ordering.
    assert_eq!(client.get_atts_by_schema_recent(&schema, &30), spanning);
    assert_eq!(client.get_atts_by_attester_recent(&attester, &30), spanning);
}

/// Issue #450: active-only recent reads skip revoked/replaced UIDs while
/// walking backward, so the surviving entries stay in strictly descending
/// order even when the skip crosses a chunk boundary. The result must equal
/// the reversed forward filtered history and, with `include_revoked == true`,
/// the unfiltered recent read.
#[test]
fn recent_filtered_skips_revoked_in_descending_order() {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.budget().reset_unlimited();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    let schema = UID(BytesN::from_array(&env, &[22; 32]));

    let total = MAX_CHUNK_SIZE + 5; // 105: chunk 1 holds 5 UIDs.
    let revoked = 8; // Revoke the 8 newest UIDs (indices 97..104).
    let uid_at = |i: u32| {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&i.to_be_bytes());
        UID(BytesN::from_array(&env, &raw))
    };
    for i in 0..total {
        sas_client.relay_index(&indexer_id, &uid_at(i), &recipient, &schema, &attester, &0);
    }
    env.as_contract(&indexer_id, || {
        for i in (total - revoked)..total {
            set_index_status(&env, &uid_at(i), IndexStatus::Revoked);
        }
    });

    // The newest active UID is the first non-revoked one below the tail.
    let active = client.get_recipient_recent_filtered(&recipient, &10, &false);
    assert_eq!(active.len(), 10);
    assert_eq!(active.first(), Some(uid_at(total - revoked - 1)));
    for i in 0..active.len() {
        assert_eq!(active.get(i), Some(uid_at(total - revoked - 1 - i)));
    }

    // Consistency with the forward filtered history, reversed.
    let forward_active = client.get_recipient_filtered(&recipient, &false);
    assert_eq!(forward_active.len(), total - revoked);
    for i in 0..active.len() {
        assert_eq!(
            active.get(i),
            forward_active.get(forward_active.len() - 1 - i)
        );
    }

    // Historical mode ignores status and matches the unfiltered recent read.
    assert_eq!(
        client.get_recipient_recent_filtered(&recipient, &10, &true),
        client.get_atts_by_recipient_recent(&recipient, &10)
    );

    // Schema and attester filtered variants agree with the recipient read.
    assert_eq!(
        client.get_schema_recent_filtered(&schema, &10, &false),
        active
    );
    assert_eq!(
        client.get_attester_recent_filtered(&attester, &10, &false),
        active
    );

    // A limit past the active count returns every surviving UID.
    let all_active = client.get_recipient_recent_filtered(&recipient, &(total + 10), &false);
    assert_eq!(all_active.len(), total - revoked);
    assert_eq!(all_active.last(), Some(uid_at(0)));
}

/// Issue #450: the recent reads count toward the per-ledger query limit,
/// even when the key has never been indexed.
#[test]
fn recent_reads_enforce_the_per_ledger_query_limit() {
    let env = Env::default();
    let (_indexer_id, client, _sas) = setup_indexed(&env);
    env.budget().reset_unlimited();
    let unknown = Address::generate(&env);
    let unknown_schema = UID(BytesN::from_array(&env, &[0x66; 32]));

    assert!(client.get_atts_by_recipient_recent(&unknown, &5).is_empty());
    assert!(client
        .get_atts_by_schema_recent(&unknown_schema, &5)
        .is_empty());

    for _ in 2..MAX_QUERIES_PER_BLOCK {
        client.get_atts_by_attester_recent(&unknown, &1);
    }
    assert_eq!(
        client.try_get_recipient_recent_filtered(&unknown, &1, &false),
        Err(Ok(SASError::LimitExceeded.into()))
    );
}

/// A direct call from a bare test invocation (no authorizing contract in
/// the call stack) must be rejected: the indexer's trust boundary is the
/// bound SAS contract, not "whoever calls the entry point."
#[test]
fn test_index_attestation_rejects_direct_caller() {
    let env = Env::default();
    let (_indexer_id, client, _sas) = setup_indexed(&env);
    // `setup_indexed` mocks all auths for its own `init` call; clear that
    // back out so this call has no authorization, as the test intends.
    env.set_auths(&[]);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    let res = client.try_index_attestation(&uid, &recipient, &schema_uid, &attester, &0);
    assert!(res.is_err());
}

/// An arbitrary contract that is not the bound SAS contract cannot inject
/// UIDs into any of the three lookup tables.
#[test]
fn test_index_attestation_rejects_unrelated_contract() {
    let env = Env::default();
    let (indexer_id, _client, _sas) = setup_indexed(&env);
    let attacker = env.register_contract(None, mock_attacker::MockAttacker);
    let attacker_client = mock_attacker::MockAttackerClient::new(&env, &attacker);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[9u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[9u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    let res =
        attacker_client.try_relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

    assert!(res.is_err());

    let indexer_client = IndexerClient::new(&env, &indexer_id);
    assert_eq!(
        indexer_client
            .get_attestations_by_recipient(&recipient)
            .len(),
        0
    );
    assert_eq!(
        indexer_client.get_attestations_by_schema(&schema_uid).len(),
        0
    );
    assert_eq!(
        indexer_client.get_attestations_by_attester(&attester).len(),
        0
    );
}

/// Before `init`, there is no trusted SAS address to authorize against, so
/// writes must be rejected outright rather than silently accepted.
#[test]
fn test_index_attestation_rejects_before_init() {
    let env = Env::default();
    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    let res = client.try_index_attestation(&uid, &recipient, &schema_uid, &attester, &0);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::Unauthorized.into()))
    );
}

#[test]
fn test_reindexing_identical_metadata_is_a_no_op() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    // Same call three times — a retried cross-contract call / migration replay.

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);
    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);
    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

    assert_eq!(client.get_attestations_by_recipient(&recipient).len(), 1);
    assert_eq!(client.get_attestations_by_schema(&schema_uid).len(), 1);
    assert_eq!(client.get_attestations_by_attester(&attester).len(), 1);
}

/// Issue #220: `get_count_by_*` reads the same authoritative counter
/// `index_total` derives chunk cursors from, without fetching any UIDs.
#[test]
fn test_get_count_by_defaults_to_zero_for_unindexed_key() {
    let env = Env::default();
    let (_indexer_id, client, _sas) = setup_indexed(&env);

    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[9u8; 32]));
    let attester = Address::generate(&env);

    assert_eq!(client.get_count_by_recipient(&recipient), 0);
    assert_eq!(client.get_count_by_schema(&schema_uid), 0);
    assert_eq!(client.get_count_by_attester(&attester), 0);
}

#[test]
fn test_get_count_by_tracks_indexing_across_chunk_boundary() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);
    env.budget().reset_unlimited();

    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[9u8; 32]));
    let attester = Address::generate(&env);

    let total = MAX_CHUNK_SIZE + 1;
    for i in 0..total {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_be_bytes());
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));

        sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

        assert_eq!(client.get_count_by_recipient(&recipient), i + 1);
        assert_eq!(client.get_count_by_schema(&schema_uid), i + 1);
        assert_eq!(client.get_count_by_attester(&attester), i + 1);
    }

    // Counts agree with the full-history read length, across the
    // MAX_CHUNK_SIZE rollover.
    assert_eq!(
        client.get_count_by_recipient(&recipient),
        client.get_attestations_by_recipient(&recipient).len()
    );
    assert_eq!(
        client.get_count_by_schema(&schema_uid),
        client.get_attestations_by_schema(&schema_uid).len()
    );
    assert_eq!(
        client.get_count_by_attester(&attester),
        client.get_attestations_by_attester(&attester).len()
    );

    // Status transitions (Active -> Revoked/Replaced) don't decrement the
    // count: the UID remains indexed, only its filtered visibility changes.
    let uid0 = UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32]));
    env.as_contract(&indexer_id, || {
        set_index_status(&env, &uid0, IndexStatus::Revoked);
    });
    assert_eq!(client.get_count_by_recipient(&recipient), total);
}

#[test]
fn test_reusing_a_uid_with_a_different_recipient_is_rejected() {
    let env = Env::default();
    let (indexer_id, _client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let attester = Address::generate(&env);

    sas_client.relay_index(
        &indexer_id,
        &uid,
        &Address::generate(&env),
        &schema_uid,
        &attester,
        &0,
    );
    let res = sas_client.try_relay_index(
        &indexer_id,
        &uid,
        &Address::generate(&env),
        &schema_uid,
        &attester,
        &0,
    );
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::DuplicateAttestation.into()))
    );
}

#[test]
fn test_reusing_a_uid_with_a_different_schema_or_attester_is_rejected() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_a = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let schema_b = UID(soroban_sdk::BytesN::from_array(&env, &[3u8; 32]));
    let recipient = Address::generate(&env);
    let attester_a = Address::generate(&env);
    let attester_b = Address::generate(&env);

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_a, &attester_a, &0);

    let wrong_schema =
        sas_client.try_relay_index(&indexer_id, &uid, &recipient, &schema_b, &attester_a, &0);

    assert_eq!(
        wrong_schema,
        Err(Ok(soroban_sas_common::SASError::DuplicateAttestation.into()))
    );

    let wrong_attester =
        sas_client.try_relay_index(&indexer_id, &uid, &recipient, &schema_a, &attester_b, &0);

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
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    assert_eq!(client.get_attestation_status(&uid), None);

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

    // A freshly indexed UID has no explicit status entry; `None` is read as
    // active by the filtered queries.
    assert_eq!(client.get_attestation_status(&uid), None);
}

#[test]
fn test_reverse_lookup() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[4u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[10u8; 32]));
    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[11u8; 32]));

    sas_client.relay_index(&indexer_id, &uid1, &recipient, &schema_uid, &attester, &0);
    sas_client.relay_index(&indexer_id, &uid2, &recipient, &schema_uid, &attester, &0);

    let recipient_uids = client.get_attestations_by_recipient(&recipient);
    assert_eq!(recipient_uids.len(), 2);

    let schema_uids = client.get_attestations_by_schema(&schema_uid);
    assert_eq!(schema_uids.len(), 2);
}

#[test]
fn test_attester_indexing_large_datasets() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[5u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    for i in 0..50u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));

        sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);
    }

    let attester_uids = client.get_attestations_by_attester(&attester);
    assert_eq!(attester_uids.len(), 50);
}

#[test]
fn test_cursor_pagination_large_datasets() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[6u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    // Each `index_attestation` is its own transaction on-chain, with its own
    // budget; the test host accumulates all 101 into one. Reset so this
    // fixture (now writing the per-key counter to persistent storage, #219)
    // cannot exhaust the budget the assertions below need.
    env.budget().reset_unlimited();

    for i in 0..101u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));

        sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);
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

/// Indexes `total` UIDs (big-endian position in the first four bytes) under
/// one recipient/schema/attester triple through the bound mock SAS, and
/// returns them in insertion order.
fn index_sequential(
    env: &Env,
    indexer_id: &Address,
    sas: &Address,
    recipient: &Address,
    schema_uid: &UID,
    attester: &Address,
    total: u32,
) -> alloc::vec::Vec<UID> {
    let sas_client = mock::MockSasClient::new(env, sas);
    let mut uids = alloc::vec::Vec::new();
    for i in 0..total {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&i.to_be_bytes());
        let uid = UID(soroban_sdk::BytesN::from_array(env, &bytes));
        sas_client.relay_index(indexer_id, &uid, recipient, schema_uid, attester, &0);
        uids.push(uid);
    }
    uids
}

/// #306: all three dimensions page through the same history with the same
/// semantics — first, middle, and final pages; pages straddling the chunk
/// boundary; and empty results at/after the end, for `limit == 0`, and for
/// saturating cursor/limit values.
#[test]
fn test_paginated_reads_cover_every_dimension_and_boundary() {
    extern crate std;
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    env.budget().reset_unlimited();

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[8u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    let total = MAX_CHUNK_SIZE + 5;
    let expected = index_sequential(
        &env,
        &indexer_id,
        &sas,
        &recipient,
        &schema_uid,
        &attester,
        total,
    );

    #[allow(clippy::type_complexity)]
    let pages: [(&str, &dyn Fn(u32, u32) -> soroban_sdk::Vec<UID>); 3] = [
        ("recipient", &|c, l| {
            client.get_atts_by_recipient_paginated(&recipient, &c, &l)
        }),
        ("schema", &|c, l| {
            client.get_atts_by_schema_paginated(&schema_uid, &c, &l)
        }),
        ("attester", &|c, l| {
            client.get_atts_by_attester_paginated(&attester, &c, &l)
        }),
    ];
    for (dimension, page) in pages {
        let to_std = |v: soroban_sdk::Vec<UID>| v.iter().collect::<std::vec::Vec<_>>();

        // First page, a middle page straddling chunk 0 -> chunk 1, and the
        // final (short) page.
        assert_eq!(to_std(page(0, 10)), expected[0..10], "{dimension}");
        assert_eq!(to_std(page(95, 10)), expected[95..105], "{dimension}");
        assert_eq!(to_std(page(100, 10)), expected[100..105], "{dimension}");
        // Exactly at, and beyond, the end.
        assert!(page(total, 10).is_empty(), "{dimension}");
        assert!(page(total + 1, 10).is_empty(), "{dimension}");
        assert!(page(u32::MAX, u32::MAX).is_empty(), "{dimension}");
        // A zero limit never returns data.
        assert!(page(0, 0).is_empty(), "{dimension}");
        // An oversized limit is clamped to what exists without overflowing.
        assert_eq!(to_std(page(3, u32::MAX)), expected[3..], "{dimension}");

        // Walking with a page size that doesn't divide `total` reassembles
        // the complete read exactly: no duplicates, no gaps.
        let mut cursor = 0u32;
        let mut walked = std::vec::Vec::new();
        loop {
            let current = page(cursor, 7);
            if current.is_empty() {
                break;
            }
            cursor += current.len();
            walked.extend(current.iter());
        }
        assert_eq!(walked, expected, "{dimension}");
    }

    // Counts pair with pages for computing totals.
    assert_eq!(client.get_count_by_schema(&schema_uid), total);
    assert_eq!(client.get_count_by_attester(&attester), total);
}

/// #306: pages are stable while the index grows — appending new UIDs never
/// shifts an earlier page, so a caller resuming at `cursor + page.len()`
/// sees each UID exactly once.
#[test]
fn test_paginated_reads_are_stable_under_concurrent_appends() {
    extern crate std;
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    env.budget().reset_unlimited();

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[9u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    let first = index_sequential(
        &env,
        &indexer_id,
        &sas,
        &recipient,
        &schema_uid,
        &attester,
        4,
    );

    let page_one = client.get_atts_by_schema_paginated(&schema_uid, &0, &3);
    assert_eq!(page_one.iter().collect::<std::vec::Vec<_>>(), first[0..3]);

    // A new attestation lands between the caller's page requests.
    let late = UID(soroban_sdk::BytesN::from_array(&env, &[0xEEu8; 32]));
    mock::MockSasClient::new(&env, &sas).relay_index(
        &indexer_id,
        &late,
        &recipient,
        &schema_uid,
        &attester,
        &0,
    );

    // The earlier page is unchanged and the next page picks up where it
    // left off, then the appended UID.
    assert_eq!(
        client.get_atts_by_schema_paginated(&schema_uid, &0, &3),
        page_one
    );
    let page_two = client.get_atts_by_schema_paginated(&schema_uid, &page_one.len(), &3);
    assert_eq!(
        page_two.iter().collect::<std::vec::Vec<_>>(),
        std::vec![first[3].clone(), late]
    );
}

/// #306: an unknown key pages as empty without creating storage, and the
/// new reads count toward the per-ledger query cap like the recipient read.
#[test]
fn test_paginated_reads_of_unknown_keys_are_empty_and_rate_limited() {
    let env = Env::default();
    let (_indexer_id, client, _sas) = setup_indexed(&env);
    env.budget().reset_unlimited();
    let unknown_schema = UID(soroban_sdk::BytesN::from_array(&env, &[0x55u8; 32]));
    let unknown_attester = Address::generate(&env);

    assert!(client
        .get_atts_by_schema_paginated(&unknown_schema, &0, &10)
        .is_empty());
    assert!(client
        .get_atts_by_attester_paginated(&unknown_attester, &0, &10)
        .is_empty());

    for _ in 2..MAX_QUERIES_PER_BLOCK {
        client.get_atts_by_attester_paginated(&unknown_attester, &0, &1);
    }
    assert_eq!(
        client.try_get_atts_by_schema_paginated(&unknown_schema, &0, &1),
        Err(Ok(SASError::LimitExceeded.into()))
    );
}

/// Once the instance TTL (holding INDEXER_ADMIN and SAS_CONTRACT) has
/// decayed close to expiry, ordinary write traffic (`index_attestation`)
/// must renew it. Exercised by jumping the ledger forward by nearly the
/// full renewal window twice in a row, indexing an attestation in between
/// each jump; if `index_attestation` did not renew the TTL, the second
/// call would panic on an archived instance.
#[test]
fn test_index_attestation_renews_decayed_instance_ttl() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let (indexer_id, _client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[7u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_EXTEND_TO_LEDGERS - 1000;
    });
    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[8u8; 32]));

    sas_client.relay_index(&indexer_id, &uid1, &recipient, &schema_uid, &attester, &0);

    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_EXTEND_TO_LEDGERS - 1000;
    });
    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[9u8; 32]));

    sas_client.relay_index(&indexer_id, &uid2, &recipient, &schema_uid, &attester, &0);
}

#[test]
fn test_instance_ttl_renewed_by_trusted_write_and_read() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);
    let admin = client.get_admin().expect("admin set by setup_indexed");

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[7u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_EXTEND_TO_LEDGERS - 1000;
    });
    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[8u8; 32]));

    sas_client.relay_index(&indexer_id, &uid1, &recipient, &schema_uid, &attester, &0);

    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_EXTEND_TO_LEDGERS - 1000;
    });
    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[9u8; 32]));

    sas_client.relay_index(&indexer_id, &uid2, &recipient, &schema_uid, &attester, &0);

    // get_admin/get_sas read instance storage directly; if the instance
    // had expired, these would panic rather than returning stale data.
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

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

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
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);
    let admin = client.get_admin().expect("admin set by setup_indexed");

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[88u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[89u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

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
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

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

        sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);
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

/// Issue #219: per-key UID counters (`RCOUNT`/`SCOUNT`/`ACOUNT`) live in
/// persistent storage, not instance storage, so they cannot silently reset
/// to zero if instance storage's independent expiry lapses. Simulates a
/// total instance storage wipe (the worst case of "instance expired") by
/// directly removing every instance key the contract uses, then proves the
/// counter is still readable, correct, and — critically — that indexing a
/// further UID for the same key appends rather than duplicating chunk 0.
#[test]
fn test_recipient_counter_survives_simulated_instance_storage_expiry() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[7u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));

    sas_client.relay_index(&indexer_id, &uid1, &recipient, &schema_uid, &attester, &0);

    let count_key = (RECIPIENT_TOTAL, recipient.clone());
    env.as_contract(&indexer_id, || {
        assert_eq!(
            env.storage().persistent().get::<_, u32>(&count_key),
            Some(1)
        );
        // Simulate instance storage having expired entirely: this is exactly
        // where the counter used to live (#219). Wiping it must not touch
        // the persistent counter or the chunk it counts.
        env.storage().instance().remove(&INDEXER_ADMIN);
        env.storage().instance().remove(&SAS_CONTRACT);
        env.storage().instance().remove(&INDEXER_VERSION);
    });

    env.as_contract(&indexer_id, || {
        assert_eq!(
            env.storage().persistent().get::<_, u32>(&count_key),
            Some(1),
            "counter must survive an instance storage wipe"
        );
    });
    assert_eq!(client.get_attestations_by_recipient(&recipient).len(), 1);

    // `index_attestation` only needs `SAS_CONTRACT` to authorize the caller,
    // so restore just that (as `init` originally set it) and index a second
    // UID for the same recipient. With the old instance-backed counter this
    // would have read back 0, recomputed chunk_index 0, and appended into
    // the still-full-of-one chunk 0 as an overwrite/duplicate rather than a
    // clean append at index 1.
    env.as_contract(&indexer_id, || {
        env.storage().instance().set(&SAS_CONTRACT, &sas);
    });

    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));

    sas_client.relay_index(&indexer_id, &uid2, &recipient, &schema_uid, &attester, &0);

    env.as_contract(&indexer_id, || {
        assert_eq!(
            env.storage().persistent().get::<_, u32>(&count_key),
            Some(2)
        );
    });
    let all = client.get_attestations_by_recipient(&recipient);
    assert_eq!(all.len(), 2);
    assert_eq!(all.get(0), Some(uid1));
    assert_eq!(all.get(1), Some(uid2));
}

/// Issue #79: reading a recipient index renews the TTL of the chunks it
/// touches, so a hot-but-static index is not archived out from under callers.
#[test]
fn test_recipient_read_preserves_hot_index_ttl() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[11u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[12u8; 32]));

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

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

/// Issue #80: reading a schema index renews the TTL of the chunks it touches,
/// so a widely queried but static schema is not archived out from under
/// callers.
#[test]
fn test_schema_read_preserves_hot_index_ttl() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[21u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[22u8; 32]));

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

    let chunk_key = (schema_uid.clone(), 0u32);
    let at_write = chunk_live_until(&env, &chunk_key).expect("chunk written");

    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    assert_eq!(chunk_live_until(&env, &chunk_key), Some(at_write));

    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    assert_eq!(client.get_attestations_by_schema(&schema_uid).len(), 1);
    assert_eq!(chunk_live_until(&env, &chunk_key), Some(expected));

    // The filtered view renews too.
    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    assert_eq!(client.get_schema_filtered(&schema_uid, &true).len(), 1);
    assert_eq!(chunk_live_until(&env, &chunk_key), Some(expected));
}

/// Issue #81: reading an attester index renews the TTL of the chunks it
/// touches, so issuer history is not archived while consumers actively query
/// it.
#[test]
fn test_attester_read_preserves_hot_index_ttl() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[23u8; 32]));
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[24u8; 32]));

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

    let chunk_key = (attester.clone(), 0u32);
    let at_write = chunk_live_until(&env, &chunk_key).expect("chunk written");

    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    assert_eq!(chunk_live_until(&env, &chunk_key), Some(at_write));

    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    assert_eq!(client.get_attestations_by_attester(&attester).len(), 1);
    assert_eq!(chunk_live_until(&env, &chunk_key), Some(expected));

    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    assert_eq!(client.get_attester_filtered(&attester, &true).len(), 1);
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
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

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
        sas_client.relay_index(
            &indexer_id,
            &uid_at(i),
            &recipient,
            &schema_uid,
            &attester,
            &0,
        );
    }

    // Revoke everything in chunk 0, leaving only the single UID in chunk 1.
    env.as_contract(&indexer_id, || {
        for i in 0..MAX_CHUNK_SIZE {
            set_index_status(&env, &uid_at(i), IndexStatus::Revoked);
        }
    });

    // The active-only scan walks past all 100 revoked entries and returns the
    // one live UID from the next chunk.
    let active = client.get_recipient_page_filtered(&recipient, &0, &5, &false);
    assert_eq!(active.len(), 1);
    assert_eq!(active.first(), Some(uid_at(MAX_CHUNK_SIZE)));
    assert_eq!(client.get_recipient_filtered(&recipient, &false).len(), 1);

    // The historical view is unaffected by status.
    let historical = client.get_recipient_page_filtered(&recipient, &0, &5, &true);
    assert_eq!(historical.len(), 5);
    assert_eq!(historical.first(), Some(uid_at(0)));
    assert_eq!(
        client.get_recipient_filtered(&recipient, &true).len(),
        total
    );

    // A cursor landing inside the second chunk still resolves.
    let tail = client.get_recipient_page_filtered(&recipient, &MAX_CHUNK_SIZE, &5, &false);
    assert_eq!(tail.len(), 1);
}

#[test]
fn test_chunk_boundaries_99_100_101_and_multiple_keys() {
    extern crate std;
    let mut pairs = std::vec::Vec::new();
    for i in 0u32..101 {
        for key in [[0; 4], [1; 4]] {
            let mut uid = [0; 32];
            uid[..4].copy_from_slice(&i.to_be_bytes());
            pairs.push((key, uid));
        }
    }
    chunking_test_support::check_chunking(&pairs);
}

#[test]
fn test_chunking_seed_boundaries() {
    extern crate std;
    for count in [0, 1, 100, 101, 200, 201, 300, 301] {
        let pairs = std::vec![([0; 4], [7; 32]); count];
        chunking_test_support::check_chunking(&pairs);
    }
}

/// Issue #310: `get_*_by_issuer` reads must agree with the corresponding
/// `get_*_by_attester` reads, since "issuer" is the attester dimension under
/// the naming attestation issuers actually look up by.
#[test]
fn test_get_by_issuer_matches_get_by_attester_happy_path() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let issuer = Address::generate(&env);
    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[3u8; 32]));

    assert_eq!(client.get_count_by_issuer(&issuer), 0);
    assert_eq!(client.get_attestations_by_issuer(&issuer).len(), 0);

    for i in 0u8..5 {
        let mut bytes = [0u8; 32];
        bytes[0] = i;
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));

        sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &issuer, &0);
    }

    assert_eq!(client.get_count_by_issuer(&issuer), 5);
    assert_eq!(
        client.get_count_by_issuer(&issuer),
        client.get_count_by_attester(&issuer)
    );
    assert_eq!(
        client.get_attestations_by_issuer(&issuer),
        client.get_attestations_by_attester(&issuer)
    );
    assert_eq!(
        client.get_atts_by_issuer_paginated(&issuer, &0, &3),
        client.get_atts_by_attester_paginated(&issuer, &0, &3)
    );
    assert_eq!(
        client.get_issuer_filtered(&issuer, &true),
        client.get_attester_filtered(&issuer, &true)
    );
    assert_eq!(
        client
            .get_issuer_page_filtered(&issuer, &0, &3, &true)
            .len(),
        3
    );
    assert_eq!(
        client.get_issuer_page_filtered(&issuer, &0, &3, &true),
        client.get_atts_by_issuer_paginated(&issuer, &0, &3)
    );
}

/// Issue #310: an issuer with no indexed attestations reads as empty rather
/// than trapping, matching the other lookup dimensions (see
/// `test_get_count_by_defaults_to_zero_for_unindexed_key`).
#[test]
fn test_get_by_issuer_unindexed_key_is_empty() {
    let env = Env::default();
    let (_indexer_id, client, _sas) = setup_indexed(&env);

    let issuer = Address::generate(&env);

    assert_eq!(client.get_count_by_issuer(&issuer), 0);
    assert_eq!(client.get_attestations_by_issuer(&issuer).len(), 0);
    assert_eq!(
        client.get_atts_by_issuer_paginated(&issuer, &0, &10).len(),
        0
    );
    assert_eq!(client.get_issuer_filtered(&issuer, &true).len(), 0);
    assert_eq!(
        client
            .get_issuer_page_filtered(&issuer, &0, &10, &true)
            .len(),
        0
    );
}

/// Issue #310: revoked UIDs are hidden from the active-only issuer views,
/// same as the attester views (see `test_filtered_pagination_skips_a_full_chunk_of_revoked_uids`).
#[test]
fn test_get_by_issuer_filtered_excludes_revoked() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let issuer = Address::generate(&env);
    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[4u8; 32]));
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[5u8; 32]));

    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &issuer, &0);

    env.as_contract(&indexer_id, || {
        set_index_status(&env, &uid, IndexStatus::Revoked);
    });

    assert_eq!(client.get_issuer_filtered(&issuer, &true).len(), 1);
    assert_eq!(client.get_issuer_filtered(&issuer, &false).len(), 0);
    assert_eq!(
        client
            .get_issuer_page_filtered(&issuer, &0, &10, &false)
            .len(),
        0
    );
    // Count is unaffected by status: the UID stays indexed.
    assert_eq!(client.get_count_by_issuer(&issuer), 1);
}

/// `live_until_ledger` recorded for `contract`'s instance entry, read from
/// the ledger snapshot the same way as [`chunk_live_until`].
fn instance_live_until(env: &Env, contract: &Address) -> Option<u32> {
    use soroban_sdk::xdr::{LedgerKey, ScAddress, ScVal};

    let target = ScAddress::from(contract);
    env.to_ledger_snapshot()
        .ledger_entries
        .iter()
        .find_map(|(key, (_, live_until))| match &**key {
            LedgerKey::ContractData(data)
                if data.contract == target && data.key == ScVal::LedgerKeyContractInstance =>
            {
                *live_until
            }
            _ => None,
        })
}

/// A UID made of `raw`.
fn raw_uid(env: &Env, raw: [u8; 32]) -> UID {
    UID(BytesN::from_array(env, &raw))
}

/// The UID `index_sequential` assigns to `position`: its big-endian bytes,
/// then zeros.
fn sequential_uid(env: &Env, position: u32) -> UID {
    let mut raw = [0u8; 32];
    raw[0..4].copy_from_slice(&position.to_be_bytes());
    raw_uid(env, raw)
}

/// Whether `indexer` stores an `(INDEXED_KEY, uid)` record, read directly.
fn has_index_record(env: &Env, indexer: &Address, uid: &UID) -> bool {
    let record_key = (INDEXED_KEY, uid.clone());
    env.as_contract(indexer, || env.storage().persistent().has(&record_key))
}

/// The per-ledger query counter in `indexer`'s instance storage, once a
/// rate-limited read has set it.
fn query_count(env: &Env, indexer: &Address) -> Option<u32> {
    let key = QUERY_COUNTER_COUNT;
    env.as_contract(indexer, || env.storage().instance().get(&key))
}

/// #542: `is_attestation_indexed` answers from the direct record across
/// varied UID sets: attestations scattered over distinct recipients,
/// schemas and attesters, one key's history rolling over into a second
/// chunk, and UIDs that were never indexed, including near misses of
/// indexed ones and schema UIDs, which only exist as chunk key prefixes.
#[test]
fn test_is_attestation_indexed_across_varied_uid_sets() {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);
    // The 101-entry history below accumulates into one test budget.
    env.budget().reset_unlimited();

    // Scattered: each UID has its own recipient, schema and attester.
    let mut scattered = alloc::vec::Vec::new();
    for n in 1..=5u8 {
        let uid = raw_uid(&env, [0xa0 | n; 32]);
        let schema_uid = raw_uid(&env, [0xb0 | n; 32]);
        let recipient = Address::generate(&env);
        let attester = Address::generate(&env);
        assert!(!client.is_attestation_indexed(&uid));
        sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);
        assert!(client.is_attestation_indexed(&uid));
        scattered.push((uid, schema_uid));
    }

    // Sequential: one key's history across the first chunk boundary.
    let recipient = Address::generate(&env);
    let schema_uid = raw_uid(&env, [0x5c; 32]);
    let attester = Address::generate(&env);
    let total = MAX_CHUNK_SIZE + 1;
    let history = index_sequential(
        &env,
        &indexer_id,
        &sas,
        &recipient,
        &schema_uid,
        &attester,
        total,
    );
    for uid in &history {
        assert!(client.is_attestation_indexed(uid));
    }
    // Later writes leave earlier verdicts unchanged.
    for (uid, _) in &scattered {
        assert!(client.is_attestation_indexed(uid));
    }

    // Never indexed: the next sequential position, a one-byte near miss of
    // the first sequential UID (all zeros), the next scattered pattern and
    // an all-ones UID.
    let mut near_miss = [0u8; 32];
    near_miss[31] = 1;
    let unindexed = [
        sequential_uid(&env, total),
        raw_uid(&env, near_miss),
        raw_uid(&env, [0xa6; 32]),
        raw_uid(&env, [0xff; 32]),
    ];
    for uid in &unindexed {
        assert!(!client.is_attestation_indexed(uid));
    }
    // Schema UIDs key their chunks as `(schema_uid, chunk)`, but were never
    // indexed as attestations.
    assert!(!client.is_attestation_indexed(&schema_uid));
    for (_, scattered_schema) in &scattered {
        assert!(!client.is_attestation_indexed(scattered_schema));
    }

    // An identical retry keeps the UID indexed, and so do lifecycle
    // changes: revoked and replaced UIDs stay in the history.
    let first = &history[0];
    sas_client.relay_index(&indexer_id, first, &recipient, &schema_uid, &attester, &0);
    env.as_contract(&indexer_id, || {
        set_index_status(&env, first, IndexStatus::Revoked);
        set_index_status(&env, &history[1], IndexStatus::Replaced);
    });
    assert!(client.is_attestation_indexed(first));
    assert!(client.is_attestation_indexed(&history[1]));
}

/// #542: looking up UIDs that were never indexed writes nothing. The ledger
/// holds exactly the same entries afterwards, no index record exists for
/// them, and unlike the paginated reads the lookup leaves the per-ledger
/// query counter in instance storage untouched, so the call stays
/// read-only.
#[test]
fn test_is_attestation_indexed_unknown_uid_creates_no_storage() {
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);
    let recipient = Address::generate(&env);
    let schema_uid = raw_uid(&env, [0x21; 32]);
    let attester = Address::generate(&env);
    let indexed = raw_uid(&env, [0x22; 32]);
    sas_client.relay_index(
        &indexer_id,
        &indexed,
        &recipient,
        &schema_uid,
        &attester,
        &0,
    );

    let entries_before = env.to_ledger_snapshot().ledger_entries;
    let unknown = [
        raw_uid(&env, [0x23; 32]),
        raw_uid(&env, [0x00; 32]),
        raw_uid(&env, [0xff; 32]),
    ];
    for uid in &unknown {
        assert!(!client.is_attestation_indexed(uid));
    }
    assert!(client.is_attestation_indexed(&indexed));
    assert_eq!(env.to_ledger_snapshot().ledger_entries, entries_before);

    for uid in &unknown {
        assert!(!has_index_record(&env, &indexer_id, uid));
        assert_eq!(chunk_live_until(&env, &(INDEXED_KEY, uid.clone())), None);
    }
    assert_eq!(query_count(&env, &indexer_id), None);
    // Control: a paginated read does write the counter.
    assert_eq!(
        client
            .get_atts_by_recipient_paginated(&recipient, &0, &10)
            .len(),
        1
    );
    assert_eq!(query_count(&env, &indexer_id), Some(1));
}

/// #542: a lookup renews the instance TTL, and the record's TTL when the
/// UID is indexed, so a UID that is only ever checked stays live. Looking
/// up an unknown UID renews the instance too and still leaves no record.
#[test]
fn test_is_attestation_indexed_renews_instance_and_record_ttl() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);
    let recipient = Address::generate(&env);
    let schema_uid = raw_uid(&env, [0x31; 32]);
    let attester = Address::generate(&env);
    let uid = raw_uid(&env, [0x32; 32]);
    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

    let record_key = (INDEXED_KEY, uid.clone());
    let at_write = chunk_live_until(&env, &record_key).expect("record written");

    // Let half the retention window elapse without any write.
    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    assert_eq!(chunk_live_until(&env, &record_key), Some(at_write));

    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    assert!(client.is_attestation_indexed(&uid));
    assert_eq!(chunk_live_until(&env, &record_key), Some(expected));
    assert_eq!(instance_live_until(&env, &indexer_id), Some(expected));

    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    let unknown = raw_uid(&env, [0x33; 32]);
    assert!(!client.is_attestation_indexed(&unknown));
    assert_eq!(instance_live_until(&env, &indexer_id), Some(expected));
    assert!(!has_index_record(&env, &indexer_id, &unknown));
}

/// CPU instructions and memory bytes the test host metered for a call.
#[derive(Clone, Copy, Default)]
struct Metered {
    cpu: u64,
    mem: u64,
}

impl core::fmt::Display for Metered {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cpu={} mem={}", self.cpu, self.mem)
    }
}

impl core::ops::AddAssign for Metered {
    fn add_assign(&mut self, other: Self) {
        self.cpu += other.cpu;
        self.mem += other.mem;
    }
}

/// Runs `f` on a freshly reset budget and returns its result along with
/// what the test host metered for it.
fn measure<T>(env: &Env, f: impl FnOnce() -> T) -> (T, Metered) {
    env.budget().reset_default();
    let result = f();
    let budget = env.budget();
    let cost = Metered {
        cpu: budget.cpu_instruction_cost(),
        mem: budget.memory_bytes_cost(),
    };
    (result, cost)
}

/// Answers "is `uid` indexed?" the way a caller had to before #542: page
/// through `recipient`'s history one chunk-sized page at a time until the
/// UID shows up or the history ends.
fn chunk_walk_finds(client: &IndexerClient<'_>, recipient: &Address, uid: &UID) -> bool {
    let mut cursor = 0u32;
    loop {
        let page = client.get_atts_by_recipient_paginated(recipient, &cursor, &MAX_CHUNK_SIZE);
        if page.is_empty() {
            return false;
        }
        if page.contains(uid) {
            return true;
        }
        cursor += page.len();
    }
}

/// #542: answering "is this UID indexed?" from the direct record costs at
/// least 70% fewer CPU instructions than walking the recipient's paginated
/// chunks for the same UIDs. The probes cover the first, last and boundary
/// positions of a three-chunk history, plus UIDs that were never indexed,
/// for which the walk has to read every chunk. Each lookup is metered on a
/// freshly reset budget, and the direct lookup runs first, so it pays any
/// first-access cost for its key. Run with `--nocapture` to print the
/// measurements.
#[test]
fn test_is_attestation_indexed_cpu_is_70_percent_below_chunk_walk() {
    extern crate std;
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let (indexer_id, client, sas) = setup_indexed(&env);
    // Building the history accumulates into one test budget; every
    // measurement below starts from a reset one.
    env.budget().reset_unlimited();
    let recipient = Address::generate(&env);
    let schema_uid = raw_uid(&env, [0x42; 32]);
    let attester = Address::generate(&env);
    // Three chunks: 100, 100 and 50 UIDs.
    let total = 250u32;
    let history = index_sequential(
        &env,
        &indexer_id,
        &sas,
        &recipient,
        &schema_uid,
        &attester,
        total,
    );

    let mut probes = alloc::vec::Vec::new();
    for position in [0usize, 1, 99, 100, 149, 199, 200, 249] {
        probes.push((history[position].clone(), true));
    }
    let mut near_miss = [0u8; 32];
    near_miss[31] = 1;
    let unindexed = [
        sequential_uid(&env, total),
        raw_uid(&env, near_miss),
        schema_uid,
        raw_uid(&env, [0xff; 32]),
    ];
    probes.extend(unindexed.map(|uid| (uid, false)));

    let mut direct = Metered::default();
    let mut walk = Metered::default();
    for (uid, indexed) in &probes {
        let (found, lookup_cost) = measure(&env, || client.is_attestation_indexed(uid));
        let (walked, walk_cost) = measure(&env, || chunk_walk_finds(&client, &recipient, uid));
        assert_eq!(found, *indexed);
        assert_eq!(walked, *indexed);
        assert!(
            lookup_cost.cpu < walk_cost.cpu,
            "direct {lookup_cost}, chunk walk {walk_cost}"
        );
        std::println!("indexed={indexed}: direct {lookup_cost}, chunk walk {walk_cost}");
        direct += lookup_cost;
        walk += walk_cost;
    }
    std::println!("total: direct {direct}, chunk walk {walk}");
    // At least 70% lower means at most 30% of the chunk walk.
    assert!(
        direct.cpu.saturating_mul(10) <= walk.cpu.saturating_mul(3),
        "direct {direct}, chunk walk {walk}"
    );
    assert!(direct.mem < walk.mem, "direct {direct}, chunk walk {walk}");
}

/// Test that index_attestation is idempotent: replaying the same attestation
/// with identical metadata is a no-op and doesn't cause duplicates.
#[test]
fn test_index_attestation_idempotent_replay() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let attester = Address::generate(&env);
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[10u8; 32]));

    // Index the attestation once
    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);
    assert_eq!(client.get_count_by_recipient(&recipient), 1);
    assert_eq!(client.get_count_by_schema(&schema_uid), 1);
    assert_eq!(client.get_count_by_attester(&attester), 1);

    // Replay the same attestation with identical metadata (simulating
    // a bulk_reindex replay after an indexer outage). This should be a no-op.
    sas_client.relay_index(&indexer_id, &uid, &recipient, &schema_uid, &attester, &0);

    // Verify counts haven't changed (no duplicates)
    assert_eq!(client.get_count_by_recipient(&recipient), 1);
    assert_eq!(client.get_count_by_schema(&schema_uid), 1);
    assert_eq!(client.get_count_by_attester(&attester), 1);

    // Verify the UID appears exactly once in the index
    let recipient_uids = client.get_attestations_by_recipient(&recipient);
    assert_eq!(recipient_uids.len(), 1);
    assert_eq!(recipient_uids.get(0), Some(uid));
}

/// Test that simulates bulk_reindex partial failure scenario: some UIDs succeed
/// before failure, then retrying the entire batch doesn't create duplicates.
#[test]
fn test_bulk_reindex_partial_failure_idempotency() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let attester = Address::generate(&env);

    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[10u8; 32]));
    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[11u8; 32]));
    let uid3 = UID(soroban_sdk::BytesN::from_array(&env, &[12u8; 32]));

    // Simulate initial indexing: first two succeed, third "fails" (not indexed)
    sas_client.relay_index(&indexer_id, &uid1, &recipient, &schema_uid, &attester, &0);
    sas_client.relay_index(&indexer_id, &uid2, &recipient, &schema_uid, &attester, &0);
    // uid3 not indexed yet

    assert_eq!(client.get_count_by_recipient(&recipient), 2);

    // Now retry all three (simulating bulk_reindex after fixing the issue)
    sas_client.relay_index(&indexer_id, &uid1, &recipient, &schema_uid, &attester, &0);
    sas_client.relay_index(&indexer_id, &uid2, &recipient, &schema_uid, &attester, &0);
    sas_client.relay_index(&indexer_id, &uid3, &recipient, &schema_uid, &attester, &0);

    // Verify no duplicates: should still be 3 total (not 5)
    assert_eq!(client.get_count_by_recipient(&recipient), 3);
    assert_eq!(client.get_count_by_schema(&schema_uid), 3);
    assert_eq!(client.get_count_by_attester(&attester), 3);

    // Verify all three UIDs are present exactly once
    let recipient_uids = client.get_attestations_by_recipient(&recipient);
    assert_eq!(recipient_uids.len(), 3);
    assert!(recipient_uids.contains(&uid1));
    assert!(recipient_uids.contains(&uid2));
    assert!(recipient_uids.contains(&uid3));
}

/// Test expiration status indexing: perpetual attestations are indexed
/// separately from expiring attestations.
#[test]
fn test_expiration_status_indexing() {
    let env = Env::default();
    let (indexer_id, client, sas) = setup_indexed(&env);
    let sas_client = mock::MockSasClient::new(&env, &sas);

    let recipient = Address::generate(&env);
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let attester = Address::generate(&env);

    // Index a perpetual attestation (expiration_time == 0)
    let uid_perpetual = UID(soroban_sdk::BytesN::from_array(&env, &[10u8; 32]));
    sas_client.relay_index(
        &indexer_id,
        &uid_perpetual,
        &recipient,
        &schema_uid,
        &attester,
        &0, // expiration_time = 0 means perpetual
    );

    // Index an expiring attestation (expiration_time > 0)
    let uid_expiring = UID(soroban_sdk::BytesN::from_array(&env, &[11u8; 32]));
    sas_client.relay_index(
        &indexer_id,
        &uid_expiring,
        &recipient,
        &schema_uid,
        &attester,
        &9999999999, // far future expiration
    );

    // Verify counts by expiration status
    assert_eq!(
        client.get_count_by_expiration(&ExpirationStatus::Perpetual),
        1
    );
    assert_eq!(
        client.get_count_by_expiration(&ExpirationStatus::Expiring),
        1
    );

    // Verify attestations are in the correct buckets
    let perpetual_uids = client.get_attestations_by_expiration(&ExpirationStatus::Perpetual);
    assert_eq!(perpetual_uids.len(), 1);
    assert_eq!(perpetual_uids.get(0), Some(uid_perpetual.clone()));

    let expiring_uids = client.get_attestations_by_expiration(&ExpirationStatus::Expiring);
    assert_eq!(expiring_uids.len(), 1);
    assert_eq!(expiring_uids.get(0), Some(uid_expiring.clone()));

    // Add more attestations to test chunking
    for i in 0..50u8 {
        let mut bytes = [0u8; 32];
        bytes[0] = 20 + i;
        let uid = UID(soroban_sdk::BytesN::from_array(&env, &bytes));
        let expiration = if i % 2 == 0 { 0 } else { 9999999999 };
        sas_client.relay_index(
            &indexer_id,
            &uid,
            &recipient,
            &schema_uid,
            &attester,
            &expiration,
        );
    }

    // Verify updated counts
    assert_eq!(
        client.get_count_by_expiration(&ExpirationStatus::Perpetual),
        26 // 1 original + 25 new
    );
    assert_eq!(
        client.get_count_by_expiration(&ExpirationStatus::Expiring),
        26 // 1 original + 25 new
    );

    // Test pagination
    let page = client.get_atts_by_expiration_paginated(&ExpirationStatus::Perpetual, &0, &10);
    assert_eq!(page.len(), 10);
}
