use crate::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::{SchemaRegisteredEvent, INSTANCE_EXTEND_TO_LEDGERS};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
use soroban_sdk::{symbol_short, Address, Env, IntoVal, String};
use soroban_sas_common::{
    ContractUpgradedEvent, SchemaFeeUpdatedEvent, SchemaRegisteredEvent, TreasuryUpdatedEvent,
};
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{symbol_short, Address, BytesN, Env, IntoVal, String};

#[test]
fn test_register_schema() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    let uid = client.register(&owner, &schema_str, &resolver, &true);
    let record = client.get_schema(&uid).unwrap();

    assert_eq!(record.schema, schema_str);
    assert!(record.revocable);
    assert_eq!(record.resolver, resolver);
}

#[test]
fn test_register_rejects_malformed_schema_strings() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let resolver = Address::generate(&env);

    env.mock_all_auths();

    for schema in ["!!!", " ", "12345"] {
        let schema = String::from_str(&env, schema);
        let res = client.try_register(&owner, &schema, &resolver, &true);
        assert_eq!(res, Err(Ok(soroban_sas_common::SASError::InvalidSchema.into())));
    }
}

#[test]
fn test_register_emits_schema_registered_event() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    let uid = client.register(&owner, &schema_str, &resolver, &true);

    let expected = SchemaRegisteredEvent {
        schema_uid: uid.clone(),
        owner: owner.clone(),
    };
    assert_eq!(
        env.events().all(),
        soroban_sdk::vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("REGISTER"), uid.clone()).into_val(&env),
                expected.into_val(&env),
            )
        ]
    );
}

/*
#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn test_duplicate_schema() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    // First registration succeeds
    client.register(&schema_str, &resolver, &true);

    // Second registration with exactly the same parameters should panic
    // (SASError::SchemaAlreadyExists is #2 assuming it's the second variant)
    client.register(&schema_str, &resolver, &true);
}
*/

/*
#[test]
fn test_upgrade() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);

    // Simulate upgrade call (we mock the wasm hash)
    let new_wasm_hash = BytesN::from_array(&env, &[0u8; 32]);

    // In tests, environment requires mock auth setup for `admin.require_auth()`
    env.mock_all_auths();

    client.upgrade(&new_wasm_hash);
}
*/

#[test]
fn test_fee_and_treasury() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    client.init(&admin);

    env.mock_all_auths();
    client.set_fee(&1000);
    client.set_treasury(&treasury);
    client.withdraw_fees(&500);
}

#[test]
fn test_set_fee_emits_event_with_old_and_new_value() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);
    env.mock_all_auths();

    client.set_fee(&1000);
    let expected_first = SchemaFeeUpdatedEvent {
        old_fee: None,
        new_fee: 1000,
        authorizer: admin.clone(),
    };
    let events = env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("FEEUPD"), admin.clone()).into_val(&env),
                expected_first.into_val(&env),
            )
        ]
    );

    client.set_fee(&2000);
    let expected_second = SchemaFeeUpdatedEvent {
        old_fee: Some(1000),
        new_fee: 2000,
        authorizer: admin.clone(),
    };
    let events = env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                contract_id,
                (symbol_short!("FEEUPD"), admin).into_val(&env),
                expected_second.into_val(&env),
            )
        ]
    );
}

#[test]
fn test_set_fee_requires_admin_auth() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);

    let res = client.try_set_fee(&1000);
    assert!(res.is_err());
}

#[test]
fn test_set_treasury_emits_event_with_old_and_new_value() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury_one = Address::generate(&env);
    let treasury_two = Address::generate(&env);
    client.init(&admin);
    env.mock_all_auths();

    client.set_treasury(&treasury_one);
    let expected_first = TreasuryUpdatedEvent {
        old_treasury: None,
        new_treasury: treasury_one.clone(),
        authorizer: admin.clone(),
    };
    let events = env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("TRSUPD"), admin.clone()).into_val(&env),
                expected_first.into_val(&env),
            )
        ]
    );

    client.set_treasury(&treasury_two);
    let expected_second = TreasuryUpdatedEvent {
        old_treasury: Some(treasury_one),
        new_treasury: treasury_two,
        authorizer: admin.clone(),
    };
    let events = env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                contract_id,
                (symbol_short!("TRSUPD"), admin).into_val(&env),
                expected_second.into_val(&env),
            )
        ]
    );
}

#[test]
fn test_set_treasury_requires_admin_auth() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    client.init(&admin);

    let res = client.try_set_treasury(&treasury);
    assert!(res.is_err());
}

/// Exercises `record_upgrade_event` (the event-payload half of `upgrade`,
/// factored out so it can be tested without `update_current_contract_wasm`)
/// directly, since Soroban requires a real, previously uploaded Wasm blob
/// to target a swap against, which isn't practical to construct in a unit
/// test. `upgrade`'s admin-auth requirement and its call into
/// `update_current_contract_wasm` are still exercised end-to-end by
/// `test_upgrade_requires_admin_auth` below.
#[test]
fn test_record_upgrade_event_reports_old_and_new_hash() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);

    let first_hash = BytesN::from_array(&env, &[1u8; 32]);
    env.as_contract(&contract_id, || {
        crate::SchemaRegistry::record_upgrade_event(&env, &admin, first_hash.clone());
    });
    // The first upgrade has no prior tracked hash, so it reports the new
    // hash as both old and new rather than a placeholder value.
    let expected_first = ContractUpgradedEvent {
        old_wasm_hash: first_hash.clone(),
        new_wasm_hash: first_hash.clone(),
        authorizer: admin.clone(),
    };
    let events = env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("UPGRADED"), admin.clone()).into_val(&env),
                expected_first.into_val(&env),
            )
        ]
    );

    let second_hash = BytesN::from_array(&env, &[2u8; 32]);
    env.as_contract(&contract_id, || {
        crate::SchemaRegistry::record_upgrade_event(&env, &admin, second_hash.clone());
    });
    let expected_second = ContractUpgradedEvent {
        old_wasm_hash: first_hash,
        new_wasm_hash: second_hash,
        authorizer: admin.clone(),
    };
    let events = env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                contract_id,
                (symbol_short!("UPGRADED"), admin).into_val(&env),
                expected_second.into_val(&env),
            )
        ]
    );
}

#[test]
fn test_upgrade_requires_admin_auth() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);

    let new_hash = BytesN::from_array(&env, &[9u8; 32]);
    let res = client.try_upgrade(&new_hash);
    assert!(res.is_err());
}

#[test]
fn test_deprecate() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    client.init(&admin);
    let uid = client.register(&owner, &schema_str, &resolver, &true);

    // Check it's active
    assert!(client.get_schema(&uid).is_some());

    // Deprecate
    client.deprecate(&uid, &owner);

    // Check it's no longer active
    assert!(client.get_schema(&uid).is_none());
}

#[test]
fn test_deprecate_by_admin() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    client.init(&admin);
    let uid = client.register(&owner, &schema_str, &resolver, &true);
    client.deprecate(&uid, &admin);

    assert!(client.get_schema(&uid).is_none());
}

#[test]
fn test_deprecate_rejects_unrelated_authorizer() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let unrelated = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    client.init(&admin);
    let uid = client.register(&owner, &schema_str, &resolver, &true);

    let res = client.try_deprecate(&uid, &unrelated);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::Unauthorized.into()))
    );
}

#[test]
fn test_validate_schema() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    client.init(&admin);
    let uid = client.register(&owner, &schema_str, &resolver, &true);

    assert!(client.validate_schema(&uid));

    client.deprecate(&uid, &owner);
    assert!(!client.validate_schema(&uid));
}

#[test]
fn test_init_twice_is_rejected() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);

    let res = client.try_init(&admin);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::AlreadyInitialized.into()))
    );
}

/// After the ledger has advanced far past deployment, `init`'s instance-TTL
/// extension must still be in effect: reading configuration through any
/// admin-gated entry point (here, a second `init`, which reads
/// REGISTRY_ADMIN before rejecting the call) must not panic on an expired
/// instance. Before this extension existed, an instance created this long
/// ago and never renewed would already be archived and unreadable.
#[test]
fn test_instance_configuration_survives_long_after_init() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);

    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_EXTEND_TO_LEDGERS - 1000;
    });

    let res = client.try_init(&admin);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::AlreadyInitialized.into()))
    );
}

/// Ordinary public traffic (here, `register`, which requires no special
/// admin access) must also renew the instance TTL, not just admin-only
/// entry points — so a schema registry that only ever receives
/// registrations, and no admin calls, still keeps its own configuration
/// alive. Exercised by advancing the ledger twice in a row by nearly the
/// full renewal window and registering in between each jump; if `register`
/// did not renew the TTL, the second `register` call would panic on an
/// archived instance.
#[test]
fn test_ordinary_traffic_renews_decayed_instance_ttl() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    client.init(&admin);

    let owner = Address::generate(&env);
    let resolver = Address::generate(&env);
    env.mock_all_auths();

    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_EXTEND_TO_LEDGERS - 1000;
    });
    client.register(
        &owner,
        &String::from_str(&env, "schema one"),
        &resolver,
        &true,
    );

    env.ledger().with_mut(|li| {
        li.sequence_number += INSTANCE_EXTEND_TO_LEDGERS - 1000;
    });
    client.register(
        &owner,
        &String::from_str(&env, "schema two"),
        &resolver,
        &true,
    );
#[test]
fn test_get_schemas_overflow_deterministic() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    env.mock_all_auths();
    // Empty registry: start = u32::MAX with large limit must not trap and returns empty
    let empty = client.get_schemas(&u32::MAX, &u32::MAX);
    assert_eq!(empty.len(), 0);
    let empty2 = client.get_schemas(&u32::MAX, &1);
    assert_eq!(empty2.len(), 0);

    // Register a few schemas to have non-zero count
    let owner = Address::generate(&env);
    for i in 0..3 {
        let schema = String::from_str(&env, "bool like_soroban");
        let resolver = Address::generate(&env);
        // Use distinct revocable to avoid collision reuse of resolver
        client.register(&owner, &schema, &resolver, &(i % 2 == 0));
    }
    // start beyond count must return empty even with overflowing limit
    let beyond = client.get_schemas(&1000, &u32::MAX);
    assert_eq!(beyond.len(), 0);
    // start = u32::MAX, limit = u32::MAX with count=3 must be deterministic empty, no panic
    let overflow = client.get_schemas(&u32::MAX, &u32::MAX);
    assert_eq!(overflow.len(), 0);
    // start = u32::MAX-1, limit = 10 -> saturating_add wraps to MAX, still >= count => empty
    let start = u32::MAX - 1;
    let near_max = client.get_schemas(&start, &10);
    assert_eq!(near_max.len(), 0);
}

#[test]
fn test_get_schemas_pagination_boundaries() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    env.mock_all_auths();
    let owner = Address::generate(&env);

    // Empty count: any pagination returns empty
    assert_eq!(client.get_schemas(&0, &10).len(), 0);
    assert_eq!(client.get_schemas(&0, &0).len(), 0);

    // Register 5 schemas with distinct resolver/revocable combos
    for _ in 0..5 {
        let schema = String::from_str(&env, "bool like_soroban");
        let resolver = Address::generate(&env);
        client.register(&owner, &schema, &resolver, &true);
    }

    // Final page: start=4, limit=10 => only 1 left
    let final_page = client.get_schemas(&4, &10);
    assert_eq!(final_page.len(), 1);

    // Oversized limit beyond count but capped to budget: start=0, limit=1000 => returns all 5
    let oversized = client.get_schemas(&0, &1000);
    assert_eq!(oversized.len(), 5);

    // Normal page
    let page = client.get_schemas(&0, &2);
    assert_eq!(page.len(), 2);
    let page2 = client.get_schemas(&2, &2);
    assert_eq!(page2.len(), 2);
}

#[test]
fn test_get_schemas_page_size_capped_to_budget() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    env.mock_all_auths();
    let owner = Address::generate(&env);

    // Register 101 schemas to exceed MAX_GET_SCHEMAS_PAGE_SIZE (100)
    for i in 0..101 {
        let schema = String::from_str(&env, "bool like_soroban");
        let resolver = Address::generate(&env);
        let revocable = i % 2 == 0;
        client.register(&owner, &schema, &resolver, &revocable);
    }
    // Request limit = u32::MAX should be capped to 100, not 101
    let capped = client.get_schemas(&0, &u32::MAX);
    assert_eq!(capped.len(), 100);
    // Request 200 also capped to 100
    let capped2 = client.get_schemas(&0, &200);
    assert_eq!(capped2.len(), 100);
    // Subsequent page gets the remainder
    let remainder = client.get_schemas(&100, &u32::MAX);
    assert_eq!(remainder.len(), 1);
}

#[test]
fn test_register_same_schema_different_policy_distinct_uids() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let schema = String::from_str(&env, "bool like_soroban");
    let resolver_a = Address::generate(&env);
    let resolver_b = Address::generate(&env);

    // Same schema string but different resolver -> distinct UIDs, both succeed
    let uid_a = client.register(&owner, &schema, &resolver_a, &true);
    let uid_b = client.register(&owner, &schema, &resolver_b, &true);
    assert_ne!(uid_a, uid_b);

    // Same schema + same resolver but different revocable -> distinct UIDs
    let schema2 = String::from_str(&env, "uint32 value");
    let resolver_c = Address::generate(&env);
    let uid_c = client.register(&owner, &schema2, &resolver_c, &true);
    let uid_d = client.register(&owner, &schema2, &resolver_c, &false);
    assert_ne!(uid_c, uid_d);

    // Identical tuple must collide
    let schema3 = String::from_str(&env, "string name");
    let resolver_e = Address::generate(&env);
    let uid_e = client.register(&owner, &schema3, &resolver_e, &true);
    let res = client.try_register(&owner, &schema3, &resolver_e, &true);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::SchemaAlreadyExists.into()))
    );
    // Ensure original still retrievable
    assert!(client.get_schema(&uid_e).is_some());
}

#[test]
fn test_uid_derivation_is_deterministic_and_includes_policy() {
    use soroban_sdk::{xdr::ToXdr, Bytes, BytesN};
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let schema = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    // Register and fetch UID
    let uid = client.register(&owner, &schema, &resolver, &true);

    // Recompute expected UID off-chain using the canonical preimage:
    // SHA256( XDR(schema) || XDR(resolver) || byte(revocable) )
    let mut payload = Bytes::new(&env);
    payload.append(&schema.clone().to_xdr(&env));
    payload.append(&resolver.clone().to_xdr(&env));
    payload.append(&Bytes::from_slice(&env, &[1u8]));
    let expected = soroban_sas_common::UID(BytesN::from_array(&env, &env.crypto().sha256(&payload).to_array()));
    assert_eq!(uid, expected);

    // False case: revocable false yields different hash
    let mut payload2 = Bytes::new(&env);
    payload2.append(&schema.clone().to_xdr(&env));
    payload2.append(&resolver.clone().to_xdr(&env));
    payload2.append(&Bytes::from_slice(&env, &[0u8]));
    let expected_false = soroban_sas_common::UID(BytesN::from_array(&env, &env.crypto().sha256(&payload2).to_array()));
    assert_ne!(uid, expected_false);
}

#[test]
fn test_uid_golden_vectors() {
    use soroban_sdk::{xdr::ToXdr, Bytes, BytesN};
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let schema = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    let uid_true = client.register(&owner, &schema, &resolver, &true);
    // Compute expected via canonical preimage
    let mut payload_true = Bytes::new(&env);
    payload_true.append(&schema.clone().to_xdr(&env));
    payload_true.append(&resolver.clone().to_xdr(&env));
    payload_true.append(&Bytes::from_slice(&env, &[1u8]));
    let expected_true = soroban_sas_common::UID(BytesN::from_array(&env, &env.crypto().sha256(&payload_true).to_array()));
    assert_eq!(uid_true, expected_true);

    // Golden vector: same schema/resolver with revocable=false must be distinct
    let uid_false = client.register(&owner, &schema, &resolver, &false);
    let mut payload_false = Bytes::new(&env);
    payload_false.append(&schema.clone().to_xdr(&env));
    payload_false.append(&resolver.clone().to_xdr(&env));
    payload_false.append(&Bytes::from_slice(&env, &[0u8]));
    let expected_false = soroban_sas_common::UID(BytesN::from_array(&env, &env.crypto().sha256(&payload_false).to_array()));
    assert_eq!(uid_false, expected_false);
    assert_ne!(uid_true, uid_false);

    // Lock that a different resolver changes UID even with same schema and revocable
    let resolver2 = Address::generate(&env);
    let uid_other_resolver = client.register(&owner, &schema, &resolver2, &true);
    assert_ne!(uid_true, uid_other_resolver);
}
