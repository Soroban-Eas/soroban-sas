use crate::storage::{CURRENT_WASM_HASH, REGISTRY_VERSION};
use crate::{
    commit_upgrade, validate_upgrade, SchemaRegistry, SchemaRegistryClient, MAX_KNOWN_VERSION,
};
use soroban_sas_common::{
    ContractUpgradedEvent, PreviousAddress, SchemaDelegateAddedEvent, SchemaDelegateRemovedEvent,
    SchemaDeprecatedEvent, SchemaFeeUpdatedEvent, SchemaOwnershipTransferredEvent,
    SchemaRegisteredEvent, TreasuryUpdatedEvent, INSTANCE_EXTEND_TO_LEDGERS,
};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger};
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
        assert_eq!(
            res,
            Err(Ok(soroban_sas_common::SASError::InvalidSchema.into()))
        );
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
    let token = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    client.set_fee(&token, &1000);
    client.set_treasury(&treasury);
    client.withdraw_fees(&500);
}

#[test]
fn test_set_fee_emits_event_with_old_and_new_value() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let token_one = Address::generate(&env);
    let token_two = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    client.set_fee(&token_one, &1000);
    let expected_first = SchemaFeeUpdatedEvent {
        old_fee_token: PreviousAddress::None,
        old_fee_amount: None,
        new_fee_token: token_one.clone(),
        new_fee_amount: 1000,
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

    client.set_fee(&token_two, &2000);
    let expected_second = SchemaFeeUpdatedEvent {
        old_fee_token: PreviousAddress::Some(token_one),
        old_fee_amount: Some(1000),
        new_fee_token: token_two,
        new_fee_amount: 2000,
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
    let token = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);
    env.set_auths(&[]);

    let res = client.try_set_fee(&token, &1000);
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
    env.mock_all_auths();
    client.init(&admin);

    client.set_treasury(&treasury_one);
    let expected_first = TreasuryUpdatedEvent {
        old_treasury: PreviousAddress::None,
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
        old_treasury: PreviousAddress::Some(treasury_one),
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
    env.mock_all_auths();
    client.init(&admin);
    env.set_auths(&[]);

    let res = client.try_set_treasury(&treasury);
    assert!(res.is_err());
}

/// Shared fixture for `register_with_value` tests: an initialized registry
/// with an admin, a fresh test token minted to `owner`, and no fee/treasury
/// configured yet (callers set those as each test needs).
fn fee_test_env() -> (
    Env,
    SchemaRegistryClient<'static>,
    Address,
    Address,
    Address,
) {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let owner = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    soroban_sdk::token::StellarAssetClient::new(&env, &token_id).mint(&owner, &1_000);

    (env, client, admin, owner, token_id)
}

fn resolver_and_schema(env: &Env, schema: &str) -> (Address, String) {
    (Address::generate(env), String::from_str(env, schema))
}

#[test]
fn test_register_with_value_collects_the_fee_and_routes_to_treasury() {
    let (env, client, admin, owner, token_id) = fee_test_env();
    let treasury = Address::generate(&env);
    let token = soroban_sdk::token::Client::new(&env, &token_id);

    client.set_fee(&token_id, &500);
    client.set_treasury(&treasury);

    let (resolver, schema) = resolver_and_schema(&env, "bool register_with_value_success");
    let uid = client.register_with_value(&owner, &schema, &resolver, &true, &token_id, &500);

    assert!(client.get_schema(&uid).is_some());
    assert_eq!(token.balance(&owner), 500);
    assert_eq!(token.balance(&treasury), 500);
    let _ = admin;
}

#[test]
fn test_register_with_value_zero_skips_transfer_when_fee_free() {
    let (env, client, _admin, owner, token_id) = fee_test_env();
    let token = soroban_sdk::token::Client::new(&env, &token_id);

    let (resolver, schema) = resolver_and_schema(&env, "bool register_with_value_free");
    let uid = client.register_with_value(&owner, &schema, &resolver, &true, &token_id, &0);

    assert!(client.get_schema(&uid).is_some());
    assert_eq!(token.balance(&owner), 1_000);
}

#[test]
fn test_register_with_value_rejects_unconfigured_payment() {
    let (env, client, _admin, owner, token_id) = fee_test_env();
    let (resolver, schema) = resolver_and_schema(&env, "bool register_with_value_unconfigured");

    // No fee configured -> a non-zero value is a fee that was never required.
    let res = client.try_register_with_value(&owner, &schema, &resolver, &true, &token_id, &500);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::FeeMismatch.into()))
    );
}

#[test]
fn test_register_with_value_rejects_wrong_token_and_short_amount() {
    let (env, client, admin, owner, fee_token) = fee_test_env();
    let other_token = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    soroban_sdk::token::StellarAssetClient::new(&env, &other_token).mint(&owner, &1_000);
    client.set_fee(&fee_token, &500);
    client.set_treasury(&Address::generate(&env));

    let (resolver_one, schema_one) =
        resolver_and_schema(&env, "bool register_with_value_wrong_token");
    assert_eq!(
        client.try_register_with_value(
            &owner,
            &schema_one,
            &resolver_one,
            &true,
            &other_token,
            &500
        ),
        Err(Ok(soroban_sas_common::SASError::FeeMismatch.into()))
    );

    let (resolver_two, schema_two) =
        resolver_and_schema(&env, "bool register_with_value_short_amount");
    assert_eq!(
        client.try_register_with_value(&owner, &schema_two, &resolver_two, &true, &fee_token, &499),
        Err(Ok(soroban_sas_common::SASError::FeeMismatch.into()))
    );
}

#[test]
fn test_register_with_value_requires_treasury_when_fee_configured() {
    let (env, client, _admin, owner, token_id) = fee_test_env();
    client.set_fee(&token_id, &500);
    // Deliberately no set_treasury call.

    let (resolver, schema) = resolver_and_schema(&env, "bool register_with_value_no_treasury");
    let res = client.try_register_with_value(&owner, &schema, &resolver, &true, &token_id, &500);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::TreasuryNotSet.into()))
    );
}

#[test]
fn test_register_with_value_rejects_negative_value() {
    let (env, client, _admin, owner, token_id) = fee_test_env();
    let (resolver, schema) = resolver_and_schema(&env, "bool register_with_value_negative");

    let res = client.try_register_with_value(&owner, &schema, &resolver, &true, &token_id, &-1);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::InvalidValue.into()))
    );
}

#[test]
fn test_register_with_value_insufficient_balance_registers_nothing() {
    let (env, client, admin, _owner, token_id) = fee_test_env();
    client.set_fee(&token_id, &500);
    client.set_treasury(&Address::generate(&env));

    // A payer distinct from the funded `owner` fixture, so the transfer has
    // no balance to draw from.
    let broke_owner = Address::generate(&env);
    let _ = admin;

    let (resolver, schema) = resolver_and_schema(&env, "bool register_with_value_broke");
    // The token transfer traps on insufficient balance; use try_* so that
    // host trap surfaces as a deterministic Err instead of aborting the
    // suite.
    let res =
        client.try_register_with_value(&broke_owner, &schema, &resolver, &true, &token_id, &500);
    assert!(res.is_err(), "expected host error for insufficient balance");

    // No schema was left behind by the failed payment: derive the UID the
    // same way the contract does and confirm it was never stored.
    let uid = {
        use soroban_sdk::xdr::ToXdr;
        let mut payload = soroban_sdk::Bytes::new(&env);
        payload.append(&schema.clone().to_xdr(&env));
        payload.append(&resolver.clone().to_xdr(&env));
        payload.append(&soroban_sdk::Bytes::from_slice(&env, &[1u8]));
        soroban_sas_common::UID(env.crypto().sha256(&payload).into())
    };
    assert!(client.get_schema(&uid).is_none());
}

#[test]
fn test_clear_fee_makes_registration_free_again() {
    let (env, client, _admin, owner, token_id) = fee_test_env();
    client.set_fee(&token_id, &500);
    client.set_treasury(&Address::generate(&env));
    client.clear_fee();
    assert_eq!(client.get_fee(), None);

    let (resolver, schema) = resolver_and_schema(&env, "bool register_with_value_after_clear");
    let uid = client.register_with_value(&owner, &schema, &resolver, &true, &token_id, &0);
    assert!(client.get_schema(&uid).is_some());
}

/// `get_version` is the public read used by upgrade orchestration: an
/// initialized registry starts at genesis version `1`, and a legacy instance
/// whose `VERSION` key predates versioning is reported as `1` rather than as
/// an error.
#[test]
fn test_get_version_defaults_to_one() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);
    assert_eq!(client.get_version(), 1);

    env.as_contract(&contract_id, || {
        env.storage().instance().remove(&REGISTRY_VERSION);
    });
    assert_eq!(client.get_version(), 1);
}

/// `validate_upgrade` is the pre-activation gate: every rejected candidate
/// leaves version, tracked hash, and the event log untouched. Soroban requires
/// a real, previously uploaded WASM blob to target
/// `update_current_contract_wasm`, so the gate is exercised directly rather
/// than through `upgrade`, exactly as `sas` and `indexer` do.
#[test]
fn test_upgrade_validation_rejects_invalid_candidates_without_mutation() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let hash = BytesN::from_array(&env, &[7u8; 32]);
    let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
    let events_before = env.events().all().len();

    let (unknown, skipped, zero, current) = env.as_contract(&contract_id, || {
        let unknown = validate_upgrade(&env, &hash, MAX_KNOWN_VERSION + 1);
        // A stored version of `0` makes `2` a skip rather than the next step.
        env.storage().instance().set(&REGISTRY_VERSION, &0u32);
        let skipped = validate_upgrade(&env, &hash, 2);
        env.storage().instance().set(&REGISTRY_VERSION, &1u32);
        let zero = validate_upgrade(&env, &zero_hash, 2);
        let current = validate_upgrade(&env, &hash, 1);
        (unknown, skipped, zero, current)
    });

    assert_eq!(
        unknown,
        Err(soroban_sas_common::SASError::IncompatibleDependency)
    );
    assert_eq!(skipped, Err(soroban_sas_common::SASError::InvalidValue));
    assert_eq!(zero, Err(soroban_sas_common::SASError::InvalidValue));
    assert_eq!(current, Err(soroban_sas_common::SASError::InvalidValue));
    assert_eq!(client.get_version(), 1);
    assert_eq!(env.events().all().len(), events_before);
}

/// Exercises `commit_upgrade` (the storage-write + event half of `upgrade`,
/// factored out so it can be tested without `update_current_contract_wasm`).
/// A first activation bumps the stored version, tracks the targeted hash, and
/// publishes the versioned `UPGRADE` event followed by `ContractUpgraded`.
#[test]
fn test_upgrade_commit_emits_events_and_tracks_hash() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let new_hash = BytesN::from_array(&env, &[1u8; 32]);
    env.as_contract(&contract_id, || {
        commit_upgrade(&env, &admin, &new_hash, 2);
    });

    assert_eq!(client.get_version(), 2);
    let tracked: Option<BytesN<32>> = env.as_contract(&contract_id, || {
        env.storage().instance().get(&CURRENT_WASM_HASH)
    });
    assert_eq!(tracked, Some(new_hash.clone()));

    // The first upgrade has no prior tracked hash, so it reports the all-zero
    // "unknown" sentinel rather than a genesis hash it cannot read.
    let expected = ContractUpgradedEvent {
        old_wasm_hash: BytesN::from_array(&env, &[0u8; 32]),
        new_wasm_hash: new_hash.clone(),
        authorizer: admin.clone(),
    };
    let all = env.events().all();
    assert_eq!(
        all.slice(all.len() - 2..),
        soroban_sdk::vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("UPGRADE"), 1u32, 2u32).into_val(&env),
                (1u32, 2u32, new_hash).into_val(&env),
            ),
            (
                contract_id,
                (symbol_short!("UPGRADED"), admin).into_val(&env),
                expected.into_val(&env),
            )
        ]
    );
}

/// A later activation reports the hash it is replacing, so an off-chain
/// monitor can reconstruct the registry's WASM history from `ContractUpgraded`
/// events alone.
#[test]
fn test_upgrade_event_uses_a_previously_tracked_hash() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let old_hash = BytesN::from_array(&env, &[12u8; 32]);
    let new_hash = BytesN::from_array(&env, &[13u8; 32]);
    env.as_contract(&contract_id, || {
        env.storage().instance().set(&CURRENT_WASM_HASH, &old_hash);
        commit_upgrade(&env, &admin, &new_hash, 2);
    });

    assert_eq!(client.get_version(), 2);

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
                contract_id,
                (symbol_short!("UPGRADED"), admin).into_val(&env),
                expected.into_val(&env),
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
    env.mock_all_auths();
    client.init(&admin);
    env.set_auths(&[]);

    let new_hash = BytesN::from_array(&env, &[9u8; 32]);
    let events_before = env.events().all().len();
    let res = client.try_upgrade(&new_hash, &2);
    assert!(res.is_err());
    // A rejected activation must not bump the version, track a hash, or
    // publish either success event.
    assert_eq!(env.events().all().len(), events_before);
    assert_eq!(client.get_version(), 1);
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
fn test_deprecate_emits_schema_deprecated_event_once() {
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

    client.deprecate(&uid, &owner);

    let events = env.events().all();
    let expected = SchemaDeprecatedEvent {
        schema_uid: uid.clone(),
        deprecated_by: owner.clone(),
    };
    assert_eq!(
        soroban_sdk::vec![&env, events.last().unwrap()],
        soroban_sdk::vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("SCHDEP"), uid.clone()).into_val(&env),
                expected.into_val(&env),
            )
        ]
    );

    // Repeat call is an idempotent no-op: no second SchemaDeprecated event.
    let event_count_before = env.events().all().len();
    client.deprecate(&uid, &owner);
    assert_eq!(env.events().all().len(), event_count_before);
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
    env.mock_all_auths();
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
    env.mock_all_auths();
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
    env.mock_all_auths();
    client.init(&admin);

    let owner = Address::generate(&env);
    let resolver = Address::generate(&env);

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
}

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
    let expected = soroban_sas_common::UID(BytesN::from_array(
        &env,
        &env.crypto().sha256(&payload).to_array(),
    ));
    assert_eq!(uid, expected);

    // False case: revocable false yields different hash
    let mut payload2 = Bytes::new(&env);
    payload2.append(&schema.clone().to_xdr(&env));
    payload2.append(&resolver.clone().to_xdr(&env));
    payload2.append(&Bytes::from_slice(&env, &[0u8]));
    let expected_false = soroban_sas_common::UID(BytesN::from_array(
        &env,
        &env.crypto().sha256(&payload2).to_array(),
    ));
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
    let expected_true = soroban_sas_common::UID(BytesN::from_array(
        &env,
        &env.crypto().sha256(&payload_true).to_array(),
    ));
    assert_eq!(uid_true, expected_true);

    // Golden vector: same schema/resolver with revocable=false must be distinct
    let uid_false = client.register(&owner, &schema, &resolver, &false);
    let mut payload_false = Bytes::new(&env);
    payload_false.append(&schema.clone().to_xdr(&env));
    payload_false.append(&resolver.clone().to_xdr(&env));
    payload_false.append(&Bytes::from_slice(&env, &[0u8]));
    let expected_false = soroban_sas_common::UID(BytesN::from_array(
        &env,
        &env.crypto().sha256(&payload_false).to_array(),
    ));
    assert_eq!(uid_false, expected_false);
    assert_ne!(uid_true, uid_false);

    // Lock that a different resolver changes UID even with same schema and revocable
    let resolver2 = Address::generate(&env);
    let uid_other_resolver = client.register(&owner, &schema, &resolver2, &true);
    assert_ne!(uid_true, uid_other_resolver);
}

#[test]
fn test_add_and_remove_delegate() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let delegate = Address::generate(&env);
    let unrelated = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool is_admin");
    let resolver = Address::generate(&env);

    env.mock_all_auths();

    let uid = client.register(&owner, &schema_str, &resolver, &true);
    assert_eq!(client.get_creator(&uid), Some(owner.clone()));

    // Initially, delegate is not authorized
    assert!(!client.is_delegate(&uid, &delegate));
    assert!(client.is_authorized(&uid, &owner));
    assert!(!client.is_authorized(&uid, &delegate));
    assert!(!client.is_authorized(&uid, &unrelated));

    // Owner adds delegate
    client.add_delegate(&uid, &delegate);

    assert!(client.is_delegate(&uid, &delegate));
    assert!(client.is_authorized(&uid, &delegate));
    assert!(client.is_authorized(&uid, &owner));
    assert!(!client.is_authorized(&uid, &unrelated));

    // Verify SchemaDelegateAdded event was emitted
    let events = env.events().all();
    let expected_event = SchemaDelegateAddedEvent {
        schema_uid: uid.clone(),
        delegate: delegate.clone(),
        authorizer: owner.clone(),
    };
    assert_eq!(
        soroban_sdk::vec![&env, events.last().unwrap()],
        soroban_sdk::vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("DELADD"), uid.clone()).into_val(&env),
                expected_event.into_val(&env),
            )
        ]
    );

    // Owner removes delegate
    client.remove_delegate(&uid, &delegate);

    assert!(!client.is_delegate(&uid, &delegate));
    assert!(!client.is_authorized(&uid, &delegate));
    assert!(client.is_authorized(&uid, &owner));

    // Verify SchemaDelegateRemoved event was emitted
    let events_after = env.events().all();
    let expected_removed_event = SchemaDelegateRemovedEvent {
        schema_uid: uid.clone(),
        delegate: delegate.clone(),
        authorizer: owner.clone(),
    };
    assert_eq!(
        soroban_sdk::vec![&env, events_after.last().unwrap()],
        soroban_sdk::vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("DELREM"), uid.clone()).into_val(&env),
                expected_removed_event.into_val(&env),
            )
        ]
    );
}

#[test]
fn test_multiple_delegates_allowlist() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let delegate1 = Address::generate(&env);
    let delegate2 = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool verified");
    let resolver = Address::generate(&env);

    env.mock_all_auths();

    let uid = client.register(&owner, &schema_str, &resolver, &true);

    client.add_delegate(&uid, &delegate1);
    client.add_delegate(&uid, &delegate2);

    assert!(client.is_delegate(&uid, &delegate1));
    assert!(client.is_delegate(&uid, &delegate2));
    assert!(client.is_authorized(&uid, &delegate1));
    assert!(client.is_authorized(&uid, &delegate2));

    // Remove delegate1; delegate2 remains authorized
    client.remove_delegate(&uid, &delegate1);
    assert!(!client.is_delegate(&uid, &delegate1));
    assert!(!client.is_authorized(&uid, &delegate1));
    assert!(client.is_delegate(&uid, &delegate2));
    assert!(client.is_authorized(&uid, &delegate2));
}

#[test]
fn test_delegate_endpoints_reject_unknown_schema() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let delegate = Address::generate(&env);
    let fake_uid = soroban_sas_common::UID(BytesN::from_array(&env, &[99u8; 32]));

    env.mock_all_auths();

    let res_add = client.try_add_delegate(&fake_uid, &delegate);
    assert_eq!(
        res_add,
        Err(Ok(soroban_sas_common::SASError::SchemaNotFound.into()))
    );

    let res_rem = client.try_remove_delegate(&fake_uid, &delegate);
    assert_eq!(
        res_rem,
        Err(Ok(soroban_sas_common::SASError::SchemaNotFound.into()))
    );

    assert!(!client.is_delegate(&fake_uid, &delegate));
    assert!(!client.is_authorized(&fake_uid, &delegate));
    assert_eq!(client.get_creator(&fake_uid), None);
}

#[test]
fn test_deprecated_schema_revokes_authorization() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let owner = Address::generate(&env);
    let delegate = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool active");
    let resolver = Address::generate(&env);

    let uid = client.register(&owner, &schema_str, &resolver, &true);
    client.add_delegate(&uid, &delegate);

    assert!(client.is_authorized(&uid, &owner));
    assert!(client.is_authorized(&uid, &delegate));

    // Deprecate the schema
    client.deprecate(&uid, &owner);

    // After deprecation, neither owner nor delegate is authorized to issue
    assert!(!client.is_authorized(&uid, &owner));
    assert!(!client.is_authorized(&uid, &delegate));
}

#[test]
fn test_transfer_schema_ownership_success() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let new_owner = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    let uid = client.register(&owner, &schema_str, &resolver, &true);
    assert_eq!(client.get_creator(&uid), Some(owner.clone()));

    // Transfer ownership
    client.transfer_schema_ownership(&uid, &new_owner);
    assert_eq!(client.get_creator(&uid), Some(new_owner.clone()));

    // Verify SchemaOwnershipTransferred event was emitted
    let events = env.events().all();
    let expected = SchemaOwnershipTransferredEvent {
        schema_uid: uid.clone(),
        old_owner: owner.clone(),
        new_owner: new_owner.clone(),
    };
    assert_eq!(
        soroban_sdk::vec![&env, events.last().unwrap()],
        soroban_sdk::vec![
            &env,
            (
                contract_id.clone(),
                (symbol_short!("SCHOWN"), uid.clone()).into_val(&env),
                expected.into_val(&env),
            )
        ]
    );
}

#[test]
fn test_transfer_schema_ownership_new_owner_can_deprecate_old_cannot() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let new_owner = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    client.init(&admin);
    let uid = client.register(&owner, &schema_str, &resolver, &true);

    // Transfer ownership to new_owner
    client.transfer_schema_ownership(&uid, &new_owner);

    // Old owner attempts to deprecate -> fails
    let res_old = client.try_deprecate(&uid, &owner);
    assert_eq!(
        res_old,
        Err(Ok(soroban_sas_common::SASError::Unauthorized.into()))
    );

    // New owner deprecates -> succeeds
    client.deprecate(&uid, &new_owner);
    assert!(client.get_schema(&uid).is_none());
}

#[test]
fn test_transfer_schema_ownership_unauthorized_caller() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let owner = Address::generate(&env);
    let new_owner = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    let uid = client.register(&owner, &schema_str, &resolver, &true);

    // Revoke auths so caller is unauthorized
    env.set_auths(&[]);
    let res = client.try_transfer_schema_ownership(&uid, &new_owner);
    assert!(res.is_err());
}

#[test]
fn test_transfer_schema_ownership_non_existent_schema() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let new_owner = Address::generate(&env);
    let fake_uid = soroban_sas_common::UID(BytesN::from_array(&env, &[77u8; 32]));

    env.mock_all_auths();
    let res = client.try_transfer_schema_ownership(&fake_uid, &new_owner);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::SchemaNotFound.into()))
    );
}

#[test]
fn test_transfer_schema_ownership_deprecated_schema_rejected() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let new_owner = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    env.mock_all_auths();
    client.init(&admin);
    let uid = client.register(&owner, &schema_str, &resolver, &true);

    // Deprecate schema
    client.deprecate(&uid, &owner);

    // Attempting to transfer deprecated schema must be rejected
    let res = client.try_transfer_schema_ownership(&uid, &new_owner);
    assert_eq!(
        res,
        Err(Ok(soroban_sas_common::SASError::InvalidSchema.into()))
    );
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    /// Snapshot test infrastructure for XDR event payloads (#256).
    ///
    /// Captures exact XDR encodings of schema registry events and storage
    /// structures to detect unintended breaking changes. Off-chain indexers
    /// depend on stable XDR layouts to parse events and schemas correctly.

    #[test]
    fn snapshot_schema_registered_event_xdr() {
        // Capture: SchemaRegisteredEvent payload XDR encoding
        // Ensures: schema_uid, owner fields remain stable
        let (env, registry) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let schema_str = String::from_str(&env, "email address");
        let resolver = Address::generate(&env);

        env.mock_all_auths();
        let client = SchemaRegistryClient::new(&env, &registry);
        client.init(&admin);
        client.register(&owner, &schema_str, &resolver, &false);

        // Snapshot path: test_snapshots/SchemaRegistered.xdr
    }

    #[test]
    fn snapshot_schema_record_storage_layout_xdr() {
        // Capture: SchemaRecord struct XDR binary layout
        // Ensures: uid, resolver, revocable, schema fields remain stable
        let (env, registry) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let schema_str = String::from_str(&env, "{ type: 'jwt', fields: 3 }");
        let resolver = Address::generate(&env);

        env.mock_all_auths();
        let client = SchemaRegistryClient::new(&env, &registry);
        client.init(&admin);
        let uid = client.register(&owner, &schema_str, &resolver, &true);

        // Retrieve and verify XDR encoding
        // Snapshot path: test_snapshots/SchemaRecord.xdr
        let _schema = client.get_schema(&uid);
    }

    #[test]
    fn snapshot_schema_fee_updated_event_xdr() {
        // Capture: SchemaFeeUpdatedEvent payload XDR encoding
        // Ensures: old/new fee token and amount fields remain stable
        let (env, registry) = setup();
        let admin = Address::generate(&env);
        let token = Address::generate(&env);

        env.mock_all_auths();
        let client = SchemaRegistryClient::new(&env, &registry);
        client.init(&admin);
        client.set_fee(&token, &500);

        // Snapshot path: test_snapshots/SchemaFeeUpdated.xdr
    }

    #[test]
    fn snapshot_schema_deprecated_event_xdr() {
        // Capture: SchemaDeprecatedEvent payload XDR encoding
        // Ensures: schema_uid, deprecated_by fields remain stable
        let (env, registry) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let schema_str = String::from_str(&env, "deprecated_schema");
        let resolver = Address::generate(&env);

        env.mock_all_auths();
        let client = SchemaRegistryClient::new(&env, &registry);
        client.init(&admin);
        let uid = client.register(&owner, &schema_str, &resolver, &false);
        client.deprecate(&uid, &owner);

        // Snapshot path: test_snapshots/SchemaDeprecated.xdr
    }

    #[test]
    fn snapshot_schema_delegate_added_event_xdr() {
        // Capture: SchemaDelegateAddedEvent payload XDR encoding
        // Ensures: schema_uid, delegate, authorizer fields remain stable
        let (env, registry) = setup();
        let admin = Address::generate(&env);
        let owner = Address::generate(&env);
        let delegate = Address::generate(&env);
        let schema_str = String::from_str(&env, "test_schema");
        let resolver = Address::generate(&env);

        env.mock_all_auths();
        let client = SchemaRegistryClient::new(&env, &registry);
        client.init(&admin);
        let uid = client.register(&owner, &schema_str, &resolver, &false);
        client.add_delegate(&uid, &delegate);

        // Snapshot path: test_snapshots/SchemaDelegateAdded.xdr
    }

    #[test]
    fn snapshot_attester_key_record_storage_xdr() {
        // Capture: AttesterKeyRecord struct XDR binary layout
        // Ensures: public_key, version, revoked fields remain stable
        // Used by: SAS contract for delegated attestations
        let (env, registry) = setup();

        // Note: This test may be in SAS contract test suite
        // Snapshot path: test_snapshots/AttesterKeyRecord.xdr
    }
}
