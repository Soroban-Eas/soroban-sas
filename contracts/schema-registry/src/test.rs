use crate::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::SchemaRegisteredEvent;
use soroban_sdk::testutils::{Address as _, Events as _};
use soroban_sdk::{symbol_short, Address, Env, IntoVal, String};

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
