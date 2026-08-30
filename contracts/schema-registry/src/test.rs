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

#[test]
fn test_get_version_defaults_to_one() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    assert_eq!(client.get_version(), 1);
}

#[test]
fn test_upgrade_preserves_schemas_and_config() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let treasury = Address::generate(&env);
    client.init(&admin);

    env.mock_all_auths();
    // Register two schemas
    let owner = Address::generate(&env);
    let resolver = Address::generate(&env);
    let s1 = String::from_str(&env, "bool like_soroban");
    let s2 = String::from_str(&env, "string name, uint32 age");
    let uid1 = client.register(&owner, &s1, &resolver, &true);
    let uid2 = client.register(&owner, &s2, &resolver, &false);
    client.set_fee(&1000);
    client.set_treasury(&treasury);

    // Upload the actual compiled WASM so the host's `update_current_contract_wasm`
    // finds the hash. The build artifact is produced by `cargo build -p schema-registry --release --target wasm32-unknown-unknown`.
    let wasm_bytes = include_bytes!("../../../target/wasm32-unknown-unknown/release/schema_registry.wasm");
    let wasm = soroban_sdk::Bytes::from_slice(&env, wasm_bytes);
    let hash = env.deployer().upload_contract_wasm(wasm);
    // Check version before upgrade
    {
        let v_before = client.get_version();
        assert_eq!(v_before, 1, "version before upgrade should be 1");
    }
    let hash_clone = hash.clone();
    client.upgrade(&hash_clone, &2);
    // Raw instance check
    {
        let raw: u32 = env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .get(&crate::storage::REGISTRY_VERSION)
                .unwrap_or(0)
        });
        // Use host debug event to surface value (since println not available)
        // We'll assert this raw value to get diagnostic.
        if raw != 2 {
            panic!("raw version after upgrade is {}, expected 2, hash={:?}", raw, hash_clone.to_array());
        }
    }

    assert_eq!(client.get_version(), 2);
    // Schemas survive
    assert_eq!(client.get_schema(&uid1).unwrap().schema, s1);
    assert_eq!(client.get_schema(&uid2).unwrap().schema, s2);
    assert_eq!(client.get_schemas(&0, &10).len(), 2);
    // Upgrade event emitted — at least one event after upgrade
    let events = env.events().all();
    assert!(
        events.len() >= 1,
        "expected at least one event after upgrade"
    );
}

#[test]
fn test_upgrade_rejects_incompatible_version() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    env.mock_all_auths();
    let hash = soroban_sdk::BytesN::from_array(&env, &[7u8; 32]);
    // Must be exactly old+1 (2); 3 is unknown future.
    let res = client.try_upgrade(&hash, &3);
    assert_eq!(res, Err(Ok(soroban_sas_common::SASError::IncompatibleDependency.into())));
    // Downgrade / same version also rejected as InvalidValue
    let res2 = client.try_upgrade(&hash, &1);
    assert_eq!(res2, Err(Ok(soroban_sas_common::SASError::InvalidValue.into())));
}

#[test]
fn test_upgrade_rejects_zero_hash() {
    let env = Env::default();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);
    env.mock_all_auths();
    let zero = soroban_sdk::BytesN::from_array(&env, &[0u8; 32]);
    let res = client.try_upgrade(&zero, &2);
    assert_eq!(res, Err(Ok(soroban_sas_common::SASError::InvalidValue.into())));
}
