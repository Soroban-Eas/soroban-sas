use crate::{SchemaRegistry, SchemaRegistryClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, Env, String};

fn setup(env: &Env) -> (SchemaRegistryClient, Address) {
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(env, &contract_id);
    let admin = Address::generate(env);
    client.init(&admin);
    (client, admin)
}

fn setup_token(env: &Env) -> (Address, token::StellarAssetClient) {
    let issuer = Address::generate(env);
    let asset = env.register_stellar_asset_contract(issuer);
    let asset_admin = token::StellarAssetClient::new(env, &asset);
    (asset, asset_admin)
}

#[test]
fn test_register_schema() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup(&env);

    let caller = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    let uid = client.register(&caller, &schema_str, &resolver, &true);
    let record = client.get_schema(&uid).unwrap();

    assert_eq!(record.schema, schema_str);
    assert!(record.revocable);
    assert_eq!(record.resolver, resolver);
}

#[test]
fn test_fee_and_treasury() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup(&env);
    let (asset, asset_admin) = setup_token(&env);
    let treasury = Address::generate(&env);

    client.set_fee(&asset, &1000);
    client.set_treasury(&treasury);

    assert_eq!(client.get_fee(), Some((asset.clone(), 1000)));
    assert_eq!(client.get_treasury(), Some(treasury.clone()));

    let caller = Address::generate(&env);
    asset_admin.mint(&caller, &2500);

    let token_client = token::Client::new(&env, &asset);
    let schema_str = String::from_str(&env, "bool paid_schema");
    let resolver = Address::generate(&env);

    let uid = client.register(&caller, &schema_str, &resolver, &true);
    assert!(client.get_schema(&uid).is_some());

    // The fee was routed atomically from the caller to the treasury.
    assert_eq!(token_client.balance(&caller), 1500);
    assert_eq!(token_client.balance(&treasury), 1000);
}

#[test]
fn test_register_fails_with_insufficient_balance() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup(&env);
    let (asset, asset_admin) = setup_token(&env);
    let treasury = Address::generate(&env);

    client.set_fee(&asset, &1000);
    client.set_treasury(&treasury);

    let caller = Address::generate(&env);
    asset_admin.mint(&caller, &999);

    let schema_str = String::from_str(&env, "bool poor_caller");
    let resolver = Address::generate(&env);

    let result = client.try_register(&caller, &schema_str, &resolver, &true);
    assert!(result.is_err());

    // Nothing was registered and no funds moved.
    let token_client = token::Client::new(&env, &asset);
    assert_eq!(token_client.balance(&caller), 999);
    assert_eq!(token_client.balance(&treasury), 0);
}

#[test]
fn test_register_fails_without_treasury() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup(&env);
    let (asset, _asset_admin) = setup_token(&env);

    client.set_fee(&asset, &1000);

    let caller = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool no_treasury");
    let resolver = Address::generate(&env);

    let result = client.try_register(&caller, &schema_str, &resolver, &true);
    assert_eq!(
        result,
        Err(Ok(soroban_sdk::Error::from_contract_error(502)))
    );
}

#[test]
fn test_fee_toggle() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup(&env);
    let (asset, _asset_admin) = setup_token(&env);
    let treasury = Address::generate(&env);

    client.set_fee(&asset, &1000);
    client.set_treasury(&treasury);
    assert!(client.get_fee().is_some());

    // Disable the fee: registration becomes free even with zero balance.
    client.set_fee_enabled(&false);
    assert_eq!(client.get_fee(), None);

    let caller = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool free_again");
    let resolver = Address::generate(&env);
    let uid = client.register(&caller, &schema_str, &resolver, &true);
    assert!(client.get_schema(&uid).is_some());

    // Re-enable: the previous asset/amount are kept.
    client.set_fee_enabled(&true);
    assert_eq!(client.get_fee(), Some((asset, 1000)));
}

#[test]
fn test_enable_fee_without_config() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup(&env);

    let result = client.try_set_fee_enabled(&true);
    assert_eq!(
        result,
        Err(Ok(soroban_sdk::Error::from_contract_error(501)))
    );
}

#[test]
fn test_set_fee_rejects_non_positive_amount() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup(&env);
    let (asset, _asset_admin) = setup_token(&env);

    let result = client.try_set_fee(&asset, &0);
    assert_eq!(
        result,
        Err(Ok(soroban_sdk::Error::from_contract_error(503)))
    );
}

#[test]
fn test_set_fee_requires_admin_auth() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let (asset, _asset_admin) = setup_token(&env);

    // No auth is mocked, so the admin's require_auth must fail.
    assert!(client.try_set_fee(&asset, &1000).is_err());
    assert_eq!(client.get_fee(), None);
}

#[test]
fn test_set_treasury_requires_admin_auth() {
    let env = Env::default();
    let (client, _admin) = setup(&env);
    let treasury = Address::generate(&env);

    assert!(client.try_set_treasury(&treasury).is_err());
    assert_eq!(client.get_treasury(), None);
}

#[test]
fn test_set_fee_enabled_requires_admin_auth() {
    let env = Env::default();
    let (client, _admin) = setup(&env);

    assert!(client.try_set_fee_enabled(&false).is_err());
}

#[test]
fn test_deprecate() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup(&env);

    let caller = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    let uid = client.register(&caller, &schema_str, &resolver, &true);

    // Check it's active
    assert!(client.get_schema(&uid).is_some());

    // Deprecate
    client.deprecate(&uid);

    // Check it's no longer active
    assert!(client.get_schema(&uid).is_none());
}

#[test]
fn test_validate_schema() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _admin) = setup(&env);

    let caller = Address::generate(&env);
    let schema_str = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);

    let uid = client.register(&caller, &schema_str, &resolver, &true);

    assert!(client.validate_schema(&uid));

    client.deprecate(&uid);
    assert!(!client.validate_schema(&uid));
}
