use super::*;
use soroban_sas_common::{Attestation, UID};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token::StellarAssetClient, Address, Bytes, BytesN, Env};

struct TestFixture {
    env: Env,
    client: TokenGatedResolverClient<'static>,
    admin: Address,
    token_id: Address,
}

fn setup() -> TestFixture {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, TokenGatedResolver);
    let client = TokenGatedResolverClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let token_admin = Address::generate(&env);
    let token_id = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();

    TestFixture {
        env,
        client,
        admin,
        token_id,
    }
}

fn create_attestation(env: &Env, attester: &Address, recipient: &Address) -> Attestation {
    Attestation {
        uid: UID(BytesN::from_array(env, &[1u8; 32])),
        schema_uid: UID(BytesN::from_array(env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(env),
        valid_from: 0,
    }
}

#[test]
fn test_initialize_and_get_config() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &100, &10, &FeeDisposal::Transfer);

    let cfg = f.client.config();
    assert_eq!(cfg.admin, f.admin);
    assert_eq!(cfg.token, f.token_id);
    assert_eq!(cfg.min_balance, 100);
    assert_eq!(cfg.fee_amount, 10);
    assert_eq!(cfg.fee_disposal, FeeDisposal::Transfer);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_initialize_already_initialized() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &100, &0, &FeeDisposal::None);
    f.client
        .initialize(&f.admin, &f.token_id, &100, &0, &FeeDisposal::None);
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn test_initialize_invalid_threshold() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &-1, &0, &FeeDisposal::None);
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn test_initialize_invalid_fee_negative() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &100, &-5, &FeeDisposal::Transfer);
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn test_initialize_invalid_fee_with_none_disposal() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &100, &10, &FeeDisposal::None);
}

#[test]
fn test_admin_config_setters() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &100, &0, &FeeDisposal::None);

    let new_admin = Address::generate(&f.env);
    f.client.set_admin(&new_admin);
    assert_eq!(f.client.config().admin, new_admin);

    f.client.set_min_balance(&250);
    assert_eq!(f.client.config().min_balance, 250);

    let new_token = Address::generate(&f.env);
    f.client.set_token(&new_token);
    assert_eq!(f.client.config().token, new_token);

    f.client.set_fee(&15, &FeeDisposal::Burn);
    assert_eq!(f.client.config().fee_amount, 15);
    assert_eq!(f.client.config().fee_disposal, FeeDisposal::Burn);
}

#[test]
fn test_is_eligible_and_balance_of() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &100, &0, &FeeDisposal::None);

    let user = Address::generate(&f.env);
    assert_eq!(f.client.balance_of(&user), 0);
    assert!(!f.client.is_eligible(&user));

    StellarAssetClient::new(&f.env, &f.token_id).mint(&user, &99);
    assert_eq!(f.client.balance_of(&user), 99);
    assert!(!f.client.is_eligible(&user));

    StellarAssetClient::new(&f.env, &f.token_id).mint(&user, &1);
    assert_eq!(f.client.balance_of(&user), 100);
    assert!(f.client.is_eligible(&user));
}

#[test]
fn test_on_attest_succeeds_with_sufficient_balance() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &100, &0, &FeeDisposal::None);

    let attester = Address::generate(&f.env);
    let recipient = Address::generate(&f.env);
    StellarAssetClient::new(&f.env, &f.token_id).mint(&recipient, &150);

    let attestation = create_attestation(&f.env, &attester, &recipient);
    f.client.on_attest(&attestation);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn test_on_attest_reverts_when_below_threshold() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &100, &0, &FeeDisposal::None);

    let attester = Address::generate(&f.env);
    let recipient = Address::generate(&f.env);
    StellarAssetClient::new(&f.env, &f.token_id).mint(&recipient, &99);

    let attestation = create_attestation(&f.env, &attester, &recipient);
    f.client.on_attest(&attestation);
}

#[test]
fn test_on_attest_fee_transfer_to_admin() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &50, &20, &FeeDisposal::Transfer);

    let attester = Address::generate(&f.env);
    let recipient = Address::generate(&f.env);
    StellarAssetClient::new(&f.env, &f.token_id).mint(&recipient, &50);
    StellarAssetClient::new(&f.env, &f.token_id).mint(&attester, &20);

    let attestation = create_attestation(&f.env, &attester, &recipient);
    f.client.on_attest(&attestation);

    let token_client = token::Client::new(&f.env, &f.token_id);
    assert_eq!(token_client.balance(&attester), 0);
    assert_eq!(token_client.balance(&f.admin), 20);
}

#[test]
fn test_on_attest_fee_burn() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &50, &20, &FeeDisposal::Burn);

    let attester = Address::generate(&f.env);
    let recipient = Address::generate(&f.env);
    StellarAssetClient::new(&f.env, &f.token_id).mint(&recipient, &50);
    StellarAssetClient::new(&f.env, &f.token_id).mint(&attester, &30);

    let attestation = create_attestation(&f.env, &attester, &recipient);
    f.client.on_attest(&attestation);

    let token_client = token::Client::new(&f.env, &f.token_id);
    assert_eq!(token_client.balance(&attester), 10);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn test_on_attest_insufficient_fee_reverts() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &50, &20, &FeeDisposal::Transfer);

    let attester = Address::generate(&f.env);
    let recipient = Address::generate(&f.env);
    StellarAssetClient::new(&f.env, &f.token_id).mint(&recipient, &50);
    StellarAssetClient::new(&f.env, &f.token_id).mint(&attester, &10); // Less than 20

    let attestation = create_attestation(&f.env, &attester, &recipient);
    f.client.on_attest(&attestation);
}

#[test]
fn test_on_revoke_succeeds() {
    let f = setup();
    f.client
        .initialize(&f.admin, &f.token_id, &50, &0, &FeeDisposal::None);

    let attester = Address::generate(&f.env);
    let recipient = Address::generate(&f.env);
    let attestation = create_attestation(&f.env, &attester, &recipient);
    f.client.on_revoke(&attestation);
}
