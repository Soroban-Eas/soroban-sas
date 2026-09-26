use crate::{SASClient, SAS};
use soroban_sas_common::{Attestation, SASError, UID};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env};

#[contract]
struct MockRegistry;

#[contractimpl]
impl MockRegistry {
    pub fn on_attest(_env: Env, _attestation: Attestation) {}

    pub fn is_authorized(_env: Env, _uid: UID, _attester: Address) -> bool {
        true
    }

    #[allow(non_snake_case)]
    pub fn SASREG(_env: Env) -> bool {
        true
    }

    pub fn get_schema(env: Env, uid: UID) -> Option<soroban_sas_common::SchemaRecord> {
        Some(soroban_sas_common::SchemaRecord {
            uid,
            resolver: env.current_contract_address(),
            revocable: true,
            schema: soroban_sdk::String::from_str(&env, "bool valid"),
            deprecated: false,
        })
    }
}

fn fixture(env: &Env, attester: &Address, recipient: &Address, seed: [u8; 32]) -> Attestation {
    let schema_uid = UID(BytesN::from_array(env, &[2u8; 32]));
    let data = Bytes::from_array(env, &seed);
    let uid = soroban_sas_common::attestation_uid(env, &schema_uid, recipient, attester, &data);

    Attestation {
        uid,
        schema_uid,
        time: 0,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data,
    }
}

fn setup(env: &Env) -> Address {
    let registry_id = env.register_contract(None, MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let client = SASClient::new(env, &sas_id);
    let admin = Address::generate(env);

    env.mock_all_auths();
    client.init(&admin, &registry_id);
    sas_id
}

#[test]
fn rejects_zero_account_attester() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);
    let attester = Address::from_string(&soroban_sdk::String::from_str(
        &env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    ));
    let recipient = Address::generate(&env);
    let attestation = fixture(&env, &attester, &recipient, [17u8; 32]);

    env.mock_all_auths();
    let result = client.try_attest(&attestation);
    assert_eq!(result, Err(Ok(SASError::InvalidRecipient.into())));
}

#[test]
fn rejects_zero_contract_attester() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);
    let attester = Address::from_string(&soroban_sdk::String::from_str(
        &env,
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    ));
    let recipient = Address::generate(&env);
    let attestation = fixture(&env, &attester, &recipient, [18u8; 32]);

    env.mock_all_auths();
    let result = client.try_attest(&attestation);
    assert_eq!(result, Err(Ok(SASError::InvalidRecipient.into())));
}

#[test]
fn accepts_valid_attester() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let attestation = fixture(&env, &attester, &recipient, [19u8; 32]);

    env.mock_all_auths();
    let uid = client.attest(&attestation);
    assert_eq!(uid, attestation.uid);
}
