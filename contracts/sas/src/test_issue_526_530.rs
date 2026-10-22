use crate::{SASClient, SAS};
use soroban_sas_common::{
    attestation_uid, Attestation, AttestationIssuedWithFeeEvent, SASError, UID,
};
use soroban_sdk::{
    symbol_short, testutils::Address as _, testutils::Events as _, Address, Bytes, BytesN, Env,
    IntoVal, Vec,
};

fn fixture() -> (Env, SASClient<'static>, Address, Address, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let registry = env.register_contract(None, crate::test::mock1::MockRegistry);
    let id = env.register_contract(None, SAS);
    let client = SASClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.init(&admin, &registry);
    let issuer = Address::generate(&env);
    let recipient = Address::generate(&env);
    (env, client, id, admin, issuer, recipient)
}

fn attestation(env: &Env, issuer: &Address, recipient: &Address, schema: u8) -> Attestation {
    let schema_uid = UID(BytesN::from_array(env, &[schema; 32]));
    let data = Bytes::from_array(env, &[42u8; 16]);
    let uid = attestation_uid(env, &schema_uid, recipient, issuer, &data);
    Attestation {
        uid,
        schema_uid,
        time: 0,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: issuer.clone(),
        revocable: true,
        data,
    }
}

#[test]
fn paid_issuance_quotes_per_byte_and_rejects_underpayment() {
    let (env, sas, id, admin, issuer, recipient) = fixture();
    let token = env.register_stellar_asset_contract_v2(admin).address();
    soroban_sdk::token::StellarAssetClient::new(&env, &token).mint(&issuer, &1000);
    sas.set_fee(&token, &100);
    sas.set_fee_per_byte(&2);
    let a = attestation(&env, &issuer, &recipient, 2);
    assert_eq!(sas.quote_attestation_fee(&a.schema_uid, &0), 100);
    assert_eq!(sas.quote_attestation_fee(&a.schema_uid, &16), 132);
    assert_eq!(sas.quote_attestation_fee(&a.schema_uid, &32), 164);
    assert_eq!(
        sas.try_attest_with_value(&a, &token, &131),
        Err(Ok(SASError::InsufficientFee.into()))
    );
    assert!(!sas.verify_attestation(&a.uid));
    sas.attest_with_value(&a, &token, &132);
    assert_eq!(
        soroban_sdk::token::Client::new(&env, &token).balance(&id),
        132
    );
    let fee_event = AttestationIssuedWithFeeEvent {
        uid: a.uid.clone(),
        schema_uid: a.schema_uid.clone(),
        attester: a.attester.clone(),
        recipient: a.recipient.clone(),
        fee_amount: 132,
    };
    let events = env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                id.clone(),
                (
                    symbol_short!("ATTFEE"),
                    a.schema_uid.clone(),
                    a.attester.clone()
                )
                    .into_val(&env),
                fee_event.into_val(&env),
            )
        ]
    );

    let free = attestation(&env, &issuer, &recipient, 3);
    sas.set_schema_zero_fee(&free.schema_uid, &true);
    assert_eq!(sas.quote_attestation_fee(&free.schema_uid, &16), 0);
    sas.attest_with_value(&free, &token, &0);
    assert_eq!(
        soroban_sdk::token::Client::new(&env, &token).balance(&id),
        132
    );
    sas.set_schema_zero_fee(&free.schema_uid, &false);
    assert_eq!(sas.quote_attestation_fee(&free.schema_uid, &16), 132);
}

#[test]
fn byte_fee_cannot_be_bypassed_by_unpaid_attestation() {
    let (env, sas, _id, admin, issuer, recipient) = fixture();
    let token = env.register_stellar_asset_contract_v2(admin).address();
    sas.set_fee(&token, &100);
    sas.set_fee_per_byte(&1);
    let a = attestation(&env, &issuer, &recipient, 2);
    assert_eq!(
        sas.try_attest(&a),
        Err(Ok(SASError::InsufficientFee.into()))
    );
    assert!(!sas.verify_attestation(&a.uid));
    sas.set_schema_zero_fee(&a.schema_uid, &true);
    sas.attest(&a);
    assert!(sas.verify_attestation(&a.uid));
}

#[test]
fn emergency_pause_blocks_mutations_but_keeps_reads() {
    let (env, sas, _id, _admin, issuer, recipient) = fixture();
    let a = attestation(&env, &issuer, &recipient, 2);
    sas.attest(&a);
    sas.pause();
    assert!(sas.is_paused());
    let b = attestation(&env, &issuer, &recipient, 3);
    assert_eq!(sas.try_attest(&b), Err(Ok(SASError::ProtocolPaused.into())));
    assert_eq!(
        sas.try_revoke(&a.uid),
        Err(Ok(SASError::ProtocolPaused.into()))
    );
    assert_eq!(
        sas.try_replace_attestation(&a.uid, &b),
        Err(Ok(SASError::ProtocolPaused.into()))
    );
    assert_eq!(
        sas.try_reindex_attestation(&a.uid),
        Err(Ok(SASError::ProtocolPaused.into()))
    );
    assert_eq!(
        sas.try_bulk_reindex(&Vec::<UID>::new(&env)),
        Err(Ok(SASError::ProtocolPaused.into()))
    );
    assert_eq!(sas.get_attestation(&a.uid).unwrap().uid, a.uid);
    assert!(sas.verify_attestation(&a.uid));
    sas.unpause();
    assert!(!sas.is_paused());
    sas.attest(&b);
    assert!(sas.verify_attestation(&b.uid));
}

#[test]
fn pause_requires_admin_authorization() {
    let (env, sas, _id, _admin, _issuer, _recipient) = fixture();
    env.set_auths(&[]);
    assert!(sas.try_pause().is_err());
    env.mock_all_auths();
    assert!(!sas.is_paused());
}
