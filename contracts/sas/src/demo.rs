//! A narrated, end-to-end walkthrough of the attestation service, run
//! entirely in-process (no network, no funded accounts) against the *real*
//! `schema-registry` and `sas` contracts — not mocks. Run it with:
//!
//!   cargo test -p sas --lib demo:: -- --nocapture
//!
//! and record the terminal output: it prints each step of the protocol as
//! it happens, so the output itself tells the story of what the service
//! does — register a schema, issue an attestation against it, verify it,
//! then revoke it and verify again.

use crate::{SASClient, SAS};
use schema_registry::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::{Attestation, UID};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, String as SorobanString};

/// A resolver that accepts every attestation unconditionally. Schemas name a
/// resolver contract that gets the final say on each attestation issued
/// against them (fraud checks, KYC gates, whatever the schema author wants)
/// — this demo's schema just doesn't need one.
mod noop_resolver {
    use super::*;

    #[contract]
    pub struct NoopResolver;

    #[contractimpl]
    impl NoopResolver {
        pub fn on_attest(_env: Env, _attestation: Attestation) {}
        pub fn on_revoke(_env: Env, _attestation: Attestation) {}
    }
}

#[test]
fn demo_register_schema_then_attest_verify_and_revoke() {
    let env = Env::default();
    env.mock_all_auths();

    println!("\n=== soroban-sas: schema -> attestation -> verification demo ===\n");

    // --- Deploy the three parties: a schema registry, the core SAS
    // contract, and a resolver the demo schema will delegate to. ---
    let admin = Address::generate(&env);
    let registry_id = env.register_contract(None, SchemaRegistry);
    let registry = SchemaRegistryClient::new(&env, &registry_id);
    registry.init(&admin);

    let sas_id = env.register_contract(None, SAS);
    let sas = SASClient::new(&env, &sas_id);
    sas.init(&admin, &registry_id);

    let resolver_id = env.register_contract(None, noop_resolver::NoopResolver);

    println!(
        "1. Deployed schema-registry ({registry_id:?}) and sas ({sas_id:?}), bound together.\n"
    );

    // --- Step 1: register a schema. This is the "shape of the claim" every
    // attestation issued under it will follow. ---
    let issuer = Address::generate(&env);
    let schema_str = SorobanString::from_str(&env, "bool is_verified_human");
    let schema_uid = registry.register(&issuer, &schema_str, &resolver_id, &true);

    println!("2. Registered schema \"bool is_verified_human\"");
    println!("   schema_uid: {}\n", hex::encode(schema_uid.0.to_array()));

    // --- Step 2: schema owner authorizes a delegate. ---
    let attester = Address::generate(&env);
    registry.add_delegate(&schema_uid, &attester);
    println!("3. Schema owner authorized delegate: {attester:?}\n");

    // --- Step 3: delegate issues an attestation against that schema. ---
    let recipient = Address::generate(&env);
    let attestation = Attestation {
        uid: demo_attestation_uid(&env, &schema_uid.0, &attester, &recipient),
        schema_uid: schema_uid.clone(),
        time: 0, // normalized to ledger time by the contract
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };
    let attestation_uid = sas.attest(&attestation);

    println!("4. Authorized delegate issued an attestation against that schema:");
    println!("   attester:   {attester:?}");
    println!("   recipient:  {recipient:?}");
    println!(
        "   uid:        {}\n",
        hex::encode(attestation_uid.0.to_array())
    );

    // --- Step 4: anyone can verify it on-chain. ---
    let is_valid = sas.verify_attestation(&attestation_uid);
    println!("5. verify_attestation(uid) -> {is_valid}\n");
    assert!(is_valid);

    let record = sas.get_attestation(&attestation_uid).unwrap();
    println!(
        "   Full record: recipient={:?}, revocable={}, revoked={}\n",
        record.recipient,
        record.revocable,
        record.revocation_time != 0
    );

    // --- Step 5: the attester revokes it; verification now reflects that.
    // A fresh Env's ledger timestamp starts at 0, which would make the
    // recorded revocation_time indistinguishable from "never revoked" —
    // advance the clock first, exactly as a real network would have.
    env.ledger().with_mut(|li| li.timestamp = 1000);
    sas.revoke(&attestation_uid);
    let is_valid_after_revoke = sas.verify_attestation(&attestation_uid);
    println!("6. Attester revoked it. verify_attestation(uid) -> {is_valid_after_revoke}\n");
    assert!(!is_valid_after_revoke);

    println!("=== done ===\n");
}

/// A content-addressed UID for the demo attestation, following the same
/// hash-of-fields shape `AttestationRequestBuilder` uses in the SDK.
fn demo_attestation_uid(
    env: &Env,
    schema_uid: &BytesN<32>,
    attester: &Address,
    recipient: &Address,
) -> UID {
    use soroban_sdk::xdr::ToXdr;
    let mut payload = Bytes::new(env);
    payload.append(&schema_uid.clone().to_xdr(env));
    payload.append(&attester.clone().to_xdr(env));
    payload.append(&recipient.clone().to_xdr(env));
    UID(env.crypto().sha256(&payload))
}
