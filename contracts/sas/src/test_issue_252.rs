//! Regression tests for #252: `replace_attestation` must not let an
//! attester shorten a non-zero `expiration_time`, which would otherwise let
//! a replacement silently expire an attestation without running the
//! schema's `on_revoke` resolver hook or emitting `AttestationRevoked`.

use crate::{SASClient, SAS};
use soroban_sas_common::{Attestation, SASError, UID};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env};

#[contract]
struct MockRegistry;

#[contractimpl]
impl MockRegistry {
    pub fn on_attest(_env: Env, _attestation: Attestation) {}

    pub fn on_revoke(_env: Env, _attestation: Attestation) {}

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
        })
    }
}

struct Fixture {
    env: Env,
    sas_client: SASClient<'static>,
    attester: Address,
    recipient: Address,
    old_uid: UID,
}

/// Attests one revocable attestation whose `expiration_time` is `old_exp`
/// (ledger time is fixed at 5000, so any `old_exp > 5000` is still valid at
/// setup time) and returns everything a `replace_attestation` test needs.
fn setup(old_exp: u64) -> Fixture {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 5000);

    let registry_id = env.register_contract(None, MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let schema_uid = UID(BytesN::from_array(&env, &[2u8; 32]));
    let data = Bytes::from_array(&env, &[1u8; 32]);
    let old_uid =
        soroban_sas_common::attestation_uid(&env, &schema_uid, &recipient, &attester, &data);

    let old_attestation = Attestation {
        uid: old_uid.clone(),
        schema_uid,
        time: 1000,
        expiration_time: old_exp,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data,
    };
    sas_client.attest(&old_attestation);

    Fixture {
        env,
        sas_client,
        attester,
        recipient,
        old_uid,
    }
}

impl Fixture {
    /// A replacement attestation reusing this fixture's attester and
    /// recipient (the invariants `replace_attestation` enforces), with the
    /// given `expiration_time` and a UID seed so distinct replacements in
    /// the same test don't collide.
    fn new_attestation(&self, expiration_time: u64, seed: u8) -> Attestation {
        let schema_uid = UID(BytesN::from_array(&self.env, &[3u8; 32]));
        let data = Bytes::from_array(&self.env, &[seed; 32]);
        let uid = soroban_sas_common::attestation_uid(
            &self.env,
            &schema_uid,
            &self.recipient,
            &self.attester,
            &data,
        );
        Attestation {
            uid,
            schema_uid,
            time: 2000,
            expiration_time,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[9u8; 32])),
            recipient: self.recipient.clone(),
            attester: self.attester.clone(),
            revocable: true,
            data,
        }
    }
}

#[test]
fn extending_expiration_succeeds() {
    let f = setup(10_000);
    let new_attestation = f.new_attestation(20_000, 2);

    let returned_uid = f
        .sas_client
        .replace_attestation(&f.old_uid, &new_attestation);
    assert_eq!(returned_uid, new_attestation.uid);
    assert!(f.sas_client.verify_attestation(&new_attestation.uid));
}

#[test]
fn replacing_with_perpetual_succeeds() {
    let f = setup(10_000);
    let new_attestation = f.new_attestation(0, 2);

    let returned_uid = f
        .sas_client
        .replace_attestation(&f.old_uid, &new_attestation);
    assert_eq!(returned_uid, new_attestation.uid);
    assert!(f.sas_client.verify_attestation(&new_attestation.uid));
}

#[test]
fn shortening_expiration_panics_with_invalid_ttl() {
    let f = setup(20_000);
    // Shorter, but still in the future relative to ledger time (5000) — this
    // must still be rejected, since the rule compares against the old
    // attestation's expiration, not "already expired".
    let new_attestation = f.new_attestation(10_000, 2);

    let res = f
        .sas_client
        .try_replace_attestation(&f.old_uid, &new_attestation);
    assert_eq!(res, Err(Ok(SASError::InvalidTTL.into())));
}

#[test]
fn shortening_to_an_already_past_timestamp_panics_with_invalid_ttl() {
    // This is the exact bypass #252 describes: replacing a multi-year
    // attestation with one whose expiration is already in the past, which
    // would otherwise expire it immediately without `on_revoke` or
    // `AttestationRevoked`.
    let f = setup(1_000_000);
    let new_attestation = f.new_attestation(1, 2);

    let res = f
        .sas_client
        .try_replace_attestation(&f.old_uid, &new_attestation);
    assert_eq!(res, Err(Ok(SASError::InvalidTTL.into())));

    // The old attestation must be untouched: still valid, never revoked.
    assert!(f.sas_client.verify_attestation(&f.old_uid));
}

#[test]
fn equal_expiration_succeeds() {
    let f = setup(10_000);
    let new_attestation = f.new_attestation(10_000, 2);

    let returned_uid = f
        .sas_client
        .replace_attestation(&f.old_uid, &new_attestation);
    assert_eq!(returned_uid, new_attestation.uid);
}

#[test]
fn replacing_a_perpetual_attestation_with_any_expiration_succeeds() {
    // Old attestation never expires; #252 only constrains shortening a
    // *non-zero* expiration, so any replacement expiration is accepted here.
    // (6000 is still in the future relative to the fixture's ledger time of
    // 5000 — attest_internal separately rejects an already-past
    // expiration_time at issuance, which is not what this test covers.)
    let f = setup(0);
    let new_attestation = f.new_attestation(6000, 2);

    let returned_uid = f
        .sas_client
        .replace_attestation(&f.old_uid, &new_attestation);
    assert_eq!(returned_uid, new_attestation.uid);
}
