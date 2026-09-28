//! Tests for batched off-chain delegation signatures (issue #293).
//!
//! `multi_attest_by_delegation` and `multi_revoke_by_delegation` extend the
//! single-item delegation paths to mirror `multi_attest` / `multi_revoke`.
//! These tests pin the batch semantics: parallel-vector length validation,
//! per-item signature binding to the signed payload, per-attester nonce
//! ordering, and the all-or-nothing nature of a failed batch.

use crate::{SASClient, SAS, MAX_MULTI_ATTEST, MAX_MULTI_REVOKE};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{
    hash_delegated_revocation, hash_offchain_attestation, Attestation, AttestationDomain, SASError,
    UID,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, String as SorobanString};

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
            deprecated: false,
        })
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

/// Builds an `Attestation` whose content-addressed `uid` matches its fields.
fn fixture(env: &Env, attester: &Address, recipient: &Address, seed: [u8; 32]) -> Attestation {
    let schema_uid = UID(BytesN::from_array(env, &[2u8; 32]));
    let data = Bytes::from_array(env, &seed);
    let uid = soroban_sas_common::attestation_uid(env, &schema_uid, recipient, attester, &data);

    Attestation {
        uid,
        schema_uid,
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data,
    }
}

fn key(seed: [u8; 32]) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

fn account(env: &Env, signing_key: &SigningKey) -> Address {
    let strkey = stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string();
    Address::from_string(&SorobanString::from_str(env, &strkey))
}

fn public_key(env: &Env, signing_key: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &signing_key.verifying_key().to_bytes())
}

fn sign_attestation(
    env: &Env,
    sas_id: &Address,
    signing_key: &SigningKey,
    attestation: &Attestation,
    nonce: u64,
) -> BytesN<64> {
    let domain = AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: sas_id.clone(),
        nonce,
    };
    let digest = hash_offchain_attestation(env, attestation, &domain);
    BytesN::from_array(env, &signing_key.sign(&digest.to_array()).to_bytes())
}

fn sign_revocation(
    env: &Env,
    sas_id: &Address,
    signing_key: &SigningKey,
    uid: &UID,
    attester: &Address,
    nonce: u64,
) -> BytesN<64> {
    let domain = AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: sas_id.clone(),
        nonce,
    };
    let digest = hash_delegated_revocation(env, uid, attester, &domain);
    BytesN::from_array(env, &signing_key.sign(&digest.to_array()).to_bytes())
}

fn vec_att(env: &Env, items: &[Attestation]) -> soroban_sdk::Vec<Attestation> {
    let mut out = soroban_sdk::Vec::new(env);
    for item in items {
        out.push_back(item.clone());
    }
    out
}

fn vec_u64(env: &Env, items: &[u64]) -> soroban_sdk::Vec<u64> {
    let mut out = soroban_sdk::Vec::new(env);
    for item in items {
        out.push_back(*item);
    }
    out
}

fn vec_uid(env: &Env, items: &[UID]) -> soroban_sdk::Vec<UID> {
    let mut out = soroban_sdk::Vec::new(env);
    for item in items {
        out.push_back(item.clone());
    }
    out
}

fn vec_sig(env: &Env, items: &[BytesN<64>]) -> soroban_sdk::Vec<BytesN<64>> {
    let mut out = soroban_sdk::Vec::new(env);
    for item in items {
        out.push_back(item.clone());
    }
    out
}

fn vec_pub(env: &Env, items: &[BytesN<32>]) -> soroban_sdk::Vec<BytesN<32>> {
    let mut out = soroban_sdk::Vec::new(env);
    for item in items {
        out.push_back(item.clone());
    }
    out
}

#[test]
fn multi_attest_by_delegation_issues_a_batch_and_consumes_each_nonce() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);

    let key_a = key([41u8; 32]);
    let key_b = key([42u8; 32]);
    let attester_a = account(&env, &key_a);
    let attester_b = account(&env, &key_b);
    let att_a = fixture(&env, &attester_a, &Address::generate(&env), [10u8; 32]);
    let att_b = fixture(&env, &attester_b, &Address::generate(&env), [11u8; 32]);

    let nonces = [1u64, 1u64];
    let signatures = [
        sign_attestation(&env, &sas_id, &key_a, &att_a, nonces[0]),
        sign_attestation(&env, &sas_id, &key_b, &att_b, nonces[1]),
    ];
    let public_keys = [public_key(&env, &key_a), public_key(&env, &key_b)];

    let uids = client.multi_attest_by_delegation(
        &vec_att(&env, &[att_a.clone(), att_b.clone()]),
        &vec_u64(&env, &nonces),
        &vec_sig(&env, &signatures),
        &vec_pub(&env, &public_keys),
    );

    assert_eq!(uids.len(), 2);
    assert_eq!(uids.get(0).unwrap(), att_a.uid);
    assert_eq!(uids.get(1).unwrap(), att_b.uid);
    assert!(client.verify_attestation(&att_a.uid));
    assert!(client.verify_attestation(&att_b.uid));
    assert_eq!(client.get_delegation_nonce(&attester_a), Some(1));
    assert_eq!(client.get_delegation_nonce(&attester_b), Some(1));
}

#[test]
fn multi_attest_by_delegation_rejects_mismatched_vector_lengths() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);

    let key_a = key([41u8; 32]);
    let attester = account(&env, &key_a);
    let att_a = fixture(&env, &attester, &Address::generate(&env), [10u8; 32]);
    let att_b = fixture(&env, &attester, &Address::generate(&env), [11u8; 32]);

    // Two attestations but only one nonce/signature/key.
    let one_sig = vec_sig(
        &env,
        &[sign_attestation(&env, &sas_id, &key_a, &att_a, 1)],
    );
    let res = client.try_multi_attest_by_delegation(
        &vec_att(&env, &[att_a, att_b]),
        &vec_u64(&env, &[1, 2]),
        &one_sig,
        &vec_pub(&env, &[public_key(&env, &key_a)]),
    );

    assert_eq!(res, Err(Ok(SASError::InvalidValue.into())));
}

#[test]
fn multi_attest_by_delegation_is_all_or_nothing_and_does_not_consume_nonces() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);

    let key_a = key([41u8; 32]);
    let attester = account(&env, &key_a);
    let att_a = fixture(&env, &attester, &Address::generate(&env), [10u8; 32]);
    let att_b = fixture(&env, &attester, &Address::generate(&env), [11u8; 32]);

    let nonces = [1u64, 2u64];
    // Sign item B, then submit a mutated copy: the whole batch must fail.
    let mut tampered_b = att_b.clone();
    tampered_b.data = Bytes::from_slice(&env, &[9, 9, 9]);
    let signatures = [
        sign_attestation(&env, &sas_id, &key_a, &att_a, nonces[0]),
        sign_attestation(&env, &sas_id, &key_a, &att_b, nonces[1]),
    ];
    let public_keys = [public_key(&env, &key_a), public_key(&env, &key_a)];

    let res = client.try_multi_attest_by_delegation(
        &vec_att(&env, &[att_a.clone(), tampered_b]),
        &vec_u64(&env, &nonces),
        &vec_sig(&env, &signatures),
        &vec_pub(&env, &public_keys),
    );
    assert!(res.is_err());

    // A reverted batch leaves no trace: neither item was issued and no nonce
    // was consumed, so the correctly signed batch still succeeds unchanged.
    assert_eq!(client.get_delegation_nonce(&attester), None);
    assert!(!client.verify_attestation(&att_a.uid));
    assert!(!client.verify_attestation(&att_b.uid));

    let uids = client.multi_attest_by_delegation(
        &vec_att(&env, &[att_a.clone(), att_b.clone()]),
        &vec_u64(&env, &nonces),
        &vec_sig(&env, &signatures),
        &vec_pub(&env, &public_keys),
    );
    assert_eq!(uids.len(), 2);
    assert_eq!(client.get_delegation_nonce(&attester), Some(2));
}

#[test]
fn multi_attest_by_delegation_enforces_strictly_increasing_nonces_per_attester() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);

    let key_a = key([41u8; 32]);
    let attester = account(&env, &key_a);
    let att_a = fixture(&env, &attester, &Address::generate(&env), [10u8; 32]);
    let att_b = fixture(&env, &attester, &Address::generate(&env), [11u8; 32]);

    // Out-of-order nonces for the same attester: the second item replays a
    // value at or below the first item's high-watermark.
    let descending = [2u64, 1u64];
    let descending_signatures = [
        sign_attestation(&env, &sas_id, &key_a, &att_a, descending[0]),
        sign_attestation(&env, &sas_id, &key_a, &att_b, descending[1]),
    ];
    let public_keys = [public_key(&env, &key_a), public_key(&env, &key_a)];
    let res = client.try_multi_attest_by_delegation(
        &vec_att(&env, &[att_a.clone(), att_b.clone()]),
        &vec_u64(&env, &descending),
        &vec_sig(&env, &descending_signatures),
        &vec_pub(&env, &public_keys),
    );
    assert!(res.is_err());
    assert_eq!(client.get_delegation_nonce(&attester), None);

    // The same items in ascending order succeed.
    let ascending = [1u64, 2u64];
    let ascending_signatures = [
        sign_attestation(&env, &sas_id, &key_a, &att_a, ascending[0]),
        sign_attestation(&env, &sas_id, &key_a, &att_b, ascending[1]),
    ];
    client.multi_attest_by_delegation(
        &vec_att(&env, &[att_a, att_b]),
        &vec_u64(&env, &ascending),
        &vec_sig(&env, &ascending_signatures),
        &vec_pub(&env, &public_keys),
    );
    assert_eq!(client.get_delegation_nonce(&attester), Some(2));
}

#[test]
fn multi_attest_by_delegation_rejects_an_oversized_batch() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);

    let attester = Address::generate(&env);
    let count = MAX_MULTI_ATTEST + 1;
    let mut attestations = soroban_sdk::Vec::new(&env);
    let mut nonces = soroban_sdk::Vec::new(&env);
    let mut signatures = soroban_sdk::Vec::new(&env);
    let mut public_keys = soroban_sdk::Vec::new(&env);
    for i in 0..count {
        attestations.push_back(fixture(&env, &attester, &Address::generate(&env), [i as u8; 32]));
        nonces.push_back(i as u64 + 1);
        signatures.push_back(BytesN::from_array(&env, &[0u8; 64]));
        public_keys.push_back(BytesN::from_array(&env, &[0u8; 32]));
    }

    let res = client.try_multi_attest_by_delegation(
        &attestations,
        &nonces,
        &signatures,
        &public_keys,
    );
    assert_eq!(res, Err(Ok(SASError::BatchTooLarge.into())));
}

#[test]
fn multi_revoke_by_delegation_revokes_a_batch_and_consumes_nonces() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);

    let key_a = key([41u8; 32]);
    let attester = account(&env, &key_a);
    let att_a = fixture(&env, &attester, &Address::generate(&env), [10u8; 32]);
    let att_b = fixture(&env, &attester, &Address::generate(&env), [11u8; 32]);

    env.mock_all_auths();
    client.attest(&att_a);
    client.attest(&att_b);

    let nonces = [1u64, 2u64];
    let signatures = [
        sign_revocation(&env, &sas_id, &key_a, &att_a.uid, &attester, nonces[0]),
        sign_revocation(&env, &sas_id, &key_a, &att_b.uid, &attester, nonces[1]),
    ];
    let public_keys = [public_key(&env, &key_a), public_key(&env, &key_a)];

    env.ledger().with_mut(|li| li.timestamp = 5000);
    client.multi_revoke_by_delegation(
        &vec_uid(&env, &[att_a.uid.clone(), att_b.uid.clone()]),
        &vec_u64(&env, &nonces),
        &vec_sig(&env, &signatures),
        &vec_pub(&env, &public_keys),
    );

    assert!(!client.verify_attestation(&att_a.uid));
    assert!(!client.verify_attestation(&att_b.uid));
    assert_eq!(client.get_delegation_nonce(&attester), Some(2));
}

#[test]
fn multi_revoke_by_delegation_rejects_duplicate_uids() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);

    let key_a = key([41u8; 32]);
    let attester = account(&env, &key_a);
    let att_a = fixture(&env, &attester, &Address::generate(&env), [10u8; 32]);

    env.mock_all_auths();
    client.attest(&att_a);

    let signatures = [
        sign_revocation(&env, &sas_id, &key_a, &att_a.uid, &attester, 1),
        sign_revocation(&env, &sas_id, &key_a, &att_a.uid, &attester, 2),
    ];
    let res = client.try_multi_revoke_by_delegation(
        &vec_uid(&env, &[att_a.uid.clone(), att_a.uid.clone()]),
        &vec_u64(&env, &[1, 2]),
        &vec_sig(&env, &signatures),
        &vec_pub(&env, &[public_key(&env, &key_a), public_key(&env, &key_a)]),
    );

    assert_eq!(res, Err(Ok(SASError::DuplicateAttestation.into())));
    assert_eq!(client.get_delegation_nonce(&attester), None);
    assert!(client.verify_attestation(&att_a.uid));
}

#[test]
fn multi_revoke_by_delegation_rejects_a_key_that_is_not_the_recorded_attester() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);

    let key_a = key([41u8; 32]);
    let key_b = key([42u8; 32]);
    let attester = account(&env, &key_a);
    let att_a = fixture(&env, &attester, &Address::generate(&env), [10u8; 32]);

    env.mock_all_auths();
    client.attest(&att_a);

    // A valid signature from the recorded attester, but paired with a
    // different public key in the batch: the binding check must reject it.
    let signature = sign_revocation(&env, &sas_id, &key_a, &att_a.uid, &attester, 1);
    let res = client.try_multi_revoke_by_delegation(
        &vec_uid(&env, &[att_a.uid.clone()]),
        &vec_u64(&env, &[1]),
        &vec_sig(&env, &[signature]),
        &vec_pub(&env, &[public_key(&env, &key_b)]),
    );

    assert_eq!(res, Err(Ok(SASError::Unauthorized.into())));
    assert!(client.verify_attestation(&att_a.uid));
}

#[test]
fn multi_revoke_by_delegation_rejects_an_oversized_batch() {
    let env = Env::default();
    let sas_id = setup(&env);
    let client = SASClient::new(&env, &sas_id);

    let count = MAX_MULTI_REVOKE + 1;
    let mut uids = soroban_sdk::Vec::new(&env);
    let mut nonces = soroban_sdk::Vec::new(&env);
    let mut signatures = soroban_sdk::Vec::new(&env);
    let mut public_keys = soroban_sdk::Vec::new(&env);
    for i in 0..count {
        uids.push_back(UID(BytesN::from_array(&env, &[i as u8; 32])));
        nonces.push_back(i as u64 + 1);
        signatures.push_back(BytesN::from_array(&env, &[0u8; 64]));
        public_keys.push_back(BytesN::from_array(&env, &[0u8; 32]));
    }

    let res =
        client.try_multi_revoke_by_delegation(&uids, &nonces, &signatures, &public_keys);
    assert_eq!(res, Err(Ok(SASError::BatchTooLarge.into())));
}
