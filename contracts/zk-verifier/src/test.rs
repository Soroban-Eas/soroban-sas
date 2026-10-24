use super::*;
use soroban_sdk::testutils::storage::{Instance as _, Persistent as _};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, vec, Address, Bytes, BytesN, Env};

#[contract]
struct MockSas;

#[contractimpl]
impl MockSas {
    pub fn verify_attestation(env: Env, uid: UID) -> bool {
        let is_valid: Option<bool> = env.storage().instance().get(&uid);
        is_valid.unwrap_or(true)
    }

    pub fn get_valid_from(env: Env, uid: UID) -> u64 {
        let vf: Option<u64> = env.storage().instance().get(&(symbol_short!("vf"), uid));
        vf.unwrap_or(0)
    }
}

fn create_proof(
    env: &Env,
    attestation_uid: UID,
    schema_uid: UID,
    nullifier: [u8; 32],
    commitment: [u8; 32],
    timestamp: u64,
) -> ZkAttestationProof {
    let nullifier_bytes = BytesN::from_array(env, &nullifier);
    let commitment_bytes = BytesN::from_array(env, &commitment);

    let mut binding_payload = Bytes::new(env);
    binding_payload.append(&commitment_bytes.clone().into());
    binding_payload.append(&nullifier_bytes.clone().into());
    let hash: BytesN<32> = env.crypto().sha256(&binding_payload).into();

    let mut proof_bytes = Bytes::new(env);
    proof_bytes.append(&hash.into());
    // Append mock zk-proof witness data
    proof_bytes.append(&Bytes::from_array(env, &[0x42; 64]));

    ZkAttestationProof {
        attestation_uid,
        schema_uid,
        nullifier: nullifier_bytes,
        commitment: commitment_bytes,
        proof: proof_bytes,
        timestamp,
    }
}

fn setup_test() -> (Env, Address, Address, Address, ZkVerifierClient<'static>) {
    let env = Env::default();
    let admin = Address::generate(&env);
    let sas = env.register_contract(None, MockSas);
    let verifier_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &verifier_id);

    env.mock_all_auths();
    client.init(&admin, &sas);

    (env, admin, sas, verifier_id, client)
}

#[test]
fn test_zk_proof_verification_success_and_nullifier_consumption() {
    let (env, _admin, _sas, _verifier, client) = setup_test();

    env.ledger().with_mut(|li| li.timestamp = 1000);

    let attestation_uid = UID(BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(BytesN::from_array(&env, &[2u8; 32]));
    let nullifier = [3u8; 32];
    let commitment = [4u8; 32];

    let proof = create_proof(
        &env,
        attestation_uid,
        schema_uid,
        nullifier,
        commitment,
        1000,
    );

    let nullifier_bytes = BytesN::from_array(&env, &nullifier);
    let commitment_bytes = BytesN::from_array(&env, &commitment);

    assert!(!client.is_nullifier_used(&nullifier_bytes));
    assert!(!client.is_commitment_verified(&commitment_bytes));

    let res = client.verify_and_consume_proof(&proof);
    assert!(res);

    assert!(client.is_nullifier_used(&nullifier_bytes));
    assert!(client.is_commitment_verified(&commitment_bytes));

    // Replay with identical nullifier must fail
    let replay_err = client.try_verify_and_consume_proof(&proof);
    let replay_code = replay_err.err().unwrap().unwrap();
    assert_eq!(replay_code, ZkVerifierError::NullifierSpent);
    // The error is also reachable under the `ZKError` spelling used by the
    // ZK verifier documentation.
    assert_eq!(replay_code, ZKError::NullifierSpent);
}

#[test]
fn test_zk_proof_tampered_proof_rejected() {
    let (env, _admin, _sas, _verifier, client) = setup_test();

    env.ledger().with_mut(|li| li.timestamp = 1000);

    let attestation_uid = UID(BytesN::from_array(&env, &[10u8; 32]));
    let schema_uid = UID(BytesN::from_array(&env, &[11u8; 32]));
    let mut proof = create_proof(
        &env,
        attestation_uid,
        schema_uid,
        [12u8; 32],
        [13u8; 32],
        1000,
    );

    // Tamper with proof bytes
    proof.proof = Bytes::from_array(&env, &[0xDE, 0xAD, 0xBE, 0xEF]);

    let res = client.try_verify_and_consume_proof(&proof);
    assert_eq!(res.err().unwrap().unwrap(), ZkVerifierError::InvalidProof);
}

#[test]
fn test_zk_proof_expired_or_stale_proof_rejected() {
    let (env, _admin, _sas, _verifier, client) = setup_test();

    env.ledger().with_mut(|li| li.timestamp = 1_000_000);

    let attestation_uid = UID(BytesN::from_array(&env, &[20u8; 32]));
    let schema_uid = UID(BytesN::from_array(&env, &[21u8; 32]));

    // Proof generated older than MAX_ZK_PROOF_AGE_SECONDS
    let stale_timestamp = 1_000_000 - MAX_ZK_PROOF_AGE_SECONDS - 1;
    let proof = create_proof(
        &env,
        attestation_uid,
        schema_uid,
        [22u8; 32],
        [23u8; 32],
        stale_timestamp,
    );

    let res = client.try_verify_and_consume_proof(&proof);
    assert_eq!(res.err().unwrap().unwrap(), ZkVerifierError::ProofTooOld);
}

#[test]
fn test_zk_proof_invalid_onchain_attestation_rejected() {
    let (env, _admin, sas, _verifier, client) = setup_test();

    env.ledger().with_mut(|li| li.timestamp = 1000);

    let attestation_uid = UID(BytesN::from_array(&env, &[30u8; 32]));
    let schema_uid = UID(BytesN::from_array(&env, &[31u8; 32]));

    // Mark attestation as invalid in SAS mock
    env.as_contract(&sas, || {
        env.storage().instance().set(&attestation_uid, &false);
    });

    let proof = create_proof(
        &env,
        attestation_uid,
        schema_uid,
        [32u8; 32],
        [33u8; 32],
        1000,
    );

    let res = client.try_verify_and_consume_proof(&proof);
    assert_eq!(
        res.err().unwrap().unwrap(),
        ZkVerifierError::AttestationRevokedOrInvalid
    );
}

#[test]
fn test_zk_proof_timelocked_attestation_activation() {
    let (env, _admin, sas, _verifier, client) = setup_test();

    let attestation_uid = UID(BytesN::from_array(&env, &[40u8; 32]));
    let schema_uid = UID(BytesN::from_array(&env, &[41u8; 32]));

    // Set valid_from = 2000 on SAS mock
    env.as_contract(&sas, || {
        env.storage()
            .instance()
            .set(&(symbol_short!("vf"), attestation_uid.clone()), &2000u64);
    });

    // Current time = 1500 (before activation)
    env.ledger().with_mut(|li| li.timestamp = 1500);

    let proof = create_proof(
        &env,
        attestation_uid.clone(),
        schema_uid.clone(),
        [42u8; 32],
        [43u8; 32],
        1500,
    );

    let res = client.try_verify_and_consume_proof(&proof);
    assert_eq!(
        res.err().unwrap().unwrap(),
        ZkVerifierError::AttestationNotYetActive
    );

    // Advance time to 2000 (activation point)
    env.ledger().with_mut(|li| li.timestamp = 2000);
    let proof_activated = create_proof(
        &env,
        attestation_uid,
        schema_uid,
        [44u8; 32],
        [45u8; 32],
        2000,
    );

    assert!(client.verify_and_consume_proof(&proof_activated));
}

/// Nullifiers are the contract's only replay key, so the storage key must
/// separate them exactly: two nullifiers that differ in a single bit are
/// different nullifiers, and one spent nullifier never blocks another.
#[test]
fn test_nullifier_collision_resistance() {
    let (env, _admin, _sas, _verifier, client) = setup_test();

    env.ledger().with_mut(|li| li.timestamp = 1000);

    let attestation_uid = UID(BytesN::from_array(&env, &[50u8; 32]));
    let schema_uid = UID(BytesN::from_array(&env, &[51u8; 32]));

    // Three nullifiers: one, the same one with the last bit flipped, and a
    // completely different one.
    let nullifier_a = [0x00u8; 32];
    let mut nullifier_b = [0x00u8; 32];
    nullifier_b[31] = 0x01;
    let nullifier_c = [0xffu8; 32];

    // Every one of them is accepted: no two of them collide.
    for (index, nullifier) in [nullifier_a, nullifier_b, nullifier_c].iter().enumerate() {
        let proof = create_proof(
            &env,
            attestation_uid.clone(),
            schema_uid.clone(),
            *nullifier,
            [60u8 + index as u8; 32],
            1000,
        );
        assert!(client.verify_and_consume_proof(&proof));
    }

    // All three are recorded independently.
    for nullifier in [nullifier_a, nullifier_b, nullifier_c] {
        assert!(client.is_nullifier_used(&BytesN::from_array(&env, &nullifier)));
    }

    // A nullifier that differs in a single bit from a spent one is still
    // unspent, so a near-miss is never rejected as a replay.
    let mut near_miss = nullifier_a;
    near_miss[0] = 0x01;
    assert!(!client.is_nullifier_used(&BytesN::from_array(&env, &near_miss)));

    // Re-using a spent nullifier is rejected even when the rest of the
    // proof is different: the nullifier alone decides.
    let replay = create_proof(
        &env,
        attestation_uid,
        schema_uid,
        nullifier_a,
        [99u8; 32],
        1000,
    );
    assert_eq!(
        client
            .try_verify_and_consume_proof(&replay)
            .err()
            .unwrap()
            .unwrap(),
        ZkVerifierError::NullifierSpent
    );
}

/// Checking and recording a nullifier is atomic: a rejected proof must not
/// consume its nullifier, and the nullifier must still be usable afterwards.
#[test]
fn test_nullifier_is_not_consumed_by_a_rejected_proof() {
    let (env, _admin, _sas, _verifier, client) = setup_test();

    env.ledger().with_mut(|li| li.timestamp = 1000);

    let attestation_uid = UID(BytesN::from_array(&env, &[70u8; 32]));
    let schema_uid = UID(BytesN::from_array(&env, &[71u8; 32]));
    let nullifier = [72u8; 32];
    let commitment = [73u8; 32];

    // A proof with a tampered payload is rejected ...
    let mut tampered = create_proof(
        &env,
        attestation_uid.clone(),
        schema_uid.clone(),
        nullifier,
        commitment,
        1000,
    );
    tampered.proof = Bytes::from_array(&env, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(
        client
            .try_verify_and_consume_proof(&tampered)
            .err()
            .unwrap()
            .unwrap(),
        ZkVerifierError::InvalidProof
    );

    // ... and leaves the nullifier unspent, so the same nullifier can still
    // be presented with a valid proof.
    assert!(!client.is_nullifier_used(&BytesN::from_array(&env, &nullifier)));

    let valid = create_proof(
        &env,
        attestation_uid,
        schema_uid,
        nullifier,
        commitment,
        1000,
    );
    assert!(client.verify_and_consume_proof(&valid));
    assert!(client.is_nullifier_used(&BytesN::from_array(&env, &nullifier)));
}

/// A nullifier record must not expire before the contract instance that
/// guards it, so it is renewed with the instance's own TTL policy.
#[test]
fn test_nullifier_ttl_is_aligned_with_the_contract_instance() {
    let (env, _admin, _sas, verifier, client) = setup_test();

    env.ledger().with_mut(|li| li.timestamp = 1000);

    let attestation_uid = UID(BytesN::from_array(&env, &[80u8; 32]));
    let schema_uid = UID(BytesN::from_array(&env, &[81u8; 32]));
    let nullifier = [82u8; 32];

    let proof = create_proof(
        &env,
        attestation_uid,
        schema_uid,
        nullifier,
        [83u8; 32],
        1000,
    );
    assert!(client.verify_and_consume_proof(&proof));

    let key = DataKey::Nullifier(BytesN::from_array(&env, &nullifier));

    env.as_contract(&verifier, || {
        // The record is kept in persistent storage, and it survives at least
        // the shared one-year retention window.
        assert_eq!(
            env.storage().persistent().get(&key),
            Some(1000u64),
            "the nullifier must be recorded in persistent storage"
        );
        assert!(env.storage().persistent().get_ttl(&key) >= INSTANCE_EXTEND_TO_LEDGERS);
    });

    // Age the ledger until both the instance and the nullifier record fall
    // below the shared renewal threshold.
    env.ledger().with_mut(|li| li.sequence_number = 6_000_000);
    env.as_contract(&verifier, || {
        assert!(env.storage().instance().get_ttl() < INSTANCE_TTL_THRESHOLD_LEDGERS);
        assert!(env.storage().persistent().get_ttl(&key) < INSTANCE_TTL_THRESHOLD_LEDGERS);
    });

    // Any call renews the instance and the nullifier record with the same
    // policy, so the two end up with the very same horizon.
    assert!(client.is_nullifier_used(&BytesN::from_array(&env, &nullifier)));

    env.as_contract(&verifier, || {
        assert_eq!(
            env.storage().persistent().get_ttl(&key),
            env.storage().instance().get_ttl(),
            "the nullifier record must be renewed with the instance's TTL policy"
        );
    });
}

/// Off-chain clients need to know which of several nullifiers are already
/// spent, without one contract call per nullifier.
#[test]
fn test_batch_nullifier_query() {
    let (env, _admin, _sas, _verifier, client) = setup_test();

    env.ledger().with_mut(|li| li.timestamp = 1000);

    let attestation_uid = UID(BytesN::from_array(&env, &[90u8; 32]));
    let schema_uid = UID(BytesN::from_array(&env, &[91u8; 32]));

    let spent = [92u8; 32];
    let fresh = [93u8; 32];

    let proof = create_proof(&env, attestation_uid, schema_uid, spent, [94u8; 32], 1000);
    assert!(client.verify_and_consume_proof(&proof));

    let spent_bytes = BytesN::from_array(&env, &spent);
    let fresh_bytes = BytesN::from_array(&env, &fresh);

    // Nothing is spent yet: the query agrees with the single check.
    assert!(!client.is_nullifier_used(&fresh_bytes));

    // The batch query answers for every nullifier, in order, and agrees with
    // the single nullifier check.
    let flags = client.are_nullifiers_used(&vec![
        &env,
        spent_bytes.clone(),
        fresh_bytes.clone(),
        spent_bytes.clone(),
    ]);
    assert_eq!(flags, vec![&env, true, false, true]);

    // The query never spends a nullifier.
    assert!(!client.is_nullifier_used(&fresh_bytes));

    // An empty batch is answered with an empty result.
    assert!(client.are_nullifiers_used(&vec![&env]).is_empty());
}

#[test]
fn test_batch_nullifier_query_rejects_oversized_batch() {
    let (env, _admin, _sas, _verifier, client) = setup_test();
    let mut nullifiers = Vec::new(&env);
    for i in 0..=MAX_NULLIFIER_BATCH {
        let mut bytes = [0u8; 32];
        bytes[0] = i as u8;
        nullifiers.push_back(BytesN::from_array(&env, &bytes));
    }

    let res = client.try_are_nullifiers_used(&nullifiers);
    assert_eq!(res.err().unwrap().unwrap(), ZkVerifierError::BatchTooLarge);
}

#[test]
fn test_distinct_nullifiers_are_independent() {
    let (env, _admin, _sas, _verifier, client) = setup_test();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let schema_uid = UID(BytesN::from_array(&env, &[61u8; 32]));
    let first = create_proof(
        &env,
        UID(BytesN::from_array(&env, &[0u8; 32])),
        schema_uid.clone(),
        [62u8; 32],
        [63u8; 32],
        1000,
    );
    let second = create_proof(
        &env,
        UID(BytesN::from_array(&env, &[0u8; 32])),
        schema_uid,
        [64u8; 32],
        [65u8; 32],
        1000,
    );

    assert!(client.verify_and_consume_proof(&first));
    assert!(client.verify_and_consume_proof(&second));

    let query = Vec::from_array(
        &env,
        [
            BytesN::from_array(&env, &[62u8; 32]),
            BytesN::from_array(&env, &[64u8; 32]),
        ],
    );
    assert_eq!(
        client.are_nullifiers_used(&query),
        Vec::from_array(&env, [true, true])
    );
}

#[test]
fn test_nullifier_collision_is_rejected_even_with_a_new_commitment() {
    let (env, _admin, _sas, _verifier, client) = setup_test();
    env.ledger().with_mut(|li| li.timestamp = 1000);

    let schema_uid = UID(BytesN::from_array(&env, &[71u8; 32]));
    let nullifier = [72u8; 32];

    let first = create_proof(
        &env,
        UID(BytesN::from_array(&env, &[0u8; 32])),
        schema_uid.clone(),
        nullifier,
        [73u8; 32],
        1000,
    );
    assert!(client.verify_and_consume_proof(&first));

    // Same nullifier, different commitment and proof: still a replay.
    let second = create_proof(
        &env,
        UID(BytesN::from_array(&env, &[0u8; 32])),
        schema_uid,
        nullifier,
        [74u8; 32],
        1000,
    );
    let res = client.try_verify_and_consume_proof(&second);
    assert_eq!(res.err().unwrap().unwrap(), ZkVerifierError::NullifierSpent);
}
