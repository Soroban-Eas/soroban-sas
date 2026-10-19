use super::*;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env};

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

fn setup_test() -> (Env, Address, Address, ZkVerifierClient<'static>) {
    let env = Env::default();
    let admin = Address::generate(&env);
    let sas = env.register_contract(None, MockSas);
    let verifier_id = env.register_contract(None, ZkVerifier);
    let client = ZkVerifierClient::new(&env, &verifier_id);

    env.mock_all_auths();
    client.init(&admin, &sas);

    (env, admin, sas, client)
}

#[test]
fn test_zk_proof_verification_success_and_nullifier_consumption() {
    let (env, _admin, _sas, client) = setup_test();

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
    assert_eq!(
        replay_err.err().unwrap().unwrap(),
        ZkVerifierError::NullifierAlreadyUsed
    );
}

#[test]
fn test_zk_proof_tampered_proof_rejected() {
    let (env, _admin, _sas, client) = setup_test();

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
    let (env, _admin, _sas, client) = setup_test();

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
    let (env, _admin, sas, client) = setup_test();

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
    let (env, _admin, sas, client) = setup_test();

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
