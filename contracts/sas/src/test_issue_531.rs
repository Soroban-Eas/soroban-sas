//! Verifier-contract boundary tests; the mock is not a cryptographic prover.
use crate::{SASClient, SAS};
use soroban_sas_common::{attestation_uid, Attestation, SASError, UID};
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, Address, Bytes, BytesN, Env, Vec,
};

#[contract]
struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    /// Only tests verifier invocation and input plumbing. Production adapters
    /// MUST cryptographically validate Groth16 or UltraPlonk with a fixed VK.
    pub fn verify_proof(_env: Env, proof: Bytes, inputs: Vec<BytesN<32>>) -> bool {
        inputs.len() == 3 && proof.get(0) == Some(0xa1)
    }
}

fn attestation(env: &Env, issuer: &Address, recipient: &Address, n: u8) -> Attestation {
    let schema_uid = UID(BytesN::from_array(env, &[n; 32]));
    let data = Bytes::from_array(env, &[n; 8]);
    Attestation {
        uid: attestation_uid(env, &schema_uid, recipient, issuer, &data),
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
fn proof_adapter_rejects_bad_proofs_and_consumes_nullifier_once() {
    let env = Env::default();
    env.mock_all_auths();
    let registry = env.register_contract(None, crate::test::mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas = SASClient::new(&env, &sas_id);
    sas.init(&Address::generate(&env), &registry);
    let issuer = Address::generate(&env);
    let recipient = Address::generate(&env);
    let a = attestation(&env, &issuer, &recipient, 2);
    let b = attestation(&env, &issuer, &recipient, 3);
    let nullifier = BytesN::from_array(&env, &[99u8; 32]);
    let valid = Bytes::from_array(&env, &[0xa1, 0x42]);
    let invalid = Bytes::from_array(&env, &[0x00, 0x42]);

    assert_eq!(
        sas.try_attest_with_zk(&a, &valid, &nullifier),
        Err(Ok(SASError::InvalidZKProof.into()))
    );
    let verifier = env.register_contract(None, MockVerifier);
    sas.set_zk_verifier(&verifier);
    assert_eq!(sas.get_zk_verifier(), Some(verifier));
    assert_eq!(
        sas.try_attest_with_zk(&a, &invalid, &nullifier),
        Err(Ok(SASError::InvalidZKProof.into()))
    );
    assert!(!sas.is_zk_nullifier_used(&nullifier));
    sas.attest_with_zk(&a, &valid, &nullifier);
    assert!(sas.verify_attestation(&a.uid));
    assert!(sas.is_zk_nullifier_used(&nullifier));
    assert_eq!(
        sas.try_attest_with_zk(&b, &valid, &nullifier),
        Err(Ok(SASError::NullifierAlreadyUsed.into()))
    );
    assert!(!sas.verify_attestation(&b.uid));
}
