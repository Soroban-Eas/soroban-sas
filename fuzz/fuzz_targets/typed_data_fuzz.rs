#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::{
    hash_attestation_struct, hash_delegated_revocation, hash_domain, Attestation, AttestationDomain, UID,
};
use soroban_sdk::{Address, Bytes, BytesN, Env};

fuzz_target!(|data: &[u8]| {
    let env = Env::default();

    if data.len() < 160 {
        return;
    }

    let uid = UID(BytesN::from_array(&env, &data[0..32].try_into().unwrap()));
    let schema_uid = UID(BytesN::from_array(&env, &data[32..64].try_into().unwrap()));
    let ref_uid = UID(BytesN::from_array(&env, &data[64..96].try_into().unwrap()));
    let network_id = BytesN::from_array(&env, &data[96..128].try_into().unwrap());
    let nonce = u64::from_be_bytes(data[128..136].try_into().unwrap());
    let data_payload = Bytes::from_slice(&env, &data[136..]);

    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid,
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid,
        recipient: Address::generate(&env),
        attester: Address::generate(&env),
        revocable: true,
        data: data_payload,
    };

    let domain = AttestationDomain {
        network_id,
        contract: Address::generate(&env),
        nonce,
    };

    let _ = hash_domain(&env, &domain);
    let _ = hash_attestation_struct(&env, &attestation);
    let _ = hash_delegated_revocation(&env, &uid, &attestation.attester, &domain);
});
