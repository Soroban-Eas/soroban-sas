use crate::UID;

#[test]
fn test_uid_deterministic() {
    let env = soroban_sdk::Env::default();
    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    assert_eq!(uid1, uid2);

    let uid3 = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    assert_ne!(uid1, uid3);
}

use crate::validation::validate_schema_syntax;
use crate::validation::validate_ttl;
use crate::validation::validate_recipient;
use soroban_sdk::Env;

#[test]
fn test_validate_ttl() {
    let env = Env::default();

    // Valid cases
    assert!(validate_ttl(&env, 100, 200).is_ok());
    assert!(validate_ttl(&env, 100, 0).is_ok()); // no expiration

    // Invalid cases
    assert!(validate_ttl(&env, 200, 100).is_err());
    assert!(validate_ttl(&env, 100, 100).is_err()); // expired exactly at current time
}

#[test]
fn test_validate_schema_syntax_rejects_malformed_strings() {
    let env = Env::default();

    for schema in ["!!!", " ", "12345", "field_only"] {
        let schema = soroban_sdk::String::from_str(&env, schema);
        assert_eq!(
            validate_schema_syntax(&env, &schema),
            Err(crate::errors::SASError::InvalidSchema)
        );
    }

    let schema = soroban_sdk::String::from_str(&env, "first_name String, last_name String");
    assert!(validate_schema_syntax(&env, &schema).is_ok());
}

#[test]
fn test_validate_recipient_rejects_zero_addresses() {
    let env = Env::default();

    let zero_account = account_address(&env, &[0u8; 32]);
    let zero_contract = Address::from_string(&SorobanString::from_str(
        &env,
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    ));

    assert_eq!(
        validate_recipient(&env, &zero_account),
        Err(crate::errors::SASError::InvalidRecipient)
    );
    assert_eq!(
        validate_recipient(&env, &zero_contract),
        Err(crate::errors::SASError::InvalidRecipient)
    );
}

use crate::merkle::MerkleRoot;
use soroban_sdk::BytesN;

use crate::typed_data::{
    attester_matches_key, hash_offchain_attestation, verify_offchain_signature, AttestationDomain,
};
use crate::Attestation;
use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, String as SorobanString};

fn account_address(env: &Env, public_key: &[u8; 32]) -> Address {
    let strkey = stellar_strkey::ed25519::PublicKey(*public_key).to_string();
    Address::from_string(&SorobanString::from_str(env, &strkey))
}

fn sample_attestation(env: &Env, attester: Address) -> Attestation {
    Attestation {
        uid: UID(BytesN::from_array(env, &[1u8; 32])),
        schema_uid: UID(BytesN::from_array(env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: Address::generate(env),
        attester,
        revocable: true,
        data: Bytes::from_slice(env, &[0xde, 0xad, 0xbe, 0xef]),
    }
}

fn sample_domain(env: &Env, nonce: u64) -> AttestationDomain {
    AttestationDomain {
        network_id: BytesN::from_array(env, &[7u8; 32]),
        contract: Address::generate(env),
        nonce,
    }
}

#[test]
fn test_offchain_hash_deterministic() {
    let env = Env::default();
    let attester = Address::generate(&env);
    let attestation = sample_attestation(&env, attester);
    let domain = sample_domain(&env, 42);

    let h1 = hash_offchain_attestation(&env, &attestation, &domain);
    let h2 = hash_offchain_attestation(&env, &attestation, &domain);
    assert_eq!(h1, h2);
}

#[test]
fn test_offchain_hash_binds_every_field() {
    let env = Env::default();
    let attester = Address::generate(&env);
    let base = sample_attestation(&env, attester.clone());
    let domain = sample_domain(&env, 42);
    let base_hash = hash_offchain_attestation(&env, &base, &domain);

    let mut tampered = base.clone();
    tampered.data = Bytes::from_slice(&env, &[0xde, 0xad, 0xbe, 0xee]);
    assert_ne!(
        base_hash,
        hash_offchain_attestation(&env, &tampered, &domain)
    );

    let mut tampered = base.clone();
    tampered.expiration_time = 1;
    assert_ne!(
        base_hash,
        hash_offchain_attestation(&env, &tampered, &domain)
    );

    let mut tampered = base.clone();
    tampered.recipient = Address::generate(&env);
    assert_ne!(
        base_hash,
        hash_offchain_attestation(&env, &tampered, &domain)
    );

    // Domain fields are bound too: nonce, contract, and network id.
    let mut other_domain = sample_domain(&env, 43);
    other_domain.contract = domain.contract.clone();
    other_domain.network_id = domain.network_id.clone();
    assert_ne!(
        base_hash,
        hash_offchain_attestation(&env, &base, &other_domain)
    );

    let mut other_domain = domain.clone();
    other_domain.network_id = BytesN::from_array(&env, &[8u8; 32]);
    assert_ne!(
        base_hash,
        hash_offchain_attestation(&env, &base, &other_domain)
    );

    let mut other_domain = domain.clone();
    other_domain.contract = Address::generate(&env);
    assert_ne!(
        base_hash,
        hash_offchain_attestation(&env, &base, &other_domain)
    );
}

#[test]
fn test_attester_matches_key() {
    let env = Env::default();
    let signing_key = SigningKey::from_bytes(&[11u8; 32]);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let attester = account_address(&env, &public_key_bytes);
    let public_key = BytesN::from_array(&env, &public_key_bytes);

    assert!(attester_matches_key(&env, &attester, &public_key));

    // A different key does not match.
    let other_key = SigningKey::from_bytes(&[12u8; 32])
        .verifying_key()
        .to_bytes();
    let other_key = BytesN::from_array(&env, &other_key);
    assert!(!attester_matches_key(&env, &attester, &other_key));

    // A contract address never matches, even when its 32-byte id equals the
    // public key: the XDR discriminants differ.
    let contract_strkey = stellar_strkey::Contract(public_key_bytes).to_string();
    let contract = Address::from_string(&SorobanString::from_str(&env, &contract_strkey));
    assert!(!attester_matches_key(&env, &contract, &public_key));
}

#[test]
fn test_offchain_signature_valid() {
    let env = Env::default();
    let signing_key = SigningKey::from_bytes(&[21u8; 32]);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let attester = account_address(&env, &public_key_bytes);

    let attestation = sample_attestation(&env, attester);
    let domain = sample_domain(&env, 1);
    let payload_hash = hash_offchain_attestation(&env, &attestation, &domain);

    let signature = signing_key.sign(&payload_hash.to_array());
    let signature = BytesN::from_array(&env, &signature.to_bytes());
    let public_key = BytesN::from_array(&env, &public_key_bytes);

    // Panics on failure; completing is success.
    verify_offchain_signature(&env, &payload_hash, &public_key, &signature);
}

#[test]
#[should_panic]
fn test_offchain_signature_tampered_payload() {
    let env = Env::default();
    let signing_key = SigningKey::from_bytes(&[21u8; 32]);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let attester = account_address(&env, &public_key_bytes);

    let attestation = sample_attestation(&env, attester);
    let domain = sample_domain(&env, 1);
    let payload_hash = hash_offchain_attestation(&env, &attestation, &domain);

    let signature = signing_key.sign(&payload_hash.to_array());
    let signature = BytesN::from_array(&env, &signature.to_bytes());
    let public_key = BytesN::from_array(&env, &public_key_bytes);

    // Signature was made over the original payload; verifying a different
    // digest must fail.
    let mut tampered = attestation.clone();
    tampered.revocable = false;
    let tampered_hash = hash_offchain_attestation(&env, &tampered, &domain);
    verify_offchain_signature(&env, &tampered_hash, &public_key, &signature);
}

#[test]
#[should_panic]
fn test_offchain_signature_wrong_key() {
    let env = Env::default();
    let signing_key = SigningKey::from_bytes(&[21u8; 32]);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let attester = account_address(&env, &public_key_bytes);

    let attestation = sample_attestation(&env, attester);
    let domain = sample_domain(&env, 1);
    let payload_hash = hash_offchain_attestation(&env, &attestation, &domain);

    let signature = signing_key.sign(&payload_hash.to_array());
    let signature = BytesN::from_array(&env, &signature.to_bytes());

    let wrong_key = SigningKey::from_bytes(&[22u8; 32])
        .verifying_key()
        .to_bytes();
    let wrong_key = BytesN::from_array(&env, &wrong_key);
    verify_offchain_signature(&env, &payload_hash, &wrong_key, &signature);
}

#[test]
fn test_merkle_root_generation() {
    let env = Env::default();
    let root_bytes = BytesN::from_array(&env, &[0u8; 32]);
    let merkle_root = MerkleRoot(root_bytes.clone());

    assert_eq!(merkle_root.0, root_bytes);
}
