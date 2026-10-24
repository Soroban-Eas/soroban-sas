// Cross-Network Replay Protection Security Test Suite
//
// Validates that delegated attestation signatures are bound to the network passphrase
// and cannot be replayed across Testnet/Mainnet/Futurenet/standalone networks.
//
// Issue: #572 - test(security): Audit and test cross-network replay protection with passphrase salts

use crate::{SASClient, SAS};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{
    hash_offchain_attestation, Attestation, AttestationDomain, SASError, UID,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{Address, Bytes, BytesN, Env, String as SorobanString};

/// Testnet passphrase (official Stellar Testnet)
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Mainnet passphrase (official Stellar Mainnet)
const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// Futurenet passphrase
const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

/// Local standalone network passphrase (common for local testing)
const STANDALONE_PASSPHRASE: &str = "Standalone Network ; February 2017";

fn attester_address_from_key(env: &Env, signing_key: &SigningKey) -> Address {
    let strkey =
        stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes()).to_string();
    Address::from_string(&SorobanString::from_str(env, &strkey))
}

/// Build a minimal valid attestation fixture
fn attestation_fixture(
    env: &Env,
    attester: &Address,
    recipient: &Address,
    schema_uid: UID,
    data: Bytes,
) -> Attestation {
    let uid = soroban_sas_common::attestation_uid(env, &schema_uid, recipient, attester, &data);
    Attestation {
        uid,
        schema_uid,
        time: 1000,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data,
    }
}

/// Derive network_id from passphrase (matching off-chain example logic)
fn network_id_from_passphrase(env: &Env, passphrase: &str) -> [u8; 32] {
    let passphrase_bytes = Bytes::from_slice(env, passphrase.as_bytes());
    let hash: BytesN<32> = env.crypto().sha256(&passphrase_bytes).into();
    hash.to_array()
}

/// Build an AttestationDomain for a given network passphrase and contract address
fn build_domain(env: &Env, passphrase: &str, contract: &Address, nonce: u64) -> AttestationDomain {
    AttestationDomain {
        network_id: BytesN::from_array(env, &network_id_from_passphrase(env, passphrase)),
        contract: contract.clone(),
        nonce,
    }
}

/// Sign an attestation for a specific network domain
fn sign_attestation(
    env: &Env,
    attestation: &Attestation,
    domain: &AttestationDomain,
    signing_key: &SigningKey,
) -> [u8; 64] {
    let digest = hash_offchain_attestation(env, attestation, domain);
    signing_key.sign(&digest.to_array()).to_bytes()
}

#[soroban_sdk::contract]
pub struct MockRegistry;

#[soroban_sdk::contractimpl]
impl MockRegistry {
    pub fn on_attest(_env: Env, _attestation: Attestation) {}
    pub fn on_revoke(_env: Env, _attestation: Attestation) {}
    pub fn validate_schema(_env: Env, _uid: UID) -> bool {
        true
    }
    pub fn is_authorized(_env: Env, _uid: UID, _attester: Address) -> bool {
        true
    }
    #[allow(non_snake_case)]
    pub fn SASREG(_env: Env) -> bool {
        true
    }
    pub fn get_schema(env: Env, uid: UID) -> Option<soroban_sas_common::SchemaRecord> {
        Some(soroban_sas_common::SchemaRecord {
            uid: uid.clone(),
            resolver: env.current_contract_address(),
            revocable: true,
            schema: soroban_sdk::String::from_str(&env, "bool like"),
            deprecated: false,
        })
    }
}

/// Deploy a fresh SAS contract instance with given passphrase (simulated via ledger network_id)
fn deploy_sas(env: &Env, admin: &Address) -> Address {
    let registry_id = env.register_contract(None, MockRegistry);
    let contract_id = env.register_contract(None, SAS);
    let client = SASClient::new(env, &contract_id);
    client.init(admin, &registry_id);
    contract_id
}

#[test]
fn test_cross_network_signature_rejected_testnet_to_mainnet() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);

    let testnet_network_id = network_id_from_passphrase(&env, TESTNET_PASSPHRASE);
    env.ledger().set_network_id(testnet_network_id);

    let sas_testnet = deploy_sas(&env, &admin);

    let schema_uid = UID(BytesN::from_array(&env, &[1u8; 32]));
    let data = Bytes::from_slice(&env, b"cross-network-test-data");

    let attester_seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&attester_seed);
    let attester_pubkey = signing_key.verifying_key().to_bytes();
    let attester = attester_address_from_key(&env, &signing_key);
    let attestation = attestation_fixture(&env, &attester, &recipient, schema_uid, data);

    // Sign with Testnet domain (nonce = 0)
    let testnet_domain = build_domain(&env, TESTNET_PASSPHRASE, &sas_testnet, 0);
    let signature = sign_attestation(&env, &attestation, &testnet_domain, &signing_key);

    // Now switch to "Mainnet" network_id
    let mainnet_network_id = network_id_from_passphrase(&env, MAINNET_PASSPHRASE);
    env.ledger().set_network_id(mainnet_network_id);

    // Deploy a separate SAS instance for Mainnet
    let sas_mainnet = deploy_sas(&env, &admin);

    // Attempt to submit the Testnet-signed attestation on Mainnet
    let client = SASClient::new(&env, &sas_mainnet);

    let result = client.try_attest_by_delegation(
        &attestation,
        &0,
        &BytesN::from_array(&env, &signature),
        &BytesN::from_array(&env, &attester_pubkey),
    );

    assert!(
        result.is_err(),
        "Cross-network replay from Testnet to Mainnet should be rejected"
    );
}

#[test]
fn test_cross_network_signature_rejected_mainnet_to_testnet() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);

    // Deploy on "Mainnet" first
    let mainnet_network_id = network_id_from_passphrase(&env, MAINNET_PASSPHRASE);
    env.ledger().set_network_id(mainnet_network_id);

    let sas_mainnet = deploy_sas(&env, &admin);

    let schema_uid = UID(BytesN::from_array(&env, &[2u8; 32]));
    let data = Bytes::from_slice(&env, b"mainnet-to-testnet-test");

    let attester_seed = [43u8; 32];
    let signing_key = SigningKey::from_bytes(&attester_seed);
    let attester_pubkey = signing_key.verifying_key().to_bytes();
    let attester = attester_address_from_key(&env, &signing_key);
    let attestation = attestation_fixture(&env, &attester, &recipient, schema_uid, data);

    // Sign with Mainnet domain
    let mainnet_domain = build_domain(&env, MAINNET_PASSPHRASE, &sas_mainnet, 0);
    let signature = sign_attestation(&env, &attestation, &mainnet_domain, &signing_key);

    // Switch to Testnet
    let testnet_network_id = network_id_from_passphrase(&env, TESTNET_PASSPHRASE);
    env.ledger().set_network_id(testnet_network_id);

    // Deploy separate Testnet SAS instance
    let sas_testnet = deploy_sas(&env, &admin);

    // Attempt replay
    let client = SASClient::new(&env, &sas_testnet);
    let result = client.try_attest_by_delegation(
        &attestation,
        &0,
        &BytesN::from_array(&env, &signature),
        &BytesN::from_array(&env, &attester_pubkey),
    );

    assert!(
        result.is_err(),
        "Cross-network replay from Mainnet to Testnet should be rejected"
    );
}

#[test]
fn test_cross_network_signature_rejected_futurenet() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);

    // Deploy on Futurenet
    let futurenet_network_id = network_id_from_passphrase(&env, FUTURENET_PASSPHRASE);
    env.ledger().set_network_id(futurenet_network_id);

    let sas_futurenet = deploy_sas(&env, &admin);

    let schema_uid = UID(BytesN::from_array(&env, &[3u8; 32]));
    let data = Bytes::from_slice(&env, b"futurenet-test-data");

    let attester_seed = [44u8; 32];
    let signing_key = SigningKey::from_bytes(&attester_seed);
    let attester_pubkey = signing_key.verifying_key().to_bytes();
    let attester = attester_address_from_key(&env, &signing_key);
    let attestation = attestation_fixture(&env, &attester, &recipient, schema_uid, data);

    // Sign with Futurenet domain
    let futurenet_domain = build_domain(&env, FUTURENET_PASSPHRASE, &sas_futurenet, 0);
    let signature = sign_attestation(&env, &attestation, &futurenet_domain, &signing_key);

    // Switch to Mainnet
    let mainnet_network_id = network_id_from_passphrase(&env, MAINNET_PASSPHRASE);
    env.ledger().set_network_id(mainnet_network_id);

    let sas_mainnet = deploy_sas(&env, &admin);

    let client = SASClient::new(&env, &sas_mainnet);
    let result = client.try_attest_by_delegation(
        &attestation,
        &0,
        &BytesN::from_array(&env, &signature),
        &BytesN::from_array(&env, &attester_pubkey),
    );

    assert!(
        result.is_err(),
        "Cross-network replay from Futurenet to Mainnet should be rejected"
    );
}

#[test]
fn test_cross_network_signature_rejected_standalone() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);

    // Deploy on Standalone
    let standalone_network_id = network_id_from_passphrase(&env, STANDALONE_PASSPHRASE);
    env.ledger().set_network_id(standalone_network_id);

    let sas_standalone = deploy_sas(&env, &admin);

    let schema_uid = UID(BytesN::from_array(&env, &[4u8; 32]));
    let data = Bytes::from_slice(&env, b"standalone-test-data");

    let attester_seed = [45u8; 32];
    let signing_key = SigningKey::from_bytes(&attester_seed);
    let attester_pubkey = signing_key.verifying_key().to_bytes();
    let attester = attester_address_from_key(&env, &signing_key);
    let attestation = attestation_fixture(&env, &attester, &recipient, schema_uid, data);

    // Sign with Standalone domain
    let standalone_domain = build_domain(&env, STANDALONE_PASSPHRASE, &sas_standalone, 0);
    let signature = sign_attestation(&env, &attestation, &standalone_domain, &signing_key);

    // Switch to Testnet
    let testnet_network_id = network_id_from_passphrase(&env, TESTNET_PASSPHRASE);
    env.ledger().set_network_id(testnet_network_id);

    let sas_testnet = deploy_sas(&env, &admin);

    let client = SASClient::new(&env, &sas_testnet);
    let result = client.try_attest_by_delegation(
        &attestation,
        &0,
        &BytesN::from_array(&env, &signature),
        &BytesN::from_array(&env, &attester_pubkey),
    );

    assert!(
        result.is_err(),
        "Cross-network replay from Standalone to Testnet should be rejected"
    );
}

#[test]
fn test_same_network_same_contract_replay_rejected_nonce() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);

    let testnet_network_id = network_id_from_passphrase(&env, TESTNET_PASSPHRASE);
    env.ledger().set_network_id(testnet_network_id);

    let sas = deploy_sas(&env, &admin);

    let schema_uid = UID(BytesN::from_array(&env, &[5u8; 32]));
    let data = Bytes::from_slice(&env, b"same-network-replay-test");

    let attester_seed = [46u8; 32];
    let signing_key = SigningKey::from_bytes(&attester_seed);
    let attester_pubkey = signing_key.verifying_key().to_bytes();
    let attester = attester_address_from_key(&env, &signing_key);
    let attestation = attestation_fixture(&env, &attester, &recipient, schema_uid, data);

    // Sign with nonce = 0
    let domain = build_domain(&env, TESTNET_PASSPHRASE, &sas, 0);
    let signature = sign_attestation(&env, &attestation, &domain, &signing_key);

    let client = SASClient::new(&env, &sas);

    // First submission should succeed
    let result1 = client.try_attest_by_delegation(
        &attestation,
        &0,
        &BytesN::from_array(&env, &signature),
        &BytesN::from_array(&env, &attester_pubkey),
    );
    assert!(
        result1.is_ok(),
        "First submission with nonce 0 should succeed"
    );

    // Second submission with SAME nonce should fail (nonce replay protection)
    let result2 = client.try_attest_by_delegation(
        &attestation,
        &0,
        &BytesN::from_array(&env, &signature),
        &BytesN::from_array(&env, &attester_pubkey),
    );
    assert!(
        result2.is_err(),
        "Replay with same nonce should be rejected"
    );
    assert_eq!(
        result2.err().unwrap().unwrap(),
        SASError::DelegationReplay.into()
    );
}

#[test]
fn test_cross_contract_same_network_replay_rejected() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);

    let testnet_network_id = network_id_from_passphrase(&env, TESTNET_PASSPHRASE);
    env.ledger().set_network_id(testnet_network_id);

    // Deploy TWO separate SAS instances on SAME network
    let sas_a = deploy_sas(&env, &admin);
    let sas_b = deploy_sas(&env, &admin);

    let schema_uid = UID(BytesN::from_array(&env, &[6u8; 32]));
    let data = Bytes::from_slice(&env, b"cross-contract-replay-test");

    let attester_seed = [47u8; 32];
    let signing_key = SigningKey::from_bytes(&attester_seed);
    let attester_pubkey = signing_key.verifying_key().to_bytes();
    let attester = attester_address_from_key(&env, &signing_key);
    let attestation = attestation_fixture(&env, &attester, &recipient, schema_uid, data);

    // Sign for SAS instance A (contract address bound in domain)
    let domain_a = build_domain(&env, TESTNET_PASSPHRASE, &sas_a, 0);
    let signature = sign_attestation(&env, &attestation, &domain_a, &signing_key);

    // Attempt to submit on SAS instance B (same network, different contract)
    let client_b = SASClient::new(&env, &sas_b);
    let result = client_b.try_attest_by_delegation(
        &attestation,
        &0,
        &BytesN::from_array(&env, &signature),
        &BytesN::from_array(&env, &attester_pubkey),
    );

    assert!(
        result.is_err(),
        "Cross-contract replay on same network should be rejected"
    );
}

#[test]
fn test_valid_signature_on_correct_network_succeeds() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let recipient = Address::generate(&env);

    let testnet_network_id = network_id_from_passphrase(&env, TESTNET_PASSPHRASE);
    env.ledger().set_network_id(testnet_network_id);

    let sas = deploy_sas(&env, &admin);

    let schema_uid = UID(BytesN::from_array(&env, &[7u8; 32]));
    let data = Bytes::from_slice(&env, b"valid-signature-test");

    let attester_seed = [48u8; 32];
    let signing_key = SigningKey::from_bytes(&attester_seed);
    let attester_pubkey = signing_key.verifying_key().to_bytes();
    let attester = attester_address_from_key(&env, &signing_key);
    let attestation = attestation_fixture(&env, &attester, &recipient, schema_uid, data);

    // Sign correctly for THIS network and THIS contract
    let domain = build_domain(&env, TESTNET_PASSPHRASE, &sas, 0);
    let signature = sign_attestation(&env, &attestation, &domain, &signing_key);

    let client = SASClient::new(&env, &sas);
    let result = client.try_attest_by_delegation(
        &attestation,
        &0,
        &BytesN::from_array(&env, &signature),
        &BytesN::from_array(&env, &attester_pubkey),
    );

    assert!(
        result.is_ok(),
        "Valid signature on correct network and contract should succeed"
    );
}

#[test]
fn test_all_four_networks_isolation_matrix() {
    let networks = [
        ("Testnet", TESTNET_PASSPHRASE),
        ("Mainnet", MAINNET_PASSPHRASE),
        ("Futurenet", FUTURENET_PASSPHRASE),
        ("Standalone", STANDALONE_PASSPHRASE),
    ];

    for (source_name, source_passphrase) in networks {
        for (target_name, target_passphrase) in networks {
            if source_name == target_name {
                continue;
            }

            let env = Env::default();
            env.mock_all_auths();

            let admin = Address::generate(&env);
            let recipient = Address::generate(&env);

            let source_network_id = network_id_from_passphrase(&env, source_passphrase);
            env.ledger().set_network_id(source_network_id);
            let sas_source = deploy_sas(&env, &admin);

            let schema_uid = UID(BytesN::from_array(&env, &[99u8; 32]));
            let data = Bytes::from_slice(&env, b"cross-network-matrix-test");

            let attester_seed = [49u8; 32];
            let signing_key = SigningKey::from_bytes(&attester_seed);
            let attester_pubkey = signing_key.verifying_key().to_bytes();
            let attester = attester_address_from_key(&env, &signing_key);
            let attestation = attestation_fixture(&env, &attester, &recipient, schema_uid, data);

            let source_domain = build_domain(&env, source_passphrase, &sas_source, 0);
            let signature = sign_attestation(&env, &attestation, &source_domain, &signing_key);

            let target_network_id = network_id_from_passphrase(&env, target_passphrase);
            env.ledger().set_network_id(target_network_id);
            let sas_target = deploy_sas(&env, &admin);

            let client = SASClient::new(&env, &sas_target);
            let result = client.try_attest_by_delegation(
                &attestation,
                &0,
                &BytesN::from_array(&env, &signature),
                &BytesN::from_array(&env, &attester_pubkey),
            );

            assert!(
                result.is_err(),
                "{} -> {} cross-network replay should be rejected",
                source_name,
                target_name
            );
        }
    }
}

#[test]
fn test_network_passphrase_hash_bound_in_domain_separator() {
    let env = Env::default();

    let testnet_id = network_id_from_passphrase(&env, TESTNET_PASSPHRASE);
    let mainnet_id = network_id_from_passphrase(&env, MAINNET_PASSPHRASE);
    let futurenet_id = network_id_from_passphrase(&env, FUTURENET_PASSPHRASE);
    let standalone_id = network_id_from_passphrase(&env, STANDALONE_PASSPHRASE);

    assert_ne!(testnet_id, mainnet_id, "Testnet != Mainnet network_id");
    assert_ne!(testnet_id, futurenet_id, "Testnet != Futurenet network_id");
    assert_ne!(
        testnet_id, standalone_id,
        "Testnet != Standalone network_id"
    );
    assert_ne!(mainnet_id, futurenet_id, "Mainnet != Futurenet network_id");
    assert_ne!(
        mainnet_id, standalone_id,
        "Mainnet != Standalone network_id"
    );
    assert_ne!(
        futurenet_id, standalone_id,
        "Futurenet != Standalone network_id"
    );

    let testnet_id_2 = network_id_from_passphrase(&env, TESTNET_PASSPHRASE);
    assert_eq!(
        testnet_id, testnet_id_2,
        "Network ID derivation must be deterministic"
    );
}

#[test]
fn test_delegation_domain_construction_matches_offchain_example() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract = deploy_sas(&env, &admin);

    let testnet_network_id = network_id_from_passphrase(&env, TESTNET_PASSPHRASE);
    env.ledger().set_network_id(testnet_network_id);

    let nonce: u64 = 42;
    let domain = build_domain(&env, TESTNET_PASSPHRASE, &contract, nonce);

    assert_eq!(
        domain.network_id,
        BytesN::from_array(&env, &testnet_network_id)
    );
    assert_eq!(domain.contract, contract);
    assert_eq!(domain.nonce, nonce);

    let expected_network_id: BytesN<32> = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, TESTNET_PASSPHRASE.as_bytes()))
        .into();
    assert_eq!(domain.network_id, expected_network_id);
}
