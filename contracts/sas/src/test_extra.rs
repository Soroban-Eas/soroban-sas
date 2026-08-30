use crate::{SAS, SASClient};
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Bytes, BytesN, Env, String as SorobanString};
use soroban_sas_common::{Attestation, SASError, SchemaRecord, UID};
use ed25519_dalek::{Signer, SigningKey};

pub mod mock_registry {
    use super::*;
    use soroban_sdk::{contract, contractimpl, Env, Symbol};

    #[contract]
    pub struct MockRegistry;

    // Store for active flag: use persistent storage key (DEPRECATED, uid) similarly
    const DEPRECATED: Symbol = soroban_sdk::symbol_short!("DEPRECATE");

    #[contractimpl]
    impl MockRegistry {
        #[allow(non_snake_case)]
        pub fn SASREG(_env: Env) -> bool { true }
        pub fn get_schema(env: Env, uid: UID) -> Option<SchemaRecord> {
            if env.storage().persistent().get::<_, bool>(&(DEPRECATED, uid.clone())).unwrap_or(false) {
                return None;
            }
            // If we have stored record for uid, return it, else None
            // For test, if uid is the known valid one (hash of "bool like_soroban"), we return Some
            // Otherwise, check persistent for record existence
            if let Some(rec) = env.storage().persistent().get::<UID, SchemaRecord>(&uid) {
                Some(rec)
            } else {
                // For unknown uid, return None, for known we need to have stored it via set_schema
                None
            }
        }
        pub fn set_schema(env: Env, uid: UID, record: SchemaRecord) {
            env.storage().persistent().set(&uid, &record);
        }
        pub fn set_deprecated(env: Env, uid: UID, val: bool) {
            env.storage().persistent().set(&(DEPRECATED, uid), &val);
        }
    }
}

#[test]
fn test_verify_offchain_rejects_unknown_and_deprecated_schema() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let seed = [31u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let attester_strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    let attester = Address::from_string(&SorobanString::from_str(&env, &attester_strkey));
    let recipient = Address::generate(&env);

    // Create a valid schema record in mock registry
    let schema_uid = UID(BytesN::from_array(&env, &[77u8; 32]));
    let resolver = Address::generate(&env);
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: resolver.clone(),
        revocable: true,
        schema: SorobanString::from_str(&env, "bool like_soroban"),
    };
    let mock_client = mock_registry::MockRegistryClient::new(&env, &registry_id);
    // Need to store via contract call so storage is in contract's context
    mock_client.set_schema(&schema_uid, &record);

    let att_uid = UID(BytesN::from_array(&env, &[42u8; 32]));
    let attestation = Attestation {
        uid: att_uid.clone(),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::from_slice(&env, &[1,2,3]),
    };
    let nonce = 7u64;
    let domain = soroban_sas_common::AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: sas_id.clone(),
        nonce,
    };
    let payload_hash = soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain);
    let signature = signing_key.sign(&payload_hash.to_array());
    let sig_bytes = BytesN::from_array(&env, &signature.to_bytes());
    let pub_bytes = BytesN::from_array(&env, &public_key);

    // Valid should succeed
    let res = sas_client.try_verify_offchain_attestation(&attestation, &nonce, &pub_bytes, &sig_bytes);
    assert!(res.is_ok());

    // Unknown schema should be InvalidSchema
    let unknown_schema_uid = UID(BytesN::from_array(&env, &[99u8; 32]));
    let mut att_unknown = attestation.clone();
    att_unknown.schema_uid = unknown_schema_uid.clone();
    let payload_hash2 = soroban_sas_common::hash_offchain_attestation(&env, &att_unknown, &domain);
    let sig2 = signing_key.sign(&payload_hash2.to_array());
    let sig_bytes2 = BytesN::from_array(&env, &sig2.to_bytes());
    let res = sas_client.try_verify_offchain_attestation(&att_unknown, &nonce, &pub_bytes, &sig_bytes2);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));

    // Deprecated should also be InvalidSchema and invalidate prior
    mock_client.set_deprecated(&schema_uid, &true);
    let res = sas_client.try_verify_offchain_attestation(&attestation, &nonce, &pub_bytes, &sig_bytes);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));

    // On-chain attest with deprecated should also be InvalidSchema
    let att2 = Attestation {
        uid: UID(BytesN::from_array(&env, &[43u8; 32])),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: Address::generate(&env),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };
    env.mock_all_auths();
    let res = sas_client.try_attest(&att2);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));
}

/// Issue #76: `set_indexer` must classify the pre-init case instead of
/// trapping on a missing admin entry, and must still gate on the configured
/// admin's authorization once `init` has run.
#[test]
fn test_set_indexer_before_init_returns_not_initialized() {
    let env = Env::default();
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let indexer = Address::generate(&env);

    env.mock_all_auths();
    let res = sas_client.try_set_indexer(&indexer);
    assert_eq!(res, Err(Ok(SASError::NotInitialized.into())));

    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let admin = Address::generate(&env);
    sas_client.init(&admin, &registry_id);

    // After init the call succeeds, and it is the configured admin whose
    // authorization is required.
    sas_client.set_indexer(&indexer);
    let auths = env.auths();
    assert_eq!(auths.first().map(|(addr, _)| addr.clone()), Some(admin));
}

/// Issue #77: attesting against an unconfigured schema registry must surface
/// the configuration failure as `NotInitialized`, not as an unclassified host
/// trap and not as whichever payload check happens to run first.
#[test]
fn test_attest_before_init_returns_not_initialized() {
    let env = Env::default();
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let attestation = Attestation {
        uid: UID(BytesN::from_array(&env, &[51u8; 32])),
        schema_uid: UID(BytesN::from_array(&env, &[52u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: Address::generate(&env),
        attester: Address::generate(&env),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();
    let res = sas_client.try_attest(&attestation);
    assert_eq!(res, Err(Ok(SASError::NotInitialized.into())));

    // An otherwise-invalid payload reports the same configuration failure, so
    // callers get one stable error code for "the contract was never set up".
    let expired = Attestation {
        uid: UID(BytesN::from_array(&env, &[53u8; 32])),
        expiration_time: 1,
        ..attestation
    };
    let res = sas_client.try_attest(&expired);
    assert_eq!(res, Err(Ok(SASError::NotInitialized.into())));
}
