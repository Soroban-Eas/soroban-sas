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

/// Issue #112: `attest_internal` must reject an attestation that claims
/// `revocable = true` under a schema whose own `revocable` flag is `false`,
/// and this must hold across every entry point that funnels through
/// `attest_internal` (direct, delegated, batch, paid, replace) since none of
/// them duplicate the check themselves.
mod revocability {
    use super::*;

    struct Fixture {
        env: Env,
        sas_client_id: Address,
        registry_id: Address,
        attester: Address,
        recipient: Address,
    }

    /// Registers a schema whose `revocable` flag is `schema_revocable` in a
    /// fresh `mock_registry::MockRegistry`, wired up to a fresh `SAS`
    /// instance, and returns everything a test needs to attest against it.
    fn setup(schema_revocable: bool) -> (Fixture, UID) {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, mock_registry::MockRegistry);
        let sas_id = env.register_contract(None, SAS);
        let sas_client = SASClient::new(&env, &sas_id);
        let admin = Address::generate(&env);
        sas_client.init(&admin, &registry_id);

        let attester = Address::generate(&env);
        let recipient = Address::generate(&env);

        let schema_uid = UID(BytesN::from_array(&env, &[9u8; 32]));
        let resolver = Address::generate(&env);
        let record = SchemaRecord {
            uid: schema_uid.clone(),
            resolver,
            revocable: schema_revocable,
            schema: SorobanString::from_str(&env, "value String"),
        };
        let mock_client = mock_registry::MockRegistryClient::new(&env, &registry_id);
        mock_client.set_schema(&schema_uid, &record);

        (
            Fixture {
                env,
                sas_client_id: sas_id,
                registry_id,
                attester,
                recipient,
            },
            schema_uid,
        )
    }

    fn attestation(
        fx: &Fixture,
        schema_uid: &UID,
        att_seed: u8,
        revocable: bool,
    ) -> Attestation {
        Attestation {
            uid: UID(BytesN::from_array(&fx.env, &[att_seed; 32])),
            schema_uid: schema_uid.clone(),
            time: 1000,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&fx.env, &[0u8; 32])),
            recipient: fx.recipient.clone(),
            attester: fx.attester.clone(),
            revocable,
            data: Bytes::new(&fx.env),
        }
    }

    #[test]
    fn direct_attest_rejects_revocable_under_non_revocable_schema() {
        let (fx, schema_uid) = setup(false);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 1, true);

        let res = sas_client.try_attest(&att);
        assert_eq!(res, Err(Ok(SASError::NotRevocable.into())));
    }

    #[test]
    fn direct_attest_accepts_irrevocable_under_non_revocable_schema() {
        let (fx, schema_uid) = setup(false);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 2, false);

        let res = sas_client.try_attest(&att);
        assert!(res.is_ok());
    }

    #[test]
    fn direct_attest_accepts_both_flags_under_revocable_schema() {
        let (fx, schema_uid) = setup(true);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let revocable_att = attestation(&fx, &schema_uid, 3, true);
        assert!(sas_client.try_attest(&revocable_att).is_ok());

        let irrevocable_att = attestation(&fx, &schema_uid, 4, false);
        assert!(sas_client.try_attest(&irrevocable_att).is_ok());
    }

    #[test]
    fn delegated_attest_rejects_revocable_under_non_revocable_schema() {
        let (fx, schema_uid) = setup(false);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let seed = [61u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let attester_strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
        let attester =
            Address::from_string(&SorobanString::from_str(&fx.env, &attester_strkey));

        let mut att = attestation(&fx, &schema_uid, 5, true);
        att.attester = attester;

        let nonce = 1u64;
        let domain = soroban_sas_common::AttestationDomain {
            network_id: fx.env.ledger().network_id(),
            contract: fx.sas_client_id.clone(),
            nonce,
        };
        let payload_hash = soroban_sas_common::hash_offchain_attestation(&fx.env, &att, &domain);
        let signature = signing_key.sign(&payload_hash.to_array());
        let sig_bytes = BytesN::from_array(&fx.env, &signature.to_bytes());
        let pub_bytes = BytesN::from_array(&fx.env, &public_key);

        let res =
            sas_client.try_attest_by_delegation(&att, &nonce, &sig_bytes, &pub_bytes);
        assert_eq!(res, Err(Ok(SASError::NotRevocable.into())));
    }

    #[test]
    fn batch_attest_rejects_revocable_under_non_revocable_schema() {
        let (fx, schema_uid) = setup(false);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let ok_att = attestation(&fx, &schema_uid, 6, false);
        let bad_att = attestation(&fx, &schema_uid, 7, true);
        let batch = soroban_sdk::vec![&fx.env, ok_att, bad_att];

        let res = sas_client.try_multi_attest(&batch);
        assert_eq!(res, Err(Ok(SASError::NotRevocable.into())));

        // The whole batch is one atomic host transaction: the rejected
        // second entry must roll back the first entry too, not leave it
        // partially committed.
        let ok_uid = UID(BytesN::from_array(&fx.env, &[6u8; 32]));
        assert!(!fx
            .env
            .as_contract(&fx.sas_client_id, || fx.env.storage().persistent().has(&ok_uid)));
    }

    #[test]
    fn paid_attest_rejects_revocable_under_non_revocable_schema() {
        let (fx, schema_uid) = setup(false);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 8, true);
        let token = Address::generate(&fx.env);

        // value = 0 performs no token transfer, so no token contract needs
        // to be deployed for this check to be exercised.
        let res = sas_client.try_attest_with_value(&att, &token, &0i128);
        assert_eq!(res, Err(Ok(SASError::NotRevocable.into())));
    }

    #[test]
    fn replace_attestation_rejects_revocable_replacement_under_non_revocable_schema() {
        let (fx, schema_uid) = setup(true);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        // Seed attestation must itself be revocable so replace_attestation's
        // own `old.revocable` guard (unrelated to this issue) doesn't block
        // reaching the replacement's schema-revocability check.
        let old_att = attestation(&fx, &schema_uid, 9, true);
        let old_uid = old_att.uid.clone();
        sas_client.attest(&old_att);

        // Register a second schema on the same registry that forbids
        // revocable attestations, and point the replacement at it.
        let non_revocable_schema_uid = UID(BytesN::from_array(&fx.env, &[11u8; 32]));
        let non_revocable_record = SchemaRecord {
            uid: non_revocable_schema_uid.clone(),
            resolver: Address::generate(&fx.env),
            revocable: false,
            schema: SorobanString::from_str(&fx.env, "value String"),
        };
        let mock_client = mock_registry::MockRegistryClient::new(&fx.env, &fx.registry_id);
        mock_client.set_schema(&non_revocable_schema_uid, &non_revocable_record);

        let new_att = attestation(&fx, &non_revocable_schema_uid, 10, true);

        let res = sas_client.try_replace_attestation(&old_uid, &new_att);
        assert_eq!(res, Err(Ok(SASError::NotRevocable.into())));
    }
}
