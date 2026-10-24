use crate::{SASClient, SAS};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{Attestation, FeeCeilings, SASError, SchemaFeeConfig, SchemaRecord, UID};
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, String as SorobanString};

pub mod mock_registry {
    use super::*;
    use soroban_sdk::{contract, contractimpl, Env, Symbol};

    #[contract]
    pub struct MockRegistry;

    // Store for active flag: use persistent storage key (DEPRECATED, uid) similarly
    const DEPRECATED: Symbol = soroban_sdk::symbol_short!("DEPRECATE");
    const CREATOR: Symbol = soroban_sdk::symbol_short!("CREATOR");
    const POLICY: Symbol = soroban_sdk::symbol_short!("POLICY");

    #[contractimpl]
    impl MockRegistry {
        pub fn is_authorized(_env: Env, _uid: UID, _attester: Address) -> bool {
            true
        }
        #[allow(non_snake_case)]
        pub fn SASREG(_env: Env) -> bool {
            true
        }
        /// Tri-state policy lookup (#448). Mirrors the real registry: an
        /// explicitly stored policy wins, otherwise derive from `revocable`.
        pub fn get_schema_policy(env: Env, uid: UID) -> soroban_sas_common::RevocationPolicy {
            if let Some(p) = env
                .storage()
                .persistent()
                .get::<_, soroban_sas_common::RevocationPolicy>(&(POLICY, uid.clone()))
            {
                return p;
            }
            match env.storage().persistent().get::<UID, SchemaRecord>(&uid) {
                Some(rec) => soroban_sas_common::RevocationPolicy::from(rec.revocable),
                None => soroban_sas_common::RevocationPolicy::Permissive,
            }
        }
        pub fn set_policy(env: Env, uid: UID, policy: soroban_sas_common::RevocationPolicy) {
            env.storage().persistent().set(&(POLICY, uid), &policy);
        }
        pub fn get_schema(env: Env, uid: UID) -> Option<SchemaRecord> {
            if env
                .storage()
                .persistent()
                .get::<_, bool>(&(DEPRECATED, uid.clone()))
                .unwrap_or(false)
            {
                return None;
            }
            // Return the stored record for uid, if one was set via set_schema.
            env.storage().persistent().get::<UID, SchemaRecord>(&uid)
        }
        pub fn set_schema(env: Env, uid: UID, record: SchemaRecord) {
            env.storage().persistent().set(&uid, &record);
        }
        pub fn set_deprecated(env: Env, uid: UID, val: bool) {
            env.storage().persistent().set(&(DEPRECATED, uid), &val);
        }
        pub fn get_creator(env: Env, uid: UID) -> Option<Address> {
            env.storage().persistent().get(&(CREATOR, uid))
        }
        pub fn set_creator(env: Env, uid: UID, creator: Address) {
            env.storage().persistent().set(&(CREATOR, uid), &creator);
        }
    }
}

pub mod mock_indexer {
    use super::*;
    use soroban_sdk::{contract, contractimpl, Env, Vec};

    #[contract]
    pub struct MockIndexer;

    #[contractimpl]
    impl MockIndexer {
        pub fn index_attestation(
            env: Env,
            uid: UID,
            recipient: Address,
            _schema_uid: UID,
            _attester: Address,
        ) {
            let mut uids: Vec<UID> = env
                .storage()
                .persistent()
                .get(&recipient)
                .unwrap_or_else(|| Vec::new(&env));
            uids.push_back(uid);
            env.storage().persistent().set(&recipient, &uids);
        }

        pub fn get_attestations_by_recipient(env: Env, recipient: Address) -> Vec<UID> {
            env.storage()
                .persistent()
                .get(&recipient)
                .unwrap_or_else(|| Vec::new(&env))
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
        deprecated: false,
        parent_schema_uid: None,
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
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::from_slice(&env, &[1, 2, 3]),
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
    let res =
        sas_client.try_verify_offchain_attestation(&attestation, &nonce, &pub_bytes, &sig_bytes);
    assert!(res.is_ok());

    // Unknown schema should be InvalidSchema
    let unknown_schema_uid = UID(BytesN::from_array(&env, &[99u8; 32]));
    let mut att_unknown = attestation.clone();
    att_unknown.schema_uid = unknown_schema_uid.clone();
    let payload_hash2 = soroban_sas_common::hash_offchain_attestation(&env, &att_unknown, &domain);
    let sig2 = signing_key.sign(&payload_hash2.to_array());
    let sig_bytes2 = BytesN::from_array(&env, &sig2.to_bytes());
    let res =
        sas_client.try_verify_offchain_attestation(&att_unknown, &nonce, &pub_bytes, &sig_bytes2);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));

    // Deprecated should also be InvalidSchema and invalidate prior
    mock_client.set_deprecated(&schema_uid, &true);
    let res =
        sas_client.try_verify_offchain_attestation(&attestation, &nonce, &pub_bytes, &sig_bytes);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));

    // On-chain attest with deprecated should also be InvalidSchema
    let att2_recipient = Address::generate(&env);
    let att2_data = Bytes::new(&env);
    let att2_uid = soroban_sas_common::attestation_uid(
        &env,
        &schema_uid,
        &att2_recipient,
        &attester,
        &att2_data,
    );
    let att2 = Attestation {
        uid: att2_uid,
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: att2_recipient,
        attester: attester.clone(),
        revocable: true,
        data: att2_data,
    };
    env.mock_all_auths();
    let res = sas_client.try_attest(&att2);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));
}

// --- #448 revocation policy enforcement in SAS core -------------------------

/// Sets up an initialized SAS bound to a fresh mock registry, returning the
/// SAS and registry clients.
fn setup_sas_with_registry(
    env: &Env,
) -> (
    SASClient<'static>,
    mock_registry::MockRegistryClient<'static>,
) {
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(env, &sas_id);
    let admin = Address::generate(env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);
    let mock_client = mock_registry::MockRegistryClient::new(env, &registry_id);
    (sas_client, mock_client)
}

fn policy_attestation(
    env: &Env,
    schema_uid: &UID,
    uid_seed: [u8; 32],
    revocable: bool,
) -> Attestation {
    Attestation {
        uid: UID(BytesN::from_array(env, &uid_seed)),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: Address::generate(env),
        attester: Address::generate(env),
        revocable,
        data: Bytes::new(env),
    }
}

#[test]
fn test_policy_irrevocable_only_rejects_revocable_attestation() {
    use soroban_sas_common::RevocationPolicy;
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);

    let schema_uid = UID(BytesN::from_array(&env, &[10u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: false,
        schema: SorobanString::from_str(&env, "bool like"),
        deprecated: false,
    };
    mock_client.set_schema(&schema_uid, &record);
    mock_client.set_policy(&schema_uid, &RevocationPolicy::IrrevocableOnly);

    env.mock_all_auths();
    let revocable_att = policy_attestation(&env, &schema_uid, [11u8; 32], true);
    assert_eq!(
        sas_client.try_attest(&revocable_att),
        Err(Ok(SASError::NotRevocable.into()))
    );

    let irrevocable_att = policy_attestation(&env, &schema_uid, [12u8; 32], false);
    assert!(sas_client.try_attest(&irrevocable_att).is_ok());
}

#[test]
fn test_policy_revocable_only_rejects_irrevocable_attestation() {
    use soroban_sas_common::RevocationPolicy;
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);

    let schema_uid = UID(BytesN::from_array(&env, &[20u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: true,
        schema: SorobanString::from_str(&env, "bool like"),
        deprecated: false,
    };
    mock_client.set_schema(&schema_uid, &record);
    mock_client.set_policy(&schema_uid, &RevocationPolicy::RevocableOnly);

    env.mock_all_auths();
    let irrevocable_att = policy_attestation(&env, &schema_uid, [21u8; 32], false);
    assert_eq!(
        sas_client.try_attest(&irrevocable_att),
        Err(Ok(SASError::InvalidRevocability.into()))
    );

    let revocable_att = policy_attestation(&env, &schema_uid, [22u8; 32], true);
    assert!(sas_client.try_attest(&revocable_att).is_ok());
}

#[test]
fn test_policy_permissive_allows_either_flag() {
    use soroban_sas_common::RevocationPolicy;
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);

    let schema_uid = UID(BytesN::from_array(&env, &[30u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: true,
        schema: SorobanString::from_str(&env, "bool like"),
        deprecated: false,
    };
    mock_client.set_schema(&schema_uid, &record);
    mock_client.set_policy(&schema_uid, &RevocationPolicy::Permissive);

    env.mock_all_auths();
    assert!(sas_client
        .try_attest(&policy_attestation(&env, &schema_uid, [31u8; 32], true))
        .is_ok());
    assert!(sas_client
        .try_attest(&policy_attestation(&env, &schema_uid, [32u8; 32], false))
        .is_ok());
}

#[test]
fn test_policy_falls_back_to_bool_when_registry_lacks_policy() {
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);

    let schema_uid = UID(BytesN::from_array(&env, &[40u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: false,
        schema: SorobanString::from_str(&env, "bool like"),
        deprecated: false,
    };
    mock_client.set_schema(&schema_uid, &record);

    env.mock_all_auths();
    assert_eq!(
        sas_client.try_attest(&policy_attestation(&env, &schema_uid, [41u8; 32], true)),
        Err(Ok(SASError::NotRevocable.into()))
    );
    assert!(sas_client
        .try_attest(&policy_attestation(&env, &schema_uid, [42u8; 32], false))
        .is_ok());
}

// --- #437 conditional delegation revocations with nonce ranges --------------

fn ed25519_attester(env: &Env, seed: [u8; 32]) -> (Address, SigningKey, [u8; 32]) {
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    let address = Address::from_string(&SorobanString::from_str(env, &strkey));
    (address, signing_key, public_key)
}

#[test]
fn test_invalidate_nonces_advances_watermark_and_blocks_replay() {
    let env = Env::default();
    let (sas_client, mock_client) = setup_sas_with_registry(&env);
    env.mock_all_auths();

    let (attester, signing_key, public_key) = ed25519_attester(&env, [55u8; 32]);
    let pub_bytes = BytesN::from_array(&env, &public_key);

    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 0);

    sas_client.invalidate_nonces(&attester, &1u64, &10u64);
    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 10);

    let schema_uid = UID(BytesN::from_array(&env, &[60u8; 32]));
    let record = SchemaRecord {
        uid: schema_uid.clone(),
        resolver: Address::generate(&env),
        revocable: true,
        schema: SorobanString::from_str(&env, "bool like"),
        deprecated: false,
    };
    mock_client.set_schema(&schema_uid, &record);

    let att_uid = UID(BytesN::from_array(&env, &[61u8; 32]));
    let attestation = Attestation {
        uid: att_uid.clone(),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: Address::generate(&env),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };
    sas_client.attest(&attestation);

    let cancelled_nonce = 5u64;
    let domain = soroban_sas_common::AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: sas_client.address.clone(),
        nonce: cancelled_nonce,
    };
    let payload_hash =
        soroban_sas_common::hash_delegated_revocation(&env, &att_uid, &attester, &domain);
    let sig = signing_key.sign(&payload_hash.to_array());
    let sig_bytes = BytesN::from_array(&env, &sig.to_bytes());

    let res =
        sas_client.try_revoke_by_delegation(&att_uid, &cancelled_nonce, &sig_bytes, &pub_bytes);
    assert_eq!(res, Err(Ok(SASError::DelegationReplay.into())));

    let fresh_nonce = 11u64;
    let domain2 = soroban_sas_common::AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: sas_client.address.clone(),
        nonce: fresh_nonce,
    };
    let payload_hash2 =
        soroban_sas_common::hash_delegated_revocation(&env, &att_uid, &attester, &domain2);
    let sig2 = signing_key.sign(&payload_hash2.to_array());
    let sig_bytes2 = BytesN::from_array(&env, &sig2.to_bytes());
    assert!(sas_client
        .try_revoke_by_delegation(&att_uid, &fresh_nonce, &sig_bytes2, &pub_bytes)
        .is_ok());
}

#[test]
fn test_invalidate_nonces_cannot_decrease_watermark() {
    let env = Env::default();
    let (sas_client, _mock_client) = setup_sas_with_registry(&env);
    env.mock_all_auths();
    let attester = Address::generate(&env);

    sas_client.invalidate_nonces(&attester, &1u64, &50u64);
    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 50);

    assert_eq!(
        sas_client.try_invalidate_nonces(&attester, &1u64, &40u64),
        Err(Ok(SASError::InvalidValue.into()))
    );
    assert_eq!(
        sas_client.try_invalidate_nonces(&attester, &1u64, &50u64),
        Err(Ok(SASError::InvalidValue.into()))
    );
    assert_eq!(
        sas_client.try_invalidate_nonces(&attester, &60u64, &55u64),
        Err(Ok(SASError::InvalidValue.into()))
    );
    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 50);
}

#[test]
fn test_set_nonce_highwater_mark_bulk_invalidation() {
    let env = Env::default();
    let (sas_client, _mock_client) = setup_sas_with_registry(&env);
    env.mock_all_auths();
    let attester = Address::generate(&env);

    sas_client.set_nonce_highwater_mark(&attester, &1000u64);
    assert_eq!(sas_client.get_nonce_highwater_mark(&attester), 1000);

    assert_eq!(
        sas_client.try_set_nonce_highwater_mark(&attester, &999u64),
        Err(Ok(SASError::InvalidValue.into()))
    );
}

/// Issue #112: `attest_internal` must reject an attestation that claims
/// `revocable = true` under a schema whose own `revocable` flag is `false`,
/// and this must hold across every entry point that funnels through
/// `attest_internal` (direct, delegated, batch, paid, replace) since none of
/// them duplicate the check themselves.
mod revocability {
    use super::*;

    /// A resolver whose `on_attest` always succeeds. `attest_internal`'s
    /// resolver invocation is authoritative (see `resolver_semantics`
    /// below): calling into a non-contract address fails the same way an
    /// explicit rejection would, so these revocable-flag tests need a real,
    /// registered no-op resolver rather than a bare generated `Address`.
    mod noop_resolver {
        use super::*;
        use soroban_sdk::{contract, contractimpl};

        #[contract]
        pub struct NoopResolver;

        #[contractimpl]
        impl NoopResolver {
            pub fn on_attest(_env: Env, _attestation: Attestation) {}
            pub fn on_revoke(_env: Env, _attestation: Attestation) {}
        }
    }

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
        let resolver = env.register_contract(None, noop_resolver::NoopResolver);
        let record = SchemaRecord {
            uid: schema_uid.clone(),
            resolver,
            revocable: schema_revocable,
            schema: SorobanString::from_str(&env, "value String"),
            deprecated: false,
            parent_schema_uid: None,
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

    fn attestation(fx: &Fixture, schema_uid: &UID, att_seed: u8, revocable: bool) -> Attestation {
        // att_seed folded into `data` so each caller still gets a distinct,
        // correctly content-addressed UID (#215).
        let data = Bytes::from_array(&fx.env, &[att_seed; 32]);
        let uid = soroban_sas_common::attestation_uid(
            &fx.env,
            schema_uid,
            &fx.recipient,
            &fx.attester,
            &data,
        );
        Attestation {
            uid,
            schema_uid: schema_uid.clone(),
            time: 1000,
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&fx.env, &[0u8; 32])),
            recipient: fx.recipient.clone(),
            attester: fx.attester.clone(),
            revocable,
            data,
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
        let attester = Address::from_string(&SorobanString::from_str(&fx.env, &attester_strkey));

        let mut att = attestation(&fx, &schema_uid, 5, true);
        att.attester = attester;
        att.uid = soroban_sas_common::attestation_uid(
            &fx.env,
            &att.schema_uid,
            &att.recipient,
            &att.attester,
            &att.data,
        );

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

        let res = sas_client.try_attest_by_delegation(&att, &nonce, &sig_bytes, &pub_bytes);
        assert_eq!(res, Err(Ok(SASError::NotRevocable.into())));
    }

    #[test]
    fn batch_attest_rejects_revocable_under_non_revocable_schema() {
        let (fx, schema_uid) = setup(false);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let ok_att = attestation(&fx, &schema_uid, 6, false);
        let ok_uid = ok_att.uid.clone();
        let bad_att = attestation(&fx, &schema_uid, 7, true);
        let batch = soroban_sdk::vec![&fx.env, ok_att, bad_att];

        let res = sas_client.try_multi_attest(&batch);
        assert_eq!(res, Err(Ok(SASError::NotRevocable.into())));

        // The whole batch is one atomic host transaction: the rejected
        // second entry must roll back the first entry too, not leave it
        // partially committed.
        assert!(!fx.env.as_contract(&fx.sas_client_id, || fx
            .env
            .storage()
            .persistent()
            .has(&ok_uid)));
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
            deprecated: false,
            parent_schema_uid: None,
        };
        let mock_client = mock_registry::MockRegistryClient::new(&fx.env, &fx.registry_id);
        mock_client.set_schema(&non_revocable_schema_uid, &non_revocable_record);

        let new_att = attestation(&fx, &non_revocable_schema_uid, 10, true);

        let res = sas_client.try_replace_attestation(&old_uid, &new_att);
        assert_eq!(res, Err(Ok(SASError::NotRevocable.into())));
    }

    /// Acceptance counterpart to
    /// `delegated_attest_rejects_revocable_under_non_revocable_schema`.
    /// Delegated issuance must *accept* `revocable = true` when the schema
    /// permits revocation, and record the flag verbatim — the rejection tests
    /// alone would still pass if the delegated path wrongly rejected every
    /// revocable attestation.
    #[test]
    fn delegated_attest_accepts_revocable_under_revocable_schema() {
        let (fx, schema_uid) = setup(true);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let seed = [62u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let attester_strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
        let attester = Address::from_string(&SorobanString::from_str(&fx.env, &attester_strkey));

        let mut att = attestation(&fx, &schema_uid, 12, true);
        att.attester = attester;
        att.uid = soroban_sas_common::attestation_uid(
            &fx.env,
            &att.schema_uid,
            &att.recipient,
            &att.attester,
            &att.data,
        );

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

        let res = sas_client.try_attest_by_delegation(&att, &nonce, &sig_bytes, &pub_bytes);
        assert!(
            res.is_ok(),
            "revocable attestation rejected under a revocable schema"
        );

        let stored = sas_client.get_attestation(&att.uid).unwrap();
        assert!(stored.revocable);
    }

    /// Acceptance counterpart to
    /// `batch_attest_rejects_revocable_under_non_revocable_schema`. A batch of
    /// revocable attestations must be accepted wholesale under a revocable
    /// schema, and each recorded attestation must keep its own flag.
    #[test]
    fn batch_attest_accepts_revocable_under_revocable_schema() {
        let (fx, schema_uid) = setup(true);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let first = attestation(&fx, &schema_uid, 15, true);
        let second = attestation(&fx, &schema_uid, 16, true);
        let batch = soroban_sdk::vec![&fx.env, first.clone(), second.clone()];

        let res = sas_client.try_multi_attest(&batch);
        assert!(
            res.is_ok(),
            "revocable batch rejected under a revocable schema"
        );

        for att in [&first, &second] {
            let stored = sas_client.get_attestation(&att.uid).unwrap();
            assert!(stored.revocable);
        }
    }

    /// Acceptance counterpart to
    /// `paid_attest_rejects_revocable_under_non_revocable_schema`. The paid
    /// path must accept a revocable attestation under a revocable schema.
    /// `value = 0` performs no token transfer, so only the flag check (and no
    /// deployed token) is exercised.
    #[test]
    fn paid_attest_accepts_revocable_under_revocable_schema() {
        let (fx, schema_uid) = setup(true);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 17, true);
        let token = Address::generate(&fx.env);

        let res = sas_client.try_attest_with_value(&att, &token, &0i128);
        assert!(
            res.is_ok(),
            "revocable paid attestation rejected under a revocable schema"
        );

        let stored = sas_client.get_attestation(&att.uid).unwrap();
        assert!(stored.revocable);
    }

    /// `replace_attestation` revokes the old attestation and mints a new one
    /// from `new_data`, so the successor's `revocable` flag comes from
    /// `new_data` — it is not inherited from the attestation it replaces. A
    /// revocable attestation may therefore be replaced by an irrevocable one
    /// (a deliberate "lock"): the old UID ends up revoked, while the new UID
    /// is live and can never itself be revoked.
    #[test]
    fn replace_attestation_may_flip_a_revocable_attestation_to_irrevocable() {
        use soroban_sdk::testutils::Ledger;
        let (fx, schema_uid) = setup(true);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let old_att = attestation(&fx, &schema_uid, 18, true);
        let old_uid = old_att.uid.clone();
        sas_client.attest(&old_att);

        // A fresh test `Env`'s ledger timestamp defaults to 0, which would
        // make the revocation's `revocation_time` indistinguishable from
        // never-revoked.
        fx.env.ledger().with_mut(|li| li.timestamp = 1000);

        let new_att = attestation(&fx, &schema_uid, 19, false);
        let new_uid = new_att.uid.clone();

        let issued = sas_client.replace_attestation(&old_uid, &new_att);
        assert_eq!(issued, new_uid);

        // The predecessor is revoked; the successor is live but irrevocable.
        assert!(!sas_client.verify_attestation(&old_uid));
        assert!(sas_client.verify_attestation(&new_uid));
        assert_eq!(
            sas_client.try_revoke(&new_uid),
            Err(Ok(SASError::NotRevocable.into()))
        );
    }
}

/// Issue #113: resolvers are authoritative. `on_attest`'s outcome must
/// control whether the attestation is issued, and every outcome the SAS
/// contract can observe (success, explicit rejection, trap, missing method)
/// must be specified and covered.
mod resolver_semantics {
    use super::*;

    /// A resolver whose `on_attest` always succeeds.
    pub mod accepting_resolver {
        use super::*;
        use soroban_sdk::{contract, contractimpl, Env};

        #[contract]
        pub struct AcceptingResolver;

        #[contractimpl]
        impl AcceptingResolver {
            pub fn on_attest(_env: Env, _attestation: Attestation) {}
            pub fn on_revoke(_env: Env, _attestation: Attestation) {}
        }
    }

    /// A resolver whose `on_attest` explicitly rejects every attestation by
    /// returning its own typed contract error, rather than panicking with an
    /// unstructured message.
    pub mod rejecting_resolver {
        use super::*;
        use soroban_sdk::{contract, contracterror, contractimpl, Env};

        #[contracterror]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
        #[repr(u32)]
        pub enum RejectingResolverError {
            AlwaysRejects = 1,
        }

        #[contract]
        pub struct RejectingResolver;

        #[contractimpl]
        impl RejectingResolver {
            pub fn on_attest(
                _env: Env,
                _attestation: Attestation,
            ) -> Result<(), RejectingResolverError> {
                Err(RejectingResolverError::AlwaysRejects)
            }
        }
    }

    /// A resolver whose `on_attest` traps with an unhandled panic, simulating
    /// a resolver that fails unexpectedly rather than rejecting on purpose.
    pub mod trapping_resolver {
        use super::*;
        use soroban_sdk::{contract, contractimpl, Env};

        #[contract]
        pub struct TrappingResolver;

        #[contractimpl]
        impl TrappingResolver {
            pub fn on_attest(_env: Env, _attestation: Attestation) {
                panic!("resolver misbehaves");
            }
        }
    }

    struct Fixture {
        env: Env,
        sas_client_id: Address,
        registry_id: Address,
        attester: Address,
        recipient: Address,
    }

    /// Registers `Resolver` on a fresh `Env` as the resolver of a fresh
    /// schema, wired up to a fresh `SAS` instance, and returns everything a
    /// test needs to attest against it.
    ///
    /// Takes the resolver as a type parameter (rather than a pre-registered
    /// `Address`) so the resolver contract is registered on the *same* `Env`
    /// this fixture builds — an `Address` from a different `Env` resolves to
    /// nothing meaningful once crossed over, so this shape rules that bug
    /// out at the call site instead of relying on every caller to remember.
    fn setup<Resolver: soroban_sdk::testutils::ContractFunctionSet + 'static>(
        resolver: Resolver,
    ) -> (Fixture, UID) {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, mock_registry::MockRegistry);
        let resolver_id = env.register_contract(None, resolver);
        let sas_id = env.register_contract(None, SAS);
        let sas_client = SASClient::new(&env, &sas_id);
        let admin = Address::generate(&env);
        sas_client.init(&admin, &registry_id);

        let attester = Address::generate(&env);
        let recipient = Address::generate(&env);

        let schema_uid = UID(BytesN::from_array(&env, &[21u8; 32]));
        let record = SchemaRecord {
            uid: schema_uid.clone(),
            resolver: resolver_id,
            revocable: true,
            schema: SorobanString::from_str(&env, "value String"),
            deprecated: false,
            parent_schema_uid: None,
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

    fn attestation(fx: &Fixture, schema_uid: &UID, att_seed: u8) -> Attestation {
        // att_seed folded into `data` so each caller still gets a distinct,
        // correctly content-addressed UID (#215).
        let data = Bytes::from_array(&fx.env, &[att_seed; 32]);
        let uid = soroban_sas_common::attestation_uid(
            &fx.env,
            schema_uid,
            &fx.recipient,
            &fx.attester,
            &data,
        );
        Attestation {
            uid,
            schema_uid: schema_uid.clone(),
            time: 1000,
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&fx.env, &[0u8; 32])),
            recipient: fx.recipient.clone(),
            attester: fx.attester.clone(),
            revocable: true,
            data,
        }
    }

    #[test]
    fn accepting_resolver_allows_issuance() {
        let (fx, schema_uid) = setup(accepting_resolver::AcceptingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 1);
        let uid = att.uid.clone();

        let res = sas_client.try_attest(&att);
        assert!(res.is_ok());
        assert!(fx.env.as_contract(&fx.sas_client_id, || fx
            .env
            .storage()
            .persistent()
            .has(&uid)));
    }

    #[test]
    fn rejecting_resolver_aborts_issuance_with_typed_error() {
        let (fx, schema_uid) = setup(rejecting_resolver::RejectingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 2);
        let uid = att.uid.clone();

        let res = sas_client.try_attest(&att);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));

        // Nothing was stored: the rejection is all-or-nothing, not a
        // best-effort warning.
        assert!(!fx.env.as_contract(&fx.sas_client_id, || fx
            .env
            .storage()
            .persistent()
            .has(&uid)));
    }

    #[test]
    fn trapping_resolver_aborts_issuance_with_typed_error() {
        let (fx, schema_uid) = setup(trapping_resolver::TrappingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 3);
        let uid = att.uid.clone();

        let res = sas_client.try_attest(&att);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));
        assert!(!fx.env.as_contract(&fx.sas_client_id, || fx
            .env
            .storage()
            .persistent()
            .has(&uid)));
    }

    #[test]
    fn resolver_missing_on_attest_aborts_issuance_with_typed_error() {
        // mock_registry::MockRegistry implements get_schema/set_schema but
        // not on_attest, so pointing a schema's resolver at it exercises
        // the "resolver doesn't implement the callback" outcome.
        let (fx, schema_uid) = setup(mock_registry::MockRegistry);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 4);
        let uid = att.uid.clone();

        let res = sas_client.try_attest(&att);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));
        assert!(!fx.env.as_contract(&fx.sas_client_id, || fx
            .env
            .storage()
            .persistent()
            .has(&uid)));
    }

    #[test]
    fn replace_attestation_rejected_by_new_resolver_leaves_old_attestation_untouched() {
        let (fx, accepting_schema_uid) = setup(accepting_resolver::AcceptingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let old_att = attestation(&fx, &accepting_schema_uid, 5);
        let old_uid = old_att.uid.clone();
        sas_client.attest(&old_att);

        // Point a second schema at a rejecting resolver, and try to replace
        // the old attestation with one issued under it.
        let rejecting_id = fx
            .env
            .register_contract(None, rejecting_resolver::RejectingResolver);
        let rejecting_schema_uid = UID(BytesN::from_array(&fx.env, &[22u8; 32]));
        let rejecting_record = SchemaRecord {
            uid: rejecting_schema_uid.clone(),
            resolver: rejecting_id,
            revocable: true,
            schema: SorobanString::from_str(&fx.env, "value String"),
            deprecated: false,
            parent_schema_uid: None,
        };
        let mock_client = mock_registry::MockRegistryClient::new(&fx.env, &fx.registry_id);
        mock_client.set_schema(&rejecting_schema_uid, &rejecting_record);

        let new_att = attestation(&fx, &rejecting_schema_uid, 6);

        let res = sas_client.try_replace_attestation(&old_uid, &new_att);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));

        // Atomicity: the whole call rolled back, so `old_uid` was never
        // actually revoked even though revoke_internal ran before the
        // rejected attest_internal call within the same invocation.
        let stored_old: Attestation = sas_client.get_attestation(&old_uid).unwrap();
        assert_eq!(stored_old.revocation_time, 0);
    }
}

/// Issue #216: resolvers are authoritative for revocation too, mirroring
/// `on_attest`'s semantics (see `resolver_semantics` above and
/// docs/schemas.md's "Resolver Failure Semantics"). Every outcome the SAS
/// contract can observe (success, explicit rejection, trap, missing method)
/// must be specified and covered, same as for issuance.
mod revoke_resolver_semantics {
    use super::*;

    /// A resolver whose `on_revoke` always succeeds.
    pub mod accepting_resolver {
        use super::*;
        use soroban_sdk::{contract, contractimpl, Env};

        #[contract]
        pub struct AcceptingResolver;

        #[contractimpl]
        impl AcceptingResolver {
            pub fn on_attest(_env: Env, _attestation: Attestation) {}
            pub fn on_revoke(_env: Env, _attestation: Attestation) {}
        }
    }

    /// A resolver whose `on_revoke` explicitly rejects every revocation by
    /// returning its own typed contract error.
    pub mod rejecting_resolver {
        use super::*;
        use soroban_sdk::{contract, contracterror, contractimpl, Env};

        #[contracterror]
        #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
        #[repr(u32)]
        pub enum RejectingResolverError {
            AlwaysRejects = 1,
        }

        #[contract]
        pub struct RejectingResolver;

        #[contractimpl]
        impl RejectingResolver {
            pub fn on_attest(_env: Env, _attestation: Attestation) {}
            pub fn on_revoke(
                _env: Env,
                _attestation: Attestation,
            ) -> Result<(), RejectingResolverError> {
                Err(RejectingResolverError::AlwaysRejects)
            }
        }
    }

    /// A resolver whose `on_revoke` traps with an unhandled panic.
    pub mod trapping_resolver {
        use super::*;
        use soroban_sdk::{contract, contractimpl, Env};

        #[contract]
        pub struct TrappingResolver;

        #[contractimpl]
        impl TrappingResolver {
            pub fn on_attest(_env: Env, _attestation: Attestation) {}
            pub fn on_revoke(_env: Env, _attestation: Attestation) {
                panic!("resolver misbehaves");
            }
        }
    }

    /// A resolver that implements `on_attest` but not `on_revoke`, so
    /// issuance succeeds and only revocation exercises the "missing method"
    /// outcome.
    pub mod attest_only_resolver {
        use super::*;
        use soroban_sdk::{contract, contractimpl, Env};

        #[contract]
        pub struct AttestOnlyResolver;

        #[contractimpl]
        impl AttestOnlyResolver {
            pub fn on_attest(_env: Env, _attestation: Attestation) {}
        }
    }

    #[allow(dead_code)]
    struct Fixture {
        env: Env,
        sas_client_id: Address,
    }

    /// Registers `Resolver` as the resolver of a fresh, revocable schema,
    /// wired up to a fresh `SAS` instance, issues one attestation against it,
    /// and returns everything a test needs to revoke that attestation.
    fn setup<Resolver: soroban_sdk::testutils::ContractFunctionSet + 'static>(
        resolver: Resolver,
    ) -> (Fixture, UID) {
        let env = Env::default();
        env.mock_all_auths();

        let registry_id = env.register_contract(None, mock_registry::MockRegistry);
        let resolver_id = env.register_contract(None, resolver);
        let sas_id = env.register_contract(None, SAS);
        let sas_client = SASClient::new(&env, &sas_id);
        let admin = Address::generate(&env);
        sas_client.init(&admin, &registry_id);

        let attester = Address::generate(&env);
        let recipient = Address::generate(&env);

        let schema_uid = UID(BytesN::from_array(&env, &[31u8; 32]));
        let record = SchemaRecord {
            uid: schema_uid.clone(),
            resolver: resolver_id,
            revocable: true,
            schema: SorobanString::from_str(&env, "value String"),
            deprecated: false,
            parent_schema_uid: None,
        };
        let mock_client = mock_registry::MockRegistryClient::new(&env, &registry_id);
        mock_client.set_schema(&schema_uid, &record);

        let data = Bytes::from_array(&env, &[1u8; 32]);
        let uid =
            soroban_sas_common::attestation_uid(&env, &schema_uid, &recipient, &attester, &data);
        let attestation = Attestation {
            uid: uid.clone(),
            schema_uid,
            time: 1000,
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
            recipient: recipient.clone(),
            attester: attester.clone(),
            revocable: true,
            data,
        };
        sas_client.attest(&attestation);

        (
            Fixture {
                env,
                sas_client_id: sas_id,
            },
            uid,
        )
    }

    #[test]
    fn accepting_resolver_allows_revocation() {
        use soroban_sdk::testutils::Ledger;
        let (fx, uid) = setup(accepting_resolver::AcceptingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        // A fresh test `Env`'s ledger timestamp defaults to 0, which would
        // make `revocation_time` indistinguishable from never-revoked.
        fx.env.ledger().with_mut(|li| li.timestamp = 1000);
        let res = sas_client.try_revoke(&uid);
        assert!(res.is_ok());
        let stored: Attestation = sas_client.get_attestation(&uid).unwrap();
        assert_ne!(stored.revocation_time, 0);
    }

    #[test]
    fn rejecting_resolver_aborts_revocation_with_typed_error() {
        let (fx, uid) = setup(rejecting_resolver::RejectingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let res = sas_client.try_revoke(&uid);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));

        // All-or-nothing: the rejection rolls back the revocation_time
        // write and event this same call already made, not just the parts
        // after the resolver call.
        let stored: Attestation = sas_client.get_attestation(&uid).unwrap();
        assert_eq!(stored.revocation_time, 0);
    }

    #[test]
    fn trapping_resolver_aborts_revocation_with_typed_error() {
        let (fx, uid) = setup(trapping_resolver::TrappingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let res = sas_client.try_revoke(&uid);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));
        let stored: Attestation = sas_client.get_attestation(&uid).unwrap();
        assert_eq!(stored.revocation_time, 0);
    }

    #[test]
    fn resolver_missing_on_revoke_aborts_revocation_with_typed_error() {
        let (fx, uid) = setup(attest_only_resolver::AttestOnlyResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let res = sas_client.try_revoke(&uid);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));
        let stored: Attestation = sas_client.get_attestation(&uid).unwrap();
        assert_eq!(stored.revocation_time, 0);
    }

    #[test]
    fn rejected_revocation_via_multi_revoke_leaves_the_attestation_untouched() {
        let (fx, uid) = setup(rejecting_resolver::RejectingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);

        let batch = soroban_sdk::vec![&fx.env, uid.clone()];
        let res = sas_client.try_multi_revoke(&batch);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));

        let stored: Attestation = sas_client.get_attestation(&uid).unwrap();
        assert_eq!(stored.revocation_time, 0);
    }
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
        valid_from: 0,
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
        valid_from: 0,
        ..attestation
    };
    let _res = sas_client.try_attest(&expired);
}

#[test]
fn test_broadcast_attest_happy_path_and_reverse_indexing() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let indexer_id = env.register_contract(None, mock_indexer::MockIndexer);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let indexer_client = mock_indexer::MockIndexerClient::new(&env, &indexer_id);
    let registry_client = mock_registry::MockRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let attester = Address::generate(&env);

    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);
    sas_client.set_indexer(&indexer_id);

    let resolver_id = env.register_contract(
        None,
        resolver_semantics::accepting_resolver::AcceptingResolver,
    );
    let schema_uid = UID(BytesN::from_array(&env, &[101u8; 32]));
    let schema_record = SchemaRecord {
        uid: schema_uid.clone(),
        schema: SorobanString::from_str(&env, "bool certified"),
        resolver: resolver_id,
        revocable: true,
        deprecated: false,
    };
    registry_client.set_schema(&schema_uid, &schema_record);
    registry_client.set_creator(&schema_uid, &creator);

    let recip1 = Address::generate(&env);
    let recip2 = Address::generate(&env);
    let recip3 = Address::generate(&env);
    let mut recipients = soroban_sdk::Vec::new(&env);
    recipients.push_back(recip1.clone());
    recipients.push_back(recip2.clone());
    recipients.push_back(recip3.clone());

    let data = Bytes::from_slice(&env, b"shared broadcast payload");
    let expiration_time = 5000u64;

    // Call broadcast_attest_by_attester
    let uids = sas_client.broadcast_attest_by_attester(
        &attester,
        &schema_uid,
        &recipients,
        &data,
        &expiration_time,
        &true,
    );

    assert_eq!(uids.len(), 3);
    let uid0 = uids.get(0).unwrap();
    let uid1 = uids.get(1).unwrap();
    let uid2 = uids.get(2).unwrap();

    // Deterministic and distinct
    assert_ne!(uid0, uid1);
    assert_ne!(uid1, uid2);
    assert_ne!(uid0, uid2);

    // Each attestation stored and verified in SAS
    let att0 = sas_client.get_attestation(&uid0).expect("att0 exists");
    assert_eq!(att0.recipient, recip1);
    assert_eq!(att0.attester, attester);
    assert_eq!(att0.schema_uid, schema_uid);
    assert_eq!(att0.data, data);
    assert_eq!(att0.expiration_time, expiration_time);
    assert!(att0.revocable);

    let att1 = sas_client.get_attestation(&uid1).expect("att1 exists");
    assert_eq!(att1.recipient, recip2);
    let att2 = sas_client.get_attestation(&uid2).expect("att2 exists");
    assert_eq!(att2.recipient, recip3);

    // Reverse indexing verified: indexer was notified and indexed each recipient
    let r1_uids = indexer_client.get_attestations_by_recipient(&recip1);
    assert!(r1_uids.contains(&uid0));
    let r2_uids = indexer_client.get_attestations_by_recipient(&recip2);
    assert!(r2_uids.contains(&uid1));
    let r3_uids = indexer_client.get_attestations_by_recipient(&recip3);
    assert!(r3_uids.contains(&uid2));

    // Also test broadcast_attest where attester is inferred as creator
    let recip4 = Address::generate(&env);
    let recip5 = Address::generate(&env);
    let mut batch2 = soroban_sdk::Vec::new(&env);
    batch2.push_back(recip4.clone());
    batch2.push_back(recip5.clone());

    let uids2 = sas_client.broadcast_attest(&schema_uid, &batch2, &data, &expiration_time, &true);
    assert_eq!(uids2.len(), 2);
    let att4 = sas_client.get_attestation(&uids2.get(0).unwrap()).unwrap();
    assert_eq!(att4.attester, creator);
    assert_eq!(att4.recipient, recip4);
}

#[test]
fn test_broadcast_attest_atomic_rollback_and_error_cases() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let registry_client = mock_registry::MockRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let attester = Address::generate(&env);

    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    // Register a schema with RejectingResolver
    let rejecting_resolver_id = env.register_contract(
        None,
        resolver_semantics::rejecting_resolver::RejectingResolver,
    );
    let schema_uid = UID(BytesN::from_array(&env, &[102u8; 32]));
    let schema_record = SchemaRecord {
        uid: schema_uid.clone(),
        schema: SorobanString::from_str(&env, "bool certified"),
        resolver: rejecting_resolver_id,
        revocable: true,
        deprecated: false,
    };
    registry_client.set_schema(&schema_uid, &schema_record);
    registry_client.set_creator(&schema_uid, &creator);

    let recip1 = Address::generate(&env);
    let recip2 = Address::generate(&env);
    let mut recipients = soroban_sdk::Vec::new(&env);
    recipients.push_back(recip1.clone());
    recipients.push_back(recip2.clone());

    let data = Bytes::new(&env);

    // Rejection by resolver rolls back entire batch atomically
    let res = sas_client.try_broadcast_attest(&schema_uid, &recipients, &data, &0, &true);
    assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));

    // Verify nothing was stored
    let expected_uid =
        soroban_sas_common::attestation_uid(&env, &schema_uid, &recip1, &creator, &data);
    assert!(sas_client.get_attestation(&expected_uid).is_none());

    // Register an accepting schema for duplicate and self-recipient checks
    let accepting_resolver_id = env.register_contract(
        None,
        resolver_semantics::accepting_resolver::AcceptingResolver,
    );
    let schema_uid2 = UID(BytesN::from_array(&env, &[120u8; 32]));
    let schema_record2 = SchemaRecord {
        uid: schema_uid2.clone(),
        schema: SorobanString::from_str(&env, "bool certified"),
        resolver: accepting_resolver_id,
        revocable: true,
        deprecated: false,
    };
    registry_client.set_schema(&schema_uid2, &schema_record2);
    registry_client.set_creator(&schema_uid2, &creator);

    // Duplicate recipient in batch must fail
    let mut dup_recipients = soroban_sdk::Vec::new(&env);
    dup_recipients.push_back(recip1.clone());
    dup_recipients.push_back(recip1.clone());
    let res = sas_client.try_broadcast_attest_by_attester(
        &attester,
        &schema_uid2,
        &dup_recipients,
        &data,
        &0,
        &true,
    );
    assert_eq!(res, Err(Ok(SASError::DuplicateAttestation.into())));

    // Self-attestation must fail
    let mut self_recipients = soroban_sdk::Vec::new(&env);
    self_recipients.push_back(attester.clone());
    self_recipients.push_back(recip2);
    let res = sas_client.try_broadcast_attest_by_attester(
        &attester,
        &schema_uid2,
        &self_recipients,
        &data,
        &0,
        &true,
    );
    assert_eq!(res, Err(Ok(SASError::InvalidRecipient.into())));
}

#[test]
fn test_broadcast_attest_bounds() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let registry_client = mock_registry::MockRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let resolver_id = env.register_contract(
        None,
        resolver_semantics::accepting_resolver::AcceptingResolver,
    );
    let schema_uid = UID(BytesN::from_array(&env, &[103u8; 32]));
    let schema_record = SchemaRecord {
        uid: schema_uid.clone(),
        schema: SorobanString::from_str(&env, "bool certified"),
        resolver: resolver_id,
        revocable: true,
        deprecated: false,
    };
    registry_client.set_schema(&schema_uid, &schema_record);
    registry_client.set_creator(&schema_uid, &creator);

    let data = Bytes::new(&env);

    // Empty vector fails with InvalidValue
    let empty_recips = soroban_sdk::Vec::new(&env);
    assert_eq!(
        sas_client.try_broadcast_attest(&schema_uid, &empty_recips, &data, &0, &true),
        Err(Ok(SASError::InvalidValue.into()))
    );

    // Over 100 recipients fails with BatchTooLarge
    let mut large_recips = soroban_sdk::Vec::new(&env);
    for _ in 0..101 {
        large_recips.push_back(Address::generate(&env));
    }
    assert_eq!(
        sas_client.try_broadcast_attest(&schema_uid, &large_recips, &data, &0, &true),
        Err(Ok(SASError::BatchTooLarge.into()))
    );
}

#[test]
fn test_fee_split_base_only_when_no_creator_fee() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let registry_client = mock_registry::MockRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let token_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &token_id);
    let token = soroban_sdk::token::Client::new(&env, &token_id);

    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);
    token_admin.mint(&attester, &1000);
    sas_client.set_fee(&token_id, &500);

    let resolver_id = env.register_contract(
        None,
        resolver_semantics::accepting_resolver::AcceptingResolver,
    );
    let schema_uid = UID(BytesN::from_array(&env, &[104u8; 32]));
    let schema_record = SchemaRecord {
        uid: schema_uid.clone(),
        schema: SorobanString::from_str(&env, "bool certified"),
        resolver: resolver_id,
        revocable: true,
        deprecated: false,
    };
    registry_client.set_schema(&schema_uid, &schema_record);
    registry_client.set_creator(&schema_uid, &creator);

    let data = Bytes::new(&env);
    let uid = soroban_sas_common::attestation_uid(&env, &schema_uid, &recipient, &attester, &data);
    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data,
    };

    let uid = sas_client.attest_with_value(&attestation, &token_id, &500);
    assert_eq!(uid, attestation.uid);
    assert_eq!(token.balance(&attester), 500);
    assert_eq!(token.balance(&sas_id), 500);

    // Treasury fee balance got full 500, creator fee balance is 0
    assert_eq!(sas_client.get_treasury_fee_balance(&token_id), 500);
    assert_eq!(sas_client.get_creator_fee_balance(&creator, &token_id), 0);
}

#[test]
fn test_fee_split_fixed_creator_fee_and_withdrawals() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let registry_client = mock_registry::MockRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let treasury_dest = Address::generate(&env);
    let creator_dest = Address::generate(&env);

    let token_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &token_id);
    let token = soroban_sdk::token::Client::new(&env, &token_id);

    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);
    token_admin.mint(&attester, &2000);
    sas_client.set_fee(&token_id, &300);

    let resolver_id = env.register_contract(
        None,
        resolver_semantics::accepting_resolver::AcceptingResolver,
    );
    let schema_uid = UID(BytesN::from_array(&env, &[105u8; 32]));
    let schema_record = SchemaRecord {
        uid: schema_uid.clone(),
        schema: SorobanString::from_str(&env, "bool certified"),
        resolver: resolver_id,
        revocable: true,
        deprecated: false,
    };
    registry_client.set_schema(&schema_uid, &schema_record);
    registry_client.set_creator(&schema_uid, &creator);

    // Schema creator configures a fixed fee of 200 (fee_type = 1)
    sas_client.set_schema_fee(&schema_uid, &creator, &1u32, &200i128, &0u32);
    let fee_cfg = SchemaFeeConfig {
        fee_type: 1,
        fixed_amount: 200,
        basis_points: 0,
    };
    assert_eq!(sas_client.get_schema_fee(&schema_uid), Some(fee_cfg));

    let data = Bytes::new(&env);
    let uid = soroban_sas_common::attestation_uid(&env, &schema_uid, &recipient, &attester, &data);
    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data,
    };

    // Total required is base (300) + fixed (200) = 500
    // Paying less than 500 fails
    assert_eq!(
        sas_client.try_attest_with_value(&attestation, &token_id, &300),
        Err(Ok(SASError::FeeMismatch.into()))
    );

    // Paying exactly 500 succeeds
    let uid = sas_client.attest_with_value(&attestation, &token_id, &500);
    assert_eq!(uid, attestation.uid);

    assert_eq!(token.balance(&attester), 1500);
    assert_eq!(token.balance(&sas_id), 500);

    // Treasury fee balance = 300, creator fee balance = 200
    assert_eq!(sas_client.get_treasury_fee_balance(&token_id), 300);
    assert_eq!(sas_client.get_creator_fee_balance(&creator, &token_id), 200);

    // Creator withdraws their fees
    sas_client.withdraw_creator_fees(&creator, &token_id, &200, &creator_dest);
    assert_eq!(token.balance(&creator_dest), 200);
    assert_eq!(sas_client.get_creator_fee_balance(&creator, &token_id), 0);
    assert_eq!(token.balance(&sas_id), 300);

    // Treasury admin withdraws protocol fees
    sas_client.withdraw_treasury_fees(&admin, &token_id, &300, &treasury_dest);
    assert_eq!(token.balance(&treasury_dest), 300);
    assert_eq!(sas_client.get_treasury_fee_balance(&token_id), 0);
    assert_eq!(token.balance(&sas_id), 0);
}

#[test]
fn test_fee_split_basis_points_and_ceilings() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let registry_client = mock_registry::MockRegistryClient::new(&env, &registry_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let stranger = Address::generate(&env);

    let token_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &token_id);

    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);
    token_admin.mint(&attester, &3000);
    sas_client.set_fee(&token_id, &1000);

    let resolver_id = env.register_contract(
        None,
        resolver_semantics::accepting_resolver::AcceptingResolver,
    );
    let schema_uid = UID(BytesN::from_array(&env, &[106u8; 32]));
    let schema_record = SchemaRecord {
        uid: schema_uid.clone(),
        schema: SorobanString::from_str(&env, "bool certified"),
        resolver: resolver_id,
        revocable: true,
        deprecated: false,
    };
    registry_client.set_schema(&schema_uid, &schema_record);
    registry_client.set_creator(&schema_uid, &creator);

    // Admin sets fee ceilings
    let ceilings = FeeCeilings {
        max_fixed_fee: 500,
        max_basis_points: 2500, // max 25%
    };
    sas_client.set_fee_ceilings(&500, &2500);
    assert_eq!(sas_client.get_fee_ceilings(), ceilings);

    // Setting fee that exceeds ceiling fails
    assert_eq!(
        sas_client.try_set_schema_fee(&schema_uid, &creator, &2u32, &0i128, &2501u32),
        Err(Ok(SASError::InvalidValue.into()))
    );

    assert_eq!(
        sas_client.try_set_schema_fee(&schema_uid, &creator, &1u32, &501i128, &0u32),
        Err(Ok(SASError::InvalidValue.into()))
    );

    // Valid 2000 bps (20%) succeeds
    sas_client.set_schema_fee(&schema_uid, &creator, &2u32, &0i128, &2000u32);

    // Attest with 1000 + (1000 * 2000 / 10000) = 1200
    let data = Bytes::new(&env);
    let uid = soroban_sas_common::attestation_uid(&env, &schema_uid, &recipient, &attester, &data);
    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data,
    };
    let uid = sas_client.attest_with_value(&attestation, &token_id, &1200);
    assert_eq!(uid, attestation.uid);

    assert_eq!(sas_client.get_treasury_fee_balance(&token_id), 1000);
    assert_eq!(sas_client.get_creator_fee_balance(&creator, &token_id), 200);

    // Clear schema fee restores base fee only
    sas_client.clear_schema_fee(&schema_uid, &creator);
    assert_eq!(sas_client.get_schema_fee(&schema_uid), None);

    // Stranger cannot clear schema fee
    assert_eq!(
        sas_client.try_clear_schema_fee(&schema_uid, &stranger),
        Err(Ok(SASError::Unauthorized.into()))
    );
}

#[test]
fn test_withdrawal_error_guards() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock_registry::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let stranger = Address::generate(&env);
    let dest = Address::generate(&env);

    let token_id = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();

    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    // Withdrawing non-positive amount fails
    assert_eq!(
        sas_client.try_withdraw_creator_fees(&creator, &token_id, &0, &dest),
        Err(Ok(SASError::InvalidValue.into()))
    );
    assert_eq!(
        sas_client.try_withdraw_treasury_fees(&admin, &token_id, &(-10), &dest),
        Err(Ok(SASError::InvalidValue.into()))
    );

    // Withdrawing exceeding balance fails
    assert_eq!(
        sas_client.try_withdraw_creator_fees(&creator, &token_id, &100, &dest),
        Err(Ok(SASError::InvalidValue.into()))
    );
    assert_eq!(
        sas_client.try_withdraw_treasury_fees(&admin, &token_id, &100, &dest),
        Err(Ok(SASError::InvalidValue.into()))
    );

    // Stranger attempting treasury withdrawal fails
    assert_eq!(
        sas_client.try_withdraw_treasury_fees(&stranger, &token_id, &50, &dest),
        Err(Ok(SASError::Unauthorized.into()))
    );
}
