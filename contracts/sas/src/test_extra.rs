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

    /// Registers a schema whose `revocable` flag is `schema_revocable` in a
    /// fresh `mock_registry::MockRegistry`, wired up to a fresh `SAS`
    /// instance, and returns everything a test needs to attest against it.
    fn setup(schema_revocable: bool) -> (Fixture, UID) {
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

        let schema_uid = UID(BytesN::from_array(&env, &[9u8; 32]));
        let resolver = Address::generate(&env);
        let record = SchemaRecord {
            uid: schema_uid.clone(),
            resolver,
            revocable: schema_revocable,
        let schema_uid = UID(BytesN::from_array(&env, &[21u8; 32]));
        let record = SchemaRecord {
            uid: schema_uid.clone(),
            resolver: resolver_id,
            revocable: true,
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
    fn attestation(fx: &Fixture, schema_uid: &UID, att_seed: u8) -> Attestation {
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
            revocable: true,
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
    fn accepting_resolver_allows_issuance() {
        let (fx, schema_uid) = setup(accepting_resolver::AcceptingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 1);
        let uid = att.uid.clone();

        let res = sas_client.try_attest(&att);
        assert!(res.is_ok());
        assert!(fx
            .env
            .as_contract(&fx.sas_client_id, || fx.env.storage().persistent().has(&uid)));
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
        assert!(!fx
            .env
            .as_contract(&fx.sas_client_id, || fx.env.storage().persistent().has(&uid)));
    }

    #[test]
    fn trapping_resolver_aborts_issuance_with_typed_error() {
        let (fx, schema_uid) = setup(trapping_resolver::TrappingResolver);
        let sas_client = SASClient::new(&fx.env, &fx.sas_client_id);
        let att = attestation(&fx, &schema_uid, 3);
        let uid = att.uid.clone();

        let res = sas_client.try_attest(&att);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));
        assert!(!fx
            .env
            .as_contract(&fx.sas_client_id, || fx.env.storage().persistent().has(&uid)));
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
        assert!(!fx
            .env
            .as_contract(&fx.sas_client_id, || fx.env.storage().persistent().has(&uid)));
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
        let rejecting_id =
            fx.env
                .register_contract(None, rejecting_resolver::RejectingResolver);
        let rejecting_schema_uid = UID(BytesN::from_array(&fx.env, &[22u8; 32]));
        let rejecting_record = SchemaRecord {
            uid: rejecting_schema_uid.clone(),
            resolver: rejecting_id,
            revocable: true,
            schema: SorobanString::from_str(&fx.env, "value String"),
        };
        let mock_client = mock_registry::MockRegistryClient::new(&fx.env, &fx.registry_id);
        mock_client.set_schema(&rejecting_schema_uid, &rejecting_record);

        let new_att = attestation(&fx, &rejecting_schema_uid, 6);

        let res = sas_client.try_replace_attestation(&old_uid, &new_att);
        assert_eq!(res, Err(Ok(SASError::ResolverRejected.into())));

        // Atomicity: the whole call rolled back, so `old_uid` was never
        // actually revoked even though revoke_internal ran before the
        // rejected attest_internal call within the same invocation.
        let stored_old: Attestation = fx
            .env
            .as_contract(&fx.sas_client_id, || fx.env.storage().persistent().get(&old_uid).unwrap());
        assert_eq!(stored_old.revocation_time, 0);
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
