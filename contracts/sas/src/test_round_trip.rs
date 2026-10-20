//! End-to-end multi-contract round-trip lifecycle tests (Issue #359).
//!
//! Exercises the complete protocol lifecycle across real instances of:
//! - `schema-registry` (Schema definition, validation, ownership, delegates, deprecation)
//! - `sas` (Attestation issuance, verification, off-chain delegation, revocation, view methods)
//! - `soroban-sas-indexer` (Downstream reverse-lookup index mirroring across all dimensions)
//! - Custom resolvers (`on_attest` and `on_revoke` validation gates)
//!
//! Runs in-process with a real Soroban mock host, validating both happy paths
//! and edge cases without requiring an external RPC node.

use crate::{SASClient, SAS};
use ed25519_dalek::{Signer, SigningKey};
use schema_registry::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::{
    hash_delegated_revocation, hash_offchain_attestation, Attestation, AttestationDomain, SASError,
    UID,
};
use soroban_sas_indexer::{Indexer, IndexerClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, String as SorobanString};

/// A custom resolver that enforces business rules:
/// - Rejects attestations whose data payload is empty or equals [0xFF; 4]
/// - Rejects revocation if data payload begins with [0xAA]
pub mod validating_resolver {
    use super::*;

    #[contract]
    pub struct ValidatingResolver;

    #[contractimpl]
    impl ValidatingResolver {
        pub fn on_attest(_env: Env, attestation: Attestation) {
            if attestation.data.is_empty() {
                panic!("empty data rejected by resolver");
            }
            if attestation.data.len() == 4 && attestation.data.get(0) == Some(0xFF) {
                panic!("0xFF magic value rejected by resolver");
            }
        }

        pub fn on_revoke(_env: Env, attestation: Attestation) {
            if !attestation.data.is_empty() && attestation.data.get(0) == Some(0xAA) {
                panic!("0xAA prefix locked from revocation by resolver");
            }
        }
    }
}

/// An open resolver that accepts all attestations and revocations.
pub mod permissive_resolver {
    use super::*;

    #[contract]
    pub struct PermissiveResolver;

    #[contractimpl]
    impl PermissiveResolver {
        pub fn on_attest(_env: Env, _attestation: Attestation) {}
        pub fn on_revoke(_env: Env, _attestation: Attestation) {}
    }
}

struct TestStack {
    env: Env,
    #[allow(dead_code)]
    admin: Address,
    registry: SchemaRegistryClient<'static>,
    sas: SASClient<'static>,
    indexer: IndexerClient<'static>,
    sas_id: Address,
    resolver_id: Address,
}

impl TestStack {
    fn setup() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        env.ledger().with_mut(|li| li.timestamp = 1_000);

        let admin = Address::generate(&env);

        let registry_id = env.register_contract(None, SchemaRegistry);
        let registry = SchemaRegistryClient::new(&env, &registry_id);
        registry.init(&admin);

        let sas_id = env.register_contract(None, SAS);
        let sas = SASClient::new(&env, &sas_id);
        sas.init(&admin, &registry_id);

        let indexer_id = env.register_contract(None, Indexer);
        let indexer = IndexerClient::new(&env, &indexer_id);
        indexer.init(&admin, &sas_id);
        sas.set_indexer(&indexer_id);

        let resolver_id = env.register_contract(None, permissive_resolver::PermissiveResolver);

        Self {
            env,
            admin,
            registry,
            sas,
            indexer,
            sas_id,
            resolver_id,
        }
    }

    fn create_attestation(
        &self,
        schema_uid: &UID,
        attester: &Address,
        recipient: &Address,
        data_bytes: &[u8],
        revocable: bool,
    ) -> Attestation {
        let data = Bytes::from_slice(&self.env, data_bytes);
        let uid =
            soroban_sas_common::attestation_uid(&self.env, schema_uid, recipient, attester, &data);
        Attestation {
            uid,
            schema_uid: schema_uid.clone(),
            time: 0,
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[0u8; 32])),
            recipient: recipient.clone(),
            attester: attester.clone(),
            revocable,
            data,
        }
    }
}

#[test]
fn test_complete_round_trip_lifecycle() {
    let stack = TestStack::setup();
    let schema_owner = Address::generate(&stack.env);
    let delegate = Address::generate(&stack.env);
    let recipient = Address::generate(&stack.env);

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 1: Schema Registration & Authorization
    // ─────────────────────────────────────────────────────────────────────────
    let schema_str = SorobanString::from_str(&stack.env, "string name, u32 age, bool verified");
    let schema_uid = stack
        .registry
        .register(&schema_owner, &schema_str, &stack.resolver_id, &true);

    // Verify schema registered accurately in SchemaRegistry
    let retrieved_schema = stack
        .registry
        .get_schema(&schema_uid)
        .expect("schema must exist after registration");
    assert_eq!(retrieved_schema.uid, schema_uid);
    assert_eq!(retrieved_schema.resolver, stack.resolver_id);
    assert!(retrieved_schema.revocable);
    assert!(!retrieved_schema.deprecated);

    let creator = stack.registry.get_creator(&schema_uid);
    assert_eq!(creator, Some(schema_owner.clone()));

    // Delegate is not yet authorized -> attestation must fail
    let unauth_attestation =
        stack.create_attestation(&schema_uid, &delegate, &recipient, b"alice,30,true", true);
    let try_unauth = stack.sas.try_attest(&unauth_attestation);
    assert_eq!(try_unauth, Err(Ok(SASError::Unauthorized.into())));

    // Authorize delegate under schema
    stack.registry.add_delegate(&schema_uid, &delegate);
    assert!(stack.registry.is_authorized(&schema_uid, &delegate));

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 2: Attestation Issuance
    // ─────────────────────────────────────────────────────────────────────────
    let attestation =
        stack.create_attestation(&schema_uid, &delegate, &recipient, b"alice,30,true", true);
    let uid = attestation.uid.clone();

    let issued_uid = stack.sas.attest(&attestation);
    assert_eq!(issued_uid, uid);

    // Verify attestation state in SAS
    assert!(stack.sas.verify_attestation(&uid));
    assert!(stack.sas.verify_attestation_view(&uid));

    let record = stack
        .sas
        .get_attestation(&uid)
        .expect("attestation record must exist");
    assert_eq!(record.uid, uid);
    assert_eq!(record.attester, delegate);
    assert_eq!(record.recipient, recipient);
    assert_eq!(record.schema_uid, schema_uid);
    assert_eq!(record.time, 1_000);
    assert_eq!(record.revocation_time, 0);

    // View method returns identical data without modifying TTL
    let view_record = stack
        .sas
        .get_attestation_view(&uid)
        .expect("view must return attestation");
    assert_eq!(view_record.uid, uid);
    assert_eq!(view_record.revocation_time, 0);

    // Duplicate attestation rejected
    let try_dup = stack.sas.try_attest(&attestation);
    assert_eq!(try_dup, Err(Ok(SASError::DuplicateAttestation.into())));

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3: Indexer Lookup Verification
    // ─────────────────────────────────────────────────────────────────────────
    let by_recipient = stack.indexer.get_attestations_by_recipient(&recipient);
    assert!(
        by_recipient.contains(&uid),
        "indexer must mirror attestation under recipient"
    );

    let by_attester = stack.indexer.get_attestations_by_attester(&delegate);
    assert!(
        by_attester.contains(&uid),
        "indexer must mirror attestation under attester"
    );

    let by_schema = stack.indexer.get_attestations_by_schema(&schema_uid);
    assert!(
        by_schema.contains(&uid),
        "indexer must mirror attestation under schema"
    );

    assert_eq!(stack.indexer.get_count_by_recipient(&recipient), 1);
    assert_eq!(stack.indexer.get_count_by_attester(&delegate), 1);
    assert_eq!(stack.indexer.get_count_by_schema(&schema_uid), 1);

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 4: Revocation & State Invariants
    // ─────────────────────────────────────────────────────────────────────────
    stack.env.ledger().with_mut(|li| li.timestamp = 2_500);

    // Revoke attestation
    stack.sas.revoke(&uid);

    // State after revocation
    assert!(
        !stack.sas.verify_attestation(&uid),
        "revoked attestation must fail verify_attestation"
    );
    assert!(
        !stack.sas.verify_attestation_view(&uid),
        "revoked attestation must fail verify_attestation_view"
    );

    let revoked_record = stack
        .sas
        .get_attestation(&uid)
        .expect("revoked record remains readable");
    assert_eq!(revoked_record.revocation_time, 2_500);

    // Repeated revocation fails with AlreadyRevoked
    let try_second_revoke = stack.sas.try_revoke(&uid);
    assert_eq!(try_second_revoke, Err(Ok(SASError::AlreadyRevoked.into())));

    // Indexer retains historical UID for discovery
    let by_recipient_post = stack.indexer.get_attestations_by_recipient(&recipient);
    assert!(by_recipient_post.contains(&uid));
}

#[test]
fn test_delegated_offchain_round_trip_lifecycle() {
    let stack = TestStack::setup();
    let schema_owner = Address::generate(&stack.env);
    let recipient = Address::generate(&stack.env);

    let schema_str = SorobanString::from_str(&stack.env, "string credential");
    let schema_uid = stack
        .registry
        .register(&schema_owner, &schema_str, &stack.resolver_id, &true);

    // Setup off-chain signing keypair
    let signing_key = SigningKey::from_bytes(&[77u8; 32]);
    let verifying_key_bytes = signing_key.verifying_key().to_bytes();
    let attester_strkey = stellar_strkey::ed25519::PublicKey(verifying_key_bytes).to_string();
    let attester = Address::from_string(&SorobanString::from_str(&stack.env, &attester_strkey));

    // Authorize attester under schema
    stack.registry.add_delegate(&schema_uid, &attester);

    // Register attester key on-chain
    let public_key_n = BytesN::from_array(&stack.env, &verifying_key_bytes);
    stack.sas.register_attester_key(&attester, &public_key_n);

    let key_record = stack
        .sas
        .get_attester_key(&attester)
        .expect("key record must exist");
    assert_eq!(key_record.public_key, public_key_n);
    assert!(!key_record.revoked);

    // Prepare off-chain attestation
    let attestation = stack.create_attestation(
        &schema_uid,
        &attester,
        &recipient,
        b"diploma_degree_2026",
        true,
    );
    let uid = attestation.uid.clone();

    let nonce = 101u64;
    let domain = AttestationDomain {
        network_id: stack.env.ledger().network_id(),
        contract: stack.sas_id.clone(),
        nonce,
    };
    let payload_hash = hash_offchain_attestation(&stack.env, &attestation, &domain);
    let signature_raw = signing_key.sign(&payload_hash.to_array());
    let signature = BytesN::from_array(&stack.env, &signature_raw.to_bytes());

    // Submit delegated attestation through relayer
    let issued_uid =
        stack
            .sas
            .attest_by_delegation(&attestation, &nonce, &signature, &public_key_n);
    assert_eq!(issued_uid, uid);
    assert!(stack.sas.verify_attestation(&uid));

    // Verify indexer indexed the attestation under actual off-chain attester
    let by_attester = stack.indexer.get_attestations_by_attester(&attester);
    assert!(by_attester.contains(&uid));

    // Replay of same nonce is rejected
    let try_replay =
        stack
            .sas
            .try_attest_by_delegation(&attestation, &nonce, &signature, &public_key_n);
    assert_eq!(try_replay, Err(Ok(SASError::DelegationReplay.into())));

    // Advance timestamp and sign delegated revocation
    stack.env.ledger().with_mut(|li| li.timestamp = 3_000);
    let revoke_nonce = 102u64;
    let revoke_domain = AttestationDomain {
        network_id: stack.env.ledger().network_id(),
        contract: stack.sas_id.clone(),
        nonce: revoke_nonce,
    };
    let revoke_hash = hash_delegated_revocation(&stack.env, &uid, &attester, &revoke_domain);
    let revoke_sig_raw = signing_key.sign(&revoke_hash.to_array());
    let revoke_sig = BytesN::from_array(&stack.env, &revoke_sig_raw.to_bytes());

    stack
        .sas
        .revoke_by_delegation(&uid, &revoke_nonce, &revoke_sig, &public_key_n);

    assert!(!stack.sas.verify_attestation(&uid));
    let rec = stack.sas.get_attestation(&uid).unwrap();
    assert_eq!(rec.revocation_time, 3_000);
}

#[test]
fn test_non_revocable_schema_rejection_lifecycle() {
    let stack = TestStack::setup();
    let attester = Address::generate(&stack.env);
    let recipient = Address::generate(&stack.env);

    // Register a non-revocable schema
    let schema_str = SorobanString::from_str(&stack.env, "string immutable_record");
    let schema_uid = stack
        .registry
        .register(&attester, &schema_str, &stack.resolver_id, &false);

    // 1. Issuing an attestation with revocable = true under a non-revocable schema must fail
    let invalid_attestation = stack.create_attestation(
        &schema_uid,
        &attester,
        &recipient,
        b"immutable_data",
        true, // Mismatched flag
    );
    let try_invalid = stack.sas.try_attest(&invalid_attestation);
    assert_eq!(try_invalid, Err(Ok(SASError::NotRevocable.into())));

    // 2. Issue valid non-revocable attestation
    let valid_attestation =
        stack.create_attestation(&schema_uid, &attester, &recipient, b"immutable_data", false);
    let uid = valid_attestation.uid.clone();
    stack.sas.attest(&valid_attestation);
    assert!(stack.sas.verify_attestation(&uid));

    // 3. Attempting to revoke non-revocable attestation must fail
    let try_revoke = stack.sas.try_revoke(&uid);
    assert_eq!(try_revoke, Err(Ok(SASError::NotRevocable.into())));
    assert!(stack.sas.verify_attestation(&uid));
}

#[test]
fn test_schema_deprecation_lifecycle() {
    let stack = TestStack::setup();
    let schema_owner = Address::generate(&stack.env);
    let recipient = Address::generate(&stack.env);

    let schema_str = SorobanString::from_str(&stack.env, "string kyc_tier");
    let schema_uid = stack
        .registry
        .register(&schema_owner, &schema_str, &stack.resolver_id, &true);

    // Issue initial attestation while schema is active
    let a1 = stack.create_attestation(&schema_uid, &schema_owner, &recipient, b"tier_1", true);
    let uid1 = a1.uid.clone();
    stack.sas.attest(&a1);
    assert!(stack.sas.verify_attestation(&uid1));

    // Deprecate the schema
    stack.registry.deprecate(&schema_uid, &schema_owner);
    assert!(stack.registry.get_schema(&schema_uid).is_none());

    // Existing attestation remains valid and verifiable
    assert!(stack.sas.verify_attestation(&uid1));

    // New attestation under deprecated schema is rejected
    let a2 = stack.create_attestation(&schema_uid, &schema_owner, &recipient, b"tier_2", true);
    let try_a2 = stack.sas.try_attest(&a2);
    assert_eq!(try_a2, Err(Ok(SASError::InvalidSchema.into())));
}

#[test]
fn test_resolver_gated_validation_lifecycle() {
    let env = Env::default();
    env.mock_all_auths();
    env.budget().reset_unlimited();

    let admin = Address::generate(&env);
    let registry_id = env.register_contract(None, SchemaRegistry);
    let registry = SchemaRegistryClient::new(&env, &registry_id);
    registry.init(&admin);

    let sas_id = env.register_contract(None, SAS);
    let sas = SASClient::new(&env, &sas_id);
    sas.init(&admin, &registry_id);

    let indexer_id = env.register_contract(None, Indexer);
    let indexer = IndexerClient::new(&env, &indexer_id);
    indexer.init(&admin, &sas_id);
    sas.set_indexer(&indexer_id);

    // Register with ValidatingResolver
    let resolver_id = env.register_contract(None, validating_resolver::ValidatingResolver);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let schema_uid = registry.register(
        &attester,
        &SorobanString::from_str(&env, "string custom_payload"),
        &resolver_id,
        &true,
    );

    // Case 1: Resolver rejects invalid payload ([0xFF; 4])
    let invalid_data = Bytes::from_slice(&env, &[0xFF, 0xFF, 0xFF, 0xFF]);
    let uid_invalid = soroban_sas_common::attestation_uid(
        &env,
        &schema_uid,
        &recipient,
        &attester,
        &invalid_data,
    );
    let invalid_attestation = Attestation {
        uid: uid_invalid.clone(),
        schema_uid: schema_uid.clone(),
        time: 0,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: invalid_data,
    };

    let try_invalid = sas.try_attest(&invalid_attestation);
    assert_eq!(try_invalid, Err(Ok(SASError::ResolverRejected.into())));
    assert!(!indexer
        .get_attestations_by_recipient(&recipient)
        .contains(&uid_invalid));

    // Case 2: Resolver accepts valid payload
    let valid_data = Bytes::from_slice(&env, b"valid payload");
    let uid_valid =
        soroban_sas_common::attestation_uid(&env, &schema_uid, &recipient, &attester, &valid_data);
    let valid_attestation = Attestation {
        uid: uid_valid.clone(),
        schema_uid: schema_uid.clone(),
        time: 0,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: valid_data,
    };

    sas.attest(&valid_attestation);
    assert!(sas.verify_attestation(&uid_valid));
    assert!(indexer
        .get_attestations_by_recipient(&recipient)
        .contains(&uid_valid));

    // Case 3: Resolver blocks revocation on protected payload (starts with 0xAA)
    let protected_data = Bytes::from_slice(&env, &[0xAA, 0x01, 0x02]);
    let uid_protected = soroban_sas_common::attestation_uid(
        &env,
        &schema_uid,
        &recipient,
        &attester,
        &protected_data,
    );
    let protected_attestation = Attestation {
        uid: uid_protected.clone(),
        schema_uid,
        time: 0,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester,
        revocable: true,
        data: protected_data,
    };

    sas.attest(&protected_attestation);
    assert!(sas.verify_attestation(&uid_protected));

    // Attempt to revoke protected attestation fails via resolver
    let try_revoke = sas.try_revoke(&uid_protected);
    assert_eq!(try_revoke, Err(Ok(SASError::ResolverRejected.into())));
    // Attestation remains active
    assert!(sas.verify_attestation(&uid_protected));
}
