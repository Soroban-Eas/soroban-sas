//! Schema attester access control list enforcement (#443).
//!
//! These deploy the real `schema-registry` and `sas` contracts together, so
//! the cross-contract fallback from `is_authorized` to the ACL is exercised
//! end to end instead of through a mock registry.
//!
//! Behaviour under test:
//! - a listed attester may issue under a restricted schema,
//! - any other issuer is rejected with `UnauthorizedAttester`,
//! - a schema without an ACL keeps the original `Unauthorized` error,
//! - owners and delegates are unaffected by the list,
//! - ACL membership grants issuance only, not revocation of other attesters'
//!   attestations.

use crate::{SASClient, SAS};
use schema_registry::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::{Attestation, SASError, UID};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, String as SorobanString};

mod accept_all_resolver {
    use super::*;

    #[contract]
    pub struct AcceptAllResolver;

    #[contractimpl]
    impl AcceptAllResolver {
        pub fn on_attest(_env: Env, _attestation: Attestation) {}
        pub fn on_revoke(_env: Env, _attestation: Attestation) {}
    }
}

struct Deployment {
    env: Env,
    sas: SASClient<'static>,
    registry: SchemaRegistryClient<'static>,
    /// Owns `schema_uid`.
    owner: Address,
    schema_uid: UID,
}

fn deploy() -> Deployment {
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

    let resolver_id = env.register_contract(None, accept_all_resolver::AcceptAllResolver);
    let owner = Address::generate(&env);
    let schema_uid = registry.register(
        &owner,
        &SorobanString::from_str(&env, "bool in_private_group"),
        &resolver_id,
        &true,
    );

    Deployment {
        env,
        sas,
        registry,
        owner,
        schema_uid,
    }
}

impl Deployment {
    /// A correctly content-addressed, revocable attestation; `seed` makes the
    /// UID unique.
    fn attestation(&self, attester: &Address, seed: u32) -> Attestation {
        let recipient = Address::generate(&self.env);
        let data = Bytes::from_array(&self.env, &seed.to_be_bytes());
        Attestation {
            uid: soroban_sas_common::attestation_uid(
                &self.env,
                &self.schema_uid,
                &recipient,
                attester,
                &data,
            ),
            schema_uid: self.schema_uid.clone(),
            time: 0,
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[0u8; 32])),
            recipient,
            attester: attester.clone(),
            revocable: true,
            data,
        }
    }
}

#[test]
fn listed_attester_can_issue_under_a_restricted_schema() {
    let d = deploy();
    let member = Address::generate(&d.env);
    d.registry.add_authorized_attester(&d.schema_uid, &member);

    let attestation = d.attestation(&member, 1);
    let uid = d.sas.attest(&attestation);

    assert_eq!(uid, attestation.uid);
    let stored = d.sas.get_attestation(&uid).unwrap();
    assert_eq!(stored.attester, member);
    assert_eq!(stored.schema_uid, d.schema_uid);
}

#[test]
fn unlisted_caller_is_rejected_with_unauthorized_attester() {
    let d = deploy();
    let member = Address::generate(&d.env);
    let outsider = Address::generate(&d.env);
    d.registry.add_authorized_attester(&d.schema_uid, &member);

    let attestation = d.attestation(&outsider, 1);
    let result = d.sas.try_attest(&attestation);

    assert_eq!(result, Err(Ok(SASError::UnauthorizedAttester.into())));
    assert!(d.sas.get_attestation(&attestation.uid).is_none());
}

#[test]
fn schema_without_an_acl_keeps_the_original_unauthorized_error() {
    let d = deploy();
    let outsider = Address::generate(&d.env);

    let attestation = d.attestation(&outsider, 1);
    let result = d.sas.try_attest(&attestation);

    assert_eq!(result, Err(Ok(SASError::Unauthorized.into())));
}

#[test]
fn owner_can_still_issue_when_the_schema_is_restricted() {
    let d = deploy();
    let member = Address::generate(&d.env);
    d.registry.add_authorized_attester(&d.schema_uid, &member);

    let attestation = d.attestation(&d.owner, 1);

    assert_eq!(d.sas.attest(&attestation), attestation.uid);
}

#[test]
fn delegate_can_still_issue_when_the_schema_is_restricted() {
    let d = deploy();
    let member = Address::generate(&d.env);
    let delegate = Address::generate(&d.env);
    d.registry.add_authorized_attester(&d.schema_uid, &member);
    d.registry.add_delegate(&d.schema_uid, &delegate);

    let attestation = d.attestation(&delegate, 1);

    assert_eq!(d.sas.attest(&attestation), attestation.uid);
}

#[test]
fn removed_attester_loses_issuance_rights() {
    let d = deploy();
    let member = Address::generate(&d.env);
    let other = Address::generate(&d.env);
    d.registry.add_authorized_attester(&d.schema_uid, &member);
    d.registry.add_authorized_attester(&d.schema_uid, &other);
    let first = d.attestation(&member, 1);
    assert_eq!(d.sas.attest(&first), first.uid);

    d.registry
        .remove_authorized_attester(&d.schema_uid, &member);

    // `other` remains on the list, so the schema is still restricted and the
    // removed attester gets the dedicated error.
    let result = d.sas.try_attest(&d.attestation(&member, 2));
    assert_eq!(result, Err(Ok(SASError::UnauthorizedAttester.into())));
    let still_allowed = d.attestation(&other, 3);
    assert_eq!(d.sas.attest(&still_allowed), still_allowed.uid);
}

#[test]
fn emptying_the_acl_returns_the_schema_to_the_default_error() {
    let d = deploy();
    let member = Address::generate(&d.env);
    d.registry.add_authorized_attester(&d.schema_uid, &member);
    d.registry
        .remove_authorized_attester(&d.schema_uid, &member);

    let result = d.sas.try_attest(&d.attestation(&member, 1));

    assert_eq!(result, Err(Ok(SASError::Unauthorized.into())));
}

#[test]
fn acl_of_one_schema_does_not_authorize_another() {
    let d = deploy();
    let member = Address::generate(&d.env);
    d.registry.add_authorized_attester(&d.schema_uid, &member);

    let resolver = d
        .env
        .register_contract(None, accept_all_resolver::AcceptAllResolver);
    let other_schema = d.registry.register(
        &d.owner,
        &SorobanString::from_str(&d.env, "bool some_other_schema"),
        &resolver,
        &true,
    );
    let recipient = Address::generate(&d.env);
    let data = Bytes::from_array(&d.env, &[1u8]);
    let attestation = Attestation {
        uid: soroban_sas_common::attestation_uid(&d.env, &other_schema, &recipient, &member, &data),
        schema_uid: other_schema,
        time: 0,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&d.env, &[0u8; 32])),
        recipient,
        attester: member,
        revocable: true,
        data,
    };

    // The other schema has no ACL, so the original error applies.
    assert_eq!(
        d.sas.try_attest(&attestation),
        Err(Ok(SASError::Unauthorized.into()))
    );
}

#[test]
fn acl_membership_does_not_allow_revoking_other_attesters_attestations() {
    let d = deploy();
    let member = Address::generate(&d.env);
    d.registry.add_authorized_attester(&d.schema_uid, &member);
    let by_owner = d.attestation(&d.owner, 1);
    d.sas.attest(&by_owner);

    let result = d.sas.try_revoke_by_authorizer(&by_owner.uid, &member);

    assert_eq!(result, Err(Ok(SASError::Unauthorized.into())));
    assert_eq!(
        d.sas
            .get_attestation(&by_owner.uid)
            .unwrap()
            .revocation_time,
        0
    );
}

#[test]
fn listed_attester_can_revoke_its_own_attestation() {
    let d = deploy();
    let member = Address::generate(&d.env);
    d.registry.add_authorized_attester(&d.schema_uid, &member);
    let attestation = d.attestation(&member, 1);
    d.sas.attest(&attestation);

    d.sas.revoke(&attestation.uid);

    assert_ne!(
        d.sas
            .get_attestation(&attestation.uid)
            .unwrap()
            .revocation_time,
        0
    );
}
