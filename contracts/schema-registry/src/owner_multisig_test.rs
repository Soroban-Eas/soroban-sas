//! Tests for multi-signature schema owners (#288).
//!
//! Covers the owner-set configuration rules, the propose/approve threshold
//! flow, the guard that stops a single owner from bypassing a multi-sig set,
//! and the invalidations that must happen when the set changes underneath an
//! in-flight transfer.

use crate::{SchemaRegistry, SchemaRegistryClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String, Vec};

/// Registers one schema and returns its UID. Each test uses a fresh `Env`, so
/// the schema string can be identical across tests without colliding.
fn register_schema(env: &Env, client: &SchemaRegistryClient, owner: &Address) -> crate::UID {
    let schema = String::from_str(env, "bool like_soroban");
    let resolver = Address::generate(env);
    client.register(owner, &schema, &resolver, &true)
}

fn deploy(env: &Env) -> SchemaRegistryClient {
    let contract_id = env.register_contract(None, SchemaRegistry);
    SchemaRegistryClient::new(env, &contract_id)
}

fn owner_vec(env: &Env, owners: &[Address]) -> Vec<Address> {
    let mut vec = Vec::new(env);
    for owner in owners.iter() {
        vec.push_back(owner.clone());
    }
    vec
}

#[test]
fn configure_owner_set_rejects_empty_owners() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);

    let res = client.try_configure_owner_set(&uid, &creator, &Vec::new(&env), &1);
    assert!(res.is_err(), "an empty owner set must be rejected");
}

#[test]
fn configure_owner_set_rejects_threshold_out_of_range() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    let too_high = client.try_configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[a.clone(), b.clone()]),
        &3,
    );
    assert!(too_high.is_err(), "threshold above owner count must be rejected");

    let zero = client.try_configure_owner_set(&uid, &creator, &owner_vec(&env, &[a, b]), &0);
    assert!(zero.is_err(), "a zero threshold must be rejected");
}

#[test]
fn configure_owner_set_rejects_duplicate_owners() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let a = Address::generate(&env);

    let res = client.try_configure_owner_set(&uid, &creator, &owner_vec(&env, &[a.clone(), a]), &1);
    assert!(res.is_err(), "duplicate owners must be rejected");
}

#[test]
fn configure_owner_set_rejects_more_than_max_owners() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);

    let mut owners = Vec::new(&env);
    for _ in 0..(crate::storage::MAX_OWNER_SET + 1) {
        owners.push_back(Address::generate(&env));
    }

    let res = client.try_configure_owner_set(&uid, &creator, &owners, &1);
    assert!(res.is_err(), "owner sets are capped at MAX_OWNER_SET");
}

#[test]
fn configure_owner_set_bumps_version_and_is_readable() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let a = Address::generate(&env);
    let b = Address::generate(&env);

    assert!(client.get_owner_set(&uid).is_none());

    let first = client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), a.clone()]),
        &2,
    );
    assert_eq!(first.version, 1);
    assert_eq!(first.threshold, 2);
    assert_eq!(first.owners.len(), 2);

    let second = client.configure_owner_set(&uid, &creator, &owner_vec(&env, &[b.clone()]), &1);
    assert_eq!(second.version, 2, "reconfiguration must bump the version");

    let stored = client.get_owner_set(&uid).unwrap();
    assert_eq!(stored.version, 2);
    assert_eq!(stored.owners.len(), 1);
    assert!(client.is_schema_owner(&uid, &b));
}

#[test]
fn configure_owner_set_rejects_unknown_schema() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let caller = Address::generate(&env);
    let owner = Address::generate(&env);
    let fake = crate::UID(soroban_sdk::BytesN::from_array(&env, &[9u8; 32]));

    let res = client.try_configure_owner_set(&fake, &caller, &owner_vec(&env, &[owner]), &1);
    assert!(res.is_err());
}

#[test]
fn multisig_transfer_requires_threshold_distinct_approvals() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);
    let third = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone(), third.clone()]),
        &2,
    );

    let new_owner = Address::generate(&env);

    let proposed = client.propose_ownership_transfer(&uid, &second, &new_owner);
    assert!(!proposed.executed, "2-of-3 needs a second approval");
    assert_eq!(proposed.approvals, 1);
    assert_eq!(proposed.threshold, 2);
    assert_eq!(client.get_creator(&uid).unwrap(), creator.clone());

    let pending = client.get_pending_ownership_transfer(&uid).unwrap();
    assert_eq!(pending.approvals.len(), 1);
    assert_eq!(pending.new_owner, new_owner);

    let approved = client.approve_ownership_transfer(&uid, &third);
    assert!(approved.executed, "second distinct approval must execute");
    assert_eq!(approved.approvals, 2);
    assert_eq!(client.get_creator(&uid).unwrap(), new_owner.clone());
    assert!(client.get_pending_ownership_transfer(&uid).is_none());
}

#[test]
fn duplicate_approval_from_same_owner_is_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    let new_owner = Address::generate(&env);
    client.propose_ownership_transfer(&uid, &creator, &new_owner);

    // The proposer already approved; approving again must not count twice.
    let res = client.try_approve_ownership_transfer(&uid, &creator);
    assert!(res.is_err(), "one owner can only approve once");
}

#[test]
fn non_owner_cannot_propose_or_approve() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    let stranger = Address::generate(&env);
    let target = Address::generate(&env);

    let propose = client.try_propose_ownership_transfer(&uid, &stranger, &target);
    assert!(propose.is_err(), "a non-owner cannot propose a transfer");

    let approve = client.try_approve_ownership_transfer(&uid, &stranger);
    assert!(approve.is_err(), "a non-owner cannot approve a transfer");
}

#[test]
fn single_signature_transfer_cannot_bypass_multisig_set() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    let target = Address::generate(&env);

    // Both single-signature entrypoints must refuse while the set requires
    // more than one approval.
    let legacy = client.try_transfer_schema_ownership(&uid, &target);
    assert!(legacy.is_err(), "transfer_schema_ownership must enforce the set");

    let sender = client.try_transfer_ownership(&creator, &uid, &target);
    assert!(sender.is_err(), "transfer_ownership must enforce the set");

    assert_eq!(
        client.get_creator(&uid).unwrap(),
        creator,
        "creator must be unchanged after the rejected attempts"
    );
}

#[test]
fn threshold_one_owner_set_keeps_single_signature_transfer_working() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let solo = Address::generate(&env);

    client.configure_owner_set(&uid, &creator, &owner_vec(&env, &[solo.clone()]), &1);

    let target = Address::generate(&env);
    client.transfer_schema_ownership(&uid, &target);
    assert_eq!(client.get_creator(&uid).unwrap(), target);
}

#[test]
fn propose_with_threshold_one_executes_immediately() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let solo = Address::generate(&env);

    client.configure_owner_set(&uid, &creator, &owner_vec(&env, &[solo.clone()]), &1);

    let target = Address::generate(&env);
    let status = client.propose_ownership_transfer(&uid, &solo, &target);

    assert!(status.executed, "a 1-of-1 set executes on proposal");
    assert_eq!(status.threshold, 1);
    assert_eq!(client.get_creator(&uid).unwrap(), target);
}

#[test]
fn propose_rejects_replacing_creator_with_itself() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    let res = client.try_propose_ownership_transfer(&uid, &creator, &creator);
    assert!(res.is_err(), "a no-op ownership transfer must be rejected");
}

#[test]
fn reconfiguring_owner_set_clears_in_flight_transfer() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    let target = Address::generate(&env);
    client.propose_ownership_transfer(&uid, &creator, &target);
    assert!(client.get_pending_ownership_transfer(&uid).is_some());

    // Approvals collected under version 1 must not be usable against the new
    // owner set, so the pending transfer is dropped outright.
    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    assert!(
        client.get_pending_ownership_transfer(&uid).is_none(),
        "reconfiguration must invalidate in-flight approvals"
    );
    assert_eq!(client.get_creator(&uid).unwrap(), creator);
}

#[test]
fn cancel_ownership_transfer_clears_pending_state() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    let target = Address::generate(&env);
    client.propose_ownership_transfer(&uid, &creator, &target);
    client.cancel_ownership_transfer(&uid, &second);

    assert!(client.get_pending_ownership_transfer(&uid).is_none());
    assert_eq!(client.get_creator(&uid).unwrap(), creator);
}

#[test]
fn cancel_ownership_transfer_rejects_non_owner() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    let target = Address::generate(&env);
    client.propose_ownership_transfer(&uid, &creator, &target);

    let stranger = Address::generate(&env);
    let res = client.try_cancel_ownership_transfer(&uid, &stranger);
    assert!(res.is_err(), "only owners may cancel a transfer");
    assert!(client.get_pending_ownership_transfer(&uid).is_some());
}

#[test]
fn owner_set_member_can_deprecate_schema() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    client.deprecate_schema(&second, &uid);
    assert!(client.get_schema(&uid).unwrap().deprecated);
}

#[test]
fn non_owner_cannot_deprecate_schema() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let creator = Address::generate(&env);
    let uid = register_schema(&env, &client, &creator);
    let second = Address::generate(&env);

    client.configure_owner_set(
        &uid,
        &creator,
        &owner_vec(&env, &[creator.clone(), second.clone()]),
        &2,
    );

    let stranger = Address::generate(&env);
    let res = client.try_deprecate_schema(&stranger, &uid);
    assert!(res.is_err(), "only owners may deprecate a schema");
}
