//! Regression coverage for the `multi_attest` reentrancy guard (#296).
//!
//! `multi_attest` iterates a batch and, for every entry, hands control to
//! external callbacks (the schema resolver's `on_attest`, and the optional
//! indexer). The guard makes the batch's critical section explicit: while a
//! batch is running, a nested `multi_attest` is rejected with
//! `SASError::Reentrancy` instead of interleaving its storage writes.
//!
//! The Soroban host already refuses direct cross-contract re-entry with a
//! `Context`/`InvalidAction` error, so the guard cannot be reached by simply
//! calling back into the contract from a resolver. These tests therefore seed
//! the guard the way an in-flight batch would, and separately assert that the
//! guard does not disturb the legitimate resolver callback path.

use crate::{SASClient, REENTRANCY_GUARD, SAS};
use soroban_sas_common::{Attestation, SASError, UID};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env};

/// Registry whose schema resolves back to itself, so every attestation goes
/// through a real resolver callback. It counts the callbacks it receives.
#[contract]
struct MockRegistry;

#[contractimpl]
impl MockRegistry {
    pub fn on_attest(env: Env, _attestation: Attestation) {
        let seen: u32 = env
            .storage()
            .instance()
            .get(&symbol_short!("SEEN"))
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&symbol_short!("SEEN"), &(seen + 1));
    }

    pub fn attestations_seen(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&symbol_short!("SEEN"))
            .unwrap_or(0)
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
            uid,
            resolver: env.current_contract_address(),
            revocable: true,
            schema: soroban_sdk::String::from_str(&env, "bool valid"),
            deprecated: false,
        })
    }
}

fn fixture(env: &Env, attester: &Address, recipient: &Address, seed: [u8; 32]) -> Attestation {
    let schema_uid = UID(BytesN::from_array(env, &[2u8; 32]));
    let data = Bytes::from_array(env, &seed);
    let uid = soroban_sas_common::attestation_uid(env, &schema_uid, recipient, attester, &data);

    Attestation {
        uid,
        schema_uid,
        time: 0,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data,
    }
}

fn setup(env: &Env) -> (SASClient<'_>, Address, Address) {
    env.mock_all_auths();

    let registry_id = env.register_contract(None, MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let client = SASClient::new(env, &sas_id);
    let admin = Address::generate(env);
    client.init(&admin, &registry_id);

    (client, sas_id, registry_id)
}

/// True while the contract believes a batch is in flight.
fn guard_is_held(env: &Env, sas_id: &Address) -> bool {
    env.as_contract(sas_id, || env.storage().instance().has(&REENTRANCY_GUARD))
}

/// A nested `multi_attest` - the exact state an in-flight batch leaves behind -
/// is rejected with the typed error and issues nothing.
#[test]
fn multi_attest_reverts_with_reentrancy_when_the_guard_is_already_held() {
    let env = Env::default();
    let (client, sas_id, _registry_id) = setup(&env);

    env.as_contract(&sas_id, || {
        env.storage().instance().set(&REENTRANCY_GUARD, &true);
    });

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let attestation = fixture(&env, &attester, &recipient, [41u8; 32]);

    let outcome = client.try_multi_attest(&soroban_sdk::vec![&env, attestation.clone()]);
    assert_eq!(outcome, Err(Ok(SASError::Reentrancy.into())));

    env.as_contract(&sas_id, || {
        assert!(!env.storage().persistent().has(&attestation.uid));
    });
}

/// The guard is released on the success path, so later batches are unaffected.
#[test]
fn multi_attest_releases_the_guard_after_a_successful_batch() {
    let env = Env::default();
    let (client, sas_id, _registry_id) = setup(&env);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let first = fixture(&env, &attester, &recipient, [42u8; 32]);

    let uids = client.multi_attest(&soroban_sdk::vec![&env, first.clone()]);
    assert_eq!(uids.len(), 1);
    assert_eq!(uids.get(0).unwrap(), first.uid);
    assert!(
        !guard_is_held(&env, &sas_id),
        "the guard must be released once the batch returns"
    );

    // A second batch proves the guard was not left behind.
    let second = fixture(&env, &attester, &recipient, [43u8; 32]);
    let second_uids = client.multi_attest(&soroban_sdk::vec![&env, second.clone()]);
    assert_eq!(second_uids.len(), 1);
    assert_eq!(second_uids.get(0).unwrap(), second.uid);
    assert!(!guard_is_held(&env, &sas_id));
}

/// Regression: the guard must not swallow or skip the resolver callback that
/// every attestation in the batch is supposed to run.
#[test]
fn multi_attest_runs_the_resolver_for_every_attestation_in_the_batch() {
    let env = Env::default();
    let (client, sas_id, registry_id) = setup(&env);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let first = fixture(&env, &attester, &recipient, [44u8; 32]);
    let second = fixture(&env, &attester, &recipient, [45u8; 32]);

    let uids = client.multi_attest(&soroban_sdk::vec![&env, first.clone(), second.clone()]);
    assert_eq!(uids.len(), 2);

    assert_eq!(
        MockRegistryClient::new(&env, &registry_id).attestations_seen(),
        2,
        "the resolver callback must run once per attestation"
    );
    assert!(!guard_is_held(&env, &sas_id));
}
