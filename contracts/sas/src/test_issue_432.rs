//! Tests for #432: expiration evaluation across read/verify paths, opt-in
//! pruning of expired records, and the ban on reviving expired attestations.

use crate::{SASClient, MAX_PRUNE_BATCH, SAS};
use soroban_sas_common::{Attestation, SASError, UID};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, vec, Address, Bytes, BytesN, Env};

#[contract]
struct MockRegistry;

#[contractimpl]
impl MockRegistry {
    pub fn on_attest(_env: Env, _attestation: Attestation) {}

    pub fn on_revoke(_env: Env, _attestation: Attestation) {}

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

struct Fixture {
    env: Env,
    client: SASClient<'static>,
    attester: Address,
    recipient: Address,
}

fn setup() -> Fixture {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = 5000);
    let registry_id = env.register_contract(None, MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let client = SASClient::new(&env, &sas_id);
    env.mock_all_auths();
    client.init(&Address::generate(&env), &registry_id);
    Fixture {
        attester: Address::generate(&env),
        recipient: Address::generate(&env),
        env,
        client,
    }
}

impl Fixture {
    fn issue(&self, expiration_time: u64, seed: u8) -> UID {
        let schema_uid = UID(BytesN::from_array(&self.env, &[2u8; 32]));
        let data = Bytes::from_array(&self.env, &[seed; 32]);
        let uid = soroban_sas_common::attestation_uid(
            &self.env,
            &schema_uid,
            &self.recipient,
            &self.attester,
            &data,
        );
        self.client.attest(&Attestation {
            uid: uid.clone(),
            schema_uid,
            time: 1000,
            expiration_time,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[0u8; 32])),
            recipient: self.recipient.clone(),
            attester: self.attester.clone(),
            revocable: true,
            data,
        });
        uid
    }

    fn set_time(&self, t: u64) {
        self.env.ledger().with_mut(|li| li.timestamp = t);
    }
}

#[test]
fn auto_prune_defaults_to_disabled_and_is_togglable() {
    let f = setup();
    assert!(!f.client.is_auto_prune_enabled());
    f.client.set_auto_prune(&true);
    assert!(f.client.is_auto_prune_enabled());
    f.client.set_auto_prune(&false);
    assert!(!f.client.is_auto_prune_enabled());
}

#[test]
fn prune_is_rejected_while_disabled() {
    let f = setup();
    let uid = f.issue(6000, 1);
    f.set_time(7000);
    let res = f.client.try_prune_expired(&vec![&f.env, uid.clone()]);
    assert_eq!(res, Err(Ok(SASError::AutoPruneDisabled.into())));
    assert!(f.client.get_attestation_view(&uid).is_some());
}

#[test]
fn expired_attestation_is_inactive_without_pruning_or_revocation() {
    let f = setup();
    let uid = f.issue(6000, 1);
    assert!(f.client.verify_attestation(&uid));
    f.set_time(6000);
    assert!(!f.client.verify_attestation(&uid));
    assert!(!f.client.verify_attestation_view(&uid));
    assert!(!f.client.verify_all_attestations(&vec![&f.env, uid.clone()]));
    let record = f.client.get_attestation_view(&uid).unwrap();
    assert_eq!(record.revocation_time, 0);
}

#[test]
fn prune_removes_only_expired_records() {
    let f = setup();
    f.client.set_auto_prune(&true);
    let expired = f.issue(6000, 1);
    let live = f.issue(100_000, 2);
    let perpetual = f.issue(0, 3);
    f.set_time(7000);

    let unknown = UID(BytesN::from_array(&f.env, &[77u8; 32]));
    let pruned = f.client.prune_expired(&vec![
        &f.env,
        expired.clone(),
        live.clone(),
        perpetual.clone(),
        unknown,
    ]);
    assert_eq!(pruned, 1);
    assert!(f.client.get_attestation_view(&expired).is_none());
    assert!(f.client.get_issuance_timestamp(&expired).is_none());
    assert!(f.client.verify_attestation_view(&live));
    assert!(f.client.verify_attestation_view(&perpetual));
}

#[test]
fn prune_is_idempotent() {
    let f = setup();
    f.client.set_auto_prune(&true);
    let uid = f.issue(6000, 1);
    f.set_time(7000);
    let batch = vec![&f.env, uid];
    assert_eq!(f.client.prune_expired(&batch), 1);
    assert_eq!(f.client.prune_expired(&batch), 0);
}

#[test]
fn prune_covers_expired_revoked_records() {
    let f = setup();
    f.client.set_auto_prune(&true);
    let uid = f.issue(6000, 1);
    f.client.revoke(&uid);
    f.set_time(7000);
    assert_eq!(f.client.prune_expired(&vec![&f.env, uid.clone()]), 1);
    assert!(f.client.get_attestation_view(&uid).is_none());
}

#[test]
fn prune_empty_batch_is_a_noop() {
    let f = setup();
    f.client.set_auto_prune(&true);
    assert_eq!(f.client.prune_expired(&vec![&f.env]), 0);
}

#[test]
fn prune_rejects_oversized_batch() {
    let f = setup();
    f.client.set_auto_prune(&true);
    let mut uids = vec![&f.env];
    for i in 0..=MAX_PRUNE_BATCH {
        let mut raw = [0u8; 32];
        raw[0] = i as u8;
        uids.push_back(UID(BytesN::from_array(&f.env, &raw)));
    }
    let res = f.client.try_prune_expired(&uids);
    assert_eq!(res, Err(Ok(SASError::BatchTooLarge.into())));
}

#[test]
fn expired_attestation_cannot_be_renewed() {
    let f = setup();
    let uid = f.issue(6000, 1);
    f.set_time(7000);
    let res = f.client.try_renew_attestation(&uid, &20_000);
    assert_eq!(res, Err(Ok(SASError::AlreadyExpired.into())));
    assert!(!f.client.verify_attestation_view(&uid));
}

#[test]
fn pruned_attestation_needs_fresh_attester_authorization_to_return() {
    let f = setup();
    f.client.set_auto_prune(&true);
    let uid = f.issue(6000, 1);
    f.set_time(7000);
    assert_eq!(f.client.prune_expired(&vec![&f.env, uid.clone()]), 1);
    // Re-issuing the same content with a future expiry goes through `attest`,
    // which requires the attester's authorization, and yields a live record.
    let again = f.issue(50_000, 1);
    assert_eq!(again, uid);
    assert!(f.client.verify_attestation(&uid));
}

#[test]
fn live_attestation_can_still_be_renewed() {
    let f = setup();
    let uid = f.issue(6000, 1);
    f.client.renew_attestation(&uid, &9000);
    f.set_time(7000);
    assert!(f.client.verify_attestation(&uid));
}
