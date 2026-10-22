//! Tests for ledger-verifiable timestamp anchors (#298).
//!
//! `Attestation.time` and `Attestation.revocation_time` are ledger close
//! times, but on their own they are unverifiable: a consumer has no way to
//! check them against the ledger that produced them. These tests cover the
//! anchors that fix that — the sequence number and close time recorded at
//! issuance and at revocation — and the `verify_timestamp` check a verifier
//! runs against a ledger header it already trusts.

use crate::timestamp::TimestampAnchor;
use crate::{SASClient, SAS};
use soroban_sas_common::{Attestation, SASError, UID};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env};

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
            schema: soroban_sdk::String::from_str(&env, "bool verified_human"),
            deprecated: false,
        })
    }
}

/// The ledger the harness issues on. Both halves of it matter: an anchor has
/// to pin a sequence *and* a close time, so every assertion below looks at a
/// ledger that differs from its neighbour in both fields.
const ISSUANCE_LEDGER: u32 = 1_000;
const ISSUANCE_TIME: u64 = 1_700_000_000;

/// The ledger revocations and replacements are moved to.
const REVOCATION_LEDGER: u32 = 2_000;
const REVOCATION_TIME: u64 = 1_700_000_500;

fn anchor(ledger_sequence: u32, ledger_timestamp: u64) -> TimestampAnchor {
    TimestampAnchor {
        ledger_sequence,
        ledger_timestamp,
    }
}

struct Harness {
    env: Env,
    client: SASClient<'static>,
    attester: Address,
    recipient: Address,
}

impl Harness {
    /// A deployed contract bound to a registry that accepts everything, with
    /// the ledger parked on the issuance sequence and close time.
    fn new() -> Self {
        let env = Env::default();
        env.ledger().with_mut(|li| {
            li.sequence_number = ISSUANCE_LEDGER;
            li.timestamp = ISSUANCE_TIME;
        });

        let registry_id = env.register_contract(None, MockRegistry);
        let sas_id = env.register_contract(None, SAS);
        let client = SASClient::new(&env, &sas_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.init(&admin, &registry_id);

        Self {
            attester: Address::generate(&env),
            recipient: Address::generate(&env),
            env,
            client,
        }
    }

    /// A correctly content-addressed attestation; `seed` gives each one its
    /// own UID so several can coexist in one test.
    fn attestation(&self, seed: u8, revocable: bool) -> Attestation {
        let schema_uid = UID(BytesN::from_array(&self.env, &[2u8; 32]));
        let data = Bytes::from_array(&self.env, &[seed; 32]);
        let uid = soroban_sas_common::attestation_uid(
            &self.env,
            &schema_uid,
            &self.recipient,
            &self.attester,
            &data,
        );
        Attestation {
            uid,
            schema_uid,
            time: 0, // the contract normalizes this to the ledger close time
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[0u8; 32])),
            recipient: self.recipient.clone(),
            attester: self.attester.clone(),
            revocable,
            data,
        }
    }

    fn issue(&self, seed: u8, revocable: bool) -> UID {
        let attestation = self.attestation(seed, revocable);
        let expected = attestation.uid.clone();
        let issued = self.client.attest(&attestation);
        assert_eq!(issued, expected, "attest returns the content-addressed UID");
        issued
    }

    /// Moves the ledger and revokes, so the revocation lands on a ledger that
    /// is distinguishable from the issuance ledger in both fields.
    fn revoke_at(&self, uid: &UID, sequence: u32, timestamp: u64) {
        self.env.ledger().with_mut(|li| {
            li.sequence_number = sequence;
            li.timestamp = timestamp;
        });
        self.client.revoke(uid);
    }

    fn move_to(&self, sequence: u32, timestamp: u64) {
        self.env.ledger().with_mut(|li| {
            li.sequence_number = sequence;
            li.timestamp = timestamp;
        });
    }
}

#[test]
fn issuance_anchor_records_the_ledger_that_issued_it() {
    let h = Harness::new();
    let uid = h.issue(1, true);

    let anchor = h
        .client
        .get_issuance_timestamp(&uid)
        .expect("an issued attestation is anchored");

    assert_eq!(anchor.ledger_sequence, ISSUANCE_LEDGER);
    assert_eq!(anchor.ledger_timestamp, ISSUANCE_TIME);

    // The anchor and the stored record have to agree for the record's own
    // `time` field to be checkable against a header.
    let record = h.client.get_attestation(&uid).unwrap();
    assert_eq!(record.time, anchor.ledger_timestamp);
}

#[test]
fn readers_and_verifier_answer_nothing_for_an_unknown_uid() {
    let h = Harness::new();
    let unknown = UID(BytesN::from_array(&h.env, &[9u8; 32]));

    assert!(h.client.get_issuance_timestamp(&unknown).is_none());
    assert!(h.client.get_revocation_timestamp(&unknown).is_none());
    assert!(!h
        .client
        .verify_timestamp(&unknown, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)));
}

#[test]
fn verify_timestamp_accepts_the_issuance_anchor() {
    let h = Harness::new();
    let uid = h.issue(2, true);

    assert!(h
        .client
        .verify_timestamp(&uid, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)));
}

#[test]
fn verify_timestamp_rejects_the_right_close_time_from_another_ledger() {
    let h = Harness::new();
    let uid = h.issue(3, true);

    // A real close time attached to the wrong sequence is exactly the claim a
    // forged anchor would make, so the sequence has to be part of the check.
    assert!(!h
        .client
        .verify_timestamp(&uid, &anchor(ISSUANCE_LEDGER + 1, ISSUANCE_TIME)));
}

#[test]
fn verify_timestamp_rejects_a_doctored_close_time() {
    let h = Harness::new();
    let uid = h.issue(4, true);

    assert!(!h
        .client
        .verify_timestamp(&uid, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME + 1)));
    assert!(!h
        .client
        .verify_timestamp(&uid, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME - 1)));
}

#[test]
fn revocation_anchor_records_the_ledger_that_revoked_it() {
    let h = Harness::new();
    let uid = h.issue(5, true);

    assert!(
        h.client.get_revocation_timestamp(&uid).is_none(),
        "a live attestation has no revocation anchor"
    );

    h.revoke_at(&uid, REVOCATION_LEDGER, REVOCATION_TIME);

    let revocation = h.client.get_revocation_timestamp(&uid).unwrap();
    assert_eq!(revocation.ledger_sequence, REVOCATION_LEDGER);
    assert_eq!(revocation.ledger_timestamp, REVOCATION_TIME);

    let record = h.client.get_attestation(&uid).unwrap();
    assert_eq!(record.revocation_time, revocation.ledger_timestamp);

    // The issuance anchor survives revocation untouched, so a verifier can
    // show the whole history rather than only the last transition.
    assert_eq!(
        h.client.get_issuance_timestamp(&uid).unwrap(),
        anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)
    );
}

#[test]
fn verify_timestamp_accepts_either_anchor_once_revoked() {
    let h = Harness::new();
    let uid = h.issue(6, true);
    h.revoke_at(&uid, REVOCATION_LEDGER, REVOCATION_TIME);

    assert!(h
        .client
        .verify_timestamp(&uid, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)));
    assert!(h
        .client
        .verify_timestamp(&uid, &anchor(REVOCATION_LEDGER, REVOCATION_TIME)));
    assert!(!h
        .client
        .verify_timestamp(&uid, &anchor(REVOCATION_LEDGER, REVOCATION_TIME + 1)));
}

#[test]
fn anchors_are_recorded_per_uid() {
    let h = Harness::new();
    let first = h.issue(7, true);

    h.move_to(REVOCATION_LEDGER, REVOCATION_TIME);
    let second = h.issue(8, true);

    assert_eq!(
        h.client.get_issuance_timestamp(&first).unwrap(),
        anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)
    );
    assert_eq!(
        h.client.get_issuance_timestamp(&second).unwrap(),
        anchor(REVOCATION_LEDGER, REVOCATION_TIME)
    );
    assert!(!h
        .client
        .verify_timestamp(&first, &anchor(REVOCATION_LEDGER, REVOCATION_TIME)));
}

#[test]
fn multi_attest_anchors_every_uid_to_the_ledger_that_ran_the_batch() {
    let h = Harness::new();

    let mut batch = soroban_sdk::Vec::new(&h.env);
    let mut uids = soroban_sdk::Vec::new(&h.env);
    for seed in [10u8, 11, 12] {
        let attestation = h.attestation(seed, true);
        uids.push_back(attestation.uid.clone());
        batch.push_back(attestation);
    }

    h.client.multi_attest(&batch);

    for uid in uids.iter() {
        assert_eq!(
            h.client.get_issuance_timestamp(&uid).unwrap(),
            anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)
        );
    }
}

#[test]
fn a_rejected_revocation_leaves_no_revocation_anchor() {
    let h = Harness::new();
    // A non-revocable attestation on a revocable schema is issued happily and
    // can never be revoked; a refusal must not be visible as an anchor, or a
    // failed call would leave a timestamp claiming a revocation happened.
    let uid = h.issue(13, false);

    let result = h.client.try_revoke(&uid);
    assert_eq!(result, Err(Ok(SASError::NotRevocable.into())));

    assert!(h.client.get_revocation_timestamp(&uid).is_none());
    assert!(h
        .client
        .verify_timestamp(&uid, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)));
}

#[test]
fn replace_attestation_anchors_both_transitions_of_the_same_call() {
    let h = Harness::new();
    let old = h.issue(14, true);

    h.move_to(REVOCATION_LEDGER, REVOCATION_TIME);
    let replacement = h.attestation(15, true);
    let new_uid = h.client.replace_attestation(&old, &replacement);

    assert_eq!(new_uid, replacement.uid);

    // One call, two anchors: the old record revoked at this ledger, the new
    // one issued at it.
    assert_eq!(
        h.client.get_revocation_timestamp(&old).unwrap(),
        anchor(REVOCATION_LEDGER, REVOCATION_TIME)
    );
    assert_eq!(
        h.client.get_issuance_timestamp(&old).unwrap(),
        anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)
    );
    assert_eq!(
        h.client.get_issuance_timestamp(&new_uid).unwrap(),
        anchor(REVOCATION_LEDGER, REVOCATION_TIME)
    );
    assert!(h.client.get_revocation_timestamp(&new_uid).is_none());
}

// ---------------------------------------------------------------------------
// Hardening against inconsistent simulated ledgers (#436)
// ---------------------------------------------------------------------------

#[test]
fn check_timestamp_accepts_both_recorded_anchors() {
    let h = Harness::new();
    let uid = h.issue(20, true);

    assert_eq!(
        h.client
            .try_check_timestamp(&uid, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)),
        Ok(Ok(()))
    );

    h.revoke_at(&uid, REVOCATION_LEDGER, REVOCATION_TIME);
    assert_eq!(
        h.client
            .try_check_timestamp(&uid, &anchor(REVOCATION_LEDGER, REVOCATION_TIME)),
        Ok(Ok(()))
    );
    assert_eq!(
        h.client
            .try_check_timestamp(&uid, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)),
        Ok(Ok(()))
    );
}

#[test]
fn check_timestamp_reports_a_doctored_close_time_as_invalid_timestamp() {
    let h = Harness::new();
    let uid = h.issue(21, true);

    // Earlier than the recorded close time, same sequence.
    assert_eq!(
        h.client
            .try_check_timestamp(&uid, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME - 1)),
        Err(Ok(SASError::InvalidTimestamp.into()))
    );
    // Later than the recorded close time (also ahead of this ledger).
    assert_eq!(
        h.client
            .try_check_timestamp(&uid, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME + 1)),
        Err(Ok(SASError::InvalidTimestamp.into()))
    );
}

#[test]
fn check_timestamp_reports_a_foreign_ledger_sequence_as_invalid_timestamp() {
    let h = Harness::new();
    let uid = h.issue(22, true);
    h.move_to(REVOCATION_LEDGER, REVOCATION_TIME);

    // The right close time attached to a ledger that was not the issuer.
    assert_eq!(
        h.client
            .try_check_timestamp(&uid, &anchor(ISSUANCE_LEDGER - 1, ISSUANCE_TIME)),
        Err(Ok(SASError::InvalidTimestamp.into()))
    );
    assert_eq!(
        h.client
            .try_check_timestamp(&uid, &anchor(ISSUANCE_LEDGER + 1, ISSUANCE_TIME)),
        Err(Ok(SASError::InvalidTimestamp.into()))
    );
    // A ledger that exists but never touched this uid.
    assert_eq!(
        h.client
            .try_check_timestamp(&uid, &anchor(REVOCATION_LEDGER, REVOCATION_TIME)),
        Err(Ok(SASError::InvalidTimestamp.into()))
    );
}

#[test]
fn a_revocation_cannot_borrow_the_issuance_sequence_or_time() {
    let h = Harness::new();
    let uid = h.issue(23, true);
    h.revoke_at(&uid, REVOCATION_LEDGER, REVOCATION_TIME);

    // Mixed halves of the two real anchors are not an anchor.
    for claim in [
        anchor(ISSUANCE_LEDGER, REVOCATION_TIME),
        anchor(REVOCATION_LEDGER, ISSUANCE_TIME),
    ] {
        assert_eq!(
            h.client.try_check_timestamp(&uid, &claim),
            Err(Ok(SASError::InvalidTimestamp.into()))
        );
        assert!(!h.client.verify_timestamp(&uid, &claim));
    }
}

#[test]
fn a_claim_from_a_ledger_that_has_not_closed_yet_is_rejected() {
    let h = Harness::new();
    let uid = h.issue(24, true);
    let genuine = anchor(ISSUANCE_LEDGER, ISSUANCE_TIME);
    assert!(h.client.verify_timestamp(&uid, &genuine));

    // A simulation running behind the network: the contract is executing on
    // a ledger that predates the recorded anchor. The anchor is real, but a
    // verdict computed here would be a verdict about the future.
    h.move_to(ISSUANCE_LEDGER - 10, ISSUANCE_TIME - 50);
    assert_eq!(
        h.client.try_check_timestamp(&uid, &genuine),
        Err(Ok(SASError::InvalidTimestamp.into()))
    );
    assert!(!h.client.verify_timestamp(&uid, &genuine));

    // Back on a consistent ledger the same claim verifies again.
    h.move_to(ISSUANCE_LEDGER, ISSUANCE_TIME);
    assert!(h.client.verify_timestamp(&uid, &genuine));
}

#[test]
fn check_timestamp_distinguishes_a_missing_anchor_from_a_bad_claim() {
    let h = Harness::new();
    let unknown = UID(BytesN::from_array(&h.env, &[9u8; 32]));

    assert_eq!(
        h.client
            .try_check_timestamp(&unknown, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)),
        Err(Ok(SASError::TimestampAnchorNotFound.into()))
    );
    assert!(!h
        .client
        .verify_timestamp(&unknown, &anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)));
}

#[test]
fn stored_anchors_that_run_backwards_fail_closed() {
    let h = Harness::new();
    let uid = h.issue(25, true);
    h.revoke_at(&uid, REVOCATION_LEDGER, REVOCATION_TIME);

    // Forge the state a mismatched simulated ledger could have produced: a
    // revocation anchor from before the issuance ledger.
    let corrupt = anchor(ISSUANCE_LEDGER - 1, ISSUANCE_TIME - 1);
    h.env.as_contract(&h.client.address, || {
        h.env.storage().persistent().set(
            &crate::timestamp::TimestampAnchorKey {
                uid: uid.clone(),
                revocation: true,
            },
            &corrupt,
        );
    });

    // Neither anchor is trusted any more, including the genuine issuance one.
    for claim in [anchor(ISSUANCE_LEDGER, ISSUANCE_TIME), corrupt.clone()] {
        assert_eq!(
            h.client.try_check_timestamp(&uid, &claim),
            Err(Ok(SASError::InvalidTimestamp.into()))
        );
        assert!(!h.client.verify_timestamp(&uid, &claim));
    }
}

#[test]
fn verify_timestamp_stays_a_boolean_and_agrees_with_check_timestamp() {
    let h = Harness::new();
    let uid = h.issue(26, true);

    for claim in [
        anchor(ISSUANCE_LEDGER, ISSUANCE_TIME),
        anchor(ISSUANCE_LEDGER, ISSUANCE_TIME - 1),
        anchor(ISSUANCE_LEDGER + 1, ISSUANCE_TIME),
        anchor(0, 0),
    ] {
        let strict = h.client.try_check_timestamp(&uid, &claim).is_ok();
        assert_eq!(h.client.verify_timestamp(&uid, &claim), strict);
    }
}

#[test]
#[should_panic(expected = "Error(Contract, #420)")]
fn an_issuance_anchor_cannot_be_rewritten() {
    let h = Harness::new();
    let uid = h.issue(27, true);
    h.move_to(REVOCATION_LEDGER, REVOCATION_TIME);

    h.env.as_contract(&h.client.address, || {
        crate::timestamp::write_anchor(&h.env, &uid, false, 1_000);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #420)")]
fn a_revocation_anchor_cannot_be_rewritten() {
    let h = Harness::new();
    let uid = h.issue(28, true);
    h.revoke_at(&uid, REVOCATION_LEDGER, REVOCATION_TIME);

    h.env.as_contract(&h.client.address, || {
        crate::timestamp::write_anchor(&h.env, &uid, true, 1_000);
    });
}

#[test]
fn rejected_reissue_and_rerevoke_leave_the_anchors_untouched() {
    let h = Harness::new();
    let attestation = h.attestation(29, true);
    let uid = h.client.attest(&attestation);

    h.move_to(REVOCATION_LEDGER, REVOCATION_TIME);
    assert_eq!(
        h.client.try_attest(&attestation),
        Err(Ok(SASError::DuplicateAttestation.into()))
    );
    assert_eq!(
        h.client.get_issuance_timestamp(&uid).unwrap(),
        anchor(ISSUANCE_LEDGER, ISSUANCE_TIME)
    );

    h.client.revoke(&uid);
    h.move_to(REVOCATION_LEDGER + 500, REVOCATION_TIME + 500);
    assert_eq!(
        h.client.try_revoke(&uid),
        Err(Ok(SASError::AlreadyRevoked.into()))
    );
    assert_eq!(
        h.client.get_revocation_timestamp(&uid).unwrap(),
        anchor(REVOCATION_LEDGER, REVOCATION_TIME)
    );
}
