//! Regression tests for #297: batch attestation verification.
//!
//! The batch entrypoints must return exactly what repeated single-UID
//! `verify_attestation` calls would return, including for missing, revoked and
//! expired UIDs, and must reject oversized batches up front instead of
//! silently truncating them.

use crate::{SASClient, SAS, MAX_VERIFY_BATCH};
use soroban_sas_common::{Attestation, UID};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Vec};

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

const LEDGER_TIME: u64 = 5_000;

struct Fixture {
    env: Env,
    sas_client: SASClient<'static>,
    schema_uid: UID,
    attester: Address,
    recipient: Address,
}

fn setup() -> Fixture {
    let env = Env::default();
    env.ledger().with_mut(|li| li.timestamp = LEDGER_TIME);

    let registry_id = env.register_contract(None, MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    Fixture {
        schema_uid: UID(BytesN::from_array(&env, &[2u8; 32])),
        attester: Address::generate(&env),
        recipient: Address::generate(&env),
        env,
        sas_client,
    }
}

impl Fixture {
    /// Issues one attestation with a distinct `data` seed (so each gets its own
    /// UID) and the given expiration time.
    fn issue(&self, expiration_time: u64, seed: u8) -> UID {
        let data = Bytes::from_array(&self.env, &[seed; 32]);
        let uid = soroban_sas_common::attestation_uid(
            &self.env,
            &self.schema_uid,
            &self.recipient,
            &self.attester,
            &data,
        );

        self.sas_client.attest(&Attestation {
            uid: uid.clone(),
            schema_uid: self.schema_uid.clone(),
            time: LEDGER_TIME - 1_000,
            expiration_time,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[0u8; 32])),
            recipient: self.recipient.clone(),
            attester: self.attester.clone(),
            revocable: true,
            data,
        });

        uid
    }

    fn never_issued(&self, seed: u8) -> UID {
        UID(BytesN::from_array(&self.env, &[seed; 32]))
    }

    fn uids(&self, uids: &[UID]) -> Vec<UID> {
        let mut vec = Vec::new(&self.env);
        for uid in uids.iter() {
            vec.push_back(uid.clone());
        }
        vec
    }

    /// Advances the ledger past `expiration_time` of the fixtures issued with
    /// the default expiration.
    fn advance_past(&self, expiration_time: u64) {
        self.env
            .ledger()
            .with_mut(|li| li.timestamp = expiration_time + 1);
    }
}

#[test]
fn batch_verify_matches_single_uid_verdicts() {
    let f = setup();
    let live = f.issue(0, 1);
    let revoked = f.issue(0, 2);
    let missing = f.never_issued(9);

    f.sas_client.revoke(&revoked);

    let batch = f.uids(&[live.clone(), revoked.clone(), missing.clone()]);
    let results = f.sas_client.verify_attestations(&batch);

    assert_eq!(results.len(), 3);
    assert_eq!(results.get(0), Some(true));
    assert_eq!(results.get(1), Some(false));
    assert_eq!(results.get(2), Some(false));

    // The batch verdict must equal the single-call verdict for every UID.
    for (uid, expected) in [
        (live.clone(), true),
        (revoked.clone(), false),
        (missing.clone(), false),
    ] {
        assert_eq!(f.sas_client.verify_attestation(&uid), expected);
    }
}

#[test]
fn batch_verify_preserves_order_and_allows_duplicates() {
    let f = setup();
    let revoked = f.issue(0, 3);
    let live = f.issue(0, 4);
    f.sas_client.revoke(&revoked);

    // Interleaved duplicates: each entry is verified independently, so callers
    // keep a stable index -> verdict mapping.
    let batch = f.uids(&[
        live.clone(),
        revoked.clone(),
        live.clone(),
        revoked.clone(),
        live.clone(),
    ]);
    let results = f.sas_client.verify_attestations(&batch);

    assert_eq!(results.len(), 5);
    assert_eq!(results.get(0), Some(true));
    assert_eq!(results.get(1), Some(false));
    assert_eq!(results.get(2), Some(true));
    assert_eq!(results.get(3), Some(false));
    assert_eq!(results.get(4), Some(true));
}

#[test]
fn batch_verify_reports_expired_attestation_as_false() {
    let f = setup();
    let expiring = f.issue(LEDGER_TIME + 500, 5);
    let batch = f.uids(&[expiring.clone()]);

    assert_eq!(f.sas_client.verify_attestations(&batch).get(0), Some(true));

    f.advance_past(LEDGER_TIME + 500);

    assert_eq!(
        f.sas_client.verify_attestations(&batch).get(0),
        Some(false),
        "an attestation past its expiration must fail verification"
    );
    assert!(!f.sas_client.verify_attestation(&expiring));
}

#[test]
fn verify_all_requires_every_uid_to_verify() {
    let f = setup();
    let live = f.issue(0, 6);
    let other_live = f.issue(0, 7);
    let revoked = f.issue(0, 8);
    f.sas_client.revoke(&revoked);

    assert!(f
        .sas_client
        .verify_all_attestations(&f.uids(&[live.clone(), other_live.clone()])));

    assert!(!f.sas_client.verify_all_attestations(&f.uids(&[
        live.clone(),
        revoked.clone()
    ])));

    assert!(!f
        .sas_client
        .verify_all_attestations(&f.uids(&[f.never_issued(10)])));
}

#[test]
fn verify_all_of_empty_batch_is_true() {
    let f = setup();
    let empty: Vec<UID> = Vec::new(&f.env);

    assert!(
        f.sas_client.verify_all_attestations(&empty),
        "an empty batch is vacuously valid"
    );
    assert_eq!(f.sas_client.verify_attestations(&empty).len(), 0);
}

#[test]
fn batch_verify_rejects_oversized_batch() {
    let f = setup();

    let mut oversized: Vec<UID> = Vec::new(&f.env);
    let mut index = 0;
    while index <= MAX_VERIFY_BATCH {
        oversized.push_back(UID(BytesN::from_array(&f.env, &[index as u8; 32])));
        index += 1;
    }

    assert!(f.sas_client.try_verify_attestations(&oversized).is_err());
    assert!(f.sas_client.try_verify_all_attestations(&oversized).is_err());
}

#[test]
fn batch_verify_accepts_exactly_max_batch() {
    let f = setup();

    let mut at_limit: Vec<UID> = Vec::new(&f.env);
    let mut index = 0;
    while index < MAX_VERIFY_BATCH {
        at_limit.push_back(f.issue(0, index as u8));
        index += 1;
    }

    let results = f.sas_client.verify_attestations(&at_limit);
    assert_eq!(results.len(), MAX_VERIFY_BATCH);

    let mut checked = 0;
    for verdict in results.iter() {
        assert!(verdict);
        checked += 1;
    }
    assert_eq!(checked, MAX_VERIFY_BATCH);
    assert!(f.sas_client.verify_all_attestations(&at_limit));
}
