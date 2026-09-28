//! SAS -> Indexer integration tests (#309).
//!
//! Unlike the rest of this crate's tests, which stand in for the Indexer
//! with `MockIndexer`/`TrappingIndexer`, these deploy the *real*
//! `schema-registry`, `sas`, and `soroban-sas-indexer` contracts into one
//! host and drive them only through their public entry points. Every
//! assertion about indexed data is cross-checked against what SAS itself
//! stored and emitted, so a divergence between the protocol's source of
//! truth and its mirror fails here rather than in production.
//!
//! Each test builds its own `Env`, so setup and teardown are deterministic
//! and no state leaks between tests.

use crate::{SASClient, SAS};
use schema_registry::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::{events::ATTESTED, Attestation, AttestationIssuedEvent, SASError, UID};
use soroban_sas_indexer::{Indexer, IndexerClient};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{
    contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env, IntoVal,
    String as SorobanString, TryFromVal, Val,
};

extern crate std;
use std::vec::Vec as StdVec;

/// A resolver that accepts every attestation and revocation, so these
/// tests exercise the SAS/Indexer boundary rather than resolver policy.
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

/// Registry + SAS + Indexer deployed and bound together exactly as an
/// operator would: `Indexer::init(admin, sas)` then `SAS::set_indexer`.
struct Deployment {
    env: Env,
    sas_id: Address,
    sas: SASClient<'static>,
    indexer_id: Address,
    indexer: IndexerClient<'static>,
    registry: SchemaRegistryClient<'static>,
    admin: Address,
    resolver_id: Address,
    /// Owns `schema_uid`, so it may attest under it without delegation.
    attester: Address,
    schema_uid: UID,
}

fn deploy() -> Deployment {
    let env = Env::default();
    env.mock_all_auths();
    // Each SAS call is its own transaction on-chain with its own budget;
    // the test host accumulates every call into one.
    env.budget().reset_unlimited();
    // A fresh Env starts at timestamp 0, which would make a revocation's
    // `revocation_time` indistinguishable from "never revoked".
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

    let resolver_id = env.register_contract(None, accept_all_resolver::AcceptAllResolver);
    let attester = Address::generate(&env);
    let schema_uid = registry.register(
        &attester,
        &SorobanString::from_str(&env, "bool verified"),
        &resolver_id,
        &true,
    );

    Deployment {
        env,
        sas_id,
        sas,
        indexer_id,
        indexer,
        registry,
        admin,
        resolver_id,
        attester,
        schema_uid,
    }
}

impl Deployment {
    /// A correctly content-addressed, revocable attestation from
    /// `attester` to `recipient`; `seed` makes the UID unique.
    fn attestation(&self, attester: &Address, recipient: &Address, seed: u32) -> Attestation {
        let data = Bytes::from_array(&self.env, &seed.to_be_bytes());
        Attestation {
            uid: soroban_sas_common::attestation_uid(
                &self.env,
                &self.schema_uid,
                recipient,
                attester,
                &data,
            ),
            schema_uid: self.schema_uid.clone(),
            time: 0,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[0u8; 32])),
            recipient: recipient.clone(),
            attester: attester.clone(),
            revocable: true,
            data,
        }
    }

    /// Registers a second real Indexer bound to this SAS, without making it
    /// the active one.
    fn second_indexer(&self) -> (Address, IndexerClient<'static>) {
        let id = self.env.register_contract(None, Indexer);
        let client = IndexerClient::new(&self.env, &id);
        client.init(&self.admin, &self.sas_id);
        (id, client)
    }

    /// `AttestationIssued` payloads SAS emitted during the most recent
    /// top-level invocation, in emission order.
    fn issued_events(&self) -> StdVec<AttestationIssuedEvent> {
        let attested: Val = ATTESTED.into_val(&self.env);
        self.env
            .events()
            .all()
            .iter()
            .filter(|(contract, topics, _)| {
                contract == &self.sas_id
                    && topics
                        .get(0)
                        .is_some_and(|topic| topic.shallow_eq(&attested))
            })
            .map(|(_, _, data)| AttestationIssuedEvent::try_from_val(&self.env, &data).unwrap())
            .collect()
    }

    /// Whether SAS emitted `IndexFailed(uid)` in the most recent invocation.
    fn index_failed_emitted(&self, uid: &UID) -> bool {
        let topics: soroban_sdk::Vec<Val> =
            (symbol_short!("IDXFAIL"), uid.clone()).into_val(&self.env);
        self.env.events().all().contains((
            self.sas_id.clone(),
            topics,
            uid.clone().into_val(&self.env),
        ))
    }

    /// Asserts the bound indexer's view of `uid` agrees with SAS storage.
    fn assert_mirrors_sas(&self, uid: &UID) {
        self.assert_mirrors_sas_in(&self.indexer, uid);
    }

    /// Asserts `indexer`'s view of `uid` agrees with what SAS stored: the
    /// UID is listed under the stored recipient, schema, and attester.
    fn assert_mirrors_sas_in(&self, indexer: &IndexerClient, uid: &UID) {
        let stored = self
            .sas
            .get_attestation(uid)
            .expect("indexed UID must exist in SAS storage");
        assert!(indexer
            .get_attestations_by_recipient(&stored.recipient)
            .contains(uid));
        assert!(indexer
            .get_attestations_by_schema(&stored.schema_uid)
            .contains(uid));
        assert!(indexer
            .get_attestations_by_attester(&stored.attester)
            .contains(uid));
    }
}

fn to_std(uids: soroban_sdk::Vec<UID>) -> StdVec<UID> {
    uids.iter().collect()
}

/// Every page of `page(cursor, limit)`, concatenated, walking by
/// `cursor + page.len()` until an empty page.
fn walk_pages(page_size: u32, page: impl Fn(u32, u32) -> soroban_sdk::Vec<UID>) -> StdVec<UID> {
    let mut cursor = 0u32;
    let mut walked = StdVec::new();
    loop {
        let current = page(cursor, page_size);
        if current.is_empty() {
            return walked;
        }
        assert!(current.len() <= page_size);
        cursor += current.len();
        walked.extend(current.iter());
    }
}

// ---------------------------------------------------------------------------
// Issuance -> ingestion -> retrieval
// ---------------------------------------------------------------------------

#[test]
fn attest_is_indexed_under_recipient_schema_and_attester_matching_sas_state() {
    let d = deploy();
    let recipient = Address::generate(&d.env);
    let attestation = d.attestation(&d.attester, &recipient, 1);

    let uid = d.sas.attest(&attestation);
    assert_eq!(uid, attestation.uid);

    // The event SAS emitted is the same record the indexer ingested.
    assert_eq!(
        d.issued_events(),
        std::vec![AttestationIssuedEvent {
            uid: uid.clone(),
            schema_uid: d.schema_uid.clone(),
            attester: d.attester.clone(),
            recipient: recipient.clone(),
        }]
    );
    assert!(!d.index_failed_emitted(&uid));

    // Retrieval by every dimension returns exactly this UID...
    let only = soroban_sdk::vec![&d.env, uid.clone()];
    assert_eq!(d.indexer.get_attestations_by_recipient(&recipient), only);
    assert_eq!(d.indexer.get_attestations_by_schema(&d.schema_uid), only);
    assert_eq!(d.indexer.get_attestations_by_attester(&d.attester), only);
    assert_eq!(d.indexer.get_count_by_recipient(&recipient), 1);
    assert_eq!(d.indexer.get_count_by_schema(&d.schema_uid), 1);
    assert_eq!(d.indexer.get_count_by_attester(&d.attester), 1);

    // ...and resolves back to the attestation SAS stored.
    d.assert_mirrors_sas(&uid);
    let stored = d.sas.get_attestation(&uid).unwrap();
    assert_eq!(stored.recipient, recipient);
    assert_eq!(stored.time, 1_000, "issuance time is the ledger time");
    assert!(d.sas.verify_attestation(&uid));
}

#[test]
fn indexing_is_authorized_by_the_bound_sas_alone() {
    let d = deploy();
    let recipient = Address::generate(&d.env);
    let attestation = d.attestation(&d.attester, &recipient, 2);

    // Only the attester's own authorization is supplied. The indexer's
    // `sas.require_auth()` must be satisfied by SAS being the direct
    // caller, not by any mocked signature.
    d.env.mock_auths(&[MockAuth {
        address: &d.attester,
        invoke: &MockAuthInvoke {
            contract: &d.sas_id,
            fn_name: "attest",
            args: (attestation.clone(),).into_val(&d.env),
            sub_invokes: &[],
        },
    }]);
    let uid = d.sas.attest(&attestation);
    assert_eq!(d.indexer.get_count_by_recipient(&recipient), 1);
    d.assert_mirrors_sas(&uid);

    // With no authorization at all, a direct write that tries to poison
    // the index is rejected, and nothing is recorded.
    d.env.set_auths(&[]);
    let forged = UID(BytesN::from_array(&d.env, &[0xABu8; 32]));
    assert!(d
        .indexer
        .try_index_attestation(&forged, &recipient, &d.schema_uid, &d.attester)
        .is_err());
    assert_eq!(d.indexer.get_count_by_recipient(&recipient), 1);
}

#[test]
fn multi_attest_preserves_issuance_order_in_every_index() {
    let d = deploy();
    let alice = Address::generate(&d.env);
    let bob = Address::generate(&d.env);
    let recipients = [&alice, &bob, &alice, &alice, &bob];

    let mut batch = soroban_sdk::Vec::new(&d.env);
    for (seed, recipient) in recipients.iter().enumerate() {
        batch.push_back(d.attestation(&d.attester, recipient, 100 + seed as u32));
    }
    let uids = d.sas.multi_attest(&batch);

    // Emission order == returned order == schema/attester index order.
    let emitted: StdVec<UID> = d.issued_events().into_iter().map(|e| e.uid).collect();
    assert_eq!(emitted, to_std(uids.clone()));
    assert_eq!(
        to_std(d.indexer.get_attestations_by_schema(&d.schema_uid)),
        emitted
    );
    assert_eq!(
        to_std(d.indexer.get_attestations_by_attester(&d.attester)),
        emitted
    );

    // Each recipient's index is the in-order subsequence addressed to it,
    // with no cross-recipient leakage.
    let for_recipient = |who: &Address| -> StdVec<UID> {
        recipients
            .iter()
            .zip(emitted.iter())
            .filter(|(r, _)| **r == who)
            .map(|(_, uid)| uid.clone())
            .collect()
    };
    assert_eq!(
        to_std(d.indexer.get_attestations_by_recipient(&alice)),
        for_recipient(&alice)
    );
    assert_eq!(
        to_std(d.indexer.get_attestations_by_recipient(&bob)),
        for_recipient(&bob)
    );
    for uid in emitted.iter() {
        d.assert_mirrors_sas(uid);
    }
}

#[test]
fn delegated_attesters_are_indexed_under_their_own_address() {
    let d = deploy();
    let delegate = Address::generate(&d.env);
    d.registry.add_delegate(&d.schema_uid, &delegate);
    let recipient = Address::generate(&d.env);

    let by_owner = d.sas.attest(&d.attestation(&d.attester, &recipient, 3));
    let by_delegate = d.sas.attest(&d.attestation(&delegate, &recipient, 4));

    assert_eq!(
        d.indexer.get_attestations_by_attester(&delegate),
        soroban_sdk::vec![&d.env, by_delegate.clone()]
    );
    assert_eq!(
        d.indexer.get_attestations_by_attester(&d.attester),
        soroban_sdk::vec![&d.env, by_owner.clone()]
    );
    assert_eq!(
        d.indexer.get_attestations_by_recipient(&recipient),
        soroban_sdk::vec![&d.env, by_owner, by_delegate]
    );
}

// ---------------------------------------------------------------------------
// Public attestations and missing recipients (#304)
// ---------------------------------------------------------------------------

#[test]
fn missing_recipient_is_rejected_before_anything_is_indexed() {
    let d = deploy();
    let zero_account = Address::from_string(&SorobanString::from_str(
        &d.env,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    ));
    let zero_contract = Address::from_string(&SorobanString::from_str(
        &d.env,
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    ));

    // "No recipient" sentinels and self-attestation are all the same typed
    // `InvalidRecipient` failure — not a trap, and not an IndexFailed.
    for (seed, recipient) in [
        zero_account.clone(),
        zero_contract.clone(),
        d.attester.clone(),
    ]
    .iter()
    .enumerate()
    {
        let attestation = d.attestation(&d.attester, recipient, 10 + seed as u32);
        assert_eq!(
            d.sas.try_attest(&attestation),
            Err(Ok(SASError::InvalidRecipient.into()))
        );
        assert_eq!(d.sas.get_attestation(&attestation.uid), None);
    }

    // Nothing reached the indexer on any dimension, so the mirror did not
    // diverge from SAS.
    assert_eq!(d.indexer.get_count_by_schema(&d.schema_uid), 0);
    assert_eq!(d.indexer.get_count_by_attester(&d.attester), 0);
    assert!(d
        .indexer
        .get_attestations_by_recipient(&zero_account)
        .is_empty());
    assert!(d
        .indexer
        .get_attestations_by_recipient(&zero_contract)
        .is_empty());

    // A batch containing one recipient-less entry is rejected atomically:
    // its valid siblings are not indexed either.
    let recipient = Address::generate(&d.env);
    let batch = soroban_sdk::vec![
        &d.env,
        d.attestation(&d.attester, &recipient, 20),
        d.attestation(&d.attester, &zero_account, 21),
    ];
    assert_eq!(
        d.sas.try_multi_attest(&batch),
        Err(Ok(SASError::InvalidRecipient.into()))
    );
    assert_eq!(d.indexer.get_count_by_recipient(&recipient), 0);

    // Regression: a concrete recipient is still issued and indexed.
    let uid = d.sas.attest(&d.attestation(&d.attester, &recipient, 22));
    assert_eq!(d.indexer.get_count_by_recipient(&recipient), 1);
    d.assert_mirrors_sas(&uid);
}

#[test]
fn contract_recipients_are_indexed_like_account_recipients() {
    let d = deploy();
    // A contract (e.g. a DAO or vault) as the subject of a public claim.
    let contract_recipient = d.resolver_id.clone();
    let account_recipient = Address::from_string(&SorobanString::from_str(
        &d.env,
        &stellar_strkey::ed25519::PublicKey([7u8; 32]).to_string(),
    ));

    let to_contract = d
        .sas
        .attest(&d.attestation(&d.attester, &contract_recipient, 30));
    let to_account = d
        .sas
        .attest(&d.attestation(&d.attester, &account_recipient, 31));

    assert_eq!(
        d.indexer.get_attestations_by_recipient(&contract_recipient),
        soroban_sdk::vec![&d.env, to_contract.clone()]
    );
    assert_eq!(
        d.indexer.get_attestations_by_recipient(&account_recipient),
        soroban_sdk::vec![&d.env, to_account.clone()]
    );
    d.assert_mirrors_sas(&to_contract);
    d.assert_mirrors_sas(&to_account);
}

// ---------------------------------------------------------------------------
// Lifecycle updates after issuance
// ---------------------------------------------------------------------------

#[test]
fn revocation_keeps_indexed_history_and_sas_stays_authoritative() {
    let d = deploy();
    let recipient = Address::generate(&d.env);
    let uid = d.sas.attest(&d.attestation(&d.attester, &recipient, 40));

    d.env.ledger().with_mut(|li| li.timestamp = 2_000);
    d.sas.revoke(&uid);

    // SAS reflects the revocation...
    assert!(!d.sas.verify_attestation(&uid));
    assert_eq!(d.sas.get_attestation(&uid).unwrap().revocation_time, 2_000);
    // ...and the append-only history still lists the UID: revocation never
    // deletes or reorders indexed entries.
    assert_eq!(
        d.indexer.get_attestations_by_recipient(&recipient),
        soroban_sdk::vec![&d.env, uid.clone()]
    );
    assert_eq!(d.indexer.get_count_by_recipient(&recipient), 1);
}

#[test]
fn replacement_is_appended_after_the_original_under_the_same_keys() {
    let d = deploy();
    let recipient = Address::generate(&d.env);
    let old_uid = d.sas.attest(&d.attestation(&d.attester, &recipient, 50));

    d.env.ledger().with_mut(|li| li.timestamp = 2_000);
    let replacement = d.attestation(&d.attester, &recipient, 51);
    let new_uid = d.sas.replace_attestation(&old_uid, &replacement);

    assert_eq!(d.sas.get_attestation(&new_uid).unwrap().ref_uid, old_uid);
    assert!(!d.sas.verify_attestation(&old_uid));
    assert!(d.sas.verify_attestation(&new_uid));
    let history = soroban_sdk::vec![&d.env, old_uid, new_uid.clone()];
    assert_eq!(d.indexer.get_attestations_by_recipient(&recipient), history);
    assert_eq!(d.indexer.get_attestations_by_schema(&d.schema_uid), history);
    d.assert_mirrors_sas(&new_uid);
}

// ---------------------------------------------------------------------------
// Failure modes that could make the mirror diverge, and their recovery
// ---------------------------------------------------------------------------

#[test]
fn fail_open_outage_is_reported_and_reindex_restores_parity_idempotently() {
    let d = deploy();
    // A real indexer that was deployed but never bound to SAS: every
    // `index_attestation` into it is rejected.
    let unbound_id = d.env.register_contract(None, Indexer);
    let unbound = IndexerClient::new(&d.env, &unbound_id);
    d.sas.set_indexer(&unbound_id);

    let recipient = Address::generate(&d.env);
    let uid = d.sas.attest(&d.attestation(&d.attester, &recipient, 60));

    // Issuance succeeded (fail-open), the gap is observable, and the mirror
    // is known to be behind. (Events are read first: they are captured per
    // top-level invocation.)
    assert!(d.index_failed_emitted(&uid));
    assert!(d.sas.verify_attestation(&uid));
    assert_eq!(unbound.get_count_by_recipient(&recipient), 0);

    // Operator repairs the indexer binding and replays the missed UID.
    unbound.init(&d.admin, &d.sas_id);
    d.sas.reindex_attestation(&uid);
    assert_eq!(
        unbound.get_attestations_by_recipient(&recipient),
        soroban_sdk::vec![&d.env, uid.clone()]
    );

    // Replaying again is a no-op: no duplicate history or inflated counts.
    d.sas.reindex_attestation(&uid);
    assert_eq!(unbound.get_count_by_recipient(&recipient), 1);
    assert_eq!(unbound.get_count_by_schema(&d.schema_uid), 1);
    assert_eq!(unbound.get_count_by_attester(&d.attester), 1);
}

#[test]
fn strict_mode_rolls_back_issuance_instead_of_diverging() {
    let d = deploy();
    let unbound_id = d.env.register_contract(None, Indexer);
    d.sas.set_indexer(&unbound_id);
    d.sas.set_indexer_strict(&true);

    let recipient = Address::generate(&d.env);
    let attestation = d.attestation(&d.attester, &recipient, 70);
    assert_eq!(
        d.sas.try_attest(&attestation),
        Err(Ok(SASError::IndexerUnavailable.into()))
    );
    // Neither side recorded anything: SAS and its mirror agree.
    assert_eq!(d.sas.get_attestation(&attestation.uid), None);
    assert_eq!(d.indexer.get_count_by_recipient(&recipient), 0);
}

#[test]
fn rebinding_the_indexer_is_forward_only_until_reconciled() {
    let d = deploy();
    let recipient = Address::generate(&d.env);
    let before = d.sas.attest(&d.attestation(&d.attester, &recipient, 80));

    let (next_id, next) = d.second_indexer();
    d.sas.set_indexer(&next_id);
    let after = d.sas.attest(&d.attestation(&d.attester, &recipient, 81));

    // Each indexer saw only the attestations issued while it was bound.
    assert_eq!(
        d.indexer.get_attestations_by_recipient(&recipient),
        soroban_sdk::vec![&d.env, before.clone()]
    );
    assert_eq!(
        next.get_attestations_by_recipient(&recipient),
        soroban_sdk::vec![&d.env, after.clone()]
    );

    // Reconciling the historical UID into the new indexer closes the gap.
    d.sas.reindex_attestation(&before);
    let reconciled = next.get_attestations_by_recipient(&recipient);
    assert_eq!(reconciled.len(), 2);
    assert!(reconciled.contains(&before) && reconciled.contains(&after));
}

#[test]
fn bulk_reindex_replays_stored_attestations_into_a_real_indexer() {
    let d = deploy();
    let unbound_id = d.env.register_contract(None, Indexer);
    let unbound = IndexerClient::new(&d.env, &unbound_id);
    d.sas.set_indexer(&unbound_id);

    let recipient = Address::generate(&d.env);
    let first = d.sas.attest(&d.attestation(&d.attester, &recipient, 90));
    let second = d.sas.attest(&d.attestation(&d.attester, &recipient, 91));
    let never_issued = UID(BytesN::from_array(&d.env, &[0xCDu8; 32]));

    unbound.init(&d.admin, &d.sas_id);
    let failed = d.sas.bulk_reindex(&soroban_sdk::vec![
        &d.env,
        first.clone(),
        never_issued.clone(),
        second.clone()
    ]);

    // Only the UID SAS never issued is reported back; the stored ones are
    // mirrored in their original order.
    assert_eq!(failed, soroban_sdk::vec![&d.env, never_issued]);
    assert_eq!(
        unbound.get_attestations_by_recipient(&recipient),
        soroban_sdk::vec![&d.env, first.clone(), second.clone()]
    );
    d.assert_mirrors_sas_in(&unbound, &first);
    d.assert_mirrors_sas_in(&unbound, &second);
}

// ---------------------------------------------------------------------------
// Pagination over SAS-issued data (#306)
// ---------------------------------------------------------------------------

#[test]
fn pages_over_sas_issued_attestations_reassemble_the_complete_history() {
    let d = deploy();
    let recipient = Address::generate(&d.env);
    let other = Address::generate(&d.env);

    // 205 attestations to `recipient` cross two indexer chunk boundaries
    // (100 and 200); one per batch to `other` interleaves in the
    // schema/attester indexes. Issued in batches, as a client would, each
    // within MAX_MULTI_ATTEST.
    let mut expected_recipient = StdVec::new();
    let mut expected_schema = StdVec::new();
    let mut seed = 1_000u32;
    for batch_len in [99u32, 99, 7] {
        let mut batch = soroban_sdk::Vec::new(&d.env);
        for _ in 0..batch_len {
            batch.push_back(d.attestation(&d.attester, &recipient, seed));
            seed += 1;
        }
        batch.push_back(d.attestation(&d.attester, &other, seed));
        seed += 1;
        for (att, uid) in batch.iter().zip(d.sas.multi_attest(&batch).iter()) {
            if att.recipient == recipient {
                expected_recipient.push(uid.clone());
            }
            expected_schema.push(uid);
        }
    }
    assert_eq!(expected_recipient.len(), 205);
    assert_eq!(d.indexer.get_count_by_recipient(&recipient), 205);
    assert_eq!(d.indexer.get_count_by_schema(&d.schema_uid), 208);

    for page_size in [1u32, 7, 100, 101] {
        // A fresh ledger per walk keeps the per-ledger query cap out of the
        // way; it is covered by the indexer's own unit tests.
        d.env.ledger().with_mut(|li| li.sequence_number += 1);
        assert_eq!(
            walk_pages(page_size, |c, l| d
                .indexer
                .get_atts_by_recipient_paginated(&recipient, &c, &l)),
            expected_recipient,
            "recipient, page size {page_size}"
        );
        d.env.ledger().with_mut(|li| li.sequence_number += 1);
        assert_eq!(
            walk_pages(page_size, |c, l| d.indexer.get_atts_by_schema_paginated(
                &d.schema_uid,
                &c,
                &l
            )),
            expected_schema,
            "schema, page size {page_size}"
        );
        d.env.ledger().with_mut(|li| li.sequence_number += 1);
        assert_eq!(
            walk_pages(page_size, |c, l| d.indexer.get_atts_by_attester_paginated(
                &d.attester,
                &c,
                &l
            )),
            expected_schema,
            "attester, page size {page_size}"
        );
    }

    // The paged view agrees with the complete read, and every paged UID
    // resolves to SAS state for the queried recipient.
    assert_eq!(
        to_std(d.indexer.get_attestations_by_recipient(&recipient)),
        expected_recipient
    );
    let page = d
        .indexer
        .get_atts_by_recipient_paginated(&recipient, &198, &10);
    assert_eq!(to_std(page.clone()), expected_recipient[198..205]);
    for uid in page.iter() {
        assert_eq!(d.sas.get_attestation(&uid).unwrap().recipient, recipient);
    }
    assert!(d
        .indexer
        .get_atts_by_recipient_paginated(&recipient, &205, &10)
        .is_empty());
}

#[test]
fn pages_stay_stable_while_sas_keeps_issuing() {
    let d = deploy();
    let recipient = Address::generate(&d.env);
    let mut issued = StdVec::new();
    for seed in 0..5u32 {
        issued.push(
            d.sas
                .attest(&d.attestation(&d.attester, &recipient, 2_000 + seed)),
        );
    }

    let first_page = d
        .indexer
        .get_atts_by_recipient_paginated(&recipient, &0, &3);
    assert_eq!(to_std(first_page.clone()), issued[0..3]);

    // New attestations land between page requests.
    issued.push(d.sas.attest(&d.attestation(&d.attester, &recipient, 2_100)));

    // The first page is unchanged; resuming at `cursor + len` sees every
    // remaining UID exactly once, including the newly appended one.
    assert_eq!(
        d.indexer
            .get_atts_by_recipient_paginated(&recipient, &0, &3),
        first_page
    );
    let rest = walk_pages(3, |c, l| {
        d.indexer
            .get_atts_by_recipient_paginated(&recipient, &(c + first_page.len()), &l)
    });
    assert_eq!(rest, issued[3..]);
}

#[test]
fn deployment_wiring_is_consistent() {
    // Guards the fixture itself: the indexer trusts exactly this SAS and
    // SAS pushes to exactly this indexer.
    let d = deploy();
    assert_eq!(d.indexer.get_sas(), Some(d.sas_id.clone()));
    assert_eq!(d.sas.get_indexer(), Some(d.indexer_id.clone()));
    assert!(!d.sas.get_indexer_strict());
}
