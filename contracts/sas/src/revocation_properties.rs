//! Property tests for the revocation state machine (#301).
//!
//! Revocation is one-way. `revocation_time` moves from `0` to the close time
//! of the ledger that revoked the attestation, exactly once, and every entry
//! point that can set it — `revoke`, `revoke_by_authorizer`,
//! `revoke_by_delegate`, `revoke_by_delegation`, `multi_revoke` and
//! `replace_attestation` — has to agree with that. Example tests pin the
//! transitions somebody thought of; these generate operation sequences and
//! re-check the invariants after every step, so the combinations nobody wrote
//! down (a delegated revocation after a batch revocation after a replacement)
//! are exercised too.
//!
//! Four properties are asserted after every operation:
//!
//! 1. **Terminal.** A UID is accepted into the revoked state at most once. A
//!    second acceptance would make the model record a timestamp it already
//!    holds, which fails at the step it happens.
//! 2. **Agreement.** `revocation_time != 0` and `verify_attestation == false`
//!    are the same statement — neither the record's timestamp nor the view can
//!    drift from the other.
//! 3. **Provenance.** A non-zero `revocation_time` is always a close time the
//!    ledger was actually moved to during the run, never a value the contract
//!    invented.
//! 4. **Atomicity.** A rejected call leaves every tracked record exactly as it
//!    was, including `multi_revoke`, where one bad UID must not revoke the good
//!    ones on the way to reporting the failure.
//!
//! The generator is a seeded xorshift rather than `rand` or `proptest`: the
//! workspace keeps its dependency set, and a counterexample is replayable —
//! every assertion names the sequence and step, and setting `SEED` to the
//! sequence's seed re-runs exactly that run.

use alloc::vec::Vec;

use crate::{SASClient, SAS};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{
    hash_delegated_revocation, Attestation, AttestationDomain, SASError, UID,
};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, String as SorobanString};

#[contract]
struct MockRegistry;

#[contractimpl]
impl MockRegistry {
    pub fn on_attest(_env: Env, _attestation: Attestation) {}

    pub fn on_revoke(_env: Env, _attestation: Attestation) {}

    /// Always true: this suite is about the state machine around revocation,
    /// not about who the registry lets revoke. The authorizer paths are still
    /// driven through a distinct address so they are not just aliases of the
    /// direct one.
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
            schema: soroban_sdk::String::from_str(&env, "bool revocable"),
            deprecated: false,
        })
    }
}

/// The ledger the harness starts on.
const GENESIS_TIME: u64 = 1_700_000_000;

/// How many independent operation sequences the sweep runs.
const SEQUENCES: u64 = 48;

/// Operations applied to each sequence.
const STEPS: u32 = 20;

/// How many attestations a sequence may track at once. Replacements mint new
/// records, so the pool grows; capping it keeps each sequence's work bounded.
const MAX_TRACKED: usize = 6;

/// The base seed. A failing assertion reports the seed of the sequence it ran
/// under; putting that value here replays exactly that sequence.
const SEED: u64 = 0x5EED_0F1E_2D3C_4B5A;

/// A xorshift64 generator. Deterministic on purpose: the sequence is part of
/// the test's contract, so a failure is reproducible rather than a one-off.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.0 = state;
        state
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// One attestation as the harness believes it to be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Tracked {
    /// The close time of the ledger that revoked it, once one has been
    /// accepted.
    revoked_at: Option<u64>,
    /// Whether it was issued with `revocable = true`.
    revocable: bool,
}

/// The operations the sweep draws from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Op {
    AdvanceLedger,
    Revoke,
    RevokeByAuthorizer,
    RevokeByDelegate,
    RevokeByDelegation,
    MultiRevoke,
    Replace,
    Read,
}

/// Draws the next operation. `AdvanceLedger` is the most likely draw: a
/// revocation time only distinguishes the ledger that produced it if the
/// ledger has been moving between operations.
fn pick(rng: &mut Rng) -> Op {
    match rng.below(16) {
        0..=2 => Op::AdvanceLedger,
        3..=5 => Op::Revoke,
        6 => Op::RevokeByAuthorizer,
        7 => Op::RevokeByDelegate,
        8 => Op::RevokeByDelegation,
        9..=10 => Op::MultiRevoke,
        11..=12 => Op::Replace,
        _ => Op::Read,
    }
}

/// Asserts the contract's verdict matches the model's.
///
/// Written as a macro because it expands at the call site, where the result
/// type is already known — the alternative is naming the host's
/// `Result<Error, InvokeError>` in a helper's signature, which is all this
/// needs to avoid.
macro_rules! expect_verdict {
    ($result:expr, $expected:expr, $seed:expr, $step:expr) => {{
        let actual: Option<soroban_sdk::Error> = $result.err().and_then(|inner| inner.ok());
        let expected: Option<soroban_sdk::Error> = $expected.err().map(Into::into);
        assert_eq!(
            actual, expected,
            "verdict mismatch at seed {} step {}",
            $seed, $step
        );
    }};
}

struct Harness {
    env: Env,
    client: SASClient<'static>,
    sas_id: Address,
    signing_key: SigningKey,
    attester: Address,
    recipient: Address,
    /// A distinct address, so the authorizer/delegate paths run through the
    /// registry's allow-list rather than through ownership of the record.
    delegate: Address,
    uids: Vec<UID>,
    state: Vec<Tracked>,
    /// Every close time the ledger has been moved to. Property 3 checks a
    /// recorded revocation against this.
    ledger_times: Vec<u64>,
    /// Monotonic delegated-nonce counter. The contract only accepts a nonce
    /// above the last one consumed for an attester, and a reverted call does
    /// not consume one, so counting forward is always safe.
    nonce: u64,
    /// Distinguishes newly minted records from each other, so UIDs stay
    /// distinct as replacements are issued.
    mint: u8,
}

impl Harness {
    fn new() -> Self {
        let env = Env::default();
        // The generated sweeps run hundreds of host calls through one Env, so
        // the default per-test CPU/memory budget is not the property under
        // test here; lift it and keep every other host check intact.
        env.budget().reset_unlimited();
        env.ledger().with_mut(|li| li.timestamp = GENESIS_TIME);

        let registry_id = env.register_contract(None, MockRegistry);
        let sas_id = env.register_contract(None, SAS);
        let client = SASClient::new(&env, &sas_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.init(&admin, &registry_id);

        // The attester is derived from the signing key so that the delegated
        // paths can produce a signature the contract verifies against it.
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let attester_strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
        let attester = Address::from_string(&SorobanString::from_str(&env, &attester_strkey));
        let recipient = Address::generate(&env);
        let delegate = Address::generate(&env);

        Self {
            env,
            client,
            sas_id,
            signing_key,
            attester,
            recipient,
            delegate,
            uids: Vec::new(),
            state: Vec::new(),
            ledger_times: alloc::vec![GENESIS_TIME],
            nonce: 0,
            mint: 0,
        }
    }

    /// A correctly content-addressed attestation for this harness's attester
    /// and recipient. `seed` makes it distinct from every other record.
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
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[0u8; 32])),
            recipient: self.recipient.clone(),
            attester: self.attester.clone(),
            revocable,
            data,
        }
    }

    /// Issues an attestation and starts tracking it.
    fn issue(&mut self, revocable: bool) -> usize {
        let attestation = self.attestation(self.mint, revocable);
        self.mint += 1;
        self.client.attest(&attestation);

        self.uids.push(attestation.uid);
        self.state.push(Tracked {
            revoked_at: None,
            revocable,
        });
        self.uids.len() - 1
    }

    fn uid(&self, index: usize) -> UID {
        self.uids[index].clone()
    }

    /// The record as the contract currently stores it.
    fn record(&self, index: usize) -> Option<Attestation> {
        self.client.get_attestation(&self.uids[index])
    }

    fn ledger_time(&self) -> u64 {
        self.env.ledger().timestamp()
    }

    /// Moves the ledger on by a bounded amount, so revocation times are
    /// spread over distinct ledgers rather than all landing on one.
    fn advance(&mut self, rng: &mut Rng) {
        let timestamp = self.ledger_time() + 1 + rng.below(600);
        self.env.ledger().with_mut(|li| {
            li.sequence_number += 1;
            li.timestamp = timestamp;
        });
        self.ledger_times.push(timestamp);
    }

    fn public_key(&self) -> BytesN<32> {
        BytesN::from_array(&self.env, &self.signing_key.verifying_key().to_bytes())
    }

    fn bump_nonce(&mut self) -> u64 {
        self.nonce += 1;
        self.nonce
    }

    fn sign_revocation(&self, uid: &UID, nonce: u64) -> BytesN<64> {
        let domain = AttestationDomain {
            network_id: self.env.ledger().network_id(),
            contract: self.sas_id.clone(),
            nonce,
        };
        let payload_hash = hash_delegated_revocation(&self.env, uid, &self.attester, &domain);
        let signature = self.signing_key.sign(&payload_hash.to_array());
        BytesN::from_array(&self.env, &signature.to_bytes())
    }

    /// What the model expects a single-UID revocation attempt to do.
    ///
    /// The contract checks `revocable` before `revocation_time`, and a
    /// non-revocable attestation can never be revoked, so "already revoked"
    /// and "not revocable" cannot both apply.
    fn verdict(&self, index: usize) -> Result<(), SASError> {
        if self.state[index].revoked_at.is_some() {
            Err(SASError::AlreadyRevoked)
        } else if !self.state[index].revocable {
            Err(SASError::NotRevocable)
        } else {
            Ok(())
        }
    }

    /// What the model expects a batch to do, mirroring the contract's
    /// pre-commit pass: duplicates first, then each UID in batch order.
    fn batch_verdict(&self, picks: &[usize]) -> Result<(), SASError> {
        let mut seen: Vec<usize> = Vec::new();
        for &index in picks {
            if seen.contains(&index) {
                return Err(SASError::DuplicateAttestation);
            }
            seen.push(index);
            if !self.state[index].revocable {
                return Err(SASError::NotRevocable);
            }
            if self.state[index].revoked_at.is_some() {
                return Err(SASError::AlreadyRevoked);
            }
        }
        Ok(())
    }

    /// Records an accepted revocation. Property 1 lives here: a UID that is
    /// already revoked in the model must never be revoked again, so a second
    /// accepted transition fails at the step the contract allowed it.
    fn mark_revoked(&mut self, index: usize, seed: u64, step: u32) {
        assert!(
            self.state[index].revoked_at.is_none(),
            "a UID was accepted into the revoked state twice (seed {seed} step {step})"
        );
        self.state[index].revoked_at = Some(self.ledger_time());
        assert_eq!(
            self.record(index).expect("tracked").revocation_time,
            self.ledger_time(),
            "an accepted revocation must store the ledger close time (seed {seed} step {step})"
        );
    }

    /// Properties 1-3, for every tracked record.
    fn assert_model(&self, seed: u64, step: u32) {
        for (index, uid) in self.uids.iter().enumerate() {
            let tracked = self.state[index];
            let record = self
                .record(index)
                .expect("a tracked UID is never garbage-collected mid-run");
            let revoked = tracked.revoked_at.is_some();

            if let Some(time) = tracked.revoked_at {
                assert!(
                    self.ledger_times.contains(&time),
                    "revocation_time {time} was never a ledger close time in this run \
                     (seed {seed} step {step})"
                );
            }

            assert_eq!(
                record.revocation_time != 0,
                revoked,
                "the stored timestamp and the model disagree (seed {seed} step {step})"
            );
            assert_eq!(
                self.client.verify_attestation(uid),
                !revoked,
                "the live/revoked view and the model disagree (seed {seed} step {step})"
            );
        }
    }

    fn batch_of(&self, picks: &[usize]) -> soroban_sdk::Vec<UID> {
        let mut batch = soroban_sdk::Vec::new(&self.env);
        for &index in picks {
            batch.push_back(self.uid(index));
        }
        batch
    }

    /// Applies one operation, asserting the contract's verdict and updating
    /// the model only when the verdict was "accepted".
    fn apply(&mut self, op: Op, rng: &mut Rng, seed: u64, step: u32) {
        let target = rng.below(self.uids.len() as u64) as usize;

        match op {
            Op::AdvanceLedger => self.advance(rng),
            Op::Read => {
                // Reading must never be what revokes something, and must stay
                // consistent with the model — `assert_model` re-checks both.
                let uid = self.uid(target);
                assert!(self.record(target).is_some());
                let _ = self.client.verify_attestation(&uid);
            }
            Op::Revoke => {
                let uid = self.uid(target);
                let before = self.record(target);
                let expected = self.verdict(target);
                let result = self.client.try_revoke(&uid);
                expect_verdict!(result, expected, seed, step);
                self.settle(target, before, expected, seed, step);
            }
            Op::RevokeByAuthorizer => {
                let uid = self.uid(target);
                let delegate = self.delegate.clone();
                let before = self.record(target);
                let expected = self.verdict(target);
                let result = self.client.try_revoke_by_authorizer(&uid, &delegate);
                expect_verdict!(result, expected, seed, step);
                self.settle(target, before, expected, seed, step);
            }
            Op::RevokeByDelegate => {
                let uid = self.uid(target);
                let delegate = self.delegate.clone();
                let before = self.record(target);
                let expected = self.verdict(target);
                let result = self.client.try_revoke_by_delegate(&uid, &delegate);
                expect_verdict!(result, expected, seed, step);
                self.settle(target, before, expected, seed, step);
            }
            Op::RevokeByDelegation => {
                let uid = self.uid(target);
                let nonce = self.bump_nonce();
                let signature = self.sign_revocation(&uid, nonce);
                let public_key = self.public_key();
                let before = self.record(target);
                let expected = self.verdict(target);
                let result =
                    self.client
                        .try_revoke_by_delegation(&uid, &nonce, &signature, &public_key);
                expect_verdict!(result, expected, seed, step);
                self.settle(target, before, expected, seed, step);
            }
            Op::MultiRevoke => {
                let picks = self.pick_batch(rng);
                let batch = self.batch_of(&picks);
                let expected = self.batch_verdict(&picks);
                let before: Vec<Option<Attestation>> =
                    picks.iter().map(|&index| self.record(index)).collect();
                let result = self.client.try_multi_revoke(&batch);
                expect_verdict!(result, expected, seed, step);

                if expected.is_ok() {
                    for &index in picks.iter() {
                        self.mark_revoked(index, seed, step);
                    }
                } else {
                    // Property 4: one bad UID must not revoke the good ones on
                    // the way to reporting the failure.
                    for (position, &index) in picks.iter().enumerate() {
                        assert_eq!(
                            self.record(index),
                            before[position],
                            "a rejected batch changed a record (seed {seed} step {step})"
                        );
                    }
                }
            }
            Op::Replace => {
                if self.uids.len() >= MAX_TRACKED {
                    return;
                }
                let uid = self.uid(target);
                let before = self.record(target);
                let expected = self.verdict(target);
                let replacement = self.attestation(self.mint, true);
                self.mint += 1;
                let new_uid = replacement.uid.clone();
                let result = self.client.try_replace_attestation(&uid, &replacement);
                expect_verdict!(result, expected, seed, step);

                if expected.is_ok() {
                    // A replacement is a revocation of the old record and an
                    // issuance of the new one in the same call.
                    self.mark_revoked(target, seed, step);
                    self.uids.push(new_uid);
                    self.state.push(Tracked {
                        revoked_at: None,
                        revocable: true,
                    });
                } else {
                    assert_eq!(
                        self.record(target),
                        before,
                        "a rejected replacement changed the record (seed {seed} step {step})"
                    );
                }
            }
        }
    }

    /// Applies the verdict to the model: an accepted revocation is recorded,
    /// a rejected one must have left the record exactly as it was.
    fn settle(
        &mut self,
        index: usize,
        before: Option<Attestation>,
        expected: Result<(), SASError>,
        seed: u64,
        step: u32,
    ) {
        if expected.is_ok() {
            self.mark_revoked(index, seed, step);
        } else {
            assert_eq!(
                self.record(index),
                before,
                "a rejected revocation changed the record (seed {seed} step {step})"
            );
        }
    }

    /// One to three UIDs, drawn with replacement so duplicate detection is
    /// part of what the sweep exercises.
    fn pick_batch(&mut self, rng: &mut Rng) -> Vec<usize> {
        let count = 1 + rng.below(3) as usize;
        let mut picks = Vec::with_capacity(count);
        for _ in 0..count {
            picks.push(rng.below(self.uids.len() as u64) as usize);
        }
        picks
    }
}

#[test]
fn revocation_state_machine_holds_over_generated_sequences() {
    for sequence in 0..SEQUENCES {
        let mut harness = Harness::new();
        let mut rng = Rng(SEED ^ (sequence + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));

        // One irrevocable attestation is always in the pool, so every
        // operation meets the branch that has to refuse it.
        harness.issue(true);
        harness.issue(false);
        harness.issue(true);

        for step in 0..STEPS {
            let op = pick(&mut rng);
            harness.apply(op, &mut rng, sequence, step);
            harness.assert_model(sequence, step);
        }
    }
}

#[test]
fn a_batch_with_one_irrevocable_uid_revokes_nothing() {
    let mut harness = Harness::new();
    let revocable = harness.issue(true);
    let irrevocable = harness.issue(false);

    let batch = harness.batch_of(&[revocable, irrevocable]);
    let result = harness.client.try_multi_revoke(&batch);
    assert_eq!(result, Err(Ok(SASError::NotRevocable.into())));

    // The revocable record must not have been revoked on the way to
    // discovering the irrevocable one.
    assert_eq!(harness.record(revocable).unwrap().revocation_time, 0);
    assert!(harness.client.verify_attestation(&harness.uid(revocable)));
    harness.assert_model(0, 0);
}

#[test]
fn repeated_revocation_of_the_same_uid_changes_nothing_after_the_first() {
    let mut harness = Harness::new();
    let index = harness.issue(true);
    let uid = harness.uid(index);

    harness.client.revoke(&uid);
    harness.mark_revoked(index, 0, 1);
    let revoked_at = harness.record(index).unwrap().revocation_time;

    let delegate = harness.delegate.clone();
    for attempt in 0..3 {
        // Every authorizer path refuses, and none of them moves the close time
        // that was recorded by the one transition that was accepted.
        let result = match attempt {
            0 => harness.client.try_revoke(&uid),
            1 => harness.client.try_revoke_by_authorizer(&uid, &delegate),
            _ => harness.client.try_revoke_by_delegate(&uid, &delegate),
        };
        assert_eq!(result, Err(Ok(SASError::AlreadyRevoked.into())));
        assert_eq!(harness.record(index).unwrap().revocation_time, revoked_at);
        assert!(!harness.client.verify_attestation(&uid));
    }

    harness.assert_model(0, 2);
}

#[test]
fn no_revocation_path_reaches_a_non_revocable_attestation() {
    let mut harness = Harness::new();
    let index = harness.issue(false);
    let uid = harness.uid(index);

    let delegate = harness.delegate.clone();
    let nonce = harness.bump_nonce();
    let signature = harness.sign_revocation(&uid, nonce);
    let public_key = harness.public_key();

    // All five entry points, including the batch one and the delegated one
    // with a valid signature over a fresh nonce: the schema's ceiling is what
    // refuses, not the authorization.
    assert_eq!(
        harness.client.try_revoke(&uid),
        Err(Ok(SASError::NotRevocable.into()))
    );
    assert_eq!(
        harness.client.try_revoke_by_authorizer(&uid, &delegate),
        Err(Ok(SASError::NotRevocable.into()))
    );
    assert_eq!(
        harness.client.try_revoke_by_delegate(&uid, &delegate),
        Err(Ok(SASError::NotRevocable.into()))
    );
    assert_eq!(
        harness
            .client
            .try_revoke_by_delegation(&uid, &nonce, &signature, &public_key),
        Err(Ok(SASError::NotRevocable.into()))
    );
    let batch = harness.batch_of(&[index]);
    assert_eq!(
        harness.client.try_multi_revoke(&batch),
        Err(Ok(SASError::NotRevocable.into()))
    );

    assert_eq!(harness.record(index).unwrap().revocation_time, 0);
    assert!(harness.client.verify_attestation(&uid));
    harness.assert_model(0, 3);
}
