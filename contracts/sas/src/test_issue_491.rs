//! Security verification: re-entrancy from resolver and indexer callbacks (#491).
//!
//! Resolvers (`on_attest` / `on_revoke`) and the indexer (`index_attestation`,
//! `handle_revoke`, `handle_replace`, `handle_renew`) are external contracts
//! that SAS hands control to in the middle of a mutating call. These tests
//! deploy hostile versions of both that try to re-enter SAS from inside the
//! callback, through `attest`, `multi_attest`, `revoke` and `multi_revoke`,
//! against every mutating entrypoint that reaches a callback.
//!
//! Each attack runs in two modes:
//!
//! - **trap**: the callback calls SAS directly; when that nested call fails,
//!   the callback traps. SAS treats a failed resolver as a rejection, so the
//!   outer call must revert with `SASError::ResolverRejected` and leave no
//!   state behind.
//! - **swallow**: the callback calls SAS through `try_*`, records what came
//!   back, and returns normally. The outer call completes; the nested call
//!   must have changed nothing.
//!
//! The attack payload is a valid attestation (and a revocable victim
//! attestation) that would succeed if the nested call were allowed to run, so
//! "nothing changed" is meaningful. After every scenario the reentrancy guard
//! must not be held and an ordinary call must succeed.
//!
//! The Soroban host refuses cross-contract re-entry (`Context` /
//! `InvalidAction`) before SAS's own `multi_attest` guard can run, so the
//! guard is exercised separately by holding it the way an in-flight batch
//! does (see also `test_issue_296`). Findings are written up in
//! `docs/security/reentrancy-verification.md`.

use crate::{SASClient, REENTRANCY_GUARD, SAS};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{
    hash_delegated_revocation, hash_offchain_attestation, Attestation, AttestationDomain, SASError,
    UID,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{ScErrorCode, ScErrorType};
use soroban_sdk::{
    contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env, String as SorobanString,
    Symbol,
};

// ─── Hostile contracts ───────────────────────────────────────────────────────

/// Which SAS entrypoint a hostile callback tries to re-enter.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Attack {
    Attest = 1,
    MultiAttest = 2,
    Revoke = 3,
    MultiRevoke = 4,
}

const ATTACKS: [Attack; 4] = [
    Attack::Attest,
    Attack::MultiAttest,
    Attack::Revoke,
    Attack::MultiRevoke,
];

const SAS_KEY: Symbol = symbol_short!("SAS");
const MODE: Symbol = symbol_short!("MODE");
const SWALLOW: Symbol = symbol_short!("SWALLOW");
const PAYLOAD: Symbol = symbol_short!("PAYLOAD");
const VICTIM: Symbol = symbol_short!("VICTIM");
const TRIES: Symbol = symbol_short!("TRIES");
const NESTED_OK: Symbol = symbol_short!("NESTOK");
const LAST_ERR: Symbol = symbol_short!("LASTERR");

/// Runs the configured attack against SAS from inside a callback.
///
/// In swallow mode the outcome is recorded (attempt count, how many nested
/// calls succeeded, and the last error's type and code) and the callback
/// returns normally; in trap mode a failed nested call traps the callback.
fn run_attack(env: &Env) {
    let mode: u32 = env.storage().instance().get(&MODE).unwrap_or(0);
    if mode == 0 {
        return;
    }
    let sas: Address = env.storage().instance().get(&SAS_KEY).unwrap();
    let swallow: bool = env.storage().instance().get(&SWALLOW).unwrap_or(false);
    let payload: Attestation = env.storage().instance().get(&PAYLOAD).unwrap();
    let victim: UID = env.storage().instance().get(&VICTIM).unwrap();
    let client = SASClient::new(env, &sas);

    let tries: u32 = env.storage().instance().get(&TRIES).unwrap_or(0);
    env.storage().instance().set(&TRIES, &(tries + 1));

    if !swallow {
        match mode {
            1 => {
                client.attest(&payload);
            }
            2 => {
                client.multi_attest(&soroban_sdk::vec![env, payload]);
            }
            3 => client.revoke(&victim),
            _ => client.multi_revoke(&soroban_sdk::vec![env, victim]),
        }
        return;
    }

    // `Ok(Ok(_))` means the nested call ran; anything else is a refusal.
    let outcome: Result<(), Option<soroban_sdk::Error>> = match mode {
        1 => match client.try_attest(&payload) {
            Ok(Ok(_)) => Ok(()),
            Err(Ok(e)) => Err(Some(e)),
            _ => Err(None),
        },
        2 => match client.try_multi_attest(&soroban_sdk::vec![env, payload]) {
            Ok(Ok(_)) => Ok(()),
            Err(Ok(e)) => Err(Some(e)),
            _ => Err(None),
        },
        3 => match client.try_revoke(&victim) {
            Ok(Ok(())) => Ok(()),
            Err(Ok(e)) => Err(Some(e)),
            _ => Err(None),
        },
        _ => match client.try_multi_revoke(&soroban_sdk::vec![env, victim]) {
            Ok(Ok(())) => Ok(()),
            Err(Ok(e)) => Err(Some(e)),
            _ => Err(None),
        },
    };
    match outcome {
        Ok(()) => {
            let ok: u32 = env.storage().instance().get(&NESTED_OK).unwrap_or(0);
            env.storage().instance().set(&NESTED_OK, &(ok + 1));
        }
        Err(Some(e)) => {
            let ty = if e.is_type(ScErrorType::Context) {
                1u32
            } else if e.is_type(ScErrorType::Contract) {
                2
            } else {
                3
            };
            let code = if e.is_type(ScErrorType::Contract) {
                e.get_code()
            } else if e.is_code(ScErrorCode::InvalidAction) {
                1
            } else {
                2
            };
            env.storage().instance().set(&LAST_ERR, &(ty, code));
        }
        Err(None) => env.storage().instance().set(&LAST_ERR, &(9u32, 9u32)),
    }
}

fn store_attack(env: &Env, sas: Address, payload: Attestation, victim: UID) {
    env.storage().instance().set(&SAS_KEY, &sas);
    env.storage().instance().set(&PAYLOAD, &payload);
    env.storage().instance().set(&VICTIM, &victim);
}

fn store_mode(env: &Env, attack: u32, swallow: bool) {
    env.storage().instance().set(&MODE, &attack);
    env.storage().instance().set(&SWALLOW, &swallow);
}

fn read_report(env: &Env) -> (u32, u32, Option<(u32, u32)>) {
    (
        env.storage().instance().get(&TRIES).unwrap_or(0),
        env.storage().instance().get(&NESTED_OK).unwrap_or(0),
        env.storage().instance().get(&LAST_ERR),
    )
}

/// Schema registry and resolver in one contract (as the other SAS test mocks
/// are): every schema resolves to this contract, so every attestation and
/// revocation runs its `on_attest` / `on_revoke`, which attack SAS when armed.
#[contract]
struct HostileResolver;

#[contractimpl]
impl HostileResolver {
    pub fn configure(env: Env, sas: Address, payload: Attestation, victim: UID) {
        store_attack(&env, sas, payload, victim);
    }

    /// `attack` is an `Attack` discriminant; 0 disarms.
    pub fn arm(env: Env, attack: u32, swallow: bool) {
        store_mode(&env, attack, swallow);
    }

    /// (attempts, nested calls that succeeded, last nested error as (type, code)).
    pub fn report(env: Env) -> (u32, u32, Option<(u32, u32)>) {
        read_report(&env)
    }

    pub fn on_attest(env: Env, _attestation: Attestation) {
        run_attack(&env);
    }

    pub fn on_revoke(env: Env, _attestation: Attestation) {
        run_attack(&env);
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
            schema: SorobanString::from_str(&env, "bool valid"),
            deprecated: false,
        })
    }
}

/// An indexer that attacks SAS from every hook SAS calls on it.
#[contract]
struct HostileIndexer;

#[contractimpl]
impl HostileIndexer {
    pub fn setup(env: Env, sas: Address, payload: Attestation, victim: UID) {
        store_attack(&env, sas, payload, victim);
    }

    pub fn set_attack(env: Env, attack: u32, swallow: bool) {
        store_mode(&env, attack, swallow);
    }

    pub fn outcome(env: Env) -> (u32, u32, Option<(u32, u32)>) {
        read_report(&env)
    }

    pub fn index_attestation(
        env: Env,
        _uid: UID,
        _recipient: Address,
        _schema_uid: UID,
        _attester: Address,
        _expiration_time: u64,
    ) {
        run_attack(&env);
    }

    pub fn handle_revoke(env: Env, _uid: UID) {
        run_attack(&env);
    }

    pub fn handle_replace(env: Env, _old_uid: UID, _new_uid: UID) {
        run_attack(&env);
    }

    pub fn handle_renew(env: Env, _uid: UID, _new_expiration_time: u64) {
        run_attack(&env);
    }
}

/// The fee token `attest_with_value` charges. SAS only ever calls `transfer`
/// on it; a Stellar Asset Contract would need a trustline for the classic
/// (`G...`) attester the delegated paths require, so this is a plain ledger.
#[contract]
struct FeeToken;

#[contractimpl]
impl FeeToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let balance = Self::balance(env.clone(), to.clone());
        env.storage().instance().set(&to, &(balance + amount));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage().instance().get(&id).unwrap_or(0)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let from_balance = Self::balance(env.clone(), from.clone());
        assert!(from_balance >= amount, "insufficient balance");
        env.storage()
            .instance()
            .set(&from, &(from_balance - amount));
        let to_balance = Self::balance(env.clone(), to.clone());
        env.storage().instance().set(&to, &(to_balance + amount));
    }
}

// ─── Fixture ─────────────────────────────────────────────────────────────────

/// The host's answer to a re-entrant call, as `run_attack` records it.
const HOST_REFUSED_REENTRY: (u32, u32) = (1, 1); // Context / InvalidAction

struct World<'a> {
    env: Env,
    sas_id: Address,
    client: SASClient<'a>,
    resolver: HostileResolverClient<'a>,
    key: SigningKey,
    attester: Address,
    recipient: Address,
    /// Issued before any attack; the target of the outer revoke paths.
    subject: Attestation,
    /// Issued before any attack; what a re-entrant revoke tries to revoke.
    victim: Attestation,
    /// What a re-entrant attest tries to issue. Never issued legitimately.
    payload: Attestation,
    /// What the outer issuance paths issue.
    outer: Attestation,
    token: Address,
}

const FEE: i128 = 25;

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[91u8; 32])
}

fn attester_address(env: &Env, key: &SigningKey) -> Address {
    let strkey = stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()).to_string();
    Address::from_string(&SorobanString::from_str(env, &strkey))
}

fn fixture(env: &Env, attester: &Address, recipient: &Address, seed: u8) -> Attestation {
    let schema_uid = UID(BytesN::from_array(env, &[2u8; 32]));
    let data = Bytes::from_array(env, &[seed; 32]);
    let uid = soroban_sas_common::attestation_uid(env, &schema_uid, recipient, attester, &data);
    Attestation {
        uid,
        schema_uid,
        time: 0,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data,
    }
}

fn world<'a>() -> World<'a> {
    // The scenario matrix builds well over a hundred environments; a snapshot
    // file per environment would be noise (same approach as the indexer tests).
    let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.mock_all_auths();
    // `revoke` records the ledger time as `revocation_time`, and 0 means "not
    // revoked": at the default timestamp of 0 a revocation is invisible.
    env.ledger().set_timestamp(1_000);

    let resolver_id = env.register_contract(None, HostileResolver);
    let sas_id = env.register_contract(None, SAS);
    let client = SASClient::new(&env, &sas_id);
    let resolver = HostileResolverClient::new(&env, &resolver_id);
    let admin = Address::generate(&env);
    client.init(&admin, &resolver_id);

    let key = signing_key();
    let attester = attester_address(&env, &key);
    let recipient = Address::generate(&env);

    let subject = fixture(&env, &attester, &recipient, 1);
    let victim = fixture(&env, &attester, &recipient, 2);
    let payload = fixture(&env, &attester, &recipient, 3);
    let outer = fixture(&env, &attester, &recipient, 4);
    client.attest(&subject);
    client.attest(&victim);

    // attest_with_value charges the configured fee.
    let token = env.register_contract(None, FeeToken);
    FeeTokenClient::new(&env, &token).mint(&attester, &1_000);
    client.set_fee(&token, &FEE);

    resolver.configure(&sas_id, &payload, &victim.uid);

    World {
        env,
        sas_id,
        client,
        resolver,
        key,
        attester,
        recipient,
        subject,
        victim,
        payload,
        outer,
        token,
    }
}

impl World<'_> {
    fn domain(&self, nonce: u64) -> AttestationDomain {
        AttestationDomain {
            network_id: self.env.ledger().network_id(),
            contract: self.sas_id.clone(),
            nonce,
        }
    }

    fn public_key(&self) -> BytesN<32> {
        BytesN::from_array(&self.env, &self.key.verifying_key().to_bytes())
    }

    fn sign_attestation(&self, attestation: &Attestation, nonce: u64) -> BytesN<64> {
        let digest = hash_offchain_attestation(&self.env, attestation, &self.domain(nonce));
        BytesN::from_array(&self.env, &self.key.sign(&digest.to_array()).to_bytes())
    }

    fn sign_revocation(&self, uid: &UID, nonce: u64) -> BytesN<64> {
        let digest = hash_delegated_revocation(&self.env, uid, &self.attester, &self.domain(nonce));
        BytesN::from_array(&self.env, &self.key.sign(&digest.to_array()).to_bytes())
    }

    fn exists(&self, uid: &UID) -> bool {
        self.client.get_attestation(uid).is_some()
    }

    fn revoked(&self, uid: &UID) -> bool {
        self.client
            .get_attestation(uid)
            .map(|a| a.revocation_time != 0)
            .unwrap_or(false)
    }

    fn guard_held(&self) -> bool {
        self.env.as_contract(&self.sas_id, || {
            self.env.storage().instance().has(&REENTRANCY_GUARD)
        })
    }

    fn token_balance(&self, who: &Address) -> i128 {
        FeeTokenClient::new(&self.env, &self.token).balance(who)
    }

    /// Everything a re-entrant call could have touched, plus what the outer
    /// call itself writes, so a revert can be checked as "exactly as before".
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            subject_revoked: self.revoked(&self.subject.uid),
            victim_revoked: self.revoked(&self.victim.uid),
            payload_exists: self.exists(&self.payload.uid),
            outer_exists: self.exists(&self.outer.uid),
            nonce: self.client.get_delegation_nonce(&self.attester),
            attester_balance: self.token_balance(&self.attester),
            sas_balance: self.token_balance(&self.sas_id),
            guard_held: self.guard_held(),
        }
    }
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    subject_revoked: bool,
    victim_revoked: bool,
    payload_exists: bool,
    outer_exists: bool,
    nonce: Option<u64>,
    attester_balance: i128,
    sas_balance: i128,
    guard_held: bool,
}

// ─── The mutating entrypoints that reach a resolver callback ─────────────────

#[derive(Clone, Copy, Debug)]
enum Entry {
    Attest,
    AttestByDelegation,
    AttestWithValue,
    MultiAttest,
    MultiAttestByDelegation,
    Revoke,
    RevokeByAuthorizer,
    RevokeByDelegate,
    RevokeByDelegation,
    MultiRevoke,
    MultiRevokeByDelegation,
    ReplaceAttestation,
}

const RESOLVER_ENTRYPOINTS: [Entry; 12] = [
    Entry::Attest,
    Entry::AttestByDelegation,
    Entry::AttestWithValue,
    Entry::MultiAttest,
    Entry::MultiAttestByDelegation,
    Entry::Revoke,
    Entry::RevokeByAuthorizer,
    Entry::RevokeByDelegate,
    Entry::RevokeByDelegation,
    Entry::MultiRevoke,
    Entry::MultiRevokeByDelegation,
    Entry::ReplaceAttestation,
];

/// The `Err(Ok(error))` an entrypoint panicked with, or `Ok(())`.
type Outcome = Result<(), soroban_sdk::Error>;

fn flatten<T, C, E>(r: Result<Result<T, C>, Result<soroban_sdk::Error, E>>) -> Outcome
where
    C: core::fmt::Debug,
    E: core::fmt::Debug,
{
    match r {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => panic!("conversion error: {e:?}"),
        Err(Ok(e)) => Err(e),
        Err(Err(e)) => panic!("invoke error: {e:?}"),
    }
}

impl World<'_> {
    /// The replacement `replace_attestation` issues for `subject`.
    fn replacement(&self) -> Attestation {
        let mut replacement = fixture(&self.env, &self.attester, &self.recipient, 5);
        replacement.ref_uid = self.subject.uid.clone();
        replacement
    }

    /// Calls `entry` the way a legitimate caller would. Delegated entrypoints
    /// are signed with the next unused nonce, so a call that reverted can be
    /// retried as-is.
    fn call(&self, entry: Entry) -> Outcome {
        let c = &self.client;
        let next = self
            .client
            .get_delegation_nonce(&self.attester)
            .unwrap_or(0)
            + 1;
        let one_att = soroban_sdk::vec![&self.env, self.outer.clone()];
        let one_uid = soroban_sdk::vec![&self.env, self.subject.uid.clone()];
        match entry {
            Entry::Attest => flatten(c.try_attest(&self.outer)),
            Entry::AttestByDelegation => flatten(c.try_attest_by_delegation(
                &self.outer,
                &next,
                &self.sign_attestation(&self.outer, next),
                &self.public_key(),
            )),
            Entry::AttestWithValue => {
                flatten(c.try_attest_with_value(&self.outer, &self.token, &FEE))
            }
            Entry::MultiAttest => flatten(c.try_multi_attest(&one_att)),
            Entry::MultiAttestByDelegation => flatten(c.try_multi_attest_by_delegation(
                &one_att,
                &soroban_sdk::vec![&self.env, next],
                &soroban_sdk::vec![&self.env, self.sign_attestation(&self.outer, next)],
                &soroban_sdk::vec![&self.env, self.public_key()],
            )),
            Entry::Revoke => flatten(c.try_revoke(&self.subject.uid)),
            Entry::RevokeByAuthorizer => {
                flatten(c.try_revoke_by_authorizer(&self.subject.uid, &self.attester))
            }
            Entry::RevokeByDelegate => {
                flatten(c.try_revoke_by_delegate(&self.subject.uid, &self.attester))
            }
            Entry::RevokeByDelegation => flatten(c.try_revoke_by_delegation(
                &self.subject.uid,
                &next,
                &self.sign_revocation(&self.subject.uid, next),
                &self.public_key(),
            )),
            Entry::MultiRevoke => flatten(c.try_multi_revoke(&one_uid)),
            Entry::MultiRevokeByDelegation => flatten(c.try_multi_revoke_by_delegation(
                &one_uid,
                &soroban_sdk::vec![&self.env, next],
                &soroban_sdk::vec![&self.env, self.sign_revocation(&self.subject.uid, next)],
                &soroban_sdk::vec![&self.env, self.public_key()],
            )),
            Entry::ReplaceAttestation => {
                flatten(c.try_replace_attestation(&self.subject.uid, &self.replacement()))
            }
        }
    }

    /// Whether `entry`'s own effect is visible: the outer attestation issued,
    /// or the subject revoked (and, for a replacement, its successor issued).
    fn effect_applied(&self, entry: Entry) -> bool {
        match entry {
            Entry::Attest
            | Entry::AttestByDelegation
            | Entry::AttestWithValue
            | Entry::MultiAttest
            | Entry::MultiAttestByDelegation => self.exists(&self.outer.uid),
            Entry::ReplaceAttestation => {
                self.revoked(&self.subject.uid) && self.exists(&self.replacement().uid)
            }
            _ => self.revoked(&self.subject.uid),
        }
    }
}

// ─── Resolver callbacks re-entering SAS ──────────────────────────────────────

/// A resolver that re-enters SAS and traps: every entrypoint reverts with
/// `ResolverRejected`, leaves no partial state, releases the guard, and works
/// normally once the resolver behaves.
#[test]
fn trapping_resolver_reentry_reverts_every_entrypoint_and_leaves_no_state() {
    for entry in RESOLVER_ENTRYPOINTS {
        for attack in ATTACKS {
            let w = world();
            let before = w.snapshot();
            w.resolver.arm(&(attack as u32), &false);

            let outcome = w.call(entry);
            assert_eq!(
                outcome,
                Err(SASError::ResolverRejected.into()),
                "{entry:?} with a resolver re-entering via {attack:?}"
            );
            assert_eq!(
                w.snapshot(),
                before,
                "{entry:?}/{attack:?}: state changed despite the revert"
            );

            // Disarmed, the very same call (same nonce) now succeeds: nothing
            // from the reverted attempt lingers, the guard included.
            w.resolver.arm(&0, &false);
            assert_eq!(
                w.call(entry),
                Ok(()),
                "{entry:?}/{attack:?}: legitimate retry failed"
            );
            assert!(
                w.effect_applied(entry),
                "{entry:?}/{attack:?}: retry had no effect"
            );
            assert!(!w.guard_held(), "{entry:?}/{attack:?}: guard left held");
            assert!(
                !w.exists(&w.payload.uid),
                "{entry:?}/{attack:?}: payload issued"
            );
            assert!(
                !w.revoked(&w.victim.uid),
                "{entry:?}/{attack:?}: victim revoked"
            );
        }
    }
}

/// A resolver that re-enters SAS but swallows the failure: the outer call
/// completes, the host refused the nested call, and the nested call changed
/// nothing.
#[test]
fn swallowed_resolver_reentry_is_refused_by_the_host_and_changes_nothing() {
    for entry in RESOLVER_ENTRYPOINTS {
        for attack in ATTACKS {
            let w = world();
            w.resolver.arm(&(attack as u32), &true);

            assert_eq!(
                w.call(entry),
                Ok(()),
                "{entry:?}/{attack:?}: outer call failed"
            );
            assert!(
                w.effect_applied(entry),
                "{entry:?}/{attack:?}: outer call had no effect"
            );

            let (tries, nested_ok, last_err) = w.resolver.report();
            assert!(
                tries >= 1,
                "{entry:?}/{attack:?}: the resolver was never called"
            );
            assert_eq!(
                nested_ok, 0,
                "{entry:?}/{attack:?}: a re-entrant call succeeded"
            );
            assert_eq!(
                last_err,
                Some(HOST_REFUSED_REENTRY),
                "{entry:?}/{attack:?}: re-entry was not refused by the host"
            );

            assert!(
                !w.exists(&w.payload.uid),
                "{entry:?}/{attack:?}: re-entrant attest issued the payload"
            );
            assert!(
                !w.revoked(&w.victim.uid),
                "{entry:?}/{attack:?}: re-entrant revoke revoked the victim"
            );
            assert!(!w.guard_held(), "{entry:?}/{attack:?}: guard left held");
        }
    }
}

// ─── Indexer callbacks re-entering SAS ───────────────────────────────────────

#[derive(Clone, Copy, Debug)]
enum IndexedEntry {
    Attest,
    MultiAttest,
    Revoke,
    ReplaceAttestation,
    RenewAttestation,
    ReindexAttestation,
    BulkReindex,
}

const INDEXER_ENTRYPOINTS: [IndexedEntry; 7] = [
    IndexedEntry::Attest,
    IndexedEntry::MultiAttest,
    IndexedEntry::Revoke,
    IndexedEntry::ReplaceAttestation,
    IndexedEntry::RenewAttestation,
    IndexedEntry::ReindexAttestation,
    IndexedEntry::BulkReindex,
];

impl World<'_> {
    fn bind_hostile_indexer(&self) -> HostileIndexerClient<'_> {
        let id = self.env.register_contract(None, HostileIndexer);
        let indexer = HostileIndexerClient::new(&self.env, &id);
        indexer.setup(&self.sas_id, &self.payload, &self.victim.uid);
        self.client.set_indexer(&id);
        indexer
    }

    fn call_indexed(&self, entry: IndexedEntry) -> Outcome {
        let c = &self.client;
        match entry {
            IndexedEntry::Attest => self.call(Entry::Attest),
            IndexedEntry::MultiAttest => self.call(Entry::MultiAttest),
            IndexedEntry::Revoke => self.call(Entry::Revoke),
            IndexedEntry::ReplaceAttestation => self.call(Entry::ReplaceAttestation),
            IndexedEntry::RenewAttestation => {
                flatten(c.try_renew_attestation(&self.subject.uid, &0))
            }
            IndexedEntry::ReindexAttestation => {
                flatten(c.try_reindex_attestation(&self.subject.uid))
            }
            IndexedEntry::BulkReindex => {
                flatten(c.try_bulk_reindex(&soroban_sdk::vec![&self.env, self.subject.uid.clone()]))
            }
        }
    }
}

/// The indexer is fail-open, so a hostile one cannot block SAS; whatever it
/// does in its hooks, a re-entrant call is refused and changes nothing.
#[test]
fn indexer_reentry_is_refused_and_changes_nothing_in_either_mode() {
    for entry in INDEXER_ENTRYPOINTS {
        for attack in ATTACKS {
            for swallow in [false, true] {
                let w = world();
                let indexer = w.bind_hostile_indexer();
                indexer.set_attack(&(attack as u32), &swallow);

                let before = w.snapshot();
                let outcome = w.call_indexed(entry);
                if !swallow && matches!(entry, IndexedEntry::ReindexAttestation) {
                    // Reindexing is the explicit repair path, so it is
                    // fail-closed: a failed push is reported, and nothing else
                    // changes.
                    assert_eq!(
                        outcome,
                        Err(SASError::IndexerUnavailable.into()),
                        "{entry:?}/{attack:?}"
                    );
                    assert_eq!(
                        w.snapshot(),
                        before,
                        "{entry:?}/{attack:?}: state changed despite the revert"
                    );
                } else {
                    assert_eq!(outcome, Ok(()), "{entry:?}/{attack:?}/swallow={swallow}");
                }

                if swallow {
                    let (tries, nested_ok, last_err) = indexer.outcome();
                    assert!(
                        tries >= 1,
                        "{entry:?}/{attack:?}: the indexer was never called"
                    );
                    assert_eq!(
                        nested_ok, 0,
                        "{entry:?}/{attack:?}: a re-entrant call succeeded"
                    );
                    assert_eq!(last_err, Some(HOST_REFUSED_REENTRY), "{entry:?}/{attack:?}");
                }
                assert!(
                    !w.exists(&w.payload.uid),
                    "{entry:?}/{attack:?}/swallow={swallow}: payload issued"
                );
                assert!(
                    !w.revoked(&w.victim.uid),
                    "{entry:?}/{attack:?}/swallow={swallow}: victim revoked"
                );
                assert!(
                    !w.guard_held(),
                    "{entry:?}/{attack:?}/swallow={swallow}: guard left held"
                );
            }
        }
    }
}

/// With the indexer fail-closed, a trapping hostile indexer aborts issuance
/// with `IndexerUnavailable`, and the revert leaves nothing behind.
#[test]
fn strict_indexer_reentry_reverts_issuance_without_partial_state() {
    for attack in ATTACKS {
        let w = world();
        let indexer = w.bind_hostile_indexer();
        w.client.set_indexer_strict(&true);
        indexer.set_attack(&(attack as u32), &false);
        let before = w.snapshot();

        assert_eq!(
            w.call(Entry::Attest),
            Err(SASError::IndexerUnavailable.into()),
            "{attack:?}"
        );
        assert_eq!(
            w.snapshot(),
            before,
            "{attack:?}: state changed despite the revert"
        );
    }
}

// ─── The contract-level guard ────────────────────────────────────────────────

/// Holds the guard the way an in-flight batch does.
fn hold_guard(w: &World) {
    w.env.as_contract(&w.sas_id, || {
        w.env.storage().instance().set(&REENTRANCY_GUARD, &true)
    });
}

/// Both guarded entrypoints refuse to run while the guard is held, with the
/// typed error, and change nothing (no attestation, no nonce consumed).
#[test]
fn every_guarded_entrypoint_rejects_a_nested_call_with_the_reentrancy_error() {
    for entry in [Entry::MultiAttest, Entry::MultiAttestByDelegation] {
        let w = world();
        hold_guard(&w);
        let before = w.snapshot();

        assert_eq!(w.call(entry), Err(SASError::Reentrancy.into()), "{entry:?}");
        assert_eq!(
            w.snapshot(),
            before,
            "{entry:?}: state changed despite the revert"
        );
    }
}

/// The guard is released after a successful batch, so the next batch (of
/// either guarded kind) runs.
#[test]
fn the_guard_is_released_after_every_successful_guarded_call() {
    let w = world();
    assert_eq!(w.call(Entry::MultiAttestByDelegation), Ok(()));
    assert!(!w.guard_held());

    let next = fixture(&w.env, &w.attester, &w.recipient, 6);
    assert_eq!(
        flatten(
            w.client
                .try_multi_attest(&soroban_sdk::vec![&w.env, next.clone()])
        ),
        Ok(())
    );
    assert!(!w.guard_held());
    assert!(w.exists(&next.uid));
}

/// A guarded batch that reverts part-way (here: a resolver rejecting it from
/// inside the critical section) does not leave the guard behind; the host
/// rolls the guard write back with everything else.
#[test]
fn a_reverted_guarded_call_does_not_leave_the_guard_held() {
    for entry in [Entry::MultiAttest, Entry::MultiAttestByDelegation] {
        let w = world();
        w.resolver.arm(&(Attack::Attest as u32), &false);
        assert_eq!(
            w.call(entry),
            Err(SASError::ResolverRejected.into()),
            "{entry:?}"
        );
        assert!(!w.guard_held(), "{entry:?}: guard left held after a revert");

        w.resolver.arm(&0, &false);
        assert_eq!(w.call(entry), Ok(()), "{entry:?}: next call blocked");
    }
}
