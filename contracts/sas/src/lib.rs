#![allow(unexpected_cfgs)]
#![no_std]

extern crate alloc;

use soroban_sas_common::{Attestation, SASError, LEDGERS_IN_ONE_YEAR, MAX_ATTESTATION_DATA_BYTES, UID};
use soroban_sdk::{
    contract, contractimpl, panic_with_error, symbol_short, token, Address, Env, IntoVal, Symbol,
};

mod events;

// v1.0.0 State Schema Frozen

#[contract]
pub struct SAS;

pub const SAS_ADMIN: Symbol = symbol_short!("ADMIN");
pub const SCHEMA_REGISTRY: Symbol = symbol_short!("REGISTRY");
pub const INDEXER: Symbol = symbol_short!("INDEXER");
pub const TREASURY: Symbol = symbol_short!("TREASURY");
/// Instance key for the `(fee_token, fee_amount)` pair required by
/// `attest_with_value`. Absent means attestation is fee-free (#164).
pub const FEE_CONFIG: Symbol = symbol_short!("FEECFG");
/// Instance key for the fail-closed indexing toggle. When `true`, a failed
/// Indexer push aborts attestation issuance with `IndexerUnavailable`
/// instead of emitting `IndexFailed` (#161). Defaults to `false` (fail-open).
pub const INDEXER_STRICT: Symbol = symbol_short!("IDXSTRICT");
pub const ATTESTER_KEY: Symbol = symbol_short!("ATTKEY");
/// Per-attester high-watermark for delegated nonces. The value stored is the
/// highest `nonce` that has been consumed for that attester; a delegated
/// signature is valid only if `nonce > last`. This provides durable replay
/// protection with one `instance` entry per attester (bounded growth) whose
/// lifetime tracks contract liveness via `extend_instance_ttl`.
pub const DELEGATION_NONCE: Symbol = symbol_short!("DELNONCE");
/// Maximum number of attestations in one multi_attest invocation. This keeps
/// authorization and storage work within the measured Soroban budget envelope.
pub const MAX_MULTI_ATTEST: u32 = 100;
/// Maximum number of UIDs in one multi_revoke invocation. Bounded like
/// `MAX_MULTI_ATTEST` so the loop cannot exhaust the Soroban budget and
/// callers get a predictable `BatchTooLarge` error up front.
pub const MAX_MULTI_REVOKE: u32 = 100;
const REGISTRY_INTERFACE_VERSION: Symbol = symbol_short!("SASREG");

fn extend_instance_ttl(env: &Env) {
    env.storage().instance().extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
}

/// Reads the admin recorded by `init`, or panics `NotInitialized`.
///
/// Reading the entry with a bare `unwrap` turns "the contract was never
/// initialized" into an unclassified host trap, which SDK and CLI callers
/// cannot distinguish from a genuine failure. Going through this guard gives
/// every initialization-dependent entry point one stable error code.
fn require_admin(env: &Env) -> Address {
    match env.storage().instance().get(&SAS_ADMIN) {
        Some(admin) => admin,
        None => panic_with_error!(env, SASError::NotInitialized),
    }
}

/// Reads the schema registry recorded by `init`, or panics `NotInitialized`.
/// Companion to [`require_admin`]; see that guard for the rationale.
fn require_registry(env: &Env) -> Address {
    match env.storage().instance().get(&SCHEMA_REGISTRY) {
        Some(registry) => registry,
        None => panic_with_error!(env, SASError::NotInitialized),
    }
}

#[contractimpl]
impl SAS {
    pub fn init(env: Env, admin: Address, registry: Address) {
        extend_instance_ttl(&env);
        if env.storage().instance().has(&SAS_ADMIN) {
            panic_with_error!(&env, SASError::AlreadyInitialized);
        }
        admin.require_auth();
        // Compatibility probe: try both upper and lower spellings to support
        // registries that expose `sasreg` vs `SASREG`. The spec historically
        // used `SASREG` while the registry implemented `sasreg`; probing both
        // keeps existing mocks (SASREG) and the real registry (sasreg) compatible.
        let compatible: bool = {
            let upper: bool = env
                .try_invoke_contract::<bool, soroban_sdk::Error>(
                    &registry,
                    &REGISTRY_INTERFACE_VERSION,
                    soroban_sdk::vec![&env],
                )
                .unwrap_or(Ok(false))
                .unwrap_or(false);
            if upper {
                true
            } else {
                env.try_invoke_contract::<bool, soroban_sdk::Error>(
                    &registry,
                    &symbol_short!("sasreg"),
                    soroban_sdk::vec![&env],
                )
                .unwrap_or(Ok(false))
                .unwrap_or(false)
            }
        };
        if !compatible {
            panic_with_error!(&env, SASError::IncompatibleDependency);
        }
        env.storage().instance().set(&SAS_ADMIN, &admin);
        env.storage().instance().set(&SCHEMA_REGISTRY, &registry);
        extend_instance_ttl(&env);
    }

    /// Returns the bound indexer, if one has been configured.
    pub fn get_indexer(env: Env) -> Option<Address> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&INDEXER)
    }

    /// Binds an Indexer contract that should mirror newly issued attestations.
    pub fn set_indexer(env: Env, indexer: Address) {
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().set(&INDEXER, &indexer);
        extend_instance_ttl(&env);
    }

    pub fn set_treasury(env: Env, treasury: Address) {
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().set(&TREASURY, &treasury);
        extend_instance_ttl(&env);
    }

    pub fn get_treasury(env: Env) -> Option<Address> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&TREASURY)
    }

    /// Returns the `(token, amount)` fee that `attest_with_value` requires, or
    /// `None` when attestation is fee-free. This is the authenticated policy
    /// callers must satisfy; it is not derived from caller input (#164).
    pub fn get_fee(env: Env) -> Option<(Address, i128)> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&FEE_CONFIG)
    }

    /// Admin: pin the fee asset and exact amount for `attest_with_value`.
    /// `amount` must be positive; call `clear_fee` for fee-free schemas
    /// instead of encoding "no fee" as an arbitrary zero (#164).
    pub fn set_fee(env: Env, token: Address, amount: i128) {
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        env.storage().instance().set(&FEE_CONFIG, &(token, amount));
        extend_instance_ttl(&env);
    }

    /// Admin: remove the fee requirement. `attest_with_value` is then callable
    /// only with `value == 0` (#164).
    pub fn clear_fee(env: Env) {
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().remove(&FEE_CONFIG);
        extend_instance_ttl(&env);
    }

    pub fn withdraw_tokens(
        env: Env,
        authorizer: Address,
        token: Address,
        amount: i128,
        destination: Address,
    ) {
        extend_instance_ttl(&env);
        if amount <= 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        let admin = require_admin(&env);
        let provided_treasury: Option<Address> = env.storage().instance().get(&TREASURY);
        if authorizer != admin && provided_treasury.as_ref() != Some(&authorizer) {
            panic_with_error!(&env, SASError::Unauthorized);
        }
        authorizer.require_auth();

        let token_client = token::Client::new(&env, &token);
        let balance = token_client.balance(&env.current_contract_address());
        if balance < amount {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        token_client.transfer(&env.current_contract_address(), &destination, &amount);
        events::publish_withdrawal(&env, &token, amount, &destination, &authorizer);
        extend_instance_ttl(&env);
    }

    pub fn attest(env: Env, attestation: Attestation) -> UID {
        attestation.attester.require_auth();
        Self::attest_internal(env, attestation)
    }

    pub fn attest_by_delegation(
        env: Env,
        attestation: Attestation,
        nonce: u64,
        signature: soroban_sdk::BytesN<64>,
        public_key: soroban_sdk::BytesN<32>,
    ) -> UID {
        if attestation.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        Self::require_attester_key(&env, &attestation.attester, &public_key);
        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        let payload_hash =
            soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain);
        soroban_sas_common::verify_offchain_signature(&env, &payload_hash, &public_key, &signature);
        Self::consume_delegation_nonce(&env, &attestation.attester, nonce);

        Self::attest_internal(env, attestation)
    }

    fn attest_internal(env: Env, mut attestation: Attestation) -> UID {
        extend_instance_ttl(&env);
        // Resolved up front so a missing registry is always reported as the
        // configuration failure it is, instead of being masked by whichever
        // payload check the attestation happens to fail first.
        let registry = require_registry(&env);

        // Bound payload size before any storage, hashing, or cross-contract
        // calls so oversized attestations fail fast with a typed error. (#157)
        if attestation.data.len() > MAX_ATTESTATION_DATA_BYTES {
            panic_with_error!(&env, SASError::PayloadTooLarge);
        }

        if env.storage().persistent().has(&attestation.uid) {
            panic_with_error!(&env, SASError::DuplicateAttestation);
        }

        if attestation.expiration_time != 0
            && attestation.expiration_time <= env.ledger().timestamp()
        {
            panic_with_error!(&env, SASError::AlreadyExpired);
        }

        if let Err(err) = soroban_sas_common::validate_recipient(&env, &attestation.recipient) {
            panic_with_error!(&env, err);
        }
        if attestation.recipient == attestation.attester {
            panic_with_error!(&env, SASError::InvalidRecipient);
        }

        let schema_opt: Option<soroban_sas_common::SchemaRecord> = env.invoke_contract(
            &registry,
            &Symbol::new(&env, "get_schema"),
            soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
        );
        let Some(schema) = schema_opt else {
            panic_with_error!(&env, SASError::InvalidSchema);
        };

        // Optional resolver callback support
        let _ = env.try_invoke_contract::<(), soroban_sdk::Error>(
            &schema.resolver,
            &Symbol::new(&env, "on_attest"),
            soroban_sdk::vec![&env, attestation.clone().into_val(&env)],
        );

        // Normalize the issuance timestamp to the authoritative ledger close
        // time so that direct, delegated, batch, paid, and replacement paths
        // all record the same canonical value. (#156)
        attestation.time = env.ledger().timestamp();

        // Store the attestation
        env.storage()
            .persistent()
            .set(&attestation.uid, &attestation);
        env.storage().persistent().extend_ttl(
            &attestation.uid,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        if let Some(indexer) = env.storage().instance().get::<_, Address>(&INDEXER) {
            Self::notify_indexer_of_issuance(&env, &indexer, &attestation);
        }

        events::publish_attested(&env, &attestation);

        attestation.uid.clone()
    }

    /// Pushes a freshly issued attestation to the bound Indexer.
    ///
    /// The attestation is the protocol's source of truth; the Indexer is a
    /// downstream mirror. The default policy is therefore **fail-open**: an
    /// unavailable, upgraded, or incompatible Indexer must not roll back
    /// issuance. A failed push emits `IndexFailed(uid)` so operators can
    /// detect the gap and repair it with `reindex_attestation` (#161).
    fn notify_indexer_of_issuance(env: &Env, indexer: &Address, attestation: &Attestation) {
        let outcome = env.try_invoke_contract::<(), soroban_sdk::Error>(
            indexer,
            &Symbol::new(env, "index_attestation"),
            soroban_sdk::vec![
                env,
                attestation.uid.clone().into_val(env),
                attestation.recipient.clone().into_val(env),
                attestation.schema_uid.clone().into_val(env),
                attestation.attester.clone().into_val(env),
            ],
        );
        if matches!(outcome, Ok(Ok(()))) {
            return;
        }
        if env
            .storage()
            .instance()
            .get(&INDEXER_STRICT)
            .unwrap_or(false)
        {
            panic_with_error!(env, SASError::IndexerUnavailable);
        }
        events::publish_index_failed(env, &attestation.uid);
    }

    /// Admin: choose the Indexer availability policy (#161).
    ///
    /// `false` (default) is fail-open: a failed Indexer push is tolerated and
    /// surfaced via an `IndexFailed` event. `true` is fail-closed: a failed
    /// push aborts the attestation with `SASError::IndexerUnavailable`, which
    /// operators pair with health checks, rotation via `set_indexer`, and the
    /// `reindex_attestation` recovery path.
    pub fn set_indexer_strict(env: Env, strict: bool) {
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().set(&INDEXER_STRICT, &strict);
        extend_instance_ttl(&env);
    }

    /// Returns the current Indexer availability policy: `true` fail-closed,
    /// `false` fail-open (the default).
    pub fn get_indexer_strict(env: Env) -> bool {
        extend_instance_ttl(&env);
        env.storage().instance().get(&INDEXER_STRICT).unwrap_or(false)
    }

    /// Replays an already-issued attestation to the currently bound Indexer.
    ///
    /// Reconciliation for the fail-open policy (#161): when an `IndexFailed`
    /// event shows the mirror missed an attestation, anyone can replay it
    /// once the Indexer is healthy. Reads the stored attestation (so a caller
    /// cannot fabricate one), requires an Indexer to be bound
    /// (`NotInitialized` otherwise), and reports a still-failing Indexer as
    /// `SASError::IndexerUnavailable` so callers know to retry later. On
    /// success emits `Reindexed(uid)`.
    pub fn reindex_attestation(env: Env, uid: UID) {
        extend_instance_ttl(&env);
        let Some(attestation) = env.storage().persistent().get::<_, Attestation>(&uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        let Some(indexer) = env.storage().instance().get::<_, Address>(&INDEXER) else {
            panic_with_error!(&env, SASError::NotInitialized);
        };
        let outcome = env.try_invoke_contract::<(), soroban_sdk::Error>(
            &indexer,
            &Symbol::new(&env, "index_attestation"),
            soroban_sdk::vec![
                &env,
                attestation.uid.clone().into_val(&env),
                attestation.recipient.clone().into_val(&env),
                attestation.schema_uid.clone().into_val(&env),
                attestation.attester.clone().into_val(&env),
            ],
        );
        if !matches!(outcome, Ok(Ok(()))) {
            panic_with_error!(&env, SASError::IndexerUnavailable);
        }
        events::publish_reindexed(&env, &uid);
    }

    pub fn revoke(env: Env, uid: UID) {
        let Some(attestation) = env.storage().persistent().get::<_, Attestation>(&uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        attestation.attester.require_auth();
        Self::revoke_internal(env, uid)
    }

    pub fn revoke_by_delegation(
        env: Env,
        uid: UID,
        nonce: u64,
        signature: soroban_sdk::BytesN<64>,
        public_key: soroban_sdk::BytesN<32>,
    ) {
        let Some(attestation) = env.storage().persistent().get::<_, Attestation>(&uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        Self::require_attester_key(&env, &attestation.attester, &public_key);
        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        let payload_hash = soroban_sas_common::hash_delegated_revocation(
            &env,
            &uid,
            &attestation.attester,
            &domain,
        );
        soroban_sas_common::verify_offchain_signature(&env, &payload_hash, &public_key, &signature);
        Self::consume_delegation_nonce(&env, &attestation.attester, nonce);

        Self::revoke_internal(env, uid)
    }

    fn revoke_internal(env: Env, uid: UID) {
        extend_instance_ttl(&env);
        let Some(mut attestation) = env.storage().persistent().get::<_, Attestation>(&uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };

        if !attestation.revocable {
            panic_with_error!(&env, SASError::NotRevocable);
        }
        if attestation.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }

        let timestamp = env.ledger().timestamp();
        attestation.revocation_time = timestamp;
        env.storage().persistent().set(&uid, &attestation);
        env.storage()
            .persistent()
            .extend_ttl(&uid, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);

        events::publish_revoked(&env, &uid, timestamp);

        // Notify indexer if bound, so revoked status is observable via
        // filtered queries. Best-effort: ignore `invoke` failure if the
        // indexer does not implement the callback (e.g. legacy indexer).
        if let Some(indexer) = env.storage().instance().get::<_, Address>(&INDEXER) {
            let _ = env.try_invoke_contract::<(), soroban_sdk::Error>(
                &indexer,
                &Symbol::new(&env, "handle_revoke"),
                soroban_sdk::vec![&env, uid.clone().into_val(&env)],
            );
        }
    }

    /// Atomically replaces `old_uid` with `new_data`: revokes the old
    /// attestation and issues a new one linked to it via `ref_uid`, in a
    /// single contract execution — so consumers checking `old_uid`'s
    /// recipient never observe a window where neither attestation is valid.
    ///
    /// `new_data.ref_uid` is set to `old_uid` by this function regardless of
    /// what the caller passed, so the linkage can't be spoofed. Requires
    /// `old_uid`'s attester to authorize the call, the old attestation to be
    /// revocable and not already revoked, and `new_data.attester`/`recipient`
    /// to match the old attestation's — a replacement changes what is being
    /// claimed, not who is claiming it or about whom.
    pub fn replace_attestation(env: Env, old_uid: UID, new_data: Attestation) -> UID {
        extend_instance_ttl(&env);
        let Some(old) = env.storage().persistent().get::<_, Attestation>(&old_uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };

        old.attester.require_auth();

        if !old.revocable {
            panic_with_error!(&env, SASError::NotRevocable);
        }
        if old.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        if new_data.attester != old.attester || new_data.recipient != old.recipient {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let new_data = Attestation {
            ref_uid: old_uid.clone(),
            ..new_data
        };
        let new_uid = new_data.uid.clone();
        let old_uid_clone = old_uid.clone();
        Self::revoke_internal(env.clone(), old_uid);
        let issued_uid = Self::attest_internal(env.clone(), new_data);
        // Notify indexer about replacement linkage so history is preserved
        // and old UID can be filtered as `Replaced` while new remains `Active`.
        if let Some(indexer) = env.storage().instance().get::<_, Address>(&INDEXER) {
            let _ = env.try_invoke_contract::<(), soroban_sdk::Error>(
                &indexer,
                &Symbol::new(&env, "handle_replace"),
                soroban_sdk::vec![
                    &env,
                    old_uid_clone.into_val(&env),
                    new_uid.into_val(&env)
                ],
            );
        }
        issued_uid
    }

    pub fn multi_attest(
        env: Env,
        attestations: soroban_sdk::Vec<Attestation>,
    ) -> soroban_sdk::Vec<UID> {
        extend_instance_ttl(&env);
        if attestations.len() > MAX_MULTI_ATTEST {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }
        let mut uids = soroban_sdk::Vec::new(&env);
        let mut authorized_attesters = soroban_sdk::Map::new(&env);
        // Map lookup avoids scanning all previously authorized attesters.
        for attestation in attestations.into_iter() {
            if !authorized_attesters.contains_key(attestation.attester.clone()) {
                attestation.attester.require_auth();
                authorized_attesters.set(attestation.attester.clone(), true);
            }
            let uid = Self::attest_internal(env.clone(), attestation);
            uids.push_back(uid);
        }
        uids
    }

    /// Issues an attestation and collects the configured fee from the
    /// attester into this contract's balance.
    ///
    /// The required `(token, value)` is fixed by `set_fee` / `clear_fee`, not
    /// by the caller: a configured fee pins both the asset and the exact
    /// amount, and with no fee configured the only accepted `value` is zero.
    /// A wrong token, a short amount, or any attempt to pay a fee that was
    /// not configured fails with `SASError::FeeMismatch` before anything is
    /// recorded (#164). `value` must still be non-negative
    /// (`SASError::InvalidValue`). The transfer happens before the
    /// attestation is stored, so a failed payment aborts the whole
    /// invocation.
    pub fn attest_with_value(
        env: Env,
        attestation: Attestation,
        token: Address,
        value: i128,
    ) -> UID {
        extend_instance_ttl(&env);
        if value < 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        // Bind payment to authenticated configuration rather than caller input.
        let configured: Option<(Address, i128)> = env.storage().instance().get(&FEE_CONFIG);
        match configured {
            Some((fee_token, fee_amount)) => {
                if token != fee_token || value != fee_amount {
                    panic_with_error!(&env, SASError::FeeMismatch);
                }
            }
            None => {
                if value != 0 {
                    panic_with_error!(&env, SASError::FeeMismatch);
                }
            }
        }

        attestation.attester.require_auth();

        if value > 0 {
            token::Client::new(&env, &token).transfer(
                &attestation.attester,
                &env.current_contract_address(),
                &value,
            );
        }

        Self::attest_internal(env, attestation)
    }

    /// Revokes up to `MAX_MULTI_REVOKE` attestations atomically.
    ///
    /// Validates the whole batch before committing anything: an oversized
    /// batch or a duplicate UID fails immediately with `BatchTooLarge` /
    /// `DuplicateAttestation` before any attestation is touched. Each
    /// distinct attester authorizes at most once per batch (via a `Map`
    /// dedup, like `multi_attest`), and the actual state mutations go
    /// through `revoke_internal` so storage-read/auth work is not repeated.
    pub fn multi_revoke(env: Env, uids: soroban_sdk::Vec<UID>) {
        extend_instance_ttl(&env);
        if uids.len() > MAX_MULTI_REVOKE {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }

        let mut seen: soroban_sdk::Map<UID, bool> = soroban_sdk::Map::new(&env);
        let mut distinct: soroban_sdk::Map<Address, bool> = soroban_sdk::Map::new(&env);
        let mut to_revoke: soroban_sdk::Vec<UID> = soroban_sdk::Vec::new(&env);

        for uid in uids.iter() {
            if seen.contains_key(uid.clone()) {
                panic_with_error!(&env, SASError::DuplicateAttestation);
            }
            seen.set(uid.clone(), true);

            let Some(attestation) = env.storage().persistent().get::<_, Attestation>(&uid) else {
                panic_with_error!(&env, SASError::AttestationNotFound);
            };
            if !attestation.revocable {
                panic_with_error!(&env, SASError::NotRevocable);
            }
            if attestation.revocation_time != 0 {
                panic_with_error!(&env, SASError::AlreadyRevoked);
            }
            if !distinct.contains_key(attestation.attester.clone()) {
                distinct.set(attestation.attester.clone(), true);
            }
            to_revoke.push_back(uid);
        }
        // Authorize each distinct attester exactly once.
        for (attester, _) in distinct.iter() {
            attester.require_auth();
        }
        // All validation + auth passed; commit.
        for uid in to_revoke.iter() {
            Self::revoke_internal(env.clone(), uid);
        }
    }

    /// Registers the ed25519 public key that backs `attester`'s Stellar
    /// account, so `verify_offchain_attestation` can bind signatures to it.
    ///
    /// This is only needed as a fallback for attester addresses that
    /// `soroban_sas_common::attester_matches_key`'s structural XDR check
    /// cannot resolve on its own — e.g. any future `Address` kind beyond a
    /// classic Ed25519 account (this SDK's `ScAddress` only has `Account`
    /// and `Contract` today, but newer Stellar protocol versions add
    /// multiplexed accounts and other address kinds). Standard account
    /// attesters do not need to call this at all.
    ///
    /// Requires `attester.require_auth()`, so only the address owner can
    /// bind a key to it.
    pub fn register_attester_key(env: Env, attester: Address, public_key: soroban_sdk::BytesN<32>) {
        extend_instance_ttl(&env);
        attester.require_auth();
        let key = (ATTESTER_KEY, attester);
        env.storage().persistent().set(&key, &public_key);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
    }

    /// Returns true if `public_key` was explicitly registered for `attester`
    /// via `register_attester_key`.
    fn registered_key_matches(
        env: &Env,
        attester: &Address,
        public_key: &soroban_sdk::BytesN<32>,
    ) -> bool {
        env.storage()
            .persistent()
            .get::<_, soroban_sdk::BytesN<32>>(&(ATTESTER_KEY, attester.clone()))
            .is_some_and(|registered| registered == *public_key)
    }

    fn require_attester_key(env: &Env, attester: &Address, public_key: &soroban_sdk::BytesN<32>) {
        if !soroban_sas_common::attester_matches_key(env, attester, public_key)
            && !Self::registered_key_matches(env, attester, public_key)
        {
            panic_with_error!(env, SASError::Unauthorized);
        }
    }

    fn consume_delegation_nonce(env: &Env, attester: &Address, nonce: u64) {
        extend_instance_ttl(env);
        let key = (DELEGATION_NONCE, attester.clone());
        if let Some(last) = env.storage().instance().get::<_, u64>(&key) {
            if nonce <= last {
                panic_with_error!(env, SASError::DelegationReplay);
            }
        }
        env.storage().instance().set(&key, &nonce);
        extend_instance_ttl(env);
    }

    /// Verifies off-chain attestation signed by attester's ed25519 key.
    /// Panics Unauthorized, AlreadyRevoked, AlreadyExpired, InvalidSchema
    /// (unknown/deprecated schema), or ed25519 error. Schema check mirrors
    /// on-chain attest: deprecated invalidates prior signatures as well.
    /// Resolver not invoked (read-only), but schema existence is consistent.
    pub fn verify_offchain_attestation(
        env: Env,
        attestation: Attestation,
        nonce: u64,
        public_key: soroban_sdk::BytesN<32>,
        signature: soroban_sdk::BytesN<64>,
    ) -> bool {
        extend_instance_ttl(&env);
        Self::require_attester_key(&env, &attestation.attester, &public_key);

        if attestation.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        if attestation.expiration_time != 0
            && env.ledger().timestamp() >= attestation.expiration_time
        {
            panic_with_error!(&env, SASError::AlreadyExpired);
        }

        // An on-chain revocation of the same UID also invalidates the
        // off-chain copy.
        if let Some(stored) = env
            .storage()
            .persistent()
            .get::<_, Attestation>(&attestation.uid)
        {
            env.storage().persistent().extend_ttl(
                &attestation.uid,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
            if stored.revocation_time != 0 {
                panic_with_error!(&env, SASError::AlreadyRevoked);
            }
        }

        // --- Schema availability check (same as on-chain attest) ---
        // Unknown or deprecated schemas are rejected with InvalidSchema.
        // Deprecated schemas invalidate previously signed payloads as well,
        // not just new issuance; see doc comment above.
        let registry = require_registry(&env);
        let schema_opt: Option<soroban_sas_common::SchemaRecord> = env.invoke_contract(
            &registry,
            &Symbol::new(&env, "get_schema"),
            soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
        );
        if schema_opt.is_none() {
            panic_with_error!(&env, SASError::InvalidSchema);
        }
        // Resolver callback is intentionally not invoked for off-chain
        // verification (read-only); see doc comment.

        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        let payload_hash =
            soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain);
        soroban_sas_common::verify_offchain_signature(&env, &payload_hash, &public_key, &signature);

        true
    }

    pub fn verify_attestation(env: Env, uid: UID) -> bool {
        extend_instance_ttl(&env);
        if let Some(attestation) = env.storage().persistent().get::<_, Attestation>(&uid) {
            env.storage()
                .persistent()
                .extend_ttl(&uid, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
            if attestation.revocation_time != 0 {
                return false;
            }
            if attestation.expiration_time != 0
                && env.ledger().timestamp() >= attestation.expiration_time
            {
                return false;
            }
            true
        } else {
            false
        }
    }

    /// Fetch an attestation by UID with TTL renewal. This is the
    /// SDK-supported view that keeps live entries from expiring: on a
    /// successful read the entry's TTL is bumped by `LEDGERS_IN_ONE_YEAR`.
    ///
    /// Returns `None` when the UID was never issued or has been
    /// garbage-collected. When the entry is archived the host traps
    /// before this code runs; callers should treat a simulation error
    /// containing "archived" as `Archived` (needs `restoreFootprint`)
    /// rather than `NotFound`. The SDK's `fetch_attestation_status`
    /// helper surfaces that distinction as a structured
    /// `AttestationResult::Archived`.
    pub fn get_attestation(env: Env, uid: UID) -> Option<Attestation> {
        if let Some(attestation) = env.storage().persistent().get::<_, Attestation>(&uid) {
            env.storage()
                .persistent()
                .extend_ttl(&uid, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
            Some(attestation)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_extra;
