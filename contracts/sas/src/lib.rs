#![allow(unexpected_cfgs)]
#![cfg_attr(not(test), no_std)]

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod frost_test;

use soroban_sas_common::{
    merkle::{verify_proof, MerkleRoot},
    Attestation, CompactAttestation, CompactAttestationKey, ContractUpgradedEvent,
    DelegationAuthorization, DelegationNonceKey, DelegationSchemaScope, FeeCeilings, FrostGroup,
    MerkleProofStep, RecipientConsentNonceKey, SASError, SchemaFeeConfig,
    SchemaMerkleRootUpdatedEvent, LEDGERS_IN_ONE_YEAR, MAX_ATTESTATION_DATA_BYTES, UID,
};
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, symbol_short, token, Address, Bytes,
    BytesN, Env, IntoVal, Symbol, TryFromVal, Val,
};

mod events;
mod merkle_disclosure;
mod timestamp;

// v1.0.0 State Schema Frozen

#[contract]
pub struct SAS;

pub const SAS_ADMIN: Symbol = symbol_short!("ADMIN");
pub const PENDING_ADMIN: Symbol = symbol_short!("PEND_ADM");
pub const SCHEMA_REGISTRY: Symbol = symbol_short!("REGISTRY");
pub const INDEXER: Symbol = symbol_short!("INDEXER");
pub const TREASURY: Symbol = symbol_short!("TREASURY");
/// Instance key for the `(fee_token, fee_amount)` pair required by
/// `attest_with_value`. Absent means attestation is fee-free (#164).
pub const FEE_CONFIG: Symbol = symbol_short!("FEECFG");
/// Storage key for schema creator custom fee configuration (#434).
/// Stored under `(SCHEMA_FEE_CONFIG, schema_uid) -> SchemaFeeConfig`.
pub const SCHEMA_FEE_CONFIG: Symbol = symbol_short!("SCHFEE");
/// Storage key for accumulated treasury fee balance (#434).
/// Stored under `(TREASURY_FEES, token) -> i128`.
pub const TREASURY_FEES: Symbol = symbol_short!("TRSFEE");
/// Storage key for accumulated schema creator fee balances (#434).
/// Stored under `(CREATOR_FEES, creator, token) -> i128`.
pub const CREATOR_FEES: Symbol = symbol_short!("CREFEE");
/// Storage key for protocol fee ceilings (#434).
/// Stored under `FEE_CEILINGS -> FeeCeilings`.
pub const FEE_CEILINGS: Symbol = symbol_short!("FEECMAX");
/// Protocol maximum allowable basis points for creator royalties (100% = 10,000 bps) (#434).
pub const MAX_CREATOR_BPS: u32 = 10_000;
/// Additional amount per data byte charged by the paid issuance path (#526).
pub const FEE_PER_BYTE: Symbol = symbol_short!("FEEBYTE");
/// Persistent key namespace for explicitly fee-exempt schemas.
pub const ZERO_FEE_SCHEMA: Symbol = symbol_short!("ZEROFEE");
/// Explicit per-attester scope on registered delegation keys (#527).
pub const DELEGATION_POLICY: Symbol = symbol_short!("DELPOL");
/// Address of a proof system verifier implementing `verify_proof` (#531).
pub const ZK_VERIFIER: Symbol = symbol_short!("ZKVERIFY");

pub const DELEGATION_PERMISSION_ISSUE: u32 = 1;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationPolicy {
    /// None allows any registered schema. Some(uid) limits the key to uid.
    pub authorized_schema_uid: DelegationSchemaScope,
    pub permissions: u32,
    /// Zero has no expiry; otherwise the last valid ledger timestamp.
    pub valid_until: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum ZkNullifierKey {
    Used(BytesN<32>),
}

/// Additional SAC fee assets; the legacy FEE_CONFIG stays the default.
pub const FEE_ASSET: Symbol = symbol_short!("FEEASSET");
pub const MULTI_ASSET_ACTIVE: Symbol = symbol_short!("MULTIFEE");
/// Instance configuration (maximum issuances, rolling ledger width).
pub const RATE_LIMIT_CONFIG: Symbol = symbol_short!("RATECFG");
pub const RATE_EXEMPT: Symbol = symbol_short!("RATEEX");
/// Temporary per-attester issuance ledger sequences (bounded by quota).
pub const RATE_HISTORY: Symbol = symbol_short!("RATEHIST");
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
pub const RECIPIENT_CONSENT_NONCE: Symbol = symbol_short!("RCONSENT");
pub const VALID_FROM: Symbol = symbol_short!("V_FROM");
/// Monotonic contract version. Missing on legacy initialized deployments,
/// which are treated as genesis version 1.
pub const SAS_VERSION: Symbol = symbol_short!("VERSION");
/// Hash targeted by the most recent successful upgrade invocation.
pub const CURRENT_WASM_HASH: Symbol = symbol_short!("WASMHASH");
/// Emergency pause flag. When `true`, write operations are blocked (#255).
pub const PAUSED: Symbol = symbol_short!("PAUSED");
/// Highest version whose upgrade path this build knows and has been audited
/// to activate. Increase only as part of a reviewed release.
pub const MAX_KNOWN_VERSION: u32 = 2;
/// Maximum number of attestations in one multi_attest invocation. This keeps
/// authorization and storage work within the measured Soroban budget envelope.
pub const MAX_MULTI_ATTEST: u32 = soroban_sas_common::MAX_MULTI_ATTEST;
/// Maximum number of UIDs in one multi_revoke invocation. Bounded like
/// `MAX_MULTI_ATTEST` so the loop cannot exhaust the Soroban budget and
/// callers get a predictable `BatchTooLarge` error up front.
pub const MAX_MULTI_REVOKE: u32 = 100;
/// Maximum number of UIDs in one `revoke_by_schema` invocation. Bounded like
/// `MAX_MULTI_REVOKE` so the loop cannot exhaust the Soroban budget and
/// callers get a predictable `BatchTooLarge` error up front.
pub const MAX_REVOKE_BY_SCHEMA: u32 = 100;
/// Ceiling on how many UIDs one `verify_attestations` /
/// `verify_all_attestations` call may check. Verification is a read (plus TTL
/// renewal), but the bound keeps the worst-case cost of a single invocation
/// predictable and matches the other batch entrypoints, so callers learn about
/// oversized batches up front as `BatchTooLarge` (#297).
pub const MAX_VERIFY_BATCH: u32 = 100;
/// Instance key for the `multi_attest` reentrancy guard. It is held (`true`)
/// for the duration of a batch and removed on the success path; a nested
/// `multi_attest` while it is held aborts with `SASError::Reentrancy` (#296).
pub const REENTRANCY_GUARD: Symbol = symbol_short!("REENTRY");
/// Instance key for the expired-attestation auto-pruning toggle. When `true`,
/// anyone may call `prune_expired` to delete expired records. Absent or
/// `false` (the default) leaves expired records in storage (#432).
pub const AUTO_PRUNE: Symbol = symbol_short!("AUTOPRUNE");
/// Ceiling on how many UIDs one `prune_expired` call may process.
pub const MAX_PRUNE_BATCH: u32 = 100;
/// Active guarded execution frames (callbacks and nested internal operations).
pub const CALL_DEPTH: Symbol = symbol_short!("CALLDEP");
const REGISTRY_INTERFACE_VERSION: Symbol = symbol_short!("SASREG");

fn extend_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
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

/// Asks the registry whether `attester` is on schema `schema_uid`'s attester
/// access control list and whether the schema has one at all (#443).
///
/// Returns `(on_acl, restricted)`. Both probes are best effort: a registry
/// that predates ACL support, or any failed call, yields `false` for that
/// half, which leaves the caller on the original `Unauthorized` path. It is
/// only consulted after `is_authorized` has already declined an issuer, so
/// owners and delegates never pay for the extra cross-contract calls.
fn schema_attester_acl_status(
    env: &Env,
    registry: &Address,
    schema_uid: &UID,
    attester: &Address,
) -> (bool, bool) {
    let on_acl: bool = match env.try_invoke_contract::<bool, soroban_sdk::Error>(
        registry,
        &Symbol::new(env, "is_attester_authorized"),
        soroban_sdk::vec![
            env,
            schema_uid.clone().into_val(env),
            attester.clone().into_val(env),
        ],
    ) {
        Ok(Ok(allowed)) => allowed,
        _ => false,
    };
    if on_acl {
        return (true, true);
    }
    let restricted: bool = match env.try_invoke_contract::<bool, soroban_sdk::Error>(
        registry,
        &Symbol::new(env, "is_schema_restricted"),
        soroban_sdk::vec![env, schema_uid.clone().into_val(env)],
    ) {
        Ok(Ok(restricted)) => restricted,
        _ => false,
    };
    (false, restricted)
}

/// Reads the schema registry recorded by `init`, or panics `NotInitialized`.
/// Companion to [`require_admin`]; see that guard for the rationale.
fn require_registry(env: &Env) -> Address {
    match env.storage().instance().get(&SCHEMA_REGISTRY) {
        Some(registry) => registry,
        None => panic_with_error!(env, SASError::NotInitialized),
    }
}

/// Splits an attestation fee between the protocol treasury and the schema
/// creator (#538).
///
/// Creator share is `value * bps / 10_000`, rounded down. The remainder stays
/// with the treasury, so the two shares always add back to `value`. A registry
/// that does not expose royalty (or a schema with `0` bps and no treasury)
/// leaves the fee on this contract, matching the pre-split withdraw path.
fn distribute_attestation_fee(env: &Env, schema_uid: &UID, token: &Address, value: i128) {
    let Ok(registry) = env
        .storage()
        .instance()
        .get::<_, Address>(&SCHEMA_REGISTRY)
        .ok_or(())
    else {
        return;
    };
    let bps: u32 = match env.try_invoke_contract::<u32, soroban_sdk::Error>(
        &registry,
        &Symbol::new(env, "get_creator_royalty"),
        soroban_sdk::vec![env, schema_uid.clone().into_val(env)],
    ) {
        Ok(Ok(bps)) => bps,
        _ => return,
    };
    if bps > 5_000 {
        panic_with_error!(env, SASError::InvalidValue);
    }
    let creator_amount = value
        .checked_mul(i128::from(bps))
        .and_then(|product| product.checked_div(10_000))
        .unwrap_or_else(|| panic_with_error!(env, SASError::InvalidValue));
    let treasury_amount = value
        .checked_sub(creator_amount)
        .unwrap_or_else(|| panic_with_error!(env, SASError::InvalidValue));

    let treasury: Option<Address> = env.storage().instance().get(&TREASURY);
    if treasury.is_none() && creator_amount == 0 {
        return;
    }
    let treasury = treasury.unwrap_or_else(|| panic_with_error!(env, SASError::TreasuryNotSet));
    let token_client = token::Client::new(env, token);
    if treasury_amount > 0 {
        token_client.transfer(&env.current_contract_address(), &treasury, &treasury_amount);
    }
    if creator_amount > 0 {
        let creator = match env.try_invoke_contract::<Option<Address>, soroban_sdk::Error>(
            &registry,
            &Symbol::new(env, "get_creator"),
            soroban_sdk::vec![env, schema_uid.clone().into_val(env)],
        ) {
            Ok(Ok(Some(creator))) => creator,
            _ => panic_with_error!(env, SASError::SchemaNotFound),
        };
        token_client.transfer(&env.current_contract_address(), &creator, &creator_amount);
    }

    env.events().publish(
        (
            soroban_sas_common::events::FEE_DISTRIBUTED,
            schema_uid.clone(),
        ),
        (treasury_amount, creator_amount),
    );
}

/// Checks if the contract is paused. Returns `true` if paused, `false` otherwise.
fn is_paused_status(env: &Env) -> bool {
    env.storage().instance().get(&PAUSED).unwrap_or(false)
}

/// Quote a paid issuance, using a single multiplication and addition regardless
/// of payload size. Explicit per-schema exemptions always take precedence.
fn fee_quote(env: &Env, schema_uid: &UID, size: u32) -> i128 {
    if size > MAX_ATTESTATION_DATA_BYTES {
        panic_with_error!(env, SASError::PayloadTooLarge);
    }
    if env
        .storage()
        .persistent()
        .get::<_, bool>(&(ZERO_FEE_SCHEMA, schema_uid.clone()))
        .unwrap_or(false)
    {
        return 0;
    }
    let base = env
        .storage()
        .instance()
        .get::<_, (Address, i128)>(&FEE_CONFIG)
        .map(|(_, amount)| amount)
        .unwrap_or(0);
    let per_byte: i128 = env.storage().instance().get(&FEE_PER_BYTE).unwrap_or(0);
    match per_byte
        .checked_mul(i128::from(size))
        .and_then(|extra| base.checked_add(extra))
    {
        Some(value) => value,
        None => panic_with_error!(env, SASError::InvalidValue),
    }
}

/// Prevent fee bypass through legacy no-payment issuance entrypoints when the
/// opt-in size-based fee policy is enabled. Exempt schemas remain free.
fn require_unpaid_allowed(env: &Env, attestation: &Attestation) {
    let rate: i128 = env.storage().instance().get(&FEE_PER_BYTE).unwrap_or(0);
    if rate > 0 && fee_quote(env, &attestation.schema_uid, attestation.data.len()) > 0 {
        panic_with_error!(env, SASError::InsufficientFee);
    }
}

/// Enforces a root-attester-approved policy even on the legacy delegated
/// entrypoints, so calling an older API cannot bypass an active restriction.
fn require_delegation_policy(env: &Env, attester: &Address, schema_uid: &UID) {
    let key = (DELEGATION_POLICY, attester.clone());
    let Some(policy) = env.storage().persistent().get::<_, DelegationPolicy>(&key) else {
        return;
    };
    if policy.permissions & DELEGATION_PERMISSION_ISSUE == 0
        || (policy.valid_until != 0 && env.ledger().timestamp() > policy.valid_until)
        || matches!(
            &policy.authorized_schema_uid,
            DelegationSchemaScope::Only(uid) if uid != schema_uid
        )
    {
        panic_with_error!(env, SASError::DelegationScopeDenied);
    }
}

/// Marks `multi_attest` as in progress, rejecting a nested invocation.
///
/// The host refuses direct cross-contract re-entry before this can fire, so
/// the guard is defense-in-depth: it pins the invariant on the contract itself
/// rather than relying on the host's current behaviour.
///
/// Soroban rolls back every storage write made by a panicking invocation, so
/// a trap inside the guarded section cannot leave the guard behind; only the
/// success path needs to release it via [`exit_reentrancy_guard`].
fn enter_reentrancy_guard(env: &Env) {
    if env
        .storage()
        .instance()
        .get::<_, bool>(&REENTRANCY_GUARD)
        .unwrap_or(false)
    {
        panic_with_error!(env, SASError::Reentrancy);
    }
    env.storage().instance().set(&REENTRANCY_GUARD, &true);
}

/// Releases the `multi_attest` reentrancy guard on the success path.
fn exit_reentrancy_guard(env: &Env) {
    env.storage().instance().remove(&REENTRANCY_GUARD);
}

/// All public mutating entrypoints must reject a callback into SAS.
fn reject_reentrant(env: &Env) {
    let guarded = env
        .storage()
        .instance()
        .get::<_, bool>(&REENTRANCY_GUARD)
        .unwrap_or(false);
    let depth = env
        .storage()
        .instance()
        .get::<_, u32>(&CALL_DEPTH)
        .unwrap_or(0);
    if guarded || depth > 0 {
        panic_with_error!(env, SASError::ReentrancyDetected);
    }
}

/// The batch entrypoints already hold the outer guard. Every private
/// callback-capable operation increments the context depth and releases
/// precisely its own frame on normal return.
fn enter_callback_context(env: &Env) -> bool {
    let guarded = env
        .storage()
        .instance()
        .get::<_, bool>(&REENTRANCY_GUARD)
        .unwrap_or(false);
    let depth = env
        .storage()
        .instance()
        .get::<_, u32>(&CALL_DEPTH)
        .unwrap_or(0);
    let next = depth.checked_add(1).unwrap_or_else(|| {
        panic_with_error!(env, SASError::ReentrancyDetected);
    });
    env.storage().instance().set(&CALL_DEPTH, &next);
    if !guarded {
        env.storage().instance().set(&REENTRANCY_GUARD, &true);
    }
    !guarded
}

fn exit_callback_context(env: &Env, owns_guard: bool) {
    let depth = env
        .storage()
        .instance()
        .get::<_, u32>(&CALL_DEPTH)
        .unwrap_or(0);
    if depth <= 1 {
        env.storage().instance().remove(&CALL_DEPTH);
    } else {
        env.storage().instance().set(&CALL_DEPTH, &(depth - 1));
    }
    if owns_guard {
        exit_reentrancy_guard(env);
    }
}

/// Sliding-window quota with bounded temporary storage. Old ledger entries
/// are discarded on every successful issuance; the key auto-expires.
fn consume_issuance_quota(env: &Env, attester: &Address) {
    let Some((max_issuances, window)): Option<(u32, u32)> =
        env.storage().instance().get(&RATE_LIMIT_CONFIG)
    else {
        return;
    };
    if env
        .storage()
        .instance()
        .get::<_, bool>(&(RATE_EXEMPT, attester.clone()))
        .unwrap_or(false)
    {
        return;
    }
    let key = (RATE_HISTORY, attester.clone());
    let prior: soroban_sdk::Vec<u32> = env
        .storage()
        .temporary()
        .get(&key)
        .unwrap_or_else(|| soroban_sdk::Vec::new(env));
    let now = env.ledger().sequence();
    let oldest = now.saturating_sub(window.saturating_sub(1));
    let mut recent = soroban_sdk::Vec::new(env);
    for issued_at in prior.iter() {
        if issued_at >= oldest && issued_at <= now {
            recent.push_back(issued_at);
        }
    }
    if recent.len() >= max_issuances {
        panic_with_error!(env, SASError::RateLimitExceeded);
    }
    recent.push_back(now);
    env.storage().temporary().set(&key, &recent);
    env.storage().temporary().extend_ttl(&key, window, window);
}

/// Returns the EIP-712 domain separator fields for off-chain structured
/// message signing. Wallet connectors (Freighter `signAuthEntry`, Albedo,
/// MetaMask Snaps) display these fields so users can verify what they sign.
///
/// The domain binds signatures to this network and contract address, matching
/// the on-chain `AttestationDomain` used by `attest_by_delegation`.
pub fn eip712_domain(env: &Env) -> soroban_sas_common::Eip712Domain {
    soroban_sas_common::Eip712Domain {
        name: soroban_sdk::String::from_str(env, "Stellar Attestation Service"),
        version: soroban_sdk::String::from_str(env, "1"),
        chain_id: env.ledger().network_id(),
        verifying_contract: env.current_contract_address(),
    }
}
/// Validates that an attestation has not expired. Returns `Ok(())` if valid,
/// or `Err(SASError::AlreadyExpired)` if the expiration time is set and has passed.
fn validate_expiration(env: &Env, expiration_time: u64) -> Result<(), SASError> {
    if expiration_time != 0 && expiration_time <= env.ledger().timestamp() {
        return Err(SASError::AlreadyExpired);
    }
    Ok(())
}

fn required_upgrade_address(env: &Env, key: &Symbol) -> Result<Address, SASError> {
    let Some(raw): Option<Val> = env.storage().instance().get(key) else {
        return Err(SASError::IncompatibleDependency);
    };
    Address::try_from_val(env, &raw).map_err(|_| SASError::IncompatibleDependency)
}

/// Reads an attestation record by UID, seamlessly supporting both the compact internal
/// storage layout ([`CompactAttestation`]) and legacy full [`Attestation`] records (#438).
fn read_attestation(env: &Env, uid: &UID) -> Option<Attestation> {
    let compact_key = CompactAttestationKey { uid: uid.clone() };
    let mut attestation = if let Some(compact) = env
        .storage()
        .persistent()
        .get::<_, CompactAttestation>(&compact_key)
    {
        Some(compact.to_attestation(env, uid))
    } else if let Some(val) = env.storage().persistent().get::<_, Val>(uid) {
        if let Ok(compact) = CompactAttestation::try_from_val(env, &val) {
            Some(compact.to_attestation(env, uid))
        } else if let Ok(legacy) = Attestation::try_from_val(env, &val) {
            Some(legacy)
        } else {
            None
        }
    } else {
        None
    }?;

    let v_key = (VALID_FROM, uid.clone());
    if let Some(valid_from) = env.storage().persistent().get(&v_key) {
        attestation.valid_from = valid_from;
    }

    Some(attestation)
}

/// Checks whether an attestation exists under either the compact or legacy key.
fn has_attestation(env: &Env, uid: &UID) -> bool {
    let compact_key = CompactAttestationKey { uid: uid.clone() };
    env.storage().persistent().has(&compact_key) || env.storage().persistent().has(uid)
}

/// Writes an attestation in the optimized [`CompactAttestation`] storage layout (#438).
fn write_attestation(env: &Env, attestation: &Attestation, ttl: u32) {
    let compact = CompactAttestation::from_attestation(env, attestation);
    let compact_key = CompactAttestationKey {
        uid: attestation.uid.clone(),
    };
    if env.storage().persistent().has(&compact_key) {
        env.storage().persistent().set(&compact_key, &compact);
        env.storage()
            .persistent()
            .extend_ttl(&compact_key, ttl, ttl);
    } else {
        env.storage().persistent().set(&attestation.uid, &compact);
        env.storage()
            .persistent()
            .extend_ttl(&attestation.uid, ttl, ttl);
    }
    let v_key = (VALID_FROM, attestation.uid.clone());
    if attestation.valid_from != 0 {
        env.storage()
            .persistent()
            .set(&v_key, &attestation.valid_from);
        env.storage().persistent().extend_ttl(&v_key, ttl, ttl);
    } else if env.storage().persistent().has(&v_key) {
        env.storage().persistent().remove(&v_key);
    }
}

/// Extends the storage TTL for an attestation across its storage key.
fn extend_attestation_ttl(env: &Env, uid: &UID, ttl: u32) {
    let compact_key = CompactAttestationKey { uid: uid.clone() };
    if env.storage().persistent().has(&compact_key) {
        env.storage()
            .persistent()
            .extend_ttl(&compact_key, ttl, ttl);
    }
    if env.storage().persistent().has(uid) {
        env.storage().persistent().extend_ttl(uid, ttl, ttl);
    }
    let v_key = (VALID_FROM, uid.clone());
    if env.storage().persistent().has(&v_key) {
        env.storage().persistent().extend_ttl(&v_key, ttl, ttl);
    }
}

/// Whether an attestation is currently usable: issued (already read), not
/// revoked, past its `valid_from` activation time (when set), and not
/// expired. Read-only; callers decide whether to renew the entry's TTL.
fn attestation_is_live(env: &Env, attestation: &Attestation) -> bool {
    if attestation.revocation_time != 0 {
        return false;
    }
    if attestation.valid_from != 0 && env.ledger().timestamp() < attestation.valid_from {
        return false;
    }
    validate_expiration(env, attestation.expiration_time).is_ok()
}

/// Removes every persistent entry that belongs to an attestation: the compact
/// and legacy records, the `valid_from` side entry and both timestamp anchors.
fn remove_attestation(env: &Env, uid: &UID) {
    let storage = env.storage().persistent();
    storage.remove(&CompactAttestationKey { uid: uid.clone() });
    storage.remove(uid);
    storage.remove(&(VALID_FROM, uid.clone()));
    timestamp::remove_anchors(env, uid);
}

/// Shared verdict for a single attestation UID (#297).
///
/// Both the single-UID entrypoint ([`SAS::verify_attestation`]) and the batch
/// entrypoints ([`SAS::verify_attestations`] / [`SAS::verify_all_attestations`])
/// route through this function, so a batched verdict can never disagree with
/// the equivalent single-call verdict. A live record has its persistent TTL
/// renewed on every check, exactly as the single-UID path always did; a
/// missing or archived UID is simply `false` and writes nothing.
fn verify_attestation_record(env: &Env, uid: &UID) -> bool {
    let Some(attestation) = read_attestation(env, uid) else {
        return false;
    };

    let ttl = SAS::compute_storage_ttl(env, attestation.expiration_time);
    extend_attestation_ttl(env, uid, ttl);

    if attestation.revocation_time != 0 {
        return false;
    }
    if attestation.valid_from != 0 && env.ledger().timestamp() < attestation.valid_from {
        return false;
    }
    if validate_expiration(env, attestation.expiration_time).is_err() {
        return false;
    }
    true
}

fn validate_upgrade(
    env: &Env,
    new_wasm_hash: &BytesN<32>,
    new_version: u32,
) -> Result<Address, SASError> {
    // This is a pre-activation sanity read of the existing layout. It cannot
    // execute or inspect the candidate WASM before Soroban installs it.
    let admin = required_upgrade_address(env, &SAS_ADMIN)?;
    let _registry = required_upgrade_address(env, &SCHEMA_REGISTRY)?;
    if env.storage().instance().has(&INDEXER) {
        let _indexer = required_upgrade_address(env, &INDEXER)?;
    }

    let old_version = env.storage().instance().get(&SAS_VERSION).unwrap_or(1u32);
    if new_version > MAX_KNOWN_VERSION {
        return Err(SASError::IncompatibleDependency);
    }
    if new_version != old_version.saturating_add(1) {
        return Err(SASError::InvalidValue);
    }
    if new_wasm_hash.to_array() == [0u8; 32] {
        return Err(SASError::InvalidValue);
    }
    Ok(admin)
}

fn commit_upgrade(env: &Env, admin: &Address, new_wasm_hash: &BytesN<32>, new_version: u32) {
    let old_wasm_hash = env
        .storage()
        .instance()
        .get(&CURRENT_WASM_HASH)
        .unwrap_or_else(|| BytesN::from_array(env, &[0u8; 32]));

    env.storage().instance().set(&SAS_VERSION, &new_version);
    env.storage()
        .instance()
        .set(&CURRENT_WASM_HASH, new_wasm_hash);
    events::publish_contract_upgraded(
        env,
        ContractUpgradedEvent {
            old_wasm_hash,
            new_wasm_hash: new_wasm_hash.clone(),
            authorizer: admin.clone(),
        },
    );
}

#[contractimpl]
impl SAS {
    /// Compatibility probe used by `Indexer::init` before binding to this
    /// contract as its SAS address — confirms the address is a real SAS v1
    /// contract rather than merely a contract address.
    pub fn sasv1(_env: Env) -> bool {
        true
    }

    /// Returns the current contract administrator.
    ///
    /// Panics with [`SASError::NotInitialized`] when the contract has not
    /// been initialized yet.
    pub fn admin(env: Env) -> Address {
        extend_instance_ttl(&env);
        require_admin(&env)
    }

    pub fn init(env: Env, admin: Address, registry: Address) {
        reject_reentrant(&env);
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
        if !env.storage().instance().has(&SAS_VERSION) {
            env.storage().instance().set(&SAS_VERSION, &1u32);
        }
        extend_instance_ttl(&env);
    }

    /// Returns the current monotonic contract version. Legacy initialized
    /// instances without the version key are treated as genesis version 1.
    pub fn get_version(env: Env) -> u32 {
        extend_instance_ttl(&env);
        env.storage().instance().get(&SAS_VERSION).unwrap_or(1)
    }

    /// Activates the next audited WASM version in place.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>, new_version: u32) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let layout_admin = match validate_upgrade(&env, &new_wasm_hash, new_version) {
            Ok(values) => values,
            Err(error) => panic_with_error!(&env, error),
        };
        let admin = require_admin(&env);
        if admin != layout_admin {
            panic_with_error!(&env, SASError::IncompatibleDependency);
        }
        admin.require_auth();

        commit_upgrade(&env, &admin, &new_wasm_hash, new_version);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Step 1 of two-step admin transfer (#228).
    /// Current admin authorizes proposing `new_admin`.
    /// Overwrites any pending proposal (allows cancellation by re-proposing self or another).
    /// Emits `AdminTransferProposed`.
    pub fn propose_admin(env: Env, new_admin: Address) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let current_admin = require_admin(&env);
        current_admin.require_auth();

        env.storage().instance().set(&PENDING_ADMIN, &new_admin);
        extend_instance_ttl(&env);

        events::publish_admin_transfer_proposed(&env, &current_admin, &new_admin);
    }

    /// Step 2 of two-step admin transfer (#228).
    /// Pending admin authorizes accepting ownership.
    /// Panics `NotInitialized` if no proposal is pending.
    /// Overwrites `SAS_ADMIN` with `pending_admin` and removes `PENDING_ADMIN`.
    /// Emits `AdminTransferCompleted`.
    pub fn accept_admin(env: Env) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let pending_admin: Address = match env.storage().instance().get(&PENDING_ADMIN) {
            Some(admin) => admin,
            None => panic_with_error!(&env, SASError::NotInitialized),
        };
        pending_admin.require_auth();

        let old_admin = require_admin(&env);
        env.storage().instance().set(&SAS_ADMIN, &pending_admin);
        env.storage().instance().remove(&PENDING_ADMIN);
        extend_instance_ttl(&env);

        events::publish_admin_transfer_completed(&env, &old_admin, &pending_admin);
    }

    /// Restrict a registered delegation key to one schema and/or expiry.
    /// This is an attester-authorized policy and applies to legacy signing APIs.
    pub fn set_delegation_policy(env: Env, attester: Address, policy: DelegationPolicy) {
        attester.require_auth();
        let key = (DELEGATION_POLICY, attester);
        env.storage().persistent().set(&key, &policy);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        extend_instance_ttl(&env);
    }

    pub fn get_delegation_policy(env: Env, attester: Address) -> Option<DelegationPolicy> {
        extend_instance_ttl(&env);
        env.storage()
            .persistent()
            .get(&(DELEGATION_POLICY, attester))
    }

    /// Emergency pause: blocks all write operations while keeping read-only
    /// operations active (#255). Only the admin can pause. Emits `ContractPaused`.
    pub fn pause(env: Env) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().set(&PAUSED, &true);
        extend_instance_ttl(&env);
        events::publish_contract_paused(&env, admin.clone());
        events::publish_protocol_paused(&env, admin);
    }

    /// Emergency unpause: resumes write operations after a `pause` (#255).
    /// Only the admin can unpause. Emits `ContractUnpaused`.
    pub fn unpause(env: Env) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().set(&PAUSED, &false);
        extend_instance_ttl(&env);
        events::publish_contract_unpaused(&env, admin.clone());
        events::publish_protocol_unpaused(&env, admin);
    }

    /// Public read: returns whether the contract is currently paused (#255).
    /// Read-only entry points remain active even when paused.
    pub fn is_paused(env: Env) -> bool {
        extend_instance_ttl(&env);
        is_paused_status(&env)
    }

    /// Returns the bound indexer, if one has been configured.
    pub fn get_indexer(env: Env) -> Option<Address> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&INDEXER)
    }

    /// Binds an Indexer contract that should mirror newly issued attestations.
    pub fn set_indexer(env: Env, indexer: Address) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        let old_indexer: Option<Address> = env.storage().instance().get(&INDEXER);
        env.storage().instance().set(&INDEXER, &indexer);
        events::publish_indexer_updated(&env, old_indexer, indexer, admin);
        extend_instance_ttl(&env);
    }

    pub fn set_treasury(env: Env, treasury: Address) {
        reject_reentrant(&env);
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

    /// Configures another authorized Stellar Asset Contract fee option.
    /// Does not change the original set_fee / get_fee interface.
    pub fn set_accepted_fee(env: Env, token: Address, amount: i128) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        env.storage().instance().set(&(FEE_ASSET, token), &amount);
        env.storage().instance().set(&MULTI_ASSET_ACTIVE, &true);
    }

    /// Removes an additional accepted fee token without touching the default.
    pub fn remove_accepted_fee(env: Env, token: Address) {
        reject_reentrant(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().remove(&(FEE_ASSET, token));
        extend_instance_ttl(&env);
    }

    pub fn get_accepted_fee(env: Env, token: Address) -> Option<i128> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&(FEE_ASSET, token))
    }

    /// Admin-configured limit; zero is not a valid quota.
    /// Both limits are bounded to keep temporary history cheap.
    pub fn set_issuance_rate_limit(env: Env, max_issuances: u32, window: u32) {
        reject_reentrant(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        if max_issuances == 0 || max_issuances > 100 || window == 0 || window > 10_000 {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        env.storage()
            .instance()
            .set(&RATE_LIMIT_CONFIG, &(max_issuances, window));
        extend_instance_ttl(&env);
    }

    pub fn clear_issuance_rate_limit(env: Env) {
        reject_reentrant(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().remove(&RATE_LIMIT_CONFIG);
        extend_instance_ttl(&env);
    }

    pub fn get_issuance_rate_limit(env: Env) -> Option<(u32, u32)> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&RATE_LIMIT_CONFIG)
    }

    pub fn set_rate_limit_exempt(env: Env, attester: Address, exempt: bool) {
        reject_reentrant(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage()
            .instance()
            .set(&(RATE_EXEMPT, attester), &exempt);
        extend_instance_ttl(&env);
    }

    pub fn is_rate_limit_exempt(env: Env, attester: Address) -> bool {
        extend_instance_ttl(&env);
        env.storage()
            .instance()
            .get(&(RATE_EXEMPT, attester))
            .unwrap_or(false)
    }

    /// Admin: pin the fee asset and exact amount for `attest_with_value`.
    /// `amount` must be positive; call `clear_fee` for fee-free schemas
    /// instead of encoding "no fee" as an arbitrary zero (#164).
    pub fn set_fee(env: Env, token: Address, amount: i128) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        let old = env.storage().instance().get(&FEE_CONFIG);
        env.storage()
            .instance()
            .set(&FEE_CONFIG, &(token.clone(), amount));
        events::publish_fee_config_updated(&env, old, Some((token, amount)), admin);
        extend_instance_ttl(&env);
    }

    /// Admin: remove the fee requirement. `attest_with_value` is then callable
    /// only with `value == 0` (#164).
    pub fn clear_fee(env: Env) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        let old = env.storage().instance().get(&FEE_CONFIG);
        env.storage().instance().remove(&FEE_CONFIG);
        env.storage().instance().remove(&FEE_PER_BYTE);
        events::publish_fee_config_updated(&env, old, None, admin);
        extend_instance_ttl(&env);
    }

    /// Per-byte fee schedule configuration. Zero restores the fixed-fee policy.
    /// Requires a configured fee token for a nonzero rate.
    pub fn set_fee_per_byte(env: Env, amount: i128) {
        let admin = require_admin(&env);
        admin.require_auth();
        if amount < 0 || (amount > 0 && !env.storage().instance().has(&FEE_CONFIG)) {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        env.storage().instance().set(&FEE_PER_BYTE, &amount);
        extend_instance_ttl(&env);
    }

    pub fn get_fee_per_byte(env: Env) -> i128 {
        extend_instance_ttl(&env);
        env.storage().instance().get(&FEE_PER_BYTE).unwrap_or(0)
    }

    /// Admin-approved schema exemption. The zero-fee rule takes priority over
    /// both the base and per-byte charges.
    pub fn set_schema_zero_fee(env: Env, schema_uid: UID, enabled: bool) {
        let admin = require_admin(&env);
        admin.require_auth();
        let key = (ZERO_FEE_SCHEMA, schema_uid);
        if enabled {
            env.storage().persistent().set(&key, &true);
            env.storage()
                .persistent()
                .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        } else {
            env.storage().persistent().remove(&key);
        }
        extend_instance_ttl(&env);
    }

    pub fn quote_attestation_fee(env: Env, schema_uid: UID, data_len: u32) -> i128 {
        extend_instance_ttl(&env);
        fee_quote(&env, &schema_uid, data_len)
    }

    pub fn withdraw_tokens(
        env: Env,
        authorizer: Address,
        token: Address,
        amount: i128,
        destination: Address,
    ) {
        reject_reentrant(&env);
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

    /// Admin: set protocol ceilings for creator fee fixed amount and basis points (#434).
    pub fn set_fee_ceilings(env: Env, max_fixed_fee: i128, max_basis_points: u32) {
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        if max_fixed_fee < 0 || max_basis_points > MAX_CREATOR_BPS {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        let ceilings = FeeCeilings {
            max_fixed_fee,
            max_basis_points,
        };
        env.storage().instance().set(&FEE_CEILINGS, &ceilings);
        extend_instance_ttl(&env);
    }

    /// Returns the currently active protocol fee ceilings (#434).
    pub fn get_fee_ceilings(env: Env) -> FeeCeilings {
        extend_instance_ttl(&env);
        env.storage()
            .instance()
            .get(&FEE_CEILINGS)
            .unwrap_or(FeeCeilings {
                max_fixed_fee: i128::MAX,
                max_basis_points: MAX_CREATOR_BPS,
            })
    }

    /// Configures creator custom fee for schema `schema_uid` (#434).
    /// `authorizer` must be schema creator or admin.
    /// `fee_type`: 1 for Fixed amount, 2 for BasisPoints.
    pub fn set_schema_fee(
        env: Env,
        schema_uid: UID,
        authorizer: Address,
        fee_type: u32,
        fixed_amount: i128,
        basis_points: u32,
    ) {
        extend_instance_ttl(&env);
        authorizer.require_auth();

        let registry = require_registry(&env);
        let creator: Option<Address> = match env
            .try_invoke_contract::<Option<Address>, soroban_sdk::Error>(
                &registry,
                &Symbol::new(&env, "get_creator"),
                soroban_sdk::vec![&env, schema_uid.clone().into_val(&env)],
            ) {
            Ok(Ok(c)) => c,
            _ => None,
        };
        let admin = require_admin(&env);
        if creator.as_ref() != Some(&authorizer) && authorizer != admin {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let ceilings = Self::get_fee_ceilings(env.clone());
        if fee_type == 1 {
            if fixed_amount < 0 || fixed_amount > ceilings.max_fixed_fee {
                panic_with_error!(&env, SASError::InvalidValue);
            }
        } else if fee_type == 2 {
            if basis_points > ceilings.max_basis_points {
                panic_with_error!(&env, SASError::InvalidValue);
            }
        } else {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        let config = SchemaFeeConfig {
            fee_type,
            fixed_amount,
            basis_points,
        };
        let key = (SCHEMA_FEE_CONFIG, schema_uid);
        env.storage().persistent().set(&key, &config);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        extend_instance_ttl(&env);
    }

    /// Clears creator custom fee for schema `schema_uid` (#434).
    pub fn clear_schema_fee(env: Env, schema_uid: UID, authorizer: Address) {
        extend_instance_ttl(&env);
        authorizer.require_auth();

        let registry = require_registry(&env);
        let creator: Option<Address> = match env
            .try_invoke_contract::<Option<Address>, soroban_sdk::Error>(
                &registry,
                &Symbol::new(&env, "get_creator"),
                soroban_sdk::vec![&env, schema_uid.clone().into_val(&env)],
            ) {
            Ok(Ok(c)) => c,
            _ => None,
        };
        let admin = require_admin(&env);
        if creator.as_ref() != Some(&authorizer) && authorizer != admin {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let key = (SCHEMA_FEE_CONFIG, schema_uid);
        env.storage().persistent().remove(&key);
        extend_instance_ttl(&env);
    }

    /// Returns the creator custom fee configuration for schema `schema_uid` (#434).
    pub fn get_schema_fee(env: Env, schema_uid: UID) -> Option<SchemaFeeConfig> {
        extend_instance_ttl(&env);
        let key = (SCHEMA_FEE_CONFIG, schema_uid);
        let config: Option<SchemaFeeConfig> = env.storage().persistent().get(&key);
        if config.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        }
        config
    }

    /// Returns accumulated treasury fee balance for a token (#434).
    pub fn get_treasury_fee_balance(env: Env, token: Address) -> i128 {
        extend_instance_ttl(&env);
        let key = (TREASURY_FEES, token);
        env.storage().persistent().get(&key).unwrap_or(0i128)
    }

    /// Returns accumulated schema creator fee balance for a token (#434).
    pub fn get_creator_fee_balance(env: Env, creator: Address, token: Address) -> i128 {
        extend_instance_ttl(&env);
        let key = (CREATOR_FEES, creator, token);
        env.storage().persistent().get(&key).unwrap_or(0i128)
    }

    /// Allows schema creators to withdraw their accumulated fee balance (#434).
    pub fn withdraw_creator_fees(
        env: Env,
        creator: Address,
        token: Address,
        amount: i128,
        destination: Address,
    ) {
        extend_instance_ttl(&env);
        if amount <= 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        creator.require_auth();

        let key = (CREATOR_FEES, creator.clone(), token.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0i128);
        if balance < amount {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        env.storage().persistent().set(&key, &(balance - amount));
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);

        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &destination,
            &amount,
        );
        events::publish_withdrawal(&env, &token, amount, &destination, &creator);
        extend_instance_ttl(&env);
    }

    /// Allows treasury admin or configured treasury address to withdraw accumulated protocol fees (#434).
    pub fn withdraw_treasury_fees(
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

        let key = (TREASURY_FEES, token.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0i128);
        if balance < amount {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        env.storage().persistent().set(&key, &(balance - amount));
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);

        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &destination,
            &amount,
        );
        events::publish_withdrawal(&env, &token, amount, &destination, &authorizer);
        extend_instance_ttl(&env);
    }

    pub fn attest(env: Env, attestation: Attestation) -> UID {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        require_unpaid_allowed(&env, &attestation);
        attestation.attester.require_auth();
        Self::attest_internal(env, attestation)
    }

    /// Pure digest oracle for cross-language off-chain signing parity (#489).
    /// Uses the exact domain of attest_by_delegation but does not mutate state.
    pub fn hash_delegation_digest(env: Env, attestation: Attestation, nonce: u64) -> BytesN<32> {
        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain)
    }

    /// Issues an attestation endorsed by an off-chain ed25519 signature and
    /// relayed by any funded account.
    ///
    /// When the schema declares a FROST threshold group (#534), `public_key`
    /// must be that group's public key and `signature` a standard 64-byte
    /// Ed25519 aggregate produced by at least `threshold` shares. The attester
    /// account key and registered attester keys are not accepted for such a
    /// schema. A FROST aggregate has exactly the same shape as a single-signer
    /// signature, so this entrypoint's calldata and its single
    /// `ed25519_verify` cost are unchanged.
    pub fn attest_by_delegation(
        env: Env,
        attestation: Attestation,
        nonce: u64,
        signature: soroban_sdk::BytesN<64>,
        public_key: soroban_sdk::BytesN<32>,
    ) -> UID {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        if attestation.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        require_unpaid_allowed(&env, &attestation);
        require_delegation_policy(&env, &attestation.attester, &attestation.schema_uid);
        Self::require_nonce_not_replayed(&env, &attestation.attester, nonce);
        let group = Self::require_delegation_key(
            &env,
            &attestation.schema_uid,
            &attestation.attester,
            &public_key,
        );
        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        let payload_hash =
            soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain);
        Self::verify_delegated_signature(&env, &payload_hash, &public_key, &signature, &group);
        Self::consume_delegation_nonce(&env, &attestation.attester, nonce);

        Self::attest_internal(env, attestation)
    }

    /// Versioned scoped issuance: signature binds the claimed schema scope,
    /// permission mask and expiry in addition to the canonical v1 payload.
    /// Wildcard scope is None. Direct root key auth is not accepted here;
    /// the signature must satisfy the registered attester-key checks.
    pub fn attest_by_scoped_delegation(
        env: Env,
        attestation: Attestation,
        nonce: u64,
        signature: BytesN<64>,
        public_key: BytesN<32>,
        authorization: DelegationAuthorization,
    ) -> UID {
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        if attestation.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        require_unpaid_allowed(&env, &attestation);
        if authorization.permissions & DELEGATION_PERMISSION_ISSUE == 0
            || (authorization.valid_until != 0
                && env.ledger().timestamp() > authorization.valid_until)
            || matches!(
                &authorization.schema_scope,
                DelegationSchemaScope::Only(uid) if uid != &attestation.schema_uid
            )
        {
            panic_with_error!(&env, SASError::DelegationScopeDenied);
        }
        Self::require_attester_key(&env, &attestation.attester, &public_key);
        require_delegation_policy(&env, &attestation.attester, &attestation.schema_uid);
        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        let digest = soroban_sas_common::hash_scoped_attestation(
            &env,
            &attestation,
            &domain,
            &authorization,
        );
        soroban_sas_common::verify_offchain_signature(&env, &digest, &public_key, &signature);
        Self::consume_delegation_nonce(&env, &attestation.attester, nonce);
        Self::attest_internal(env, attestation)
    }

    /// Install a trusted verifier contract that implements
    /// `verify_proof(proof: Bytes, public_inputs: Vec<BytesN<32>>) -> bool`.
    /// The verifier MUST actually check a Groth16 or UltraPlonk proof against
    /// a pinned verification key. This SAS contract never accepts a hash
    /// prefix, an unverified assertion, or a self-declared proof as sufficient.
    pub fn set_zk_verifier(env: Env, verifier: Address) {
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().set(&ZK_VERIFIER, &verifier);
        extend_instance_ttl(&env);
    }

    pub fn get_zk_verifier(env: Env) -> Option<Address> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&ZK_VERIFIER)
    }

    /// Transactionally verify and consume a private credential proof before
    /// issuing the corresponding attestation (#531). Public inputs are
    /// canonically bound to (attestation UID, schema UID, nullifier), avoiding
    /// proof substitution across issuers or schemas. A failed issuance rolls
    /// back nullifier consumption and any verifier-side writes.
    pub fn attest_with_zk(
        env: Env,
        attestation: Attestation,
        proof: Bytes,
        nullifier: BytesN<32>,
    ) -> UID {
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        require_unpaid_allowed(&env, &attestation);
        if proof.is_empty() || proof.len() > 4096 {
            panic_with_error!(&env, SASError::InvalidZKProof);
        }
        let key = ZkNullifierKey::Used(nullifier.clone());
        if env.storage().persistent().has(&key) {
            panic_with_error!(&env, SASError::NullifierAlreadyUsed);
        }
        let Some(verifier) = env.storage().instance().get::<_, Address>(&ZK_VERIFIER) else {
            panic_with_error!(&env, SASError::InvalidZKProof);
        };
        // A ZK verifier sees only commitment-like public values; the private
        // witness stays off-chain. The circuit must enforce the same ordering.
        let public_inputs = soroban_sdk::vec![
            &env,
            attestation.uid.0.clone(),
            attestation.schema_uid.0.clone(),
            nullifier,
        ];
        let accepted = env.try_invoke_contract::<bool, soroban_sdk::Error>(
            &verifier,
            &Symbol::new(&env, "verify_proof"),
            soroban_sdk::vec![&env, proof.into_val(&env), public_inputs.into_val(&env),],
        );
        if !matches!(accepted, Ok(Ok(true))) {
            panic_with_error!(&env, SASError::InvalidZKProof);
        }

        // The ZK proof authenticates the private statement, but does not
        // replace issuer authorization in SAS's existing schema policy.
        attestation.attester.require_auth();
        let uid = Self::attest_internal(env.clone(), attestation);
        env.storage().persistent().set(&key, &true);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        uid
    }

    pub fn is_zk_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        extend_instance_ttl(&env);
        env.storage()
            .persistent()
            .has(&ZkNullifierKey::Used(nullifier))
    }

    /// Issues a batch of off-chain-signed attestations in one relayed
    /// transaction. Companion to
    /// `attest_by_delegation`, mirroring how
    /// `multi_attest` batches the direct path.
    ///
    /// `attestations`, `nonces`, `signatures`, and `public_keys` are parallel
    /// vectors and must all have the same length; the batch is capped at
    /// `MAX_MULTI_ATTEST` (`SASError::BatchTooLarge`, checked before any
    /// signature is verified or state is written). Each item carries its own
    /// nonce and signing key, so one relayer can submit signatures produced by
    /// several independent attesters in a single transaction.
    ///
    /// Every signature is verified and its nonce consumed before the matching
    /// attestation is stored. A Soroban invocation is atomic, so a failure on
    /// any item reverts the whole batch — no partially issued attestations and
    /// no partially advanced nonce watermark. Nonces for the same attester
    /// must appear in strictly increasing order, exactly as when they are
    /// submitted one call at a time.
    pub fn multi_attest_by_delegation(
        env: Env,
        attestations: soroban_sdk::Vec<Attestation>,
        nonces: soroban_sdk::Vec<u64>,
        signatures: soroban_sdk::Vec<BytesN<64>>,
        public_keys: soroban_sdk::Vec<BytesN<32>>,
    ) -> soroban_sdk::Vec<UID> {
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        extend_instance_ttl(&env);

        let len = attestations.len();
        if len > MAX_MULTI_ATTEST {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }
        if nonces.len() != len || signatures.len() != len || public_keys.len() != len {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        // Same serialization defence as `multi_attest` (#296): a nested batch
        // cannot interleave its storage writes with ours.
        enter_reentrancy_guard(&env);
        let mut uids = soroban_sdk::Vec::new(&env);
        let mut attesters: soroban_sdk::Map<Address, bool> = soroban_sdk::Map::new(&env);

        for i in 0..len {
            let attestation = attestations.get(i).unwrap();
            let nonce = nonces.get(i).unwrap();
            let signature = signatures.get(i).unwrap();
            let public_key = public_keys.get(i).unwrap();

            if attestation.revocation_time != 0 {
                panic_with_error!(&env, SASError::AlreadyRevoked);
            }
            require_unpaid_allowed(&env, &attestation);
            require_delegation_policy(&env, &attestation.attester, &attestation.schema_uid);
            Self::require_nonce_not_replayed(&env, &attestation.attester, nonce);
            let group = Self::require_delegation_key(
                &env,
                &attestation.schema_uid,
                &attestation.attester,
                &public_key,
            );
            let domain = soroban_sas_common::AttestationDomain {
                network_id: env.ledger().network_id(),
                contract: env.current_contract_address(),
                nonce,
            };
            let payload_hash =
                soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain);
            Self::verify_delegated_signature(&env, &payload_hash, &public_key, &signature, &group);
            Self::consume_delegation_nonce(&env, &attestation.attester, nonce);

            attesters.set(attestation.attester.clone(), true);
            let uid = Self::attest_internal(env.clone(), attestation);
            uids.push_back(uid);
        }

        // Summary event, emitted last so consumers see every per-item
        // AttestationIssued event first (#213). Reaching this line means the
        // whole batch committed.
        events::publish_batch_attested(&env, uids.len(), attesters.len());
        exit_reentrancy_guard(&env);
        uids
    }

    fn attest_internal(env: Env, mut attestation: Attestation) -> UID {
        let owns_guard = enter_callback_context(&env);
        extend_instance_ttl(&env);
        // Resolved up front so a missing registry is always reported as the
        // configuration failure it is, instead of being masked by whichever
        // payload check the attestation happens to fail first.
        let registry = require_registry(&env);

        // Bound payload size before any storage, hashing, or cross-contract
        // calls so oversized attestations fail fast with a typed error. (#157)
        // Resolvers implementing `on_attest` can rely on this ceiling already
        // having been enforced — see the "Payload Size" section of
        // docs/schemas.md for the resolver-facing guarantee this provides.
        if attestation.data.len() > MAX_ATTESTATION_DATA_BYTES {
            panic_with_error!(&env, SASError::PayloadTooLarge);
        }

        if has_attestation(&env, &attestation.uid) {
            panic_with_error!(&env, SASError::DuplicateAttestation);
        }

        // Reject any attestation whose `uid` does not match the
        // content-addressed hash of its own fields, so a caller cannot
        // forge, copy, or randomly pick a UID that isn't derived from what
        // is actually being attested (#215).
        let expected_uid = soroban_sas_common::attestation_uid(
            &env,
            &attestation.schema_uid,
            &attestation.recipient,
            &attestation.attester,
            &attestation.data,
        );
        if attestation.uid != expected_uid {
            panic_with_error!(&env, SASError::InvalidUID);
        }

        if let Err(err) = validate_expiration(&env, attestation.expiration_time) {
            panic_with_error!(&env, err);
        }

        // Time-locked attestation validation (#439):
        // Ensure valid_from must be strictly less than expiration_time when expiration is non-zero.
        // Invalid time ranges (valid_from >= expiration_time > 0) revert with InvalidTimeRange.
        if attestation.expiration_time > 0 && attestation.valid_from >= attestation.expiration_time
        {
            panic_with_error!(&env, SASError::InvalidTimeRange);
        }

        // Shared with the SDK/CLI pre-flight checks so a missing
        // ("no recipient" sentinel) or self-targeted recipient is rejected
        // with the same `InvalidRecipient` wherever it is caught (#304).
        if let Err(err) = soroban_sas_common::validate_attestation_parties(
            &env,
            &attestation.recipient,
            &attestation.attester,
        ) {
            panic_with_error!(&env, err);
        }

        // Validate ref_uid integrity (#159): reject self-references and
        // references to attestations that were never issued.
        let zero_ref = UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32]));
        if attestation.ref_uid == attestation.uid {
            panic_with_error!(&env, SASError::InvalidRefUid);
        }
        if attestation.ref_uid != zero_ref && !has_attestation(&env, &attestation.ref_uid) {
            panic_with_error!(&env, SASError::InvalidRefUid);
        }

        let schema_opt: Option<soroban_sas_common::SchemaRecord> = env.invoke_contract(
            &registry,
            &Symbol::new(&env, "get_schema"),
            soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
        );
        let Some(schema) = schema_opt else {
            panic_with_error!(&env, SASError::InvalidSchema);
        };

        // Quarantine blocks new issuances only. Reads of existing attestations
        // do not come through this path (#539). A registry that predates the
        // method is treated as not quarantined.
        let quarantined: bool = match env.try_invoke_contract::<bool, soroban_sdk::Error>(
            &registry,
            &Symbol::new(&env, "is_schema_quarantined"),
            soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
        ) {
            Ok(Ok(flag)) => flag,
            _ => false,
        };
        if quarantined {
            panic_with_error!(&env, SASError::SchemaQuarantined);
        }

        // Maximum expiration window limit per schema (#441):
        let max_ttl: u64 = match env.try_invoke_contract::<u64, soroban_sdk::Error>(
            &registry,
            &Symbol::new(&env, "get_max_ttl"),
            soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
        ) {
            Ok(Ok(ttl)) => ttl,
            _ => 0,
        };
        if max_ttl > 0 {
            if attestation.expiration_time == 0 {
                panic_with_error!(&env, SASError::InvalidExpirationTime);
            }
            let current_time = env.ledger().timestamp();
            if attestation.expiration_time > current_time
                && attestation.expiration_time - current_time > max_ttl
            {
                panic_with_error!(&env, SASError::InvalidExpirationTime);
            }
        }

        // Verify attester authorization: attester must be either the original
        // schema owner or an authorized delegate in the registry allow-list (#7).
        let is_auth: bool = match env.try_invoke_contract::<bool, soroban_sdk::Error>(
            &registry,
            &Symbol::new(&env, "is_authorized"),
            soroban_sdk::vec![
                &env,
                attestation.schema_uid.clone().into_val(&env),
                attestation.attester.clone().into_val(&env),
            ],
        ) {
            Ok(Ok(auth)) => auth,
            _ => false,
        };
        if !is_auth {
            // Not the owner or a delegate: fall back to the schema's attester
            // access control list (#443). A schema that has one rejects every
            // other issuer with the dedicated `UnauthorizedAttester`; a schema
            // without one keeps the original `Unauthorized`.
            let (on_acl, restricted) = schema_attester_acl_status(
                &env,
                &registry,
                &attestation.schema_uid,
                &attestation.attester,
            );
            if !on_acl {
                if restricted {
                    panic_with_error!(&env, SASError::UnauthorizedAttester);
                }
                panic_with_error!(&env, SASError::Unauthorized);
            }
        }

        consume_issuance_quota(&env, &attestation.attester);

        // Validate policy compliance during attestation creation (#448).
        // Queries tri-state policy if supported by registry, otherwise maps from bool.
        let policy: soroban_sas_common::RevocationPolicy =
            match env
                .try_invoke_contract::<soroban_sas_common::RevocationPolicy, soroban_sdk::Error>(
                    &registry,
                    &Symbol::new(&env, "get_schema_policy"),
                    soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
                ) {
                Ok(Ok(p)) => p,
                _ => soroban_sas_common::RevocationPolicy::from(schema.revocable),
            };

        if let Err(err) = soroban_sas_common::check_policy(policy, attestation.revocable) {
            panic_with_error!(&env, err);
        }

        // Resolver callback: authoritative. A resolver is optional in the
        // sense that a schema need not name a "real" enforcement contract,
        // but once named, its `on_attest` verdict controls whether the
        // attestation is issued. Explicit rejection, a trap, and a resolver
        // that doesn't implement `on_attest` all abort this call the same
        // way (the host does not let a caller tell trap and missing-method
        // apart) — see docs/schemas.md's "Resolver Failure Semantics". A
        // panic reverts the whole transaction, including any event this
        // call would otherwise have published, so the typed error is the
        // only (and sufficient) observable signal here — there is no
        // partial-effect window to additionally report on.
        if env
            .try_invoke_contract::<(), soroban_sdk::Error>(
                &schema.resolver,
                &Symbol::new(&env, "on_attest"),
                soroban_sdk::vec![&env, attestation.clone().into_val(&env)],
            )
            .is_err()
        {
            panic_with_error!(&env, SASError::ResolverRejected);
        }

        // Normalize the issuance timestamp to the authoritative ledger close
        // time so that direct, delegated, batch, paid, and replacement paths
        // all record the same canonical value. (#156)
        attestation.time = env.ledger().timestamp();

        // Store the attestation in compact internal layout (#438)
        let ttl = Self::compute_storage_ttl(&env, attestation.expiration_time);
        write_attestation(&env, &attestation, ttl);
        // Anchor the timestamp above to the ledger that produced it, so a
        // verifier can check it against that ledger's header (#298).
        timestamp::write_anchor(&env, &attestation.uid, false, ttl);

        if let Some(indexer) = env.storage().instance().get::<_, Address>(&INDEXER) {
            Self::notify_indexer_of_issuance(&env, &indexer, &attestation);
        }

        events::publish_attested(&env, &attestation);
        extend_instance_ttl(&env);
        exit_callback_context(&env, owns_guard);

        attestation.uid.clone()
    }

    /// Computes the persistent storage TTL for an attestation entry (#160).
    ///
    /// Expiring attestations get a TTL that covers their validity window plus
    /// a one-year retention window for audit/history. Non-expiring records
    /// receive the standard one-year TTL (renewable via `get_attestation`).
    fn compute_storage_ttl(env: &Env, expiration_time: u64) -> u32 {
        if expiration_time == 0 {
            return LEDGERS_IN_ONE_YEAR;
        }
        let now = env.ledger().timestamp();
        if expiration_time <= now {
            return LEDGERS_IN_ONE_YEAR;
        }
        let seconds_remaining = expiration_time - now;
        let ledgers_remaining = seconds_remaining.div_ceil(5) as u32;
        let max_ttl = LEDGERS_IN_ONE_YEAR * 5;
        ledgers_remaining
            .saturating_add(LEDGERS_IN_ONE_YEAR)
            .min(max_ttl)
    }

    /// Pushes a freshly issued attestation to the bound Indexer.
    ///
    /// The attestation is the protocol's source of truth; the Indexer is a
    /// downstream mirror. The default policy is therefore **fail-open**: an
    /// unavailable, upgraded, or incompatible Indexer must not roll back
    /// issuance. A failed push emits `IndexFailed(uid)` so operators can
    /// detect the gap and repair it with `reindex_attestation` (#161).
    fn notify_indexer_of_issuance(env: &Env, indexer: &Address, attestation: &Attestation) {
        if Self::push_to_indexer(env, indexer, attestation) {
            if attestation.valid_from > 0 {
                let _ = env.try_invoke_contract::<(), soroban_sdk::Error>(
                    indexer,
                    &Symbol::new(env, "set_valid_from"),
                    soroban_sdk::vec![
                        env,
                        attestation.uid.clone().into_val(env),
                        attestation.valid_from.into_val(env),
                    ],
                );
            }
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

    /// The single encoding of the SAS -> Indexer write:
    /// `Indexer::index_attestation(uid, recipient, schema_uid, attester, expiration_time)`.
    /// Returns whether the indexer accepted it. Issuance, `reindex_attestation`,
    /// and `bulk_reindex` all go through here so the call shape cannot drift
    /// between them (#309).
    fn push_to_indexer(env: &Env, indexer: &Address, attestation: &Attestation) -> bool {
        let outcome = env.try_invoke_contract::<(), soroban_sdk::Error>(
            indexer,
            &Symbol::new(env, "index_attestation"),
            soroban_sdk::vec![
                env,
                attestation.uid.clone().into_val(env),
                attestation.recipient.clone().into_val(env),
                attestation.schema_uid.clone().into_val(env),
                attestation.attester.clone().into_val(env),
                attestation.expiration_time.into_val(env),
            ],
        );
        matches!(outcome, Ok(Ok(())))
    }

    /// Admin: choose the Indexer availability policy (#161).
    ///
    /// `false` (default) is fail-open: a failed Indexer push is tolerated and
    /// surfaced via an `IndexFailed` event. `true` is fail-closed: a failed
    /// push aborts the attestation with `SASError::IndexerUnavailable`, which
    /// operators pair with health checks, rotation via `set_indexer`, and the
    /// `reindex_attestation` recovery path.
    pub fn set_indexer_strict(env: Env, strict: bool) {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        let old_strict: bool = env
            .storage()
            .instance()
            .get(&INDEXER_STRICT)
            .unwrap_or(false);
        env.storage().instance().set(&INDEXER_STRICT, &strict);
        events::publish_indexer_strict_updated(&env, old_strict, strict, admin);
        extend_instance_ttl(&env);
    }

    /// Admin: enable or disable expired-attestation pruning (#432).
    ///
    /// Disabled by default. Verification and read paths already treat expired
    /// attestations as inactive regardless of this flag; it only controls
    /// whether `prune_expired` may delete the stored records.
    pub fn set_auto_prune(env: Env, enabled: bool) {
        extend_instance_ttl(&env);
        let admin = require_admin(&env);
        admin.require_auth();
        env.storage().instance().set(&AUTO_PRUNE, &enabled);
        extend_instance_ttl(&env);
    }

    /// Returns whether `prune_expired` is enabled (default `false`).
    pub fn is_auto_prune_enabled(env: Env) -> bool {
        extend_instance_ttl(&env);
        env.storage().instance().get(&AUTO_PRUNE).unwrap_or(false)
    }

    /// Public cleanup entrypoint: deletes the stored records of expired
    /// attestations and returns how many were removed (#432).
    ///
    /// Requires auto-pruning to be enabled (`AutoPruneDisabled` otherwise) and
    /// at most `MAX_PRUNE_BATCH` UIDs (`BatchTooLarge`). Only records with a
    /// non-zero `expiration_time` that has passed are removed; perpetual,
    /// still-live and unknown UIDs are skipped, so the call is idempotent and
    /// safe for anyone to invoke. A pruned UID can only come back through a
    /// new `attest` call authorized by the attester. Emits `PRUNED` per UID.
    pub fn prune_expired(env: Env, uids: soroban_sdk::Vec<UID>) -> u32 {
        extend_instance_ttl(&env);
        if !env.storage().instance().get(&AUTO_PRUNE).unwrap_or(false) {
            panic_with_error!(&env, SASError::AutoPruneDisabled);
        }
        if uids.len() > MAX_PRUNE_BATCH {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }
        let mut pruned = 0u32;
        for uid in uids.iter() {
            let Some(attestation) = read_attestation(&env, &uid) else {
                continue;
            };
            if attestation.expiration_time == 0
                || validate_expiration(&env, attestation.expiration_time).is_ok()
            {
                continue;
            }
            remove_attestation(&env, &uid);
            env.events()
                .publish((symbol_short!("PRUNED"), uid.clone()), uid);
            pruned += 1;
        }
        pruned
    }

    /// Returns the current Indexer availability policy: `true` fail-closed,
    /// `false` fail-open (the default).
    pub fn get_indexer_strict(env: Env) -> bool {
        extend_instance_ttl(&env);
        env.storage()
            .instance()
            .get(&INDEXER_STRICT)
            .unwrap_or(false)
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
    pub fn bulk_reindex(env: Env, uids: soroban_sdk::Vec<UID>) -> soroban_sdk::Vec<UID> {
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        if uids.len() > 100 {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }

        let Some(indexer) = env.storage().instance().get::<_, Address>(&INDEXER) else {
            panic_with_error!(&env, SASError::NotInitialized);
        };

        let mut failed = soroban_sdk::Vec::new(&env);
        for uid in uids.iter() {
            if let Some(attestation) = read_attestation(&env, &uid) {
                if !Self::push_to_indexer(&env, &indexer, &attestation) {
                    failed.push_back(uid);
                } else {
                    env.events()
                        .publish((soroban_sas_common::events::REINDEXED, uid), ());
                }
            } else {
                failed.push_back(uid);
            }
        }
        failed
    }

    pub fn reindex_attestation(env: Env, uid: UID) {
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let Some(attestation) = read_attestation(&env, &uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        let Some(indexer) = env.storage().instance().get::<_, Address>(&INDEXER) else {
            panic_with_error!(&env, SASError::NotInitialized);
        };
        if !Self::push_to_indexer(&env, &indexer, &attestation) {
            panic_with_error!(&env, SASError::IndexerUnavailable);
        }
        events::publish_reindexed(&env, &uid);
    }

    pub fn revoke(env: Env, uid: UID) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        let Some(attestation) = read_attestation(&env, &uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        attestation.attester.require_auth();
        Self::revoke_internal(env, uid)
    }

    /// Revokes an attestation under the authority of `authorizer`.
    /// `authorizer` must either be the original attester, or an authorized
    /// delegate / primary owner of the schema recorded in the registry (#7).
    pub fn revoke_by_authorizer(env: Env, uid: UID, authorizer: Address) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        let Some(attestation) = read_attestation(&env, &uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        authorizer.require_auth();
        if authorizer != attestation.attester {
            let registry = require_registry(&env);
            let is_auth: bool = match env.try_invoke_contract::<bool, soroban_sdk::Error>(
                &registry,
                &Symbol::new(&env, "is_authorized"),
                soroban_sdk::vec![
                    &env,
                    attestation.schema_uid.clone().into_val(&env),
                    authorizer.clone().into_val(&env),
                ],
            ) {
                Ok(Ok(auth)) => auth,
                _ => false,
            };
            if !is_auth {
                panic_with_error!(&env, SASError::Unauthorized);
            }
        }
        Self::revoke_internal(env, uid)
    }

    /// Convenience alias for `revoke_by_authorizer` using a delegate address (#7).
    pub fn revoke_by_delegate(env: Env, uid: UID, delegate: Address) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        Self::revoke_by_authorizer(env, uid, delegate);
    }

    /// Revokes an attestation under an off-chain ed25519 signature.
    ///
    /// The key binding is taken from the recorded attestation's schema: a
    /// schema with a FROST group (#534) requires the group public key and a
    /// valid aggregate, so a single participant cannot revoke a jointly
    /// endorsed attestation on its own.
    pub fn revoke_by_delegation(
        env: Env,
        uid: UID,
        nonce: u64,
        signature: soroban_sdk::BytesN<64>,
        public_key: soroban_sdk::BytesN<32>,
    ) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        let Some(attestation) = read_attestation(&env, &uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        Self::require_nonce_not_replayed(&env, &attestation.attester, nonce);
        let group = Self::require_delegation_key(
            &env,
            &attestation.schema_uid,
            &attestation.attester,
            &public_key,
        );
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
        Self::verify_delegated_signature(&env, &payload_hash, &public_key, &signature, &group);
        Self::consume_delegation_nonce(&env, &attestation.attester, nonce);

        Self::revoke_internal(env, uid)
    }

    /// Revokes a batch of attestations using off-chain delegation signatures.
    /// Companion to `revoke_by_delegation`,
    /// mirroring how `multi_revoke` batches the direct path.
    ///
    /// `uids`, `nonces`, `signatures`, and `public_keys` are parallel vectors
    /// and must all have the same length; the batch is capped at
    /// `MAX_MULTI_REVOKE` (`SASError::BatchTooLarge`). The whole batch is
    /// validated — duplicate UIDs, missing/irrevocable/already-revoked
    /// attestations, key binding, and every signature — before any nonce is
    /// consumed or any revocation is written, so an invalid item cannot leave
    /// a half-applied batch.
    ///
    /// Each item's public key and signature are checked against the
    /// **recorded** attester of that attestation, never a caller-supplied one,
    /// so a relayer cannot pair a valid signature with a different record.
    pub fn multi_revoke_by_delegation(
        env: Env,
        uids: soroban_sdk::Vec<UID>,
        nonces: soroban_sdk::Vec<u64>,
        signatures: soroban_sdk::Vec<BytesN<64>>,
        public_keys: soroban_sdk::Vec<BytesN<32>>,
    ) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        extend_instance_ttl(&env);

        let len = uids.len();
        if len > MAX_MULTI_REVOKE {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }
        if nonces.len() != len || signatures.len() != len || public_keys.len() != len {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        let mut seen: soroban_sdk::Map<UID, bool> = soroban_sdk::Map::new(&env);
        let mut distinct: soroban_sdk::Map<Address, bool> = soroban_sdk::Map::new(&env);

        // Pass 1: validate every item and verify every signature before any
        // state is written, mirroring `multi_revoke`'s all-or-nothing commit.
        for i in 0..len {
            let uid = uids.get(i).unwrap();
            let nonce = nonces.get(i).unwrap();
            let signature = signatures.get(i).unwrap();
            let public_key = public_keys.get(i).unwrap();

            if seen.contains_key(uid.clone()) {
                panic_with_error!(&env, SASError::DuplicateAttestation);
            }
            seen.set(uid.clone(), true);

            let Some(attestation) = read_attestation(&env, &uid) else {
                panic_with_error!(&env, SASError::AttestationNotFound);
            };
            if !attestation.revocable {
                panic_with_error!(&env, SASError::NotRevocable);
            }
            if attestation.revocation_time != 0 {
                panic_with_error!(&env, SASError::AlreadyRevoked);
            }

            Self::require_nonce_not_replayed(&env, &attestation.attester, nonce);
            let group = Self::require_delegation_key(
                &env,
                &attestation.schema_uid,
                &attestation.attester,
                &public_key,
            );
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
            Self::verify_delegated_signature(&env, &payload_hash, &public_key, &signature, &group);

            distinct.set(attestation.attester.clone(), true);
        }

        // Pass 2: consume each nonce and revoke, in the submitted order so
        // per-attester nonces stay strictly increasing. `uids` is unchanged
        // and each entry was already proven present in pass 1.
        for i in 0..len {
            let uid = uids.get(i).unwrap();
            let nonce = nonces.get(i).unwrap();
            let attester = read_attestation(&env, &uid).unwrap().attester;
            Self::consume_delegation_nonce(&env, &attester, nonce);
            Self::revoke_internal(env.clone(), uid);
        }

        // Summary event, emitted last so consumers see every per-item
        // AttestationRevoked event first (#213).
        events::publish_batch_revoked(&env, len, distinct.len());
    }

    fn revoke_internal(env: Env, uid: UID) {
        let owns_guard = enter_callback_context(&env);
        extend_instance_ttl(&env);
        let Some(mut attestation) = read_attestation(&env, &uid) else {
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
        let ttl = Self::compute_storage_ttl(&env, attestation.expiration_time);
        write_attestation(&env, &attestation, ttl);
        // The revocation is anchored to its own ledger; the issuance anchor
        // stays readable alongside it (#298).
        timestamp::write_anchor(&env, &uid, true, ttl);

        events::publish_revoked(&env, &uid, timestamp);

        // Resolver callback: authoritative, mirroring `on_attest`'s
        // semantics (#216; see docs/schemas.md's "Resolver Failure
        // Semantics"). Invoked after the revocation is written and its
        // event published — rather than before, as `on_attest` does with
        // issuance — so the resolver can inspect the attestation exactly as
        // it will read on-chain once this call commits. A rejection, trap,
        // or missing `on_revoke` implementation all panic with
        // `SASError::ResolverRejected`, which reverts the whole
        // invocation — the storage write and event published just above
        // included — so schemas without a real enforcement resolver are
        // unaffected and a rejected revocation leaves the attestation
        // exactly as it was.
        let registry = require_registry(&env);
        let schema_opt: Option<soroban_sas_common::SchemaRecord> = env.invoke_contract(
            &registry,
            &Symbol::new(&env, "get_schema"),
            soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
        );
        let Some(schema) = schema_opt else {
            panic_with_error!(&env, SASError::InvalidSchema);
        };
        if env
            .try_invoke_contract::<(), soroban_sdk::Error>(
                &schema.resolver,
                &Symbol::new(&env, "on_revoke"),
                soroban_sdk::vec![&env, attestation.clone().into_val(&env)],
            )
            .is_err()
        {
            panic_with_error!(&env, SASError::ResolverRejected);
        }

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
        exit_callback_context(&env, owns_guard);
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
    ///
    /// `new_data.expiration_time` must not shorten the old attestation's
    /// expiration: if both are non-zero, `new_data.expiration_time` must be
    /// `>= old.expiration_time`, or this panics with `SASError::InvalidTTL`.
    /// Replacing with `expiration_time == 0` (perpetual) is always allowed.
    /// See `docs/attestations.md` and `specs/protocol-v1.md` (#252).
    pub fn replace_attestation(env: Env, old_uid: UID, new_data: Attestation) -> UID {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        require_unpaid_allowed(&env, &new_data);
        extend_instance_ttl(&env);
        let Some(old) = read_attestation(&env, &old_uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };

        old.attester.require_auth();

        Self::replace_internal(env, old_uid, new_data, old)
    }

    /// Relayed replacement requiring independent off-chain approvals from
    /// the old attester and recipient. Both sign the same domain-separated
    /// digest of `old_uid`, the complete `new_data`, and both nonces. The
    /// attester nonce shares the delegated issuance/revocation watermark;
    /// recipient consent has its own per-recipient watermark. All writes,
    /// callbacks and indexer updates commit or revert together.
    pub fn replace_by_delegation_consent(
        env: Env,
        old_uid: UID,
        new_data: Attestation,
        attester_approval: soroban_sas_common::ReplacementApproval,
        recipient_approval: soroban_sas_common::ReplacementApproval,
    ) -> UID {
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ContractPaused);
        }
        extend_instance_ttl(&env);
        let Some(old) = read_attestation(&env, &old_uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        if new_data.attester != old.attester || new_data.recipient != old.recipient {
            panic_with_error!(&env, SASError::Unauthorized);
        }
        Self::require_attester_key(&env, &old.attester, &attester_approval.public_key);
        Self::require_attester_key(&env, &old.recipient, &recipient_approval.public_key);

        let domain = soroban_sas_common::ReplacementConsentDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            attester_nonce: attester_approval.nonce,
            recipient_nonce: recipient_approval.nonce,
        };
        let digest = soroban_sas_common::hash_delegated_replacement_consent(
            &env, &old_uid, &new_data, &domain,
        );
        soroban_sas_common::verify_offchain_signature(
            &env,
            &digest,
            &attester_approval.public_key,
            &attester_approval.signature,
        );
        soroban_sas_common::verify_offchain_signature(
            &env,
            &digest,
            &recipient_approval.public_key,
            &recipient_approval.signature,
        );
        Self::consume_delegation_nonce(&env, &old.attester, attester_approval.nonce);
        Self::consume_recipient_consent_nonce(&env, &old.recipient, recipient_approval.nonce);

        Self::replace_internal(env, old_uid, new_data, old)
    }

    fn replace_internal(env: Env, old_uid: UID, new_data: Attestation, old: Attestation) -> UID {
        if !old.revocable {
            panic_with_error!(&env, SASError::NotRevocable);
        }
        if old.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        if validate_expiration(&env, old.expiration_time).is_err() {
            panic_with_error!(&env, SASError::InvalidTTL);
        }
        if new_data.attester != old.attester || new_data.recipient != old.recipient {
            panic_with_error!(&env, SASError::Unauthorized);
        }
        // Replacements may extend an expiration or make it perpetual
        // (`expiration_time == 0`), but never shorten it: an attester could
        // otherwise bypass resolver revocation checks by "replacing" a valid
        // multi-year attestation with one whose expiration is already in the
        // past, expiring it immediately without an `on_revoke` callback or an
        // `AttestationRevoked` event (#252).
        if old.expiration_time != 0
            && new_data.expiration_time != 0
            && new_data.expiration_time < old.expiration_time
        {
            panic_with_error!(&env, SASError::InvalidTTL);
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
                soroban_sdk::vec![&env, old_uid_clone.into_val(&env), new_uid.into_val(&env)],
            );
        }
        issued_uid
    }

    /// Extends the expiration time of an existing attestation without revoking
    /// and re-issuing it. The attestation keeps its original UID.
    ///
    /// Requires authorization from the original attester (or an authorized
    /// delegate/schema owner via `revoke_by_authorizer` semantics). The
    /// attestation must be revocable and not already revoked. The new
    /// `expiration_time` must extend or maintain the current expiration:
    /// - If the current `expiration_time` is 0 (perpetual), it stays 0.
    /// - If the current `expiration_time` is non-zero, the new value must be
    ///   either 0 (perpetual) or >= the current expiration time.
    /// - Shortening the expiration is rejected with `SASError::InvalidTTL`.
    ///
    /// On success, updates the attestation's `expiration_time`, extends its
    /// storage TTL accordingly, and emits an `AttestationRenewed` event.
    /// The resolver's `on_revoke` is NOT invoked (this is not a revocation).
    pub fn renew_attestation(env: Env, uid: UID, new_expiration_time: u64) -> UID {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        extend_instance_ttl(&env);
        let Some(mut attestation) = read_attestation(&env, &uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };

        attestation.attester.require_auth();

        if !attestation.revocable {
            panic_with_error!(&env, SASError::NotRevocable);
        }
        if attestation.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        // An expired attestation is inactive and cannot be revived by renewal;
        // a fresh attestation signed by the attester is required (#432).
        if let Err(err) = validate_expiration(&env, attestation.expiration_time) {
            panic_with_error!(&env, err);
        }

        // Validate that the new expiration time extends or maintains the current one.
        // Perpetual (0) is always allowed. If current is perpetual, it stays perpetual.
        // If current is non-zero, new must be 0 (perpetual) or >= current.
        if attestation.expiration_time != 0
            && new_expiration_time != 0
            && new_expiration_time < attestation.expiration_time
        {
            panic_with_error!(&env, SASError::InvalidTTL);
        }
        // If current expiration_time is 0 (perpetual), new_expiration_time must also be 0
        // (we don't allow making a perpetual attestation expirable)
        if attestation.expiration_time == 0 && new_expiration_time != 0 {
            panic_with_error!(&env, SASError::InvalidTTL);
        }

        // Time-locked attestation validation (#439):
        // Ensure valid_from must be strictly less than expiration_time when expiration is non-zero.
        if new_expiration_time > 0 && attestation.valid_from >= new_expiration_time {
            panic_with_error!(&env, SASError::InvalidTimeRange);
        }

        // Maximum expiration window limit per schema (#441):
        let registry = require_registry(&env);
        let max_ttl: u64 = match env.try_invoke_contract::<u64, soroban_sdk::Error>(
            &registry,
            &Symbol::new(&env, "get_max_ttl"),
            soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
        ) {
            Ok(Ok(ttl)) => ttl,
            _ => 0,
        };
        if max_ttl > 0 {
            if new_expiration_time == 0 {
                panic_with_error!(&env, SASError::InvalidExpirationTime);
            }
            let current_time = env.ledger().timestamp();
            if new_expiration_time > current_time && new_expiration_time - current_time > max_ttl {
                panic_with_error!(&env, SASError::InvalidExpirationTime);
            }
        }

        // Validate the new expiration time is not already in the past
        if let Err(err) = validate_expiration(&env, new_expiration_time) {
            panic_with_error!(&env, err);
        }

        // Update the expiration time
        attestation.expiration_time = new_expiration_time;

        // Update storage with new TTL in compact layout (#438)
        let ttl = Self::compute_storage_ttl(&env, attestation.expiration_time);
        write_attestation(&env, &attestation, ttl);

        // Emit event
        events::publish_attestation_renewed(&env, &uid, &attestation.attester, new_expiration_time);

        // Notify indexer if bound
        if let Some(indexer) = env.storage().instance().get::<_, Address>(&INDEXER) {
            let _ = env.try_invoke_contract::<(), soroban_sdk::Error>(
                &indexer,
                &Symbol::new(&env, "handle_renew"),
                soroban_sdk::vec![
                    &env,
                    uid.clone().into_val(&env),
                    new_expiration_time.into_val(&env)
                ],
            );
        }

        extend_instance_ttl(&env);
        uid
    }

    pub fn multi_attest(
        env: Env,
        attestations: soroban_sdk::Vec<Attestation>,
    ) -> soroban_sdk::Vec<UID> {
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        extend_instance_ttl(&env);
        if attestations.len() > MAX_MULTI_ATTEST {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }
        // Serialize the batch: a nested `multi_attest` while this one is still
        // running is rejected, so it cannot interleave its storage writes with
        // ours. The host already refuses direct cross-contract re-entry, which
        // makes this defense-in-depth for the callback path (resolver and
        // indexer) rather than the only line of defence.
        enter_reentrancy_guard(&env);
        let mut uids = soroban_sdk::Vec::new(&env);
        let mut authorized_attesters = soroban_sdk::Map::new(&env);
        // Map lookup avoids scanning all previously authorized attesters.
        for attestation in attestations.into_iter() {
            require_unpaid_allowed(&env, &attestation);
            if !authorized_attesters.contains_key(attestation.attester.clone()) {
                attestation.attester.require_auth();
                authorized_attesters.set(attestation.attester.clone(), true);
            }
            let uid = Self::attest_internal(env.clone(), attestation);
            uids.push_back(uid);
        }
        // Summary event, emitted last so consumers see every per-item
        // AttestationIssued event first (#213). Reaching this line means the
        // whole batch committed: a panic anywhere above reverts the call and
        // this never runs.
        events::publish_batch_attested(&env, uids.len(), authorized_attesters.len());
        exit_reentrancy_guard(&env);
        uids
    }

    /// Issues an attestation and collects the configured fee from the
    /// attester into this contract's balance, splitting fees between the
    /// protocol treasury and schema creator (#164, #434).
    ///
    /// If the schema defines a custom creator royalty (fixed or basis points),
    /// that amount is added on top of the base protocol fee and credited to
    /// the schema creator's withdrawable balance. Schemas without custom
    /// fees only incur the base protocol fee. Emits `FeeDistributed`.
    pub fn attest_with_value(
        env: Env,
        attestation: Attestation,
        token: Address,
        value: i128,
    ) -> UID {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        extend_instance_ttl(&env);
        if value < 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        // The legacy token keeps its existing fee and error semantics.
        // Additional accepted SACs are read from authenticated admin state.
        let configured: Option<(Address, i128)> = env.storage().instance().get(&FEE_CONFIG);
        let base_amount = fee_quote(&env, &attestation.schema_uid, attestation.data.len());
        let rate: i128 = env.storage().instance().get(&FEE_PER_BYTE).unwrap_or(0);
        if rate > 0 && value < base_amount {
            panic_with_error!(&env, SASError::InsufficientFee);
        }

        // Query schema creator custom fee if set (#434)
        let schema_fee = Self::get_schema_fee(env.clone(), attestation.schema_uid.clone());
        let creator_amount = match &schema_fee {
            Some(cfg) => {
                if cfg.fee_type == 1 {
                    cfg.fixed_amount
                } else if cfg.fee_type == 2 {
                    if base_amount > 0 {
                        (base_amount.saturating_mul(cfg.basis_points as i128)) / 10_000
                    } else {
                        0i128
                    }
                } else {
                    0i128
                }
            }
            None => 0i128,
        };

        let total_required = base_amount.saturating_add(creator_amount);

        let additional: Option<i128> = env.storage().instance().get(&(FEE_ASSET, token.clone()));
        let is_default = configured
            .as_ref()
            .map(|(fee_token, _)| fee_token == &token)
            .unwrap_or(false);

        if is_default {
            if value != total_required {
                panic_with_error!(&env, SASError::FeeMismatch);
            }
        } else if let Some(additional_base) = additional {
            let add_required = additional_base.saturating_add(creator_amount);
            if value != add_required {
                panic_with_error!(&env, SASError::FeeMismatch);
            }
        } else if configured.is_none() && value == 0 && total_required == 0 {
            // fee-free
        } else if env
            .storage()
            .instance()
            .get(&MULTI_ASSET_ACTIVE)
            .unwrap_or(false)
        {
            panic_with_error!(&env, SASError::InvalidToken);
        } else {
            panic_with_error!(&env, SASError::FeeMismatch);
        }

        attestation.attester.require_auth();

        if value > 0 {
            let treasury: Option<Address> = env.storage().instance().get(&TREASURY);
            if !is_default && treasury.is_none() {
                panic_with_error!(&env, SASError::TreasuryNotSet);
            }
            let destination = if creator_amount > 0 {
                env.current_contract_address()
            } else {
                treasury.unwrap_or_else(|| env.current_contract_address())
            };
            token::Client::new(&env, &token).transfer(&attestation.attester, &destination, &value);

            // Credit treasury balance
            if base_amount > 0 {
                let tr_key = (TREASURY_FEES, token.clone());
                let cur_tr = env.storage().persistent().get(&tr_key).unwrap_or(0i128);
                env.storage()
                    .persistent()
                    .set(&tr_key, &(cur_tr.saturating_add(base_amount)));
                env.storage().persistent().extend_ttl(
                    &tr_key,
                    LEDGERS_IN_ONE_YEAR,
                    LEDGERS_IN_ONE_YEAR,
                );
            }

            let mut creator_addr = env.current_contract_address();
            if creator_amount > 0 {
                let registry = require_registry(&env);
                if let Ok(Ok(Some(c))) = env
                    .try_invoke_contract::<Option<Address>, soroban_sdk::Error>(
                        &registry,
                        &Symbol::new(&env, "get_creator"),
                        soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
                    )
                {
                    creator_addr = c;
                }
                let cr_key = (CREATOR_FEES, creator_addr.clone(), token.clone());
                let cur_cr = env.storage().persistent().get(&cr_key).unwrap_or(0i128);
                env.storage()
                    .persistent()
                    .set(&cr_key, &(cur_cr.saturating_add(creator_amount)));
                env.storage().persistent().extend_ttl(
                    &cr_key,
                    LEDGERS_IN_ONE_YEAR,
                    LEDGERS_IN_ONE_YEAR,
                );
            }

            events::publish_fee_distributed(
                &env,
                &attestation.schema_uid,
                &token,
                value,
                base_amount,
                creator_amount,
                &creator_addr,
            );
            distribute_attestation_fee(&env, &attestation.schema_uid, &token, value);
        }

        let uid = Self::attest_internal(env.clone(), attestation.clone());
        events::publish_attestation_with_fee(&env, &attestation, total_required);
        uid
    }

    /// Issues an identical attestation payload to multiple recipients in a single atomic transaction (#433).
    /// The authorizer is the schema creator recorded in the schema registry.
    pub fn broadcast_attest(
        env: Env,
        schema_uid: UID,
        recipients: soroban_sdk::Vec<Address>,
        data: soroban_sdk::Bytes,
        expiration_time: u64,
        revocable: bool,
    ) -> soroban_sdk::Vec<UID> {
        let registry = require_registry(&env);
        let creator: Option<Address> = match env
            .try_invoke_contract::<Option<Address>, soroban_sdk::Error>(
                &registry,
                &Symbol::new(&env, "get_creator"),
                soroban_sdk::vec![&env, schema_uid.clone().into_val(&env)],
            ) {
            Ok(Ok(c)) => c,
            _ => None,
        };
        let Some(attester) = creator else {
            panic_with_error!(&env, SASError::SchemaNotFound);
        };
        Self::broadcast_attest_by_attester(
            env,
            attester,
            schema_uid,
            recipients,
            data,
            expiration_time,
            revocable,
        )
    }

    /// Issues an identical attestation payload to multiple recipients authorized by `attester` (#433).
    /// Reverts atomically if any recipient address is invalid, duplicate, or resolver rejects.
    pub fn broadcast_attest_by_attester(
        env: Env,
        attester: Address,
        schema_uid: UID,
        recipients: soroban_sdk::Vec<Address>,
        data: soroban_sdk::Bytes,
        expiration_time: u64,
        revocable: bool,
    ) -> soroban_sdk::Vec<UID> {
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ContractPaused);
        }
        extend_instance_ttl(&env);

        let len = recipients.len();
        if len > MAX_MULTI_ATTEST {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }
        if len == 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        attester.require_auth();

        enter_reentrancy_guard(&env);
        let mut uids = soroban_sdk::Vec::new(&env);
        let mut seen: soroban_sdk::Map<Address, bool> = soroban_sdk::Map::new(&env);
        let zero_ref = UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32]));

        for i in 0..len {
            let recipient = recipients.get(i).unwrap();
            if seen.contains_key(recipient.clone()) {
                panic_with_error!(&env, SASError::DuplicateAttestation);
            }
            seen.set(recipient.clone(), true);

            let uid = soroban_sas_common::attestation_uid(
                &env,
                &schema_uid,
                &recipient,
                &attester,
                &data,
            );

            let attestation = Attestation {
                uid: uid.clone(),
                schema_uid: schema_uid.clone(),
                time: 0,
                expiration_time,
                revocation_time: 0,
                ref_uid: zero_ref.clone(),
                recipient: recipient.clone(),
                attester: attester.clone(),
                revocable,
                data: data.clone(),
                valid_from: 0,
            };

            let issued_uid = Self::attest_internal(env.clone(), attestation);
            uids.push_back(issued_uid);
        }

        events::publish_batch_attested(&env, uids.len(), 1);
        exit_reentrancy_guard(&env);
        uids
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
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
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

            let Some(attestation) = read_attestation(&env, &uid) else {
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
        // Summary event, emitted last so consumers see every per-item
        // AttestationRevoked event first (#213). Reaching this line means
        // the whole batch committed: a panic anywhere above reverts the
        // call and this never runs.
        events::publish_batch_revoked(&env, to_revoke.len(), distinct.len());
    }

    /// Revokes up to `MAX_REVOKE_BY_SCHEMA` attestations belonging to
    /// `schema_uid` in one atomic call, authorized by the schema owner or an
    /// authorized delegate of that schema.
    ///
    /// Intended for administrative recovery when a schema definition is
    /// discovered to be faulty or an issuer key is compromised: revoking
    /// thousands of attestations one by one is cost-prohibitive, so the schema
    /// authority can bulk-revoke them here.
    ///
    /// The whole batch is validated before any state is written:
    /// - `uids` must not exceed `MAX_REVOKE_BY_SCHEMA` (`BatchTooLarge`).
    /// - Duplicate UIDs are rejected (`DuplicateAttestation`).
    /// - Every UID must exist (`AttestationNotFound`), belong to
    ///   `schema_uid` (`InvalidSchema`), be revocable (`NotRevocable`), and
    ///   not already be revoked (`AlreadyRevoked`).
    ///
    /// `authorizer` must authorize the call and be either the schema owner or
    /// an authorized delegate in the registry allow-list (`Unauthorized`
    /// otherwise). Because a Soroban invocation is atomic, a failure on any
    /// item reverts the whole batch — no partially revoked set.
    pub fn revoke_by_schema(
        env: Env,
        schema_uid: UID,
        uids: soroban_sdk::Vec<UID>,
        authorizer: Address,
    ) {
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ContractPaused);
        }
        extend_instance_ttl(&env);

        let len = uids.len();
        if len > MAX_REVOKE_BY_SCHEMA {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }

        authorizer.require_auth();

        // Verify the authorizer is the schema owner or an authorized delegate.
        let registry = require_registry(&env);
        let is_auth: bool = match env.try_invoke_contract::<bool, soroban_sdk::Error>(
            &registry,
            &Symbol::new(&env, "is_authorized"),
            soroban_sdk::vec![
                &env,
                schema_uid.clone().into_val(&env),
                authorizer.clone().into_val(&env),
            ],
        ) {
            Ok(Ok(auth)) => auth,
            _ => false,
        };
        if !is_auth {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        // Pass 1: validate every item before any state is written, so an
        // invalid item cannot leave a half-applied batch.
        let mut seen: soroban_sdk::Map<UID, bool> = soroban_sdk::Map::new(&env);
        let mut to_revoke: soroban_sdk::Vec<UID> = soroban_sdk::Vec::new(&env);
        for uid in uids.iter() {
            if seen.contains_key(uid.clone()) {
                panic_with_error!(&env, SASError::DuplicateAttestation);
            }
            seen.set(uid.clone(), true);

            let Some(attestation) = read_attestation(&env, &uid) else {
                panic_with_error!(&env, SASError::AttestationNotFound);
            };
            if attestation.schema_uid != schema_uid {
                panic_with_error!(&env, SASError::InvalidSchema);
            }
            if !attestation.revocable {
                panic_with_error!(&env, SASError::NotRevocable);
            }
            if attestation.revocation_time != 0 {
                panic_with_error!(&env, SASError::AlreadyRevoked);
            }
            to_revoke.push_back(uid);
        }

        // Pass 2: commit. `revoke_internal` re-reads each record, writes the
        // revocation, emits the per-item event, and notifies the indexer.
        for uid in to_revoke.iter() {
            Self::revoke_internal(env.clone(), uid);
        }

        // Summary event, emitted last so consumers see every per-item
        // AttestationRevoked event first. Reaching this line means the whole
        // batch committed.
        events::publish_batch_revoked(&env, to_revoke.len(), 1);
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
    /// bind a key to it. Fails with `SASError::AttesterKeyAlreadyRegistered`
    /// if a non-revoked key is already on file — use `rotate_attester_key`
    /// to replace it instead, so a key can never be silently overwritten.
    /// Re-registering after a revocation is allowed and starts a new
    /// version.
    pub fn register_attester_key(env: Env, attester: Address, public_key: soroban_sdk::BytesN<32>) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        extend_instance_ttl(&env);
        attester.require_auth();

        let key = (ATTESTER_KEY, attester.clone());
        let existing: Option<soroban_sas_common::AttesterKeyRecord> =
            env.storage().persistent().get(&key);
        if let Some(record) = &existing {
            if !record.revoked {
                panic_with_error!(&env, SASError::AttesterKeyAlreadyRegistered);
            }
        }

        let version = existing.map(|record| record.version + 1).unwrap_or(1);
        let record = soroban_sas_common::AttesterKeyRecord {
            public_key: public_key.clone(),
            version,
            revoked: false,
        };
        env.storage().persistent().set(&key, &record);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);

        env.events().publish(
            (
                soroban_sas_common::events::ATTESTER_KEY_REGISTERED,
                attester.clone(),
            ),
            soroban_sas_common::AttesterKeyRegisteredEvent {
                attester,
                public_key,
                version,
            },
        );
    }

    /// Replaces `attester`'s registered delegated-verification key with
    /// `new_public_key`. Requires `attester.require_auth()`, so only the
    /// address owner can rotate its own key. Fails with
    /// `SASError::AttesterKeyNotFound` if no key was ever registered, and
    /// with `SASError::AttesterKeyRevoked` if the current key was already
    /// revoked — `register_attester_key` is used to re-register in that
    /// case instead, so the version history stays explicit about the gap.
    ///
    /// Once rotated, the old key immediately stops validating new
    /// delegated attestations or revocations: `require_attester_key` only
    /// ever compares against the current record.
    pub fn rotate_attester_key(
        env: Env,
        attester: Address,
        new_public_key: soroban_sdk::BytesN<32>,
    ) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        attester.require_auth();

        let key = (ATTESTER_KEY, attester.clone());
        let Some(record) = env
            .storage()
            .persistent()
            .get::<_, soroban_sas_common::AttesterKeyRecord>(&key)
        else {
            panic_with_error!(&env, SASError::AttesterKeyNotFound);
        };
        if record.revoked {
            panic_with_error!(&env, SASError::AttesterKeyRevoked);
        }

        let new_version = record.version + 1;
        let old_public_key = record.public_key;
        let new_record = soroban_sas_common::AttesterKeyRecord {
            public_key: new_public_key.clone(),
            version: new_version,
            revoked: false,
        };
        env.storage().persistent().set(&key, &new_record);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);

        env.events().publish(
            (
                soroban_sas_common::events::ATTESTER_KEY_ROTATED,
                attester.clone(),
            ),
            soroban_sas_common::AttesterKeyRotatedEvent {
                attester,
                old_public_key,
                new_public_key,
                new_version,
            },
        );
    }

    /// Revokes `attester`'s currently registered delegated-verification
    /// key. Requires `attester.require_auth()`, so only the address owner
    /// can revoke its own key. Fails with `SASError::AttesterKeyNotFound`
    /// if no key was ever registered, and with
    /// `SASError::AttesterKeyRevoked` if it was already revoked.
    ///
    /// After revocation, the key no longer validates any delegated
    /// operation — `attest_by_delegation`, `revoke_by_delegation`, and
    /// `verify_offchain_attestation` all reject it via
    /// `require_attester_key`. The record is retained rather than deleted
    /// so a future `register_attester_key` call continues the version
    /// sequence instead of restarting at `1`.
    pub fn revoke_attester_key(env: Env, attester: Address) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        attester.require_auth();

        let key = (ATTESTER_KEY, attester.clone());
        let Some(record) = env
            .storage()
            .persistent()
            .get::<_, soroban_sas_common::AttesterKeyRecord>(&key)
        else {
            panic_with_error!(&env, SASError::AttesterKeyNotFound);
        };
        if record.revoked {
            panic_with_error!(&env, SASError::AttesterKeyRevoked);
        }

        let revoked_record = soroban_sas_common::AttesterKeyRecord {
            revoked: true,
            ..record.clone()
        };
        env.storage().persistent().set(&key, &revoked_record);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);

        env.events().publish(
            (
                soroban_sas_common::events::ATTESTER_KEY_REVOKED,
                attester.clone(),
            ),
            soroban_sas_common::AttesterKeyRevokedEvent {
                attester,
                public_key: record.public_key,
                version: record.version,
            },
        );
    }

    /// Returns true if `public_key` is `attester`'s current, non-revoked
    /// registered key.
    fn registered_key_matches(
        env: &Env,
        attester: &Address,
        public_key: &soroban_sdk::BytesN<32>,
    ) -> bool {
        env.storage()
            .persistent()
            .get::<_, soroban_sas_common::AttesterKeyRecord>(&(ATTESTER_KEY, attester.clone()))
            .is_some_and(|record| !record.revoked && record.public_key == *public_key)
    }

    fn require_attester_key(env: &Env, attester: &Address, public_key: &soroban_sdk::BytesN<32>) {
        if !soroban_sas_common::attester_matches_key(env, attester, public_key)
            && !Self::registered_key_matches(env, attester, public_key)
        {
            panic_with_error!(env, SASError::Unauthorized);
        }
    }

    /// Resolves the FROST group a schema requires for delegated signatures
    /// (#534).
    ///
    /// Registries that predate threshold support do not expose
    /// `get_schema_frost_group`; that interface failure is treated as "no
    /// group configured", so existing deployments and lightweight registry
    /// mocks keep working and only schemas that explicitly opted in are
    /// affected. The real `SchemaRegistry` in this workspace always implements
    /// the getter.
    fn schema_frost_group(env: &Env, schema_uid: &UID) -> Option<FrostGroup> {
        let registry = require_registry(env);
        match env.try_invoke_contract::<Option<FrostGroup>, soroban_sdk::Error>(
            &registry,
            &Symbol::new(env, "get_schema_frost_group"),
            soroban_sdk::vec![env, schema_uid.clone().into_val(env)],
        ) {
            Ok(Ok(group)) => group,
            _ => None,
        }
    }

    /// Binds a delegated signature to the key allowed to authorize it.
    ///
    /// For a schema with a declared FROST group, only the group public key is
    /// accepted — the attester account key and any key registered through
    /// `register_attester_key` are intentionally ignored, so a single member
    /// cannot bypass the threshold. Every other schema keeps the existing
    /// single-signer binding, so this is backwards compatible and adds one
    /// optional cross-contract read only on delegated paths.
    ///
    /// Returns the configured group (if any) so the caller can verify the
    /// aggregate against it.
    fn require_delegation_key(
        env: &Env,
        schema_uid: &UID,
        attester: &Address,
        public_key: &soroban_sdk::BytesN<32>,
    ) -> Option<FrostGroup> {
        match Self::schema_frost_group(env, schema_uid) {
            Some(group) => {
                if *public_key != group.group_public_key {
                    panic_with_error!(env, SASError::Unauthorized);
                }
                Some(group)
            }
            None => {
                Self::require_attester_key(env, attester, public_key);
                None
            }
        }
    }

    /// Verifies a delegated payload digest against the key that was bound by
    /// [`Self::require_delegation_key`].
    ///
    /// A FROST aggregate is an ordinary Ed25519 signature, so both branches
    /// make exactly one `ed25519_verify` host call: the threshold path has the
    /// same cryptographic verification cost as a single-signer attestation.
    fn verify_delegated_signature(
        env: &Env,
        payload_hash: &BytesN<32>,
        public_key: &BytesN<32>,
        signature: &BytesN<64>,
        group: &Option<FrostGroup>,
    ) {
        match group {
            Some(group) => soroban_sas_common::verify_frost_aggregate_signature(
                env,
                payload_hash,
                group,
                signature,
            ),
            None => soroban_sas_common::verify_offchain_signature(
                env,
                payload_hash,
                public_key,
                signature,
            ),
        }
    }

    /// Fails fast on a nonce that is not strictly greater than the recorded
    /// high-watermark, without consuming it.
    ///
    /// Delegated paths call this before resolving the schema's FROST group and
    /// before verifying the signature, so a replay is rejected by local state
    /// alone. That preserves the historical failure mode (and cost) for
    /// replays even when the registry has since been archived, and it keeps the
    /// stronger rule that a *failed signature* consumes nothing: only
    /// [`Self::consume_delegation_nonce`] writes the watermark, after every
    /// check has passed.
    fn require_nonce_not_replayed(env: &Env, attester: &Address, nonce: u64) {
        extend_instance_ttl(env);
        let key = DelegationNonceKey {
            attester: attester.clone(),
        };
        if let Some(last) = env.storage().instance().get::<_, u64>(&key) {
            if nonce <= last {
                panic_with_error!(env, SASError::DelegationReplay);
            }
        }
    }

    fn consume_delegation_nonce(env: &Env, attester: &Address, nonce: u64) {
        extend_instance_ttl(env);
        let key = DelegationNonceKey {
            attester: attester.clone(),
        };
        // Re-check before writing: callers also call
        // [`Self::require_nonce_not_replayed`] before any signature work, but
        // keeping the guard here makes the invariant local to the write.
        if let Some(last) = env.storage().instance().get::<_, u64>(&key) {
            if nonce <= last {
                panic_with_error!(env, SASError::DelegationReplay);
            }
        }
        env.storage().instance().set(&key, &nonce);
        extend_instance_ttl(env);
    }

    fn consume_recipient_consent_nonce(env: &Env, recipient: &Address, nonce: u64) {
        extend_instance_ttl(env);
        let key = RecipientConsentNonceKey {
            scope: RECIPIENT_CONSENT_NONCE,
            recipient: recipient.clone(),
        };
        if let Some(last) = env.storage().instance().get::<_, u64>(&key) {
            if nonce <= last {
                panic_with_error!(env, SASError::DelegationReplay);
            }
        }
        env.storage().instance().set(&key, &nonce);
        extend_instance_ttl(env);
    }

    /// Invalidates a range of delegation nonces `[min_nonce, max_nonce]` for `attester` (#437).
    /// Requires direct caller authorization (`attester.require_auth()`).
    pub fn invalidate_nonces(env: Env, attester: Address, min_nonce: u64, max_nonce: u64) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        extend_instance_ttl(&env);
        if min_nonce > max_nonce {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        attester.require_auth();
        Self::invalidate_nonces_internal(&env, &attester, min_nonce, max_nonce);
    }

    /// Sets the nonce high-water mark for `attester` to `new_nonce` (#437).
    /// Requires direct caller authorization (`attester.require_auth()`).
    pub fn set_nonce_highwater_mark(env: Env, attester: Address, new_nonce: u64) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        extend_instance_ttl(&env);
        attester.require_auth();

        let key = DelegationNonceKey {
            attester: attester.clone(),
        };
        let current = env.storage().instance().get::<_, u64>(&key).unwrap_or(0);
        let min_nonce = current.saturating_add(1);
        Self::invalidate_nonces_internal(&env, &attester, min_nonce, new_nonce);
    }

    /// Invalidates a range of delegation nonces using an off-chain signed administrative delegation message (#437).
    pub fn invalidate_nonces_by_delegation(
        env: Env,
        attester: Address,
        min_nonce: u64,
        max_nonce: u64,
        nonce: u64,
        signature: soroban_sdk::BytesN<64>,
        public_key: soroban_sdk::BytesN<32>,
    ) {
        reject_reentrant(&env);
        if is_paused_status(&env) {
            panic_with_error!(&env, SASError::ProtocolPaused);
        }
        extend_instance_ttl(&env);
        if min_nonce > max_nonce {
            panic_with_error!(&env, SASError::InvalidValue);
        }
        Self::require_attester_key(&env, &attester, &public_key);
        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        let payload_hash = soroban_sas_common::hash_delegated_nonce_invalidation(
            &env, &attester, min_nonce, max_nonce, &domain,
        );
        soroban_sas_common::verify_offchain_signature(&env, &payload_hash, &public_key, &signature);
        Self::consume_delegation_nonce(&env, &attester, nonce);

        Self::invalidate_nonces_internal(&env, &attester, min_nonce, max_nonce);
    }

    /// Returns the current delegation nonce high-water mark for `attester` (#437).
    pub fn get_nonce_highwater_mark(env: Env, attester: Address) -> u64 {
        extend_instance_ttl(&env);
        let key = DelegationNonceKey { attester };
        env.storage().instance().get::<_, u64>(&key).unwrap_or(0)
    }

    fn invalidate_nonces_internal(env: &Env, attester: &Address, min_nonce: u64, max_nonce: u64) {
        let key = DelegationNonceKey {
            attester: attester.clone(),
        };
        let current = env.storage().instance().get::<_, u64>(&key).unwrap_or(0);
        if max_nonce <= current {
            panic_with_error!(env, SASError::InvalidValue);
        }
        env.storage().instance().set(&key, &max_nonce);
        extend_instance_ttl(env);
        events::publish_nonces_invalidated(env, attester, min_nonce, max_nonce);
    }

    /// Verifies off-chain attestation signed by attester's ed25519 key.
    /// Panics Unauthorized, AlreadyRevoked, AlreadyExpired, InvalidSchema
    /// (unknown/deprecated schema), or ed25519 error. Schema check mirrors
    /// on-chain attest: deprecated invalidates prior signatures as well.
    /// Resolver not invoked (read-only), but schema existence is consistent.
    /// For a schema with a declared FROST group (#534) the key binding is the
    /// group key instead, so aggregate signatures verify here too.
    pub fn verify_offchain_attestation(
        env: Env,
        attestation: Attestation,
        nonce: u64,
        public_key: soroban_sdk::BytesN<32>,
        signature: soroban_sdk::BytesN<64>,
    ) -> bool {
        extend_instance_ttl(&env);
        let group = Self::require_delegation_key(
            &env,
            &attestation.schema_uid,
            &attestation.attester,
            &public_key,
        );

        if attestation.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        if attestation.valid_from != 0 && env.ledger().timestamp() < attestation.valid_from {
            return false;
        }
        if let Err(err) = validate_expiration(&env, attestation.expiration_time) {
            panic_with_error!(&env, err);
        }

        // An on-chain revocation of the same UID also invalidates the
        // off-chain copy.
        if let Some(stored) = env
            .storage()
            .persistent()
            .get::<_, Attestation>(&attestation.uid)
        {
            let ttl = Self::compute_storage_ttl(&env, stored.expiration_time);
            env.storage()
                .persistent()
                .extend_ttl(&attestation.uid, ttl, ttl);
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
        Self::verify_delegated_signature(&env, &payload_hash, &public_key, &signature, &group);

        true
    }

    /// Returns the EIP-712 typed-data domain for off-chain structured message
    /// signing. Wallet connectors use this to render readable confirmation
    /// screens (schema UID, recipient, claims) instead of opaque hex blobs.
    ///
    /// The returned domain matches the on-chain `AttestationDomain` used by
    /// `attest_by_delegation`, so a signature produced over the typed payload
    /// verifies accurately on-chain.
    pub fn get_eip712_domain(env: Env) -> soroban_sas_common::Eip712Domain {
        extend_instance_ttl(&env);
        eip712_domain(&env)
    }

    /// Returns the EIP-712 typed-data payload hash for an off-chain attestation
    /// signed under `nonce`. Wallets display the structured fields; the
    /// resulting signature is verified by `attest_by_delegation`.
    pub fn get_eip712_payload_hash(env: Env, attestation: Attestation, nonce: u64) -> BytesN<32> {
        extend_instance_ttl(&env);
        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain)
    }

    pub fn verify_attestation(env: Env, uid: UID) -> bool {
        extend_instance_ttl(&env);
        verify_attestation_record(&env, &uid)
    }

    /// Verify a batch of attestations in one call (#297).
    ///
    /// Returns exactly one boolean per input UID, in the same order as `uids`,
    /// with the identical semantics of `verify_attestation`: `true`
    /// when the UID exists, is not revoked, and has not expired. Batching
    /// removes the per-call fixed cost (invocation, dispatch, instance TTL
    /// renewal) that dominates polling many UIDs one at a time, without
    /// changing a single verdict.
    ///
    /// Duplicate UIDs are allowed and each entry is verified independently, so
    /// callers keep a stable input-index -> verdict mapping. The batch is
    /// capped at [`MAX_VERIFY_BATCH`]; a larger batch is rejected with
    /// `SASError::BatchTooLarge` rather than silently truncated, matching
    /// `multi_attest` / `multi_revoke` / `bulk_reindex`.
    pub fn verify_attestations(env: Env, uids: soroban_sdk::Vec<UID>) -> soroban_sdk::Vec<bool> {
        extend_instance_ttl(&env);
        if uids.len() > MAX_VERIFY_BATCH {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }

        let mut results: soroban_sdk::Vec<bool> = soroban_sdk::Vec::new(&env);
        for uid in uids.iter() {
            results.push_back(verify_attestation_record(&env, &uid));
        }
        results
    }

    /// Returns `true` only when every UID in `uids` verifies (#297).
    ///
    /// Equivalent to requiring every entry of `verify_attestations` to
    /// be `true`, but stops at the first failing UID, so a mostly-invalid batch
    /// costs a fraction of a full scan while reporting the same combined
    /// verdict. Bounded by [`MAX_VERIFY_BATCH`] like the rest of the batch API.
    ///
    /// An empty batch is vacuously `true`, which lets callers treat this as
    /// "nothing to check, nothing failed" without special-casing the call.
    pub fn verify_all_attestations(env: Env, uids: soroban_sdk::Vec<UID>) -> bool {
        extend_instance_ttl(&env);
        if uids.len() > MAX_VERIFY_BATCH {
            panic_with_error!(&env, SASError::BatchTooLarge);
        }

        for uid in uids.iter() {
            if !verify_attestation_record(&env, &uid) {
                return false;
            }
        }
        true
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
        if let Some(attestation) = read_attestation(&env, &uid) {
            let ttl = Self::compute_storage_ttl(&env, attestation.expiration_time);
            extend_attestation_ttl(&env, &uid, ttl);
            Some(attestation)
        } else {
            None
        }
    }

    /// Pure read-only variant of [`SAS::get_attestation`] that does **not**
    /// renew the entry's TTL. Unlike `get_attestation`, this performs no
    /// storage writes, so it is safe to call from read-only simulation
    /// contexts and from SDK async wrappers that poll many UIDs
    /// concurrently without contending on the entry's rent.
    ///
    /// Returns `None` when the UID was never issued or has been
    /// garbage-collected. Archived entries trap at the host layer exactly
    /// as with `get_attestation`; callers should map that to `Archived`.
    pub fn get_attestation_view(env: Env, uid: UID) -> Option<Attestation> {
        read_attestation(&env, &uid)
    }

    /// Verifies that `leaf` is committed at position `index` in the Merkle
    /// root stored as the payload of attestation `attestation_uid` (#529).
    ///
    /// The parent attestation's `data` must be exactly 32 raw bytes: the
    /// index-bound Merkle root defined by
    /// [`soroban_sas_common::indexed_merkle_root`] (leaf
    /// `sha256(0x00 || index_be_u32 || leaf)`, nodes
    /// `sha256(0x01 || smaller || larger)`, unpaired nodes promoted). `leaf`
    /// is the raw leaf payload, not a pre-hashed leaf, and `proof` carries one
    /// sibling hash per level.
    ///
    /// Verification is read-only (no storage writes and no TTL renewal) and
    /// returns `false` for every rejection: unknown parent, revoked or
    /// expired parent, parent not yet valid at `valid_from`, a payload that
    /// is not exactly 32 bytes, a proof deeper than
    /// [`soroban_sas_common::MAX_MERKLE_PROOF_DEPTH`], and any leaf, sibling,
    /// index, or root mismatch. The index is bound into the leaf preimage, so
    /// a proof for one position cannot be replayed at another and a leaf
    /// cannot be relocated without changing the root.
    ///
    /// See `docs/batch-attestations.md` for the payload and tree
    /// conventions, including the canonical `bytes32 merkle_root` schema
    /// string.
    pub fn verify_indexed_merkle_leaf(
        env: Env,
        attestation_uid: UID,
        leaf: soroban_sdk::Bytes,
        proof: soroban_sdk::Vec<soroban_sas_common::MerkleProofStep>,
        index: u32,
    ) -> bool {
        let Some(attestation) = read_attestation(&env, &attestation_uid) else {
            return false;
        };
        if !attestation_is_live(&env, &attestation) {
            return false;
        }
        let Some(root) = soroban_sas_common::merkle_root_from_payload(&env, &attestation.data)
        else {
            return false;
        };
        soroban_sas_common::verify_indexed_proof(&env, &root, index, &leaf, &proof)
    }

    /// Pure read-only variant of [`SAS::verify_attestation`] that does
    /// **not** renew the entry's TTL. Suitable for SDK async wrappers that
    /// need a side-effect-free verdict.
    pub fn verify_attestation_view(env: Env, uid: UID) -> bool {
        let Some(attestation) = read_attestation(&env, &uid) else {
            return false;
        };
        attestation_is_live(&env, &attestation)
    }

    /// Exposes the `valid_from` activation timestamp for an attestation (#439).
    pub fn get_valid_from(env: Env, uid: UID) -> u64 {
        extend_instance_ttl(&env);
        let Some(attestation) = read_attestation(&env, &uid) else {
            return 0;
        };
        let ttl = Self::compute_storage_ttl(&env, attestation.expiration_time);
        env.storage().persistent().extend_ttl(&uid, ttl, ttl);
        attestation.valid_from
    }

    /// Migrates a legacy `Attestation` storage entry to `CompactAttestation` format (#438).
    /// Returns `true` if migration occurred, `false` if entry was already compact or missing.
    pub fn migrate_attestation(env: Env, uid: UID) -> bool {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        if let Some(val) = env.storage().persistent().get::<_, Val>(&uid) {
            if CompactAttestation::try_from_val(&env, &val).is_ok() {
                // Already in compact layout
                return false;
            }
            if let Ok(legacy) = Attestation::try_from_val(&env, &val) {
                let compact = CompactAttestation::from_attestation(&env, &legacy);
                let ttl = Self::compute_storage_ttl(&env, legacy.expiration_time);
                env.storage().persistent().set(&uid, &compact);
                env.storage().persistent().extend_ttl(&uid, ttl, ttl);
                if legacy.valid_from != 0 {
                    let v_key = (VALID_FROM, uid.clone());
                    env.storage().persistent().set(&v_key, &legacy.valid_from);
                    env.storage().persistent().extend_ttl(&v_key, ttl, ttl);
                }
                return true;
            }
        }
        false
    }

    /// Batch migrates a slice of UIDs to `CompactAttestation` format (#438).
    /// Returns the number of successfully migrated records.
    pub fn migrate_attestations(env: Env, uids: soroban_sdk::Vec<UID>) -> u32 {
        reject_reentrant(&env);
        extend_instance_ttl(&env);
        let mut count = 0u32;
        for uid in uids.iter() {
            if Self::migrate_attestation(env.clone(), uid) {
                count += 1;
            }
        }
        count
    }

    /// Returns the ledger that issued attestation `uid` — its sequence number
    /// and that ledger's close time — or `None` if the UID was never issued
    /// or its entries have been garbage-collected (#298).
    ///
    /// Extends the anchor's TTL on a successful read, like every other
    /// documented reader in this contract.
    ///
    /// An off-chain verifier starts here: fetch the ledger header for
    /// `ledger_sequence` from a source it already trusts, confirm the header's
    /// close time is `ledger_timestamp`, and the attestation's `time` is then
    /// bound to a ledger the network agreed on rather than to the attester's
    /// word. A caller that already holds a claim to check can call
    /// `verify_timestamp` first and only look up a header if it matches.
    pub fn get_issuance_timestamp(env: Env, uid: UID) -> Option<timestamp::TimestampAnchor> {
        extend_instance_ttl(&env);
        timestamp::read_and_renew_anchor(&env, &uid, false)
    }

    /// Returns the ledger that revoked attestation `uid`, or `None` if it was
    /// never revoked (or the entries are gone) (#298).
    ///
    /// Independent of `get_issuance_timestamp`: for a revoked attestation
    /// both anchors exist, so a verifier can show that the record was issued
    /// at one ledger and revoked at another, from the same pair of headers.
    /// That is the point of anchoring revocation separately — a bare
    /// `revocation_time` only says the contract was told some close time.
    pub fn get_revocation_timestamp(env: Env, uid: UID) -> Option<timestamp::TimestampAnchor> {
        extend_instance_ttl(&env);
        timestamp::read_and_renew_anchor(&env, &uid, true)
    }

    /// Returns `true` when `claim` is exactly one of the ledger anchors this
    /// contract recorded for `uid` — the issuance anchor of a live
    /// attestation, or its revocation anchor once revoked (#298).
    ///
    /// Both fields of the claim are compared, so a real close time attached to
    /// the wrong sequence number fails, and so does the right sequence number
    /// with a doctored time. `false` is also the answer for a UID that was
    /// never issued.
    ///
    /// This is a read: unlike the two readers above it renews nothing, so
    /// checking a claim costs no storage rent.
    ///
    /// Beyond equality (#436): `false` is also returned when the claim names a
    /// ledger ahead of the current one (a simulation running behind the
    /// network) or when the stored anchors are not monotonic. Use
    /// `check_timestamp` to learn which of those it was.
    pub fn verify_timestamp(env: Env, uid: UID, claim: timestamp::TimestampAnchor) -> bool {
        extend_instance_ttl(&env);
        timestamp::check_claim(&env, &uid, &claim).is_ok()
    }

    /// Strict form of `verify_timestamp` that reports why a claim fails (#436).
    ///
    /// Succeeds only when `claim` equals a recorded anchor in both ledger
    /// sequence and close time. Otherwise it traps with
    /// `SASError::InvalidTimestamp` (doctored close time, foreign or
    /// not-yet-closed ledger sequence, non-monotonic stored anchors) or
    /// `SASError::TimestampAnchorNotFound` (nothing recorded for `uid`), and
    /// leaves a diagnostic log line in test and simulation builds. Prefer it
    /// in tooling that must not mistake a lagging simulation for a forged
    /// timestamp. A read: it renews no storage TTL.
    pub fn check_timestamp(
        env: Env,
        uid: UID,
        claim: timestamp::TimestampAnchor,
    ) -> Result<(), SASError> {
        extend_instance_ttl(&env);
        timestamp::check_claim(&env, &uid, &claim)
    }

    /// Verifies that `leaf` is committed to by the Merkle root held in
    /// attestation `uid`'s `data`, using SHA-256 (#435).
    ///
    /// `proof` is the list of sibling hashes from the leaf level up. The tree
    /// format is the canonical one in `soroban_sas_common::merkle`: leaf hash
    /// `sha256(0x00 || leaf)`, node hash `sha256(0x01 || min || max)`, an odd
    /// node promoted unchanged. Returns `false`, never traps, when the
    /// attestation is missing, revoked, expired or not yet valid, when its
    /// `data` is not exactly 32 bytes, when the proof is longer than 32
    /// siblings, and for any proof that does not reproduce the root. A read
    /// that only renews TTLs, like `verify_attestation`. See
    /// docs/selective-disclosure.md.
    pub fn verify_merkle_leaf(
        env: Env,
        uid: UID,
        leaf: soroban_sdk::Bytes,
        proof: soroban_sdk::Vec<BytesN<32>>,
    ) -> bool {
        extend_instance_ttl(&env);
        merkle_disclosure::verify_leaf(
            &env,
            &uid,
            &leaf,
            &proof,
            soroban_sas_common::MerkleHash::Sha256,
        )
    }

    /// Same as `verify_merkle_leaf` for trees built with Keccak-256, as
    /// produced by Ethereum-style Merkle tooling (#435).
    pub fn verify_merkle_leaf_keccak(
        env: Env,
        uid: UID,
        leaf: soroban_sdk::Bytes,
        proof: soroban_sdk::Vec<BytesN<32>>,
    ) -> bool {
        extend_instance_ttl(&env);
        merkle_disclosure::verify_leaf(
            &env,
            &uid,
            &leaf,
            &proof,
            soroban_sas_common::MerkleHash::Keccak256,
        )
    }

    /// Returns the highest delegation nonce consumed for `attester`, or `None`
    /// if no delegated operation has ever been performed for this attester (#236).
    ///
    /// Extends instance TTL on every call.
    ///
    /// Nonce semantics:
    /// - `None`: No nonce has been consumed; any nonce ≥ 1 is valid for the next operation.
    /// - `Some(n)`: `n` is the highest nonce consumed so far; the next valid nonce is any value strictly greater than `n` (i.e. > `n`).
    pub fn get_delegation_nonce(env: Env, attester: Address) -> Option<u64> {
        extend_instance_ttl(&env);
        let key = DelegationNonceKey { attester };
        let nonce = env.storage().instance().get::<_, u64>(&key);
        extend_instance_ttl(&env);
        nonce
    }

    /// Highest consumed recipient consent nonce, or `None` before first use.
    /// The next consent nonce must be strictly greater than this value.
    pub fn get_recipient_consent_nonce(env: Env, recipient: Address) -> Option<u64> {
        extend_instance_ttl(&env);
        let key = RecipientConsentNonceKey {
            scope: RECIPIENT_CONSENT_NONCE,
            recipient,
        };
        let nonce = env.storage().instance().get::<_, u64>(&key);
        extend_instance_ttl(&env);
        nonce
    }

    /// Returns `attester`'s registered delegated-verification key record, or
    /// `None` if one was never registered (#214).
    ///
    /// Every other piece of user-facing persistent state in the protocol has
    /// a typed public reader; this closes that gap for the attester key
    /// registry, which previously required parsing raw storage off-chain.
    /// `Some(record)` is returned for both active and revoked registrations
    /// — `record.revoked` distinguishes the two — so callers can tell "never
    /// registered" apart from "registered, then revoked".
    pub fn get_attester_key(
        env: Env,
        attester: Address,
    ) -> Option<soroban_sas_common::AttesterKeyRecord> {
        extend_instance_ttl(&env);
        let key = (ATTESTER_KEY, attester);
        let record: Option<soroban_sas_common::AttesterKeyRecord> =
            env.storage().persistent().get(&key);
        if record.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        }
        record
    }
}

#[cfg(test)]
mod demo;
#[cfg(test)]
mod gas_profile_test;
#[cfg(test)]
mod perf_bench;
#[cfg(test)]
mod revocation_properties;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_extra;
#[cfg(test)]
mod test_indexer_integration;
#[cfg(test)]
mod test_issue_242;
#[cfg(test)]
mod test_issue_252;
#[cfg(test)]
mod test_issue_293;
#[cfg(test)]
mod test_issue_296;
#[cfg(test)]
mod test_merkle;
#[cfg(test)]
mod test_issue_443;
#[cfg(test)]
mod test_issue_432;
#[cfg(test)]
mod test_issue_492;
#[cfg(test)]
mod test_merkle_disclosure;
#[cfg(test)]
mod test_issue_491;
#[cfg(test)]
mod test_round_trip;
#[cfg(test)]
mod test_security_replay;
#[cfg(test)]
mod test_timestamp;
#[cfg(test)]
mod verify_batch_test;

#[cfg(test)]
mod test_issue_526_530;
#[cfg(test)]
mod test_issue_527;
#[cfg(test)]
mod test_issue_531;
