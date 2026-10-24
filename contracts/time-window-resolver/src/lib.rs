#![allow(unexpected_cfgs)]
#![cfg_attr(not(test), no_std)]

//! Time-window restriction resolver (#549).
//!
//! Some attestation use cases — daily check-ins, monthly voting allowances,
//! periodic identity re-verification — must not be re-issued to the same
//! recipient faster than a configured interval. This resolver enforces that
//! interval on behalf of a schema: `on_attest` records the ledger timestamp
//! of every accepted issuance per recipient and rejects the next one until
//! `cooldown_period_seconds` have elapsed, with
//! [`SASError::CooldownActive`].
//!
//! Attach it to a schema by registering the schema with this contract's
//! address as its resolver. `SAS::attest_internal` invokes `on_attest` before
//! the attestation is written, and treats any rejection as authoritative, so
//! a rejected issuance stores nothing (see `docs/schemas.md`, "Resolver
//! Failure Semantics").
//!
//! The cooldown is per recipient, not per schema, attester, or UID: two
//! recipients of the same schema never share a window, and a recipient that
//! was last attested through a different resolver instance has no window
//! here. The window is also independent of the attestation's own
//! `expiration_time`/`valid_from` fields, which describe the validity of an
//! issued claim rather than the cadence of issuance.
//!
//! # Timing semantics
//!
//! * The recorded time is `env.ledger().timestamp()` at callback time, not
//!   `Attestation::time`: SAS normalizes that field to ledger time *after*
//!   the resolver callback, so it is not yet authoritative here.
//! * A recipient's first attestation is always accepted. Every accepted
//!   attestation replaces the recorded time with the current ledger time.
//! * The next attestation is accepted once the elapsed time is greater than
//!   or equal to `cooldown_period_seconds`. At exactly
//!   `last_attested_time + cooldown_period_seconds` the window has expired
//!   and issuance succeeds; one second earlier it reverts with
//!   `CooldownActive`.
//! * `cooldown_period_seconds == 0` disables the restriction (every attempt
//!   is accepted and still recorded), which an admin can use to pause the
//!   policy without detaching the resolver from the schema.
//! * The arithmetic saturates, so an extreme cooldown near `u64::MAX`
//!   blocks further issuance instead of wrapping to an already-elapsed
//!   window.
//!
//! # Storage and expiry
//!
//! Configuration (admin and cooldown) lives in instance storage. Per-recipient
//! timestamps live in persistent storage and are renewed to the standard
//! one-year retention window on every read/write. Entries therefore expire
//! only after a year without activity; a recipient whose record has expired
//! is treated as never attested. Keep `cooldown_period_seconds` well below
//! that retention window so expiry can never shorten a configured cooldown.

use soroban_sas_common::{extend_instance_ttl, Attestation, SASError, LEDGERS_IN_ONE_YEAR};
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, symbol_short, Address, Env, Symbol,
};

/// First topic of every `CooldownUpdated` event.
pub const COOLDOWN_UPDATED: Symbol = symbol_short!("CDUPD");

/// Resolver configuration stored under [`DataKey::Config`].
///
/// `admin` is the only address allowed to change `cooldown_period_seconds`;
/// it is set once by `init` and never changes, so a schema's configured
/// resolver address alone cannot be used to seize control of the policy.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeWindowConfig {
    pub admin: Address,
    pub cooldown_period_seconds: u64,
}

/// Payload of the `CooldownUpdated` event.
///
/// Published with topics `(COOLDOWN_UPDATED, authorizer)` after an
/// authorized cooldown change. Both the previous and the new window are
/// included so an off-chain monitor can reconstruct the policy history
/// without polling, and can attribute the change to the authorizing admin.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CooldownUpdatedEvent {
    pub old_cooldown_period_seconds: u64,
    pub new_cooldown_period_seconds: u64,
    pub authorizer: Address,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    /// Last accepted issuance time for a recipient, keyed by address so each
    /// recipient's window is tracked independently.
    LastAttested(Address),
}

fn read_config(env: &Env) -> TimeWindowConfig {
    match env.storage().instance().get(&DataKey::Config) {
        Some(config) => config,
        None => panic_with_error!(env, SASError::NotInitialized),
    }
}

#[contract]
pub struct TimeWindowResolver;

#[contractimpl]
impl TimeWindowResolver {
    /// Initializes the resolver with the cooldown applied to every
    /// recipient and the admin allowed to change it.
    ///
    /// `admin` must authorize the call. A second `init` on the same instance
    /// reverts with [`SASError::AlreadyInitialized`], so the admin cannot be
    /// replaced by re-initialization. `cooldown_period_seconds` may be `0` to
    /// install the resolver with the restriction disabled.
    pub fn init(env: Env, admin: Address, cooldown_period_seconds: u64) {
        extend_instance_ttl(&env);
        if env.storage().instance().has(&DataKey::Config) {
            panic_with_error!(&env, SASError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(
            &DataKey::Config,
            &TimeWindowConfig {
                admin,
                cooldown_period_seconds,
            },
        );
        extend_instance_ttl(&env);
    }

    /// Returns the current configuration, or [`SASError::NotInitialized`]
    /// when `init` has not run yet.
    pub fn get_config(env: Env) -> TimeWindowConfig {
        extend_instance_ttl(&env);
        read_config(&env)
    }

    /// Returns the configured cooldown, or [`SASError::NotInitialized`].
    pub fn get_cooldown_period_seconds(env: Env) -> u64 {
        extend_instance_ttl(&env);
        read_config(&env).cooldown_period_seconds
    }

    /// Returns the admin allowed to change the cooldown, or
    /// [`SASError::NotInitialized`].
    pub fn get_admin(env: Env) -> Address {
        extend_instance_ttl(&env);
        read_config(&env).admin
    }

    /// Returns the ledger timestamp of the last accepted issuance for
    /// `recipient`, or `None` if the recipient has never been attested
    /// through this resolver (or its record has expired).
    ///
    /// Together with `get_cooldown_period_seconds`, callers can
    /// compute when the next issuance becomes possible without attempting
    /// one.
    pub fn get_last_attested_time(env: Env, recipient: Address) -> Option<u64> {
        extend_instance_ttl(&env);
        let key = DataKey::LastAttested(recipient);
        let last = env.storage().persistent().get::<_, u64>(&key);
        if last.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        }
        last
    }

    /// Admin-only: replaces the cooldown applied to every recipient.
    ///
    /// `authorizer` must authorize the call and equal the admin recorded by
    /// `init`; any other address reverts with [`SASError::Unauthorized`]
    /// before the configuration is touched. The change applies immediately
    /// to windows already in progress, because the existing per-recipient
    /// timestamps are kept: shortening the cooldown can make a recipient
    /// eligible straight away, while lengthening it can extend an active
    /// window.
    pub fn set_cooldown_period_seconds(
        env: Env,
        authorizer: Address,
        cooldown_period_seconds: u64,
    ) {
        extend_instance_ttl(&env);
        let mut config = read_config(&env);
        authorizer.require_auth();
        if authorizer != config.admin {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let old_cooldown_period_seconds = config.cooldown_period_seconds;
        config.cooldown_period_seconds = cooldown_period_seconds;
        env.storage().instance().set(&DataKey::Config, &config);
        extend_instance_ttl(&env);

        env.events().publish(
            (COOLDOWN_UPDATED, authorizer.clone()),
            CooldownUpdatedEvent {
                old_cooldown_period_seconds,
                new_cooldown_period_seconds: cooldown_period_seconds,
                authorizer,
            },
        );
    }

    /// Enforces the cooldown for the attestation's recipient and, when it
    /// passes, records the current ledger timestamp as their last accepted
    /// issuance.
    ///
    /// Called by SAS before the attestation is stored. Reverts with
    /// [`SASError::CooldownActive`] — and therefore writes nothing — while
    /// `last_attested_time + cooldown_period_seconds` is still in the
    /// future. Because issuance is a single atomic invocation, the recorded
    /// timestamp stands only if the whole attestation commits; a later
    /// failure in the same transaction rolls the record back with it.
    ///
    /// `on_attest` is invoked once per issued attestation, so a batch that
    /// issues twice to the same recipient in one call is subject to the
    /// window between the two items, exactly as two separate calls would be.
    pub fn on_attest(env: Env, attestation: Attestation) {
        extend_instance_ttl(&env);
        let cooldown_period_seconds = read_config(&env).cooldown_period_seconds;
        let key = DataKey::LastAttested(attestation.recipient.clone());
        let now = env.ledger().timestamp();

        // `0` disables the restriction entirely; skip the comparison so a
        // ledger timestamp that did not advance still accepts issuance.
        if cooldown_period_seconds != 0 {
            if let Some(last_attested_time) = env.storage().persistent().get::<_, u64>(&key) {
                let next_allowed = last_attested_time.saturating_add(cooldown_period_seconds);
                if now < next_allowed {
                    panic_with_error!(&env, SASError::CooldownActive);
                }
            }
        }

        env.storage().persistent().set(&key, &now);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
    }

    /// Accepts every revocation.
    ///
    /// Revoking an attestation does not reset the recipient's cooldown:
    /// the window governs how often claims may be issued, not how long they
    /// live. A recipient who wants a fresh claim earlier must wait for the
    /// window to expire rather than revoke and re-issue.
    pub fn on_revoke(_env: Env, _attestation: Attestation) {}
}

#[cfg(test)]
mod test;
