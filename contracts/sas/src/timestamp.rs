//! Ledger-verifiable timestamps for issuance and revocation (#298).
//!
//! `Attestation.time` is normalized to the ledger close time when an
//! attestation is issued (#156), and `revocation_time` to the close time of
//! the ledger that revoked it. Both are host-supplied values: on their own
//! they say *"a validator claimed this ledger closed at T"*, with nothing for
//! a verifier to check the claim against. A consumer holding only the
//! attestation has to trust the attester, or this contract, that the number
//! was not something else.
//!
//! This module closes that gap by recording *which ledger* each timestamp
//! came from. A close time plus the sequence number of the ledger that
//! produced it is exactly what an SCP-verified ledger header carries, so a
//! verifier that already trusts a header — the SDK reading `/ledgers/:seq`, a
//! bridge checking an SCP envelope, an auditor replaying ledger close meta —
//! can bind the attestation to that ledger with `SAS::verify_timestamp`, or
//! fetch the anchor it needs to look up with `SAS::get_issuance_timestamp` /
//! `SAS::get_revocation_timestamp`.
//!
//! What this does *not* do is prove anything about a ledger by itself: the
//! contract can only report what the host told it. The proof is the ledger
//! header, which the network signs; the anchor is the pointer to it.
//!
//! Anchors live in their own persistent entries rather than as new fields on
//! `Attestation`. The v1.0.0 state schema is frozen — adding fields would
//! change the XDR layout every indexer, SDK and stored record decodes — and a
//! side entry with the attestation's own TTL expires exactly when the record
//! it describes does.
//!
//! # Hardening for simulated environments (#436)
//!
//! Local tests and RPC simulation can run against a ledger whose close time
//! and sequence number do not line up with the ledger the anchor was written
//! on. Three rules keep that from turning into a silently wrong verdict:
//!
//! * **Immutability.** An anchor is written once. [`write_anchor`] refuses to
//!   replace an existing entry, so a later call cannot rewrite history.
//! * **Monotonicity.** A revocation anchor cannot precede its issuance anchor
//!   in sequence or in close time, and a claim cannot name a ledger that is
//!   ahead of the ledger the contract is running on.
//! * **Sequence and close time travel together.** A claim is accepted only
//!   if both fields equal a recorded anchor; every mismatch is reported as
//!   [`SASError::InvalidTimestamp`], never as a quiet `false`, by
//!   `SAS::check_timestamp`.
//!
//! Failures also write a diagnostic log line (`log!`), which is compiled out of
//! release builds and visible in test and simulation runs.

use soroban_sas_common::{SASError, LEDGERS_IN_ONE_YEAR, UID};
use soroban_sdk::{contracttype, log, panic_with_error, Env};

/// The ledger a timestamp came from: the sequence number of the ledger whose
/// close time was stamped, and that close time itself.
///
/// A verifier compares `ledger_timestamp` against the close time in the
/// header for `ledger_sequence`. Both fields are checked, so an anchor cannot
/// be satisfied by a close time that belongs to a different ledger.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)] // Optimize storage serialization
pub struct TimestampAnchor {
    pub ledger_sequence: u32,
    pub ledger_timestamp: u64,
}

/// Typed storage key for one of an attestation's anchors.
///
/// An attestation has two independent anchors over its life — the ledger that
/// issued it and, if it is revoked, the ledger that revoked it — so one key
/// type carries both, distinguished by `revocation`, rather than a second
/// storage namespace. Both are keyed by UID, which keeps the anchor adjacent
/// to (and garbage-collected with) the record it describes.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampAnchorKey {
    pub uid: UID,
    /// `false` for the issuance anchor, `true` for the revocation anchor.
    pub revocation: bool,
}

fn anchor_key(uid: &UID, revocation: bool) -> TimestampAnchorKey {
    TimestampAnchorKey {
        uid: uid.clone(),
        revocation,
    }
}

/// Records the current ledger as `uid`'s issuance or revocation anchor, with
/// the same TTL as the attestation it describes so the two expire together.
///
/// Called from `attest_internal` and `revoke_internal` — the two places that
/// write a timestamp — so every entry point that reaches either (direct,
/// delegated, batch, paid, replacement, authorizer) is anchored by
/// construction rather than by remembering to anchor it.
///
/// Anchors are immutable: if one is already recorded under the key this panics
/// with [`SASError::InvalidTimestamp`] instead of overwriting it (#436).
pub fn write_anchor(env: &Env, uid: &UID, revocation: bool, ttl: u32) {
    let storage = env.storage().persistent();
    let key = anchor_key(uid, revocation);
    if storage.has(&key) {
        log!(
            env,
            "timestamp anchor is immutable: already recorded, ledger sequence {}",
            env.ledger().sequence()
        );
        panic_with_error!(env, SASError::InvalidTimestamp);
    }
    storage.set(
        &key,
        &TimestampAnchor {
            ledger_sequence: env.ledger().sequence(),
            ledger_timestamp: env.ledger().timestamp(),
        },
    );
    storage.extend_ttl(&key, ttl, ttl);
}

/// Reads an anchor without touching storage TTLs.
///
/// The verification entry point uses this: a check is a read, and a caller
/// that only wants to know whether a claim holds should not have to pay for a
/// write to find out.
pub fn read_anchor(env: &Env, uid: &UID, revocation: bool) -> Option<TimestampAnchor> {
    env.storage().persistent().get(&anchor_key(uid, revocation))
}

/// Reads an anchor and renews its TTL, the way this contract's other
/// documented readers do. The renewal window is the protocol's standard
/// one-year retention (`LEDGERS_IN_ONE_YEAR`), matching `get_attester_key`.
pub fn read_and_renew_anchor(env: &Env, uid: &UID, revocation: bool) -> Option<TimestampAnchor> {
    let key = anchor_key(uid, revocation);
    let anchor: Option<TimestampAnchor> = env.storage().persistent().get(&key);
    if anchor.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
    }
    anchor
}

/// Checks `claim` against the anchors recorded for `uid` and says *why* it
/// fails, for `SAS::check_timestamp` and (as a boolean) `SAS::verify_timestamp`
/// (#436).
///
/// * [`SASError::TimestampAnchorNotFound`]: no issuance or revocation anchor
///   exists for `uid`.
/// * [`SASError::InvalidTimestamp`]: the stored anchors are not monotonic, the
///   claim names a ledger ahead of the current one, or the claim does not
///   equal a recorded anchor in both sequence and close time.
///
/// A read only: nothing is written and no TTL is renewed.
pub fn check_claim(env: &Env, uid: &UID, claim: &TimestampAnchor) -> Result<(), SASError> {
    let issuance = read_anchor(env, uid, false);
    let revocation = read_anchor(env, uid, true);

    if issuance.is_none() && revocation.is_none() {
        log!(
            env,
            "timestamp check: no anchor recorded for this uid, claimed sequence {}",
            claim.ledger_sequence
        );
        return Err(SASError::TimestampAnchorNotFound);
    }

    // Revocation cannot happen before issuance. Stored anchors that say
    // otherwise were written under an inconsistent ledger, so nothing about
    // this uid can be trusted.
    if let (Some(issued), Some(revoked)) = (&issuance, &revocation) {
        if revoked.ledger_sequence < issued.ledger_sequence
            || revoked.ledger_timestamp < issued.ledger_timestamp
        {
            log!(
                env,
                "timestamp check: revocation anchor precedes issuance anchor, revocation sequence {}",
                revoked.ledger_sequence
            );
            return Err(SASError::InvalidTimestamp);
        }
    }

    // A ledger that has not closed yet cannot be the source of an anchor. This
    // is what a simulation running behind the network looks like.
    if claim.ledger_sequence > env.ledger().sequence()
        || claim.ledger_timestamp > env.ledger().timestamp()
    {
        log!(
            env,
            "timestamp check: claim is ahead of the current ledger, claimed sequence {}, current sequence {}",
            claim.ledger_sequence,
            env.ledger().sequence()
        );
        return Err(SASError::InvalidTimestamp);
    }

    let mut sequence_known = false;
    for recorded in [&issuance, &revocation].into_iter().flatten() {
        if recorded == claim {
            return Ok(());
        }
        if recorded.ledger_sequence == claim.ledger_sequence {
            sequence_known = true;
        }
    }

    if sequence_known {
        log!(
            env,
            "timestamp check: close time does not match the recorded anchor for sequence {}",
            claim.ledger_sequence
        );
    } else {
        log!(
            env,
            "timestamp check: sequence {} is not a ledger this uid was anchored on",
            claim.ledger_sequence
        );
    }
    Err(SASError::InvalidTimestamp)
}
