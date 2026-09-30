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

use soroban_sas_common::{LEDGERS_IN_ONE_YEAR, UID};
use soroban_sdk::{contracttype, Env};

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
pub fn write_anchor(env: &Env, uid: &UID, revocation: bool, ttl: u32) {
    let storage = env.storage().persistent();
    let key = anchor_key(uid, revocation);
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
