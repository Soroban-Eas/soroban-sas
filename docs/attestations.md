# Attestation Lifecycle

An attestation is a claim, issued by an `attester` about a `recipient`, that
conforms to a registered schema. This document covers the lifecycle states an
attestation moves through — issuance, expiration, revocation, and
replacement — and the invariants the `SAS` contract enforces at each
transition. For the schema layer (structure, validation, revocability
ceiling), see [Schema Syntax and Payloads](schemas.md). For the on-chain event
shape emitted at each transition, see [Contract Events](events.md).

## Issuance

Attestations are issued via `attest`, `attest_with_value`, `attest_by_delegation`,
or `multi_attest`. Every issuance path funnels through the shared
`attest_internal`, so validation (recipient checks, schema lookup, resolver
invocation, `AttestationIssued` event) is applied uniformly regardless of
entry point.

## Expiration

`expiration_time` is a Unix timestamp. `expiration_time == 0` means the
attestation never expires (perpetual). A non-zero `expiration_time` in the
past at issuance time is rejected; once issued, an attestation is treated as
expired once the ledger timestamp reaches its `expiration_time`. Expiration is
a passive, read-time check — it does not trigger a resolver callback or emit
an event on its own, unlike revocation.

Every read and verify path evaluates expiration the same way:
`verify_attestation`, `verify_attestation_view`, `verify_attestations` and
`verify_all_attestations` return `false` for an expired record, with no
revocation transaction required. `get_attestation` still returns the stored
record so indexers can show its history, with `revocation_time` left at `0`.

### Pruning expired records

Expired records keep occupying persistent storage. Pruning is opt-in and
disabled by default (#432):

- `set_auto_prune(enabled)` (admin only) turns pruning on or off;
  `is_auto_prune_enabled()` reads it.
- `prune_expired(uids)` is a public entrypoint, limited to `MAX_PRUNE_BATCH`
  (100) UIDs per call. It deletes the record, its `valid_from` entry and both
  timestamp anchors for each UID whose non-zero `expiration_time` has passed,
  emits a `PRUNED` event, and returns how many were removed. Perpetual
  (`expiration_time == 0`), live and unknown UIDs are skipped, so the call is
  idempotent. While disabled it fails with `SASError::AutoPruneDisabled`.
- Expired attestations cannot be revived: `renew_attestation` on an expired
  record fails with `SASError::AlreadyExpired`. A pruned or expired claim only
  returns through a new `attest` call that the attester authorizes.
- Pruning removes the stored record permanently, so archive anything you need
  from `AttestationIssued` events or the indexer first.
## Revocation

`revoke` (and its delegated/authorizer variants) marks an attestation revoked,
invokes the schema's `on_revoke` resolver hook, and emits `AttestationRevoked`.
Only a `revocable` attestation can be revoked, and only once.

## Replacement

`replace_attestation` atomically revokes an existing attestation (`old_uid`)
and issues a new one linked back to it via `ref_uid`, so consumers never
observe a window where neither the old nor the new attestation is valid. It
requires:

- The old attestation's attester to authorize the call.
- The old attestation to be `revocable` and not already revoked.
- The replacement's `attester` and `recipient` to match the old attestation's
  — a replacement changes what is being claimed, not who is claiming it or
  about whom.

`replace_by_delegation_consent` performs the same replacement with off-chain
signatures from both the recorded attester and recipient. See
[delegation](delegation.md#delegated-replacement-with-recipient-consent) for
the digest layout, nonce rules, and relayer flow.

### Expiration monotonicity

The replacement's `expiration_time` must not be *earlier* than the old
attestation's, when both are non-zero:

- Extending the expiration (`new.expiration_time > old.expiration_time`)
  succeeds.
- Converting an expiring attestation into a perpetual one
  (`new.expiration_time == 0`) succeeds unconditionally.
- Shortening a non-zero expiration
  (`0 < new.expiration_time < old.expiration_time`) panics with
  `SASError::InvalidTTL`.

This closes an early-expiration bypass: without it, an attester could
"replace" a valid, long-lived attestation with one whose `expiration_time` is
already in the past. The replacement would read as expired the instant it is
queried — without the schema's `on_revoke` resolver hook ever running and
without an `AttestationRevoked` event ever being emitted. An attester who
genuinely wants to end an attestation early should call `revoke` instead,
which always runs the resolver hook and emits the event. See
[`specs/protocol-v1.md`](../specs/protocol-v1.md#replacement-expiration-monotonicity)
for the normative statement of this rule.

## Verifiable Timestamps

`time` is the ledger close time at which an attestation was issued (#156),
and `revocation_time` the close time at which it was revoked. Both are
host-supplied values: on their own they record what the contract was told, not
what the network agreed. Every issuance and every revocation therefore also
records the ledger it happened on, as a
`TimestampAnchor { ledger_sequence, ledger_timestamp }` (#298):

- `get_issuance_timestamp(uid)` — the ledger that issued the attestation.
- `get_revocation_timestamp(uid)` — the ledger that revoked it, `None`
  while it is live.
- `verify_timestamp(uid, claim)` — `true` when `claim` is exactly one of
  those anchors, comparing both the sequence number and the close time. It is
  a read: it renews no TTLs, so checking a claim costs no storage rent.
- `check_timestamp(uid, claim)` — the strict form of `verify_timestamp`. It
  succeeds on the same claims and otherwise traps with a specific error
  instead of returning `false` (#436):
  - `InvalidTimestamp` (420): the claim's sequence or close time does not
    match a recorded anchor (a doctored close time, or a foreign ledger
    sequence), the claim names a ledger that is ahead of the ledger the call
    runs on, or the stored anchors are not monotonic.
  - `TimestampAnchorNotFound` (421): no anchor exists for the UID.

### Simulated and test environments

Local tests and RPC simulation can execute against a ledger whose sequence
number and close time are out of step with the ledger an anchor was written
on, which used to surface as a bare `false` or an unexplained failure. Three
rules make that visible instead (#436):

- **Anchors are immutable.** An anchor is written once; any attempt to write
  an existing one fails with `InvalidTimestamp` rather than replacing it.
- **Sequence and close time must agree and move forward together.** A claim
  must equal an anchor in both fields. A claim from a ledger that has not
  closed yet is rejected, and a revocation anchor that precedes its issuance
  anchor in sequence or in close time makes every claim for that UID fail.
- **Failures leave a diagnostic.** Each rejection writes a `log!` line saying
  which rule failed (missing anchor, anchor ahead of the ledger, close time
  mismatch for a known sequence, sequence not anchored). The lines exist in
  test and simulation builds and are compiled out of release WASM.

`verify_timestamp` keeps returning a boolean and answers `false` in exactly
the cases where `check_timestamp` fails, so existing callers are unaffected.
Use `check_timestamp` in tooling that has to tell a lagging simulation apart
from a forged timestamp.

A verifier that trusts a ledger header — from an SCP envelope, ledger close
meta, or an RPC it trusts — confirms that the header's sequence number and
close time match the anchor, and the attestation's timestamp is then bound to
a ledger the network agreed on rather than to the attester's word. The header
is the proof; the anchor is the pointer to which header to fetch.

Both transitions are anchored independently, so a revoked attestation carries
its issuance and revocation anchors at once and an auditor can show that a
record was issued at one ledger and revoked at another from the same pair of
headers. Anchors live in their own persistent entries rather than as new
`Attestation` fields because the v1.0.0 state schema is frozen — adding
fields would change the XDR layout every indexer, SDK and stored record
decodes — and each entry is written with the attestation's own TTL, so it
expires exactly when the record it describes does.

A rejected revocation leaves no anchor behind: `revoke` on a non-revocable or
already-revoked attestation panics, which reverts the write along with it, so a
failed call can never be read back as a revocation that happened.

## Privacy and Selective Disclosure

Everything in an attestation is public and permanent. [Privacy Implications of
Public Attestations](privacy.md) lists what is exposed and how to avoid it, and
[Selective Disclosure](selective-disclosure.md) shows how to attest to a Merkle
root and reveal individual claims with `verify_merkle_leaf`.
