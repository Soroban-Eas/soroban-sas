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
