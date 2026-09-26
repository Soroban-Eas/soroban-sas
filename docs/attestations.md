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
