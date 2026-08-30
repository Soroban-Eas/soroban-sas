# Indexer availability and attestation fee policy

This document specifies two protocol behaviours that were previously implicit:
how the SAS contract behaves when a bound Indexer is unavailable (issue #161),
and how `attest_with_value` decides what payment is required (issue #164).

## Indexer availability (#161)

Once an Indexer is bound with `set_indexer`, `attest` / `attest_by_delegation`
/ `multi_attest` push each newly issued attestation to it via
`index_attestation`. The Indexer is a **downstream mirror**; the attestation
written to contract storage is the source of truth.

### Default: fail-open

By default the push is best-effort. If the Indexer is missing, traps, has been
upgraded to an incompatible interface, or otherwise fails, **the attestation is
still issued**. The contract emits an `IndexFailed(uid)` event (topic
`IDXFAIL`) for every push that did not succeed.

Operators reconcile a fail-open deployment by:

1. Watching for `IndexFailed` events (and comparing issued `AttestationIssued`
   events against what the Indexer has recorded).
2. Restoring Indexer availability — fix the deployment, or rotate to a new
   Indexer contract with `set_indexer`.
3. Calling `reindex_attestation(uid)` for each missed UID. This is
   permissionless, reads the stored attestation (it cannot fabricate one),
   and re-pushes it. A still-unhealthy Indexer returns
   `IndexerUnavailable`, so callers know to retry later. A successful replay
   emits `Reindexed(uid)` (topic `REINDEX`).

### Opt-in: fail-closed

Admins that require the mirror to stay in lockstep with issuance call
`set_indexer_strict(true)`. Indexing failure then aborts the whole attestation
with `IndexerUnavailable`, and no attestation is written. This trades
availability for consistency and must be paired with Indexer health checks and
a rotation runbook, because every issuance now depends on the Indexer.
`get_indexer_strict()` reports the current mode.

### Guarantee

Issuance never silently diverges from the configured policy: fail-open always
emits `IndexFailed` on a missed push, and fail-closed always aborts. There is
no path where an attestation is issued, the Indexer misses it, and nothing is
observable.

## Attestation fees (#164)

`attest_with_value(attestation, token, value)` no longer trusts the caller's
`token` and `value`. The required payment comes from authenticated on-chain
configuration:

- `set_fee(token, amount)` (admin, `amount > 0`) pins the fee **asset** and the
  **exact amount**. A call whose `token` or `value` does not match exactly
  fails atomically with `FeeMismatch` before any transfer or storage write.
- `clear_fee()` (admin) makes attestation fee-free. `attest_with_value` is then
  accepted **only** with `value == 0`; a non-zero `value` is `FeeMismatch`.
  Fee-free is represented by the absence of configuration, not by an arbitrary
  zero amount.
- `get_fee() -> Option<(Address, i128)>` exposes the policy so SDK and CLI
  front-ends can display the fee before a user signs. The SDK helper is
  `SASClient::fetch_fee`.

Wrong-token, underpayment, and "pay a fee that was never required" attempts all
fail atomically and issue nothing.
