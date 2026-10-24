# Re-entrancy verification: resolver and indexer callbacks

Security verification for issue #491. Tests:
[`contracts/sas/src/test_issue_491.rs`](../contracts/sas/src/test_issue_491.rs).
Verified against `soroban-sdk` 21.7.7 / `soroban-env-host` 21.2.1.

## Summary

| Question | Answer |
| :--- | :--- |
| Can a resolver or indexer callback re-enter SAS? | **No.** Every attempt, from every callback, against every mutating entrypoint that reaches a callback, is refused by the Soroban host with `Error(Context, InvalidAction)`. |
| Can a re-entry attempt leave partial state? | **No.** A refused nested call writes nothing. When the refusal makes the callback trap, the outer call reverts with `SASError::ResolverRejected` (resolver) or `SASError::IndexerUnavailable` (fail-closed indexer, `reindex_attestation`) and every write it made is rolled back. |
| Does the contract-level guard work? | **Yes.** `multi_attest` and `multi_attest_by_delegation` reject a nested call with `SASError::Reentrancy` while the guard is held, change nothing when they do, and release the guard after success. A reverted call cannot leave the guard behind. |
| Do legitimate calls still work afterwards? | **Yes.** After every refused attempt, the same call (same delegation nonce, same fee) succeeds once the callback behaves. |

## Threat model

A resolver is named by whoever registers a schema, and it runs inside every
`attest`/`revoke` for that schema (`on_attest`, `on_revoke`). The indexer is
set by the admin and runs on issuance, revocation, replacement, renewal and
reindexing (`index_attestation`, `handle_revoke`, `handle_replace`,
`handle_renew`). Both get control in the middle of a mutating SAS call. The
attack is to call back into SAS from there, either to:

- issue an attestation the outer caller did not authorize;
- revoke an attestation mid-flight;
- interleave a nested batch with the outer one's storage writes;
- leave SAS in a half-updated state if the outer call later fails.

The schema registry is also called during attestation (`get_schema`,
`get_max_ttl`, `get_schema_policy`, `is_authorized`), but the admin fixes it
at `init`; it is trusted configuration, not an attacker-supplied callback,
and is out of scope here.

## Method

The tests deploy two hostile contracts:

- **`HostileResolver`** acts as the schema registry and resolver for every
  schema, so it runs on every attestation and revocation.
- **`HostileIndexer`** implements every indexer hook SAS calls.

Each can be armed with one of four attacks, issued from inside the callback:

| Attack | Nested call |
| :--- | :--- |
| `Attest` | `attest(payload)` |
| `MultiAttest` | `multi_attest([payload])` |
| `Revoke` | `revoke(victim)` |
| `MultiRevoke` | `multi_revoke([victim])` |

`payload` is a valid, never-issued attestation and `victim` a live, revocable
one, both from the attester whose authorization is mocked. If the nested call
were allowed to run it would succeed, so its absence of effect is meaningful.

Each attack runs in two modes:

- **trap**: the callback makes the nested call directly; when it fails, the
  callback traps.
- **swallow**: the callback makes the nested call with `try_*`, records the
  result (attempts, successes, and the error's type and code), and returns
  normally.

Every scenario uses a fresh environment. It snapshots everything the outer
call or a nested call could touch, and afterwards checks the result:

- whether the outer attestation exists, and whether the subject is revoked;
- whether `payload` exists, and whether `victim` is revoked;
- the attester's delegation nonce;
- the attester's and SAS's fee-token balances;
- whether the reentrancy guard is held.

The ledger timestamp is non-zero, because `revocation_time == 0` means "not
revoked".

## Coverage

### Resolver callbacks: 12 entrypoints × 4 attacks × 2 modes = 96 scenarios

These are every mutating entrypoint that invokes `on_attest` or `on_revoke`:

| Entrypoint | Callback(s) |
| :--- | :--- |
| `attest` | `on_attest` |
| `attest_by_delegation` | `on_attest` |
| `attest_with_value` | `on_attest` (after the fee transfer) |
| `multi_attest` (guarded) | `on_attest` per item |
| `multi_attest_by_delegation` (guarded) | `on_attest` per item |
| `revoke` | `on_revoke` |
| `revoke_by_authorizer` | `on_revoke` |
| `revoke_by_delegate` | `on_revoke` |
| `revoke_by_delegation` | `on_revoke` |
| `multi_revoke` | `on_revoke` per item |
| `multi_revoke_by_delegation` | `on_revoke` per item |
| `replace_attestation` | `on_revoke`, then `on_attest` |

**Results:**

- **Trap mode:** every scenario reverts with `SASError::ResolverRejected`.
  The post-state equals the pre-state, including the delegation nonce and the
  fee already transferred by `attest_with_value`, and the guard is not held.
  The identical legitimate call then succeeds and takes effect.
- **Swallow mode:** every scenario completes the outer call. The nested call
  never succeeded, and the error recorded was `Error(Context, InvalidAction)`
  in every case. `payload` was never issued, `victim` was never revoked, and
  the guard is not held.

### Indexer callbacks: 7 entrypoints × 4 attacks × 2 modes = 56 scenarios

Entrypoints: `attest`, `multi_attest`, `revoke`, `replace_attestation`,
`renew_attestation`, `reindex_attestation`, `bulk_reindex`.

**Results:**

- **Swallow mode:** every scenario refuses the nested call with
  `Error(Context, InvalidAction)` and changes nothing.
- **Trap mode:** the indexer is fail-open by default, so the outer call
  completes and the nested call changes nothing. The exception is
  `reindex_attestation`, the explicit repair path, which is fail-closed and
  reverts with `SASError::IndexerUnavailable`; its post-state equals the
  pre-state.
- **Strict mode** (`set_indexer_strict(true)`), 4 scenarios: issuance with a
  trapping hostile indexer reverts with `SASError::IndexerUnavailable` and
  leaves no state behind.

### The contract-level guard

| Check | Result |
| :--- | :--- |
| `multi_attest` with the guard held | `SASError::Reentrancy`; post-state = pre-state |
| `multi_attest_by_delegation` with the guard held | `SASError::Reentrancy`; post-state = pre-state, nonce not consumed |
| Guard after a successful batch of either kind | released; the next batch runs |
| Guard after a batch reverted from inside the critical section | not held (rolled back with the rest); the next batch runs |

The host refuses re-entry before the guard is reached (see Findings), so these
tests hold the guard the way an in-flight batch does, as `test_issue_296`
does for `multi_attest`.

**Mutation check:** with `enter_reentrancy_guard` removed from
`multi_attest_by_delegation`, the guard test fails (`Ok(())` instead of
`Err(Error(Contract, 502))`). The test pins the guard.

## Findings

1. **The host is the primary defence, not the guard.** `soroban-env-host`
   rejects any call that would re-enter a contract already on the call stack,
   with `Error(Context, InvalidAction)`, before the callee runs. SAS's
   `enter_reentrancy_guard` can therefore never fire from a real callback; it
   is defense in depth, as its doc comment says. A resolver re-entering SAS
   cannot obtain `SASError::Reentrancy`; it gets the host error. A resolver
   that lets that error propagate gets its attestation or revocation
   rejected, with `ResolverRejected`.

2. **Only the two batch-attest entrypoints hold the guard.** `attest`,
   `attest_by_delegation`, `attest_with_value`, the `revoke*` family,
   `multi_revoke`, `multi_revoke_by_delegation`, `replace_attestation`,
   `renew_attestation`, `reindex_attestation` and `bulk_reindex` reach
   external callbacks without it. Given finding 1 this is not exploitable
   today: every one of them is covered above and none can be re-entered. If
   the host's re-entry rule ever changed, these would have no contract-level
   protection. Extending the guard to them is a separate decision (it costs
   two instance-storage writes per call) and is not part of this change.

3. **No partial state on any path.** Soroban rolls back every write of a
   failed invocation, including writes made before the callback (`revoke`
   writes the revocation before `on_revoke`; `attest_with_value` transfers the
   fee before `on_attest`) and the guard itself. Every trap-mode and
   strict-mode scenario confirms the post-state equals the pre-state.

4. **Documentation detail.** `docs/security.md` ("Resolver Trust Boundary")
   says `on_revoke` runs *before* revoking. In the code it runs after the
   revocation is written, within the same atomic invocation (see the comment
   in `revoke_internal`). The observable outcome is the same, since a
   rejection rolls the write back, but a resolver reading the attestation in
   `on_revoke` sees it already revoked.

## Reproducing

```bash
cargo test -p sas --lib test_issue_491
```

That runs 7 tests covering 161 scenarios, each in a fresh environment. They
build with snapshot capture off, so they write no `test_snapshots/` files.
