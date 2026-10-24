# Time-Window Resolver

## Overview

`contracts/time-window-resolver` is a schema resolver that enforces a minimum
delay between consecutive attestations issued to the same recipient. It is
intended for recurring claims whose value depends on a cadence rather than on
a single event:

- daily check-ins or streaks,
- monthly voting or spending allowances,
- periodic identity re-verification,
- rate-limited rewards and drip claims.

The resolver is registered as a schema's resolver address. `SAS` calls its
`on_attest` callback before storing any attestation issued under that schema,
so the policy applies uniformly to every issuance path — `attest`,
`attest_by_delegation`, `attest_with_value`, `multi_attest`,
`multi_attest_by_delegation`, and `replace_attestation`.

## Configuration

| Setting | Stored in | Set by |
| --- | --- | --- |
| `admin` | instance storage | `init` (immutable afterwards) |
| `cooldown_period_seconds` | instance storage | `init`, `set_cooldown_period_seconds` |
| `last_attested_time(recipient)` | persistent storage | `on_attest` |

`init(admin, cooldown_period_seconds)` requires `admin`'s authorization and
can run only once. `cooldown_period_seconds = 0` installs the resolver with
the restriction disabled.

```rust
pub fn init(env: Env, admin: Address, cooldown_period_seconds: u64);
pub fn get_config(env: Env) -> TimeWindowConfig;
pub fn get_admin(env: Env) -> Address;
pub fn get_cooldown_period_seconds(env: Env) -> u64;
pub fn get_last_attested_time(env: Env, recipient: Address) -> Option<u64>;
pub fn set_cooldown_period_seconds(env: Env, authorizer: Address, cooldown_period_seconds: u64);
pub fn on_attest(env: Env, attestation: Attestation);
pub fn on_revoke(env: Env, attestation: Attestation);
```

The admin, not the schema owner, controls the window: the resolver address is
fixed in a schema's UID at registration, so re-pointing a schema at a
different resolver is not an option. Keeping the admin role separate from
schema ownership lets the operator of the policy rotate the cooldown without
re-registering schemas, while the admin itself cannot be replaced by calling
`init` again (`SASError::AlreadyInitialized`).

## Cooldown Semantics

For a recipient with recorded time `last` and a configured window `cooldown`,
the next attestation is accepted when:

```
env.ledger().timestamp() >= last + cooldown
```

- **First issuance** — always accepted; there is no prior record.
- **Before the boundary** — the callback reverts with
  `SASError::CooldownActive` and writes nothing, so `last` is unchanged.
- **At the boundary** — accepted. At exactly `last + cooldown` the window has
  elapsed (the comparison is `<` for rejection and `>=` for acceptance).
- **After the boundary** — accepted, and `last` is replaced with the current
  ledger timestamp.
- **Zero cooldown** — no restriction; every attempt is accepted and recorded.
- **Extreme values** — arithmetic saturates, so `last + cooldown` near
  `u64::MAX` blocks issuance instead of wrapping into an already-expired
  window.

The recorded time is `env.ledger().timestamp()` at callback time, never
`Attestation::time`. `SAS::attest_internal` normalizes `Attestation::time` to
ledger time *after* the resolver callback, so a caller-supplied value there is
not authoritative.

Windows are tracked **per recipient** only. Two recipients of the same schema
never share a window, and the same recipient under two different schemas that
use different resolver instances has an independent window in each.

A batch that issues twice to the same recipient in one call is subject to the
same window between the two items as two separate calls would be: the first
item records the timestamp, and the second reverts if the window has not
elapsed (with a non-zero cooldown).

Revocation is always accepted and does **not** reset the window. A recipient
cannot revoke and immediately re-issue to bypass the cadence; the policy
governs how often claims may be issued, not how long they live.

## Atomicity

`on_attest` runs inside the issuance transaction, before the attestation is
written. It records the timestamp optimistically; if anything later in the
same invocation fails (for example a fail-closed Indexer), the whole
transaction — including the resolver's timestamp — rolls back. A timestamp is
therefore only ever committed together with a successfully issued
attestation.

## Error Surfacing Through SAS

Calling the resolver directly (or through a pre-flight check) reports
`SASError::CooldownActive` (code `421`).

Issuance through `SAS` reports `SASError::ResolverRejected`, because the
protocol treats *every* resolver rejection — typed error, trap, or missing
method — uniformly as an authoritative rejection (see
[`docs/schemas.md`](schemas.md#resolver-failure-semantics)). Clients that need
to distinguish "cooldown active" from other resolver failures can pre-check
before submitting:

```text
next_allowed = get_last_attested_time(recipient) + get_cooldown_period_seconds()
cooldown_active = get_last_attested_time(recipient) != None && now < next_allowed
```

`get_last_attested_time` and `get_cooldown_period_seconds` are read-only and
callable by anyone.

## Storage and Expiry

Configuration lives in instance storage and is renewed on every entry point.
Per-recipient timestamps live in persistent storage and are renewed to the
standard one-year retention window (`LEDGERS_IN_ONE_YEAR`) on every read and
write. A recipient's record therefore expires only after a year without any
interaction with the resolver, at which point the recipient is treated as
never attested. Configure cooldowns well below that retention window so
record expiry can never shorten a configured cooldown.

## Administrative Authorization

`set_cooldown_period_seconds(authorizer, cooldown_period_seconds)`:

1. Requires `authorizer`'s authorization.
2. Rejects any `authorizer` other than the stored admin with
   `SASError::Unauthorized`, before any state is written.
3. Stores the new window, applies it immediately to in-flight windows (the
   existing per-recipient timestamps are kept), and emits `CooldownUpdated`
   with the old value, the new value, and the authorizer.

Because the recorded timestamps are preserved, shortening the window can make
recipients eligible immediately, while lengthening it can extend a window that
was about to expire.

## Events

`CooldownUpdated` — topics `(COOLDOWN_UPDATED, authorizer)`, payload:

```rust
pub struct CooldownUpdatedEvent {
    pub old_cooldown_period_seconds: u64,
    pub new_cooldown_period_seconds: u64,
    pub authorizer: Address,
}
```

Published only after an authorized change commits; an unauthorized attempt
emits nothing.

## Tests

`contracts/time-window-resolver/src/test.rs` covers:

- initialization, re-initialization, and missing authorization,
- first issuance, rejection before the boundary, acceptance exactly at the
  boundary, and acceptance after it,
- independent windows for different recipients,
- zero cooldown and extreme (`u64::MAX`) cooldown saturation,
- the recorded timestamp coming from the ledger, not the attestation payload,
- admin-only updates, the `CooldownUpdated` event, and unauthorized attempts
  leaving state untouched,
- shortening and lengthening the window while a window is in progress,
- revocation acceptance without a cooldown reset,
- `on_attest` on an uninitialized resolver reporting `NotInitialized`.
