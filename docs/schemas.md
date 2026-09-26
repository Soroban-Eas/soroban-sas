# Schema Definitions and Payloads

Schemas are the core mechanism for defining the structure and validation rules for attestations in the Soroban Attestation Service (SAS). 

## Schema Registry
The Schema Registry smart contract acts as the source of truth for all valid schema types. When an issuer creates an attestation, the SAS contract verifies the schema against the registry.

## Schema Structure
A schema is stored as a comma-separated list of `name Type` field definitions.
Each field must name the attribute and its Soroban type, for example:

```text
first_name String, last_name String, document_id Bytes
```

This keeps the on-chain representation compact while still giving the
contracts and CLI enough structure to reject malformed inputs.

### Creating a Schema
When registering a schema, the caller provides a deterministic UID and the
schema string above. The validator rejects whitespace-only values, entries
without at least one `name Type` pair, and strings that do not resemble a
field declaration.

## Verification
When verifying an attestation off-chain or on-chain, the client decodes the raw `data` field using the associated schema definition. The schema enforces that every issued attestation strictly conforms to the expected layout.

## Revocability
A schema's `revocable` flag is a ceiling on what attestations issued under it are allowed to claim, not a mandate:

| `schema.revocable` | `attestation.revocable` | Result |
| --- | --- | --- |
| `true`  | `true`  | Allowed — the attestation may later be revoked. |
| `true`  | `false` | Allowed — a revocable schema may still issue irrevocable attestations. |
| `false` | `false` | Allowed — matches the schema's policy. |
| `false` | `true`  | **Rejected** with `SASError::NotRevocable`. |

This is enforced once, inside `attest_internal`, before the attestation is stored or the resolver is invoked — every issuance path (`attest`, `attest_by_delegation`, `attest_with_value`, `multi_attest`, and `replace_attestation`) shares this same check, so none of them can bypass it. Note this only constrains issuance: it does not change how `revoke`/`multi_revoke`/`replace_attestation` behave once an attestation exists, which continue to key off the attestation's own `revocable` flag.

## Payload Size

The `data` field of every attestation is bounded by `MAX_ATTESTATION_DATA_BYTES`
(currently 10 000 bytes), enforced in `attest_internal` before any resolver callback
is invoked. Resolver contracts implementing `on_attest` can rely on this guarantee:
the `attestation.data` field they receive will never exceed this ceiling.

Schema authors should design their data encodings to fit within this budget. The
ceiling is intentional — it keeps SHA-256 hashing, XDR encoding, event emission,
and cross-contract invocation costs within Soroban's measured budget envelope.

Changes to `MAX_ATTESTATION_DATA_BYTES` are a protocol-level breaking change and
require a versioned upgrade.

## Resolver Callbacks
Schemas can optionally specify a `resolver` contract address. If specified, the SAS contract will invoke callbacks on the resolver to enforce schema-specific rules or synchronize dependent state.

### `on_attest`
Invoked exactly once, synchronously, when a new attestation is issued using the schema — after the attestation has passed all of `attest_internal`'s own validation (duplicate UID, expiration, recipient, schema-level revocability) but before it is written to storage.
- **Payload:** The full `Attestation` record (including the assigned UID).
- **Contract:** `fn on_attest(env: Env, attestation: Attestation)`. No return value is required; a resolver signals rejection by returning a `contracterror` or by trapping (e.g. `panic_with_error!`/`panic!`).

### `on_revoke`
Invoked exactly once, synchronously, when an attestation issued under the schema is revoked — after `revocation_time` has been written to storage and the `AttestationRevoked` event published, but (like `on_attest`) before the call returns, so a rejection still rolls back everything the same invocation has done so far (#216).
- **Payload:** The full `Attestation` record, with `revocation_time` already set to the value now in storage — the resolver sees exactly what an on-chain reader would see once the call commits.
- **Contract:** `fn on_revoke(env: Env, attestation: Attestation)`. Same shape as `on_attest`: no return value is required, and a resolver signals rejection by returning a `contracterror` or by trapping.

Unlike `on_attest` (invoked before the write), `on_revoke` runs after the write and event because revocation has no separate "would-be" state to validate up front — the resolver's job is to react to (or veto) a revocation that has, from the caller's perspective, already happened, not to gate whether it may happen based on content the caller controls.

### Resolver Failure Semantics

Resolvers are **authoritative**, not advisory: `on_attest`'s outcome controls whether the attestation is issued, and `on_revoke`'s outcome controls whether the revocation stands. `attest_internal` invokes `on_attest`, and `revoke_internal` invokes `on_revoke`, via `try_invoke_contract`, inspecting the result the same way:

| Resolver outcome | Result |
| --- | --- |
| Returns successfully | The attestation is stored (`on_attest`) or the revocation stands (`on_revoke`); the call proceeds normally. |
| Explicitly rejects (returns/panics with a `contracterror`) | The whole call fails with `SASError::ResolverRejected`. Nothing is stored/revoked. |
| Traps (an unhandled `panic!`, or any other host-level abort) | Same as above — `SASError::ResolverRejected`. The Soroban host does not let a caller distinguish an intentional rejection from an unhandled trap, so both surface identically. |
| Does not implement `on_attest` / `on_revoke` | Same as above — an unrecognized function call also traps at the host level, so this is indistinguishable from the trap case and is likewise `SASError::ResolverRejected`. |

Because the whole invocation is one Soroban transaction, a `SASError::ResolverRejected` panic rolls back everything that happened earlier in the same call — including, for `replace_attestation`, the old attestation's revocation (whose own `on_revoke` call, if rejected, aborts before `attest_internal` for the replacement even runs) and, for `multi_revoke`, every other revocation already committed earlier in the same batch. A rejected replacement or batch therefore leaves every attestation involved exactly as it was — never partially revoked with no successor, and never a batch with only some of its members actually revoked.

This applies uniformly to every attestation issuance path — `attest`, `attest_by_delegation`, `attest_with_value`, `multi_attest`, and `replace_attestation` — and every revocation path — `revoke`, `revoke_by_authorizer`, `revoke_by_delegate`, `revoke_by_delegation`, `multi_revoke`, and `replace_attestation`'s own internal revocation of the old attestation — since they all funnel through `attest_internal` / `revoke_internal` respectively.

A resolver's failure is a normal, typed contract error (`SASError::ResolverRejected`), the same class of outcome as `SASError::InvalidSchema` or `SASError::NotRevocable` — callers should expect and handle it, not treat it as exceptional. There is deliberately no separate "resolver failed" event: a panic discards any event the same call would have published — including, for revocation, the `AttestationRevoked` event published just before `on_revoke` runs — so the typed error returned to the caller is the only — and sufficient — signal.

## Delegated Issuance and Schema Allow-lists (#7)

To support DAOs, enterprise organizations, and multi-issuer systems without sharing private keys or registering duplicate schemas, schema owners can maintain a dynamic allow-list of authorized delegates.

### Management
- `add_delegate(uid: UID, delegate: Address)`: Adds an address to the schema's allow-list. Requires authorization from the primary schema owner. Emits `SchemaDelegateAdded`.
- `remove_delegate(uid: UID, delegate: Address)`: Removes an address from the schema's allow-list. Requires authorization from the primary schema owner. Emits `SchemaDelegateRemoved`.

### Verification and Issuance
- When an attestation is submitted to SAS, `attest_internal` queries the schema registry's `is_authorized(uid, attester)` method.
- The issuance is accepted if `attester` is either the primary schema owner (recorded at registration) OR an authorized delegate in the allow-list, provided the schema exists and is not deprecated.
- Unauthorized attesters are rejected with `SASError::Unauthorized`.
- Cross-contract verification is encapsulated in a single `is_authorized` query to optimize gas and invocation limits.

### Revocation
- Authorized delegates can revoke their own attestations via `revoke(uid)`.
- Authorized delegates and schema owners can revoke any attestation under the schema using `revoke_by_delegate(uid, delegate)` / `revoke_by_authorizer(uid, authorizer)`.
