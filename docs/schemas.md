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

## Resolver Callbacks
Schemas can optionally specify a `resolver` contract address. If specified, the SAS contract will invoke callbacks on the resolver to enforce schema-specific rules or synchronize dependent state.

### `on_attest`
Invoked exactly once, synchronously, when a new attestation is issued using the schema — after the attestation has passed all of `attest_internal`'s own validation (duplicate UID, expiration, recipient, schema-level revocability) but before it is written to storage.
- **Payload:** The full `Attestation` record (including the assigned UID).
- **Contract:** `fn on_attest(env: Env, attestation: Attestation)`. No return value is required; a resolver signals rejection by returning a `contracterror` or by trapping (e.g. `panic_with_error!`/`panic!`).

### `on_revoke`
Not currently implemented. `revoke_internal` does not invoke the resolver at all, so registering a resolver has no effect on revocation today; a schema's resolver is consulted only by `attest_internal`. This section is aspirational and tracked as a separate gap — do not rely on `on_revoke` being called.

### Resolver Failure Semantics

Resolvers are **authoritative**, not advisory: `on_attest`'s outcome controls whether the attestation is issued. `attest_internal` invokes `on_attest` via `try_invoke_contract` and inspects the result:

| Resolver outcome | Result |
| --- | --- |
| Returns successfully | The attestation is stored and issuance proceeds normally. |
| Explicitly rejects (returns/panics with a `contracterror`) | The whole `attest` call fails with `SASError::ResolverRejected`. Nothing is stored. |
| Traps (an unhandled `panic!`, or any other host-level abort) | Same as above — `SASError::ResolverRejected`. The Soroban host does not let a caller distinguish an intentional rejection from an unhandled trap, so both surface identically. |
| Does not implement `on_attest` | Same as above — an unrecognized function call also traps at the host level, so this is indistinguishable from the trap case and is likewise `SASError::ResolverRejected`. |

Because the whole invocation is one Soroban transaction, a `SASError::ResolverRejected` panic rolls back everything that happened earlier in the same call — including, for `replace_attestation`, the old attestation's revocation. A rejected replacement therefore leaves the original attestation exactly as it was, never partially revoked with no successor.

This applies uniformly to every attestation issuance path — `attest`, `attest_by_delegation`, `attest_with_value`, `multi_attest` (a single resolver rejection fails the entire batch, consistent with its other atomic validation), and `replace_attestation` — since they all funnel through `attest_internal`.

A resolver's failure is a normal, typed contract error (`SASError::ResolverRejected`), the same class of outcome as `SASError::InvalidSchema` or `SASError::NotRevocable` — callers should expect and handle it, not treat it as exceptional. There is deliberately no separate "resolver failed" event: a panic discards any event the same call would have published, so the typed error returned to the caller is the only — and sufficient — signal.
