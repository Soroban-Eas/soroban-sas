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
Invoked exactly once when a new attestation is issued using the schema.
- **Payload:** The full `Attestation` record (including the assigned UID).

### `on_revoke`
Invoked exactly once when an existing attestation using the schema is revoked.
- **Payload:** The updated `Attestation` record, carrying the revocation timestamp.

In both cases, failure of the resolver callback will silently be ignored if it traps, matching the resolver policy where optional resolvers cannot permanently brick issuances or revocations if they fail unexpectedly, though they can enforce requirements if successful. (Note: `try_invoke_contract` is used).
