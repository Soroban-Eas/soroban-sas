# Protocol Specification

## Schema identity and UID derivation

A schema's canonical identity is the tuple `(schema string, resolver address, revocable flag)`.
The on-chain UID is `SHA256( XDR(schema) || XDR(resolver) || byte(revocable) )`, where
`XDR(...)` is the Soroban `ToXdr` encoding and `byte(revocable)` is `0x01` for `true`
and `0x00` for `false`. All three fields participate in the preimage, so two
registrations that share the same `schema` text but differ in `resolver` or
`revocable` produce distinct UIDs and do not collide; attempts to register an
identical `(schema, resolver, revocable)` tuple a second time are rejected with
`SASError::SchemaAlreadyExists`.

Rationale: `resolver` determines whether an attestation triggers external logic
and `revocable` determines whether it can be revoked — both change the
execution semantics of attestations that reference the schema. Including them
prevents a policy change from being confused with the original schema.

Migration: schemas registered under the legacy `SHA256(XDR(schema))` derivation
are not compatible with this derivation; their UIDs are not reinterpreted.
Deployments that upgrade to this version must re-register schemas or maintain a
migration map from legacy UIDs to new UIDs. New registrations after the upgrade
always use the canonical derivation. Golden vectors for the new derivation are
locked in `contracts/schema-registry` tests.

## Recipient invariants

Soroban `Address` values are already structurally validated by the host. SAS therefore applies semantic rules rather than duplicating address-format checks: the recipient must not be the protocol's zero account or zero contract sentinel, and it must differ from the attester. Self-targeting is rejected because an attestation is a claim made by an issuer about a distinct subject; accepting it would make issuer/subject separation ambiguous for consumers. These rules are applied by `attest`, `attest_with_value`, and `multi_attest` before an attestation is stored.

## Batch issuance

`multi_attest` accepts at most 100 attestations (`SASError::BatchTooLarge`). The limit bounds authorization, registry callbacks, storage, and indexing work within the measured Soroban budget envelope and is checked before processing begins, so an oversized batch cannot partially issue records. Distinct attesters are authorization-deduplicated with a Soroban `Map`, avoiding a linear scan of all earlier attesters.

## Dependency compatibility

SAS initialization performs the `sasreg` compatibility probe on the configured schema registry and rejects any dependency that does not return `true` with `SASError::IncompatibleDependency`; an arbitrary account or unrelated contract is never persisted. The schema-registry contract implements this probe as part of its v1 interface.

Indexer initialization uses the analogous `sasv1` probe on the configured SAS contract. A bad binding is rejected before state is written, and the admin/trust assumption is explicit: the initializer chooses the dependency, while the dependency proves it implements the expected interface. No contract-address-only check is treated as compatibility.

## Pagination and budget safety

`SchemaRegistry::get_schemas(start, limit)` caps `limit` to `MAX_GET_SCHEMAS_PAGE_SIZE = 100` and uses
`saturating_add` for `start + limit` so that `start = u32::MAX` or other overflow-prone
inputs return a deterministic empty page without trapping in debug or wrapping in release.
The effective range is `[start, min(count, start.saturating_add(capped_limit)))`; callers that
request beyond `count` receive an empty vector. The same capping applies to indexer
paginated reads.

## Delegated attestation nonces

Per-signature TTL tombstones have been replaced with a durable per-attester strictly
increasing nonce. The contract stores `last_nonce` per attester in instance storage
(`(DELEGATION_NONCE, attester) -> u64`) and extends instance TTL on each
delegation. A delegated signature is accepted only if `nonce > last_nonce`; replay
of any previously consumed nonce (including after ledger advancement or archival)
is rejected with `SASError::DelegationReplay`. The window is bounded to one `u64`
per attester. Out-of-order nonces smaller than the current high-watermark are
rejected; concurrent submissions must use distinct increasing nonces. Because the
high-watermark is instance state renewed on every delegation, its lifetime tracks
contract liveness rather than the one-year tombstone.

## Indexer instance retention

`INDEXER_ADMIN` and `SAS_CONTRACT` are instance entries whose TTL is renewed via
`extend_instance_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR)` on both trusted
writes (`init`, `index_attestation`) and public reads (`get_admin`, `get_sas`,
`get_attestations_by_*`, `get_atts_by_recipient_paginated`). This mirrors the
instance-retention policy of the SchemaRegistry and SAS contracts. Read-only
calls renew only the instance TTL and do not mutate persistent index chunks. Tests
verify that after ledger advancement the admin and SAS binding remain readable.

## Attestation Identity Specification

An attestation's canonical UID is a content-addressed hash derived from its own fields:
```
UID = SHA256(XDR(schema_uid) || XDR(recipient) || XDR(attester) || XDR(data))
```
Where:
- `schema_uid`: 32-byte UID of the schema defining this attestation's policy
- `recipient`: Soroban Address being attested to
- `attester`: Soroban Address performing the attestation
- `data`: Bytes payload containing attestation-specific information (max 10,000 bytes)

All four fields participate in the preimage. The UID must be computed by the caller and
provided on issuance; `SAS::attest` and `SAS::attest_with_value` reject any attestation
whose submitted `uid` does not match this hash with `SASError::InvalidUID`. This
content-addressing prevents:
- **Forgery**: an attacker cannot forge a UID that matches arbitrary data
- **Duplication**: identical attestations always produce identical UIDs
- **Collisions**: different attestations (differing in schema, recipient, attester, or data)
produce different UIDs

The UID encoding follows the Soroban `ToXdr` serialization for all four fields, matching
the schema-identity derivation to ensure XDR stability across all platform implementations.

## Off-Chain Typed Data Hashing and Delegation Signing

Delegated attestations via `attest_by_delegation` and `revoke_by_delegation` require an
Ed25519 signature over a structured typed-data message. The signature preimage is:
```
message_hash = SHA256(
    "SAS_ATTESTATION_V1" ||           // Domain separator (ASCII)
    network_id ||                      // Soroban network_id (32 bytes)
    contract_address ||                // This SAS contract address (XDR-encoded)
    nonce (u64, big-endian) ||         // Monotonic per-attester nonce
    XDR(attestation_struct)            // Full Attestation being signed
)
```
Where `attestation_struct` contains:
- uid, schema_uid, recipient, attester (addresses/UIDs)
- time, expiration_time, revocation_time (u64 timestamps, seconds since epoch)
- revocable (bool)
- data (Bytes, max 10,000 bytes)

The domain separator "SAS_ATTESTATION_V1" and network_id prevent cross-network replay attacks.
The nonce prevents replay of the same message on the same network. The signature is
verified using Ed25519 public key cryptography.

**Rationale**: Including the network and contract in the preimage ensures signatures
cannot be replayed across deployments or networks. Including the full attestation data
ensures the signer commits to every field being attested.

## Delegation Nonce State Machine

The contract stores a per-attester monotonic high-watermark nonce in instance storage:
```
DataKey::DelegationNonce(attester) -> u64  (stores the highest nonce consumed)
```

Rules:
- **Initial**: First delegation for an attester starts with `last_nonce = 0`
- **Acceptance**: A delegated signature is valid only if `submitted_nonce > last_nonce`
- **Consumption**: On acceptance, `last_nonce` is updated to `submitted_nonce`
- **Rejection**: Any nonce ≤ `last_nonce` is rejected with `SASError::DelegationReplay`
- **Ordering**: Out-of-order submissions are rejected; callers must submit increasing nonces
- **Unbounded**: The nonce space is `u64` (up to 2^64 submissions per attester)
- **TTL**: The high-watermark storage entry has its TTL renewed on every successful delegation

This provides durable replay protection: even if an attestation is revoked and the storage
entry expires, the nonce sequence resumes from the highest previously consumed value if
the entry is archived and later recreated, preventing a replayed stale signature from being
accepted as a new attestation.

## Resolver Callback Interface

When a schema defines a resolver address, the SAS contract invokes callbacks on that resolver
during attestation issuance and revocation. Resolvers implement two entry points:

```rust
pub fn on_attest(env: Env, uid: UID, attestation: Attestation) -> Result<(), SASError>
pub fn on_revoke(env: Env, uid: UID, attestation: Attestation) -> Result<(), SASError>
```

**Semantics**:
- Called after the attestation is validated but **before** it is written to storage
- If the resolver rejects (returns an error) or traps, the entire issuance/revocation is aborted
- If the resolver panics with a host trap, the transaction reverts with `SASError::ResolverRejected`
- On success, the attestation proceeds to storage immediately after the callback returns
- The `attestation` parameter includes the full attestation record being issued/revoked
- **Atomicity**: The resolver callback and storage write are in the same transaction; partial state is never committed

**Fail-Open Policy**: If a resolver address is set but cannot be invoked (missing contract,
interface mismatch, or budget exhaustion), and `INDEXER_STRICT` is `false`, the SAS contract
emits an `IndexFailed` event and proceeds. If `INDEXER_STRICT` is `true`, an `IndexerUnavailable`
error is returned and the entire operation fails.

**Rationale**: Resolvers enable on-chain validation logic (e.g., "only attester X may attest
about recipient Y") without modifying the SAS contract. Fail-open prevents a misconfigured
resolver from breaking all attestations while upgrades are staged.

## Indexer Architecture & Storage Chunking

The SAS Indexer contract stores attestations in fixed-size chunks to bound storage entries
and prevent ledger-entry size violations:

```
MAX_CHUNK_SIZE = 100 attestations per chunk
chunk_index = total_attestations / MAX_CHUNK_SIZE
DataKey::AttestationChunk(chunk_index) -> Vec<AttestationRecord>
```

When indexing a new attestation:
1. Compute `chunk_index = current_total / MAX_CHUNK_SIZE`
2. If the chunk does not exist, create it
3. Append the attestation to the chunk
4. If the chunk now has `MAX_CHUNK_SIZE` entries, stop (next attestation goes to a new chunk)
5. Emit an `IndexerUpdated` event on the next state transition

**Lookup**: To find attestations for a recipient:
- Iterate through all chunk indices from `0` to `(total / MAX_CHUNK_SIZE) + 1`
- For each chunk, scan for matching recipient addresses
- Return results in index order (oldest chunks first)

**Fail-Open vs. Fail-Closed**: Configured via `SAS::set_indexer_strict(bool)`:
- **Fail-Open** (default, `strict = false`): If the Indexer cannot be invoked, the SAS
  contract emits an `IndexFailed` event and proceeds with attestation issuance
- **Fail-Closed** (`strict = true`): If the Indexer cannot be invoked, the entire
  attestation operation fails with `SASError::IndexerUnavailable`

This allows operators to choose between high availability (fail-open, risk incomplete indexing)
or strict consistency (fail-closed, halt on indexer errors).

## Normative Cryptographic Test Vectors

The following test vectors are the authoritative reference for correct UID derivation and
signature validation across all platform implementations (Rust, TypeScript, Go, Python):

### Schema UID Test Vectors

Schema identity derivation test cases (all using Soroban XDR encoding):

| Schema | Resolver | Revocable | Expected UID (hex) |
|--------|----------|-----------|-------------------|
| `{"type": "email", "fields": 1}` | Account GBXYZ... | false | (SHA256 computation per spec above) |
| `{"type": "phone"}` | Account GABC... | true | (SHA256 computation per spec above) |

(Exact test vectors are maintained in contract test suites under `contracts/schema-registry/src/test.rs` 
and `packages/soroban-sas-common/src/test.rs`.)

### Attestation UID Test Vectors

Attestation identity derivation test cases:

| Schema UID | Recipient | Attester | Data | Expected UID (hex) |
|-----------|-----------|----------|------|-------------------|
| (32-byte UID from above) | Account A | Account B | Empty | (SHA256 computation) |
| (32-byte UID from above) | Account A | Account B | `0xDEADBEEF` | (SHA256 computation) |

(Full vectors are in `contracts/sas/src/test.rs`.)

## Protocol Compatibility and Versioning

This specification describes Protocol Version 1 (v1). Future versions may introduce
breaking changes. Compatibility rules:

### Non-Breaking Changes
- Adding new optional fields to event payloads (existing consumers ignore new fields)
- Increasing `MAX_MULTI_ATTEST`, `MAX_MULTI_REVOKE`, or `MAX_CHUNK_SIZE` (existing batch
  code continues to work)
- Relaxing validation rules (e.g., allowing larger data payloads, longer schemas)
- Adding new read-only entry points (existing clients ignore them)

### Breaking Changes
- Modifying UID derivation formulas (existing UIDs become invalid)
- Changing delegation signature preimages (existing signatures fail validation)
- Removing entry points or changing their signatures
- Changing XDR field ordering in structs

### Version Negotiation
- Contracts expose `get_version() -> u32` returning `1` for v1
- Clients MUST call `get_version()` before invoking the contract
- Clients that do not recognize the returned version MUST reject the invocation
- No in-place upgrades of persisted UIDs are performed; UIDs from v1 remain v1 UIDs
  if later code must reference them

This ensures third-party clients, indexers, and SDKs can detect version mismatches
and fail safely rather than silently producing corrupted attestations.
