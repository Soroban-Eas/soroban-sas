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

## Replacement expiration monotonicity

`replace_attestation` revokes an existing attestation and issues a replacement
linked to it via `ref_uid`, in one atomic call. If both the old attestation's
`expiration_time` and the replacement's `expiration_time` are non-zero, the
replacement's `expiration_time` must be `>= ` the old attestation's, or the
call panics with `SASError::InvalidTTL`. Replacing with `expiration_time == 0`
(perpetual, never-expiring) is always accepted, since it strictly extends the
attestation's validity window.

Rationale: without this check, an attester could bypass a schema's resolver
revocation hook by "replacing" a valid, long-lived attestation with one whose
`expiration_time` is already in the past. The replacement would read as
expired the moment it is queried, without the schema's `on_revoke` callback
ever running and without an `AttestationRevoked` event ever being emitted —
silently defeating any resolver that depends on `on_revoke` for side effects
(e.g. releasing collateral, updating an external ledger). Requiring the
replacement's expiration to be no earlier than the original's closes that gap:
an attester who wants to end an attestation early must use `revoke`, which
always runs the resolver hook and emits the event.

## Indexer instance retention

`INDEXER_ADMIN` and `SAS_CONTRACT` are instance entries whose TTL is renewed via
`extend_instance_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR)` on both trusted
writes (`init`, `index_attestation`) and public reads (`get_admin`, `get_sas`,
`get_attestations_by_*`, `get_atts_by_recipient_paginated`). This mirrors the
instance-retention policy of the SchemaRegistry and SAS contracts. Read-only
calls renew only the instance TTL and do not mutate persistent index chunks. Tests
verify that after ledger advancement the admin and SAS binding remain readable.
