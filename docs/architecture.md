# Soroban SAS Architecture

## Overview
The Soroban Attestation Service (SAS) is composed of three primary components:
1. **Schema Registry**: Stores reusable data layouts (schemas) identified by deterministic UIDs.
2. **SAS Core Contract**: Issues, revokes and verifies attestations based on registered schemas.
3. **Indexer Contract**: Provides off-chain and on-chain reverse lookups for recipients, schemas and attesters.

## Design Goals
- High throughput via parallelized state access.
- Minimal gas overhead.
- Strict payload boundaries to prevent gas exhaustion attacks.

## Storage Retention Policy

Soroban has two independent expiry mechanisms, and each contract's core
configuration is deliberately held to a stricter policy than the
attestation/schema data it governs:

- **Instance storage** holds a contract's core configuration: SAS's
  `SAS_ADMIN`, `SCHEMA_REGISTRY`, and `INDEXER` bindings; the schema
  registry's `REGISTRY_ADMIN`, `SCHEMA_FEE`, and `TREASURY`; and the
  indexer's `INDEXER_ADMIN` and `SAS_CONTRACT` binding. If instance storage
  expires and is archived, the contract's own configuration becomes
  unreadable and every entry point that depends on it stops working —
  there is no way to "read the admin address to renew the admin address."
  For this reason every contract renews its instance TTL
  (`soroban_sas_common::extend_instance_ttl`, using the shared
  `INSTANCE_TTL_THRESHOLD_LEDGERS`/`INSTANCE_EXTEND_TO_LEDGERS` constants)
  from `init` and from both admin-gated and commonly used public entry
  points, so ordinary traffic keeps configuration alive without any single
  call being solely responsible for it.
- **Persistent storage** holds the data instance configuration governs —
  attestations, schema records, delegation nonces, indexer lookup chunks —
  and is extended independently, per entry, using `LEDGERS_IN_ONE_YEAR`
  wherever it is written or read. An individual attestation or schema
  expiring does not take down the rest of the contract the way a lost
  admin binding would, so persistent entries are extended on their own
  schedule rather than the stricter instance policy. The indexer's per-key
  UID counters (`RCOUNT`/`SCOUNT`/`ACOUNT`) live here too, on the same
  horizon as the chunks they count — they used to live in instance storage,
  where their independent expiry from the chunk data they count could reset
  a counter to zero while its chunks survived, corrupting the index with
  duplicate UIDs on the next write (#219).

## Contract Upgrades

All three contracts are upgraded in place by an admin-authorized
`upgrade(new_wasm_hash, new_version)`. Each contract stores a monotonic
instance `VERSION` (a missing key on a legacy instance reads as genesis `1`),
accepts only the exact next audited version, and requires the candidate to be
non-zero and already uploaded. Validation reads the existing layout before any
state is written; the version and the targeted hash (`WASMHASH`) are then
committed, and each contract emits `ContractUpgraded` with
`(old_wasm_hash, new_wasm_hash, authorizer)` immediately before the swap is
requested. The schema registry additionally emits its own versioned
`UPGRADE("UPGRADE", old_version, new_version)` event. Because Soroban rolls a
failed invocation back, an upgrade event an off-chain consumer observes always
corresponds to an activation that durably took effect.

See [Contract Events](events.md) for the payloads and the
[Contract Upgrade and Recovery Runbook](UPGRADE_RUNBOOK.md) for the staged
activation and rollback procedure.

## Trust Boundaries

### Indexer writes

`Indexer::index_attestation` is not a public write path. It records UIDs
into the recipient, schema, and attester lookup tables, and those tables are
only useful if every entry actually corresponds to an attestation the SAS
contract issued. If any caller could invoke it directly, an attacker could
inject arbitrary UIDs and silently poison every reverse lookup the indexer
serves.

`index_attestation` therefore requires `sas.require_auth()`, where `sas` is
the address recorded by `Indexer::init`. Soroban satisfies a contract
address's `require_auth()` without an explicit signature when the call
originates from that contract's own execution — concretely, only
`SAS::attest_internal` invoking `index_attestation` as part of handling
`attest`/`attest_by_delegation`/`multi_attest`/`attest_with_value` can
satisfy it. An external account, or any other contract (including one that
merely forwards the same arguments), cannot produce this authorization and
the call is rejected. A call made before `Indexer::init` has bound a SAS
address is rejected outright, since there is no trusted address to
authorize against yet.

This mirrors how `SAS::init` and `Indexer::init` already gate on a
compatibility probe (`sasreg`/`sasv1`) before trusting a configured
dependency address — the indexer's SAS binding is a similar one-way trust
relationship, just enforced per-call instead of once at initialization.

### Indexer Reconciliation

When running under default fail-open mode, any downstream indexing failures emit `IndexFailed(uid)` (`IDXFAIL`) events rather than rolling back core attestation writes. Operators recover missed entries using `SAS::reindex_attestation(uid)`.

For operational instructions covering event detection, unreconciled UID enumeration, CLI/SDK invocation, health checks, and retry strategies, see the [Indexer Reconciliation Runbook](reconciliation.md) and [Indexer Availability Policy](indexer-availability-and-fees.md).


## Attestation Lifecycle and State Machine

An attestation within the Soroban SAS framework flows through several definitive states managed strictly by the core SAS smart contract:
- **Issuance (`attest` / `multi_attest`)**: A new, revocable or non-revocable attestation is firmly anchored to the chain. A deterministic `UID` is assigned based strictly on `(schema_uid, recipient, attester, data, time, expiration_time, revocable)`.
- **Active State**: While `timestamp < expiration_time` (and `expiration_time != 0`) and `revocation_time == 0`, the attestation is publicly active.
- **Revoked State (`revoke`)**: If the attestation was initialized with `revocable = true`, the `attester` (or a delegated proxy) can flip the state by setting the `revocation_time` parameter on-chain. From this moment, `verify_attestation` returns `false`.
- **Expired State**: Occurs naturally when the ledger timestamp overtakes `expiration_time`. No explicit transaction is needed to reach this state. Expired attestations strictly cannot be actively rotated or replaced in-place.
- **Replacement (`replace_attestation`)**: Binds an active, non-revoked attestation into a revoked state natively, synchronously emitting a new child attestation mapped backwards through the `ref_uid` pointer structure.
