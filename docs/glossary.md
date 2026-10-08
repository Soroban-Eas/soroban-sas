# Soroban Attestation Service (SAS) Glossary of Terms

This document provides definitive, protocol-level definitions and technical context for key terms and concepts used across the Soroban Attestation Service (SAS) contracts, SDKs, indexers, and documentation.

---

## Core Attestation Concepts

### Attestation
An authenticated, structured digital statement made by an entity (**Attester / Issuer**) about a subject (**Recipient**) or condition. On Soroban SAS, an attestation is identified by a unique 32-byte identifier (`BytesN<32>`), conforms to an on-chain registered **Schema**, and may be either stored persistently on ledger (on-chain) or cryptographically signed and verified off-chain.

### Schema
A formal data definition specifying the field names, types, and serialization rules for an attestation payload. Schemas are registered once in the **Schema Registry** contract and receive a deterministic 32-byte identifier computed from their canonical string definition, resolver contract address, and revocability flag.

### Schema Registry
The core smart contract responsible for recording, indexing, and managing schema definitions. It guarantees schema immutability: once a schema is registered with a specific UID, its definition and configured resolver contract cannot be altered.

### Attestation Registry (EAS Contract)
The central Soroban contract that records on-chain attestations, validates schema conformance, enforces resolver hooks, handles revocations, and emits ledger events for off-chain indexers.

---

## Participants & Roles

### Attester (Issuer)
The Stellar account (`Address`) or smart contract that authors and authorizes an attestation. In on-chain attestations, the attester must invoke the transaction and satisfy `require_auth()`. In delegated or off-chain attestations, the attester cryptographically signs the attestation envelope.

### Recipient (Subject)
The entity, Stellar account (`Address`), or contract about whom the attestation is made. While many attestations target a specific recipient (e.g. KYC verification, credential issuance), recipient is optional (`None`) for general public statements or protocol status records.

### Resolver
An optional smart contract deployed on Soroban that is linked to a Schema. When configured, the resolver's hooks (`on_attest` and `on_revoke`) are executed atomically during attestation creation or revocation. Resolvers can enforce arbitrary custom logic, such as payment verification, allowlists, prerequisite checks, or secondary token mints.

---

## Lifecycle & State Concepts

### UID (Unique Identifier)
A 32-byte hash (`BytesN<32>`) representing the globally unique identifier for either a Schema or an Attestation.
- **Schema UID**: Derived deterministically by hashing `(schema_string, resolver_address, revocable)`.
- **Attestation UID**: Derived deterministically by hashing `(schema_uid, recipient, attester, time, expiration_time, data, ref_uid, nonce)`.

### Revocable vs. Irrevocable
- **Revocable Schema**: Allows the original attester (or configured resolver) to formally invalidate an existing attestation on ledger.
- **Irrevocable Schema**: Once created, attestations adhering to this schema can never be revoked. Guarantees permanent non-repudiation for credentials that should not expire or be recalled.

### Revocation
The explicit transition of an attestation state from active to revoked. Recorded in contract persistent storage with a timestamp (`revocation_time`). Any downstream contract or off-chain verifier querying the attestation registry will recognize the attestation as invalid after this timestamp.

### Expiration Time
An optional Unix timestamp (`u64`) after which an attestation is automatically considered expired by verifiers. Unlike revocation, expiration does not require a ledger transaction; it is evaluated dynamically against the current ledger timestamp (`env.ledger().timestamp()`).

### RefUID (Referenced Attestation)
A 32-byte UID linking a new attestation to an earlier attestation. This enables relational hierarchies, such as:
- Endorsements of previous attestations.
- Amendments or updates to previous attestations.
- Counter-attestations or dispute claims.

---

## Advanced Architecture Terms

### Batch Attestation
An atomic contract call (`attest_batch`) that registers multiple attestations across one or more schemas in a single transaction invocation. Reduces per-attestation transaction fees and ensures either all attestations succeed or none do.

### Merkle Tree Attestation
A mechanism for scaling high-volume attestation batches where only the Merkle root (`BytesN<32>`) is committed to Soroban storage. Individual attestations are verified off-chain or on-demand using cryptographic Merkle proofs, drastically saving ledger rent and execution gas.

### Off-Chain Attestation
An attestation payload formatted and cryptographically signed according to the Soroban SAS specification, but distributed peer-to-peer or via indexers without being written directly to Soroban storage. Verified locally by clients or relayed to contracts on demand.

### Delegated Attestation
An on-chain attestation submitted by a third party (the sponsor or relayer) on behalf of an attester who provided an authorized cryptographic signature. Allows gasless attestation flows where users do not pay network fees directly.

### Ledger Storage TTL (Time-To-Live) & Rent
Soroban persistent storage entries (such as attestations and schemas) require storage rent management. SAS contracts employ instance and persistent TTL extension routines (`extend_ttl`) to ensure attestation records remain accessible throughout their required lifetime.

---

## Summary Matrix

| Term | On-Chain Type | Storage Scope | Mutability |
| :--- | :--- | :--- | :--- |
| **Schema** | `SchemaRecord` | Persistent Storage | Immutable |
| **Attestation** | `AttestationRecord` | Persistent Storage | Revocable (if schema permits) |
| **Resolver** | `Address` | Referenced Contract | Read-only execution hook |
| **Revocation** | `u64` (Timestamp) | Persistent Storage | One-way state transition |
| **RefUID** | `BytesN<32>` | Attestation field | Immutable per record |
