# Soroban SAS — Contract Security Model and Threat Analysis

> Scope: `contracts/sas`, `contracts/schema-registry`, `contracts/indexer`, the `soroban-sas-common` signing/UID helpers, and their RPC clients. This document describes security *assumptions and verification targets*, not a claim that an independent audit has been completed. Last reviewed against repository implementation at the #498 documentation change.

## 1. System boundaries and principals

**Trust boundaries**

1. **Caller → Soroban authorization**: `require_auth` verifies an account's Soroban authorization; public view functions do not. A transaction source signature alone does **not** authorize an arbitrary `attester`.
2. **Issuer → SAS**: direct issuance needs `attestation.attester.require_auth()`. Delegated issuance accepts an Ed25519 signature bound to the network ID, contract ID, nonce and attestation digest. A channel-account relayer cannot forge the issuer's signature.
3. **SAS → Registry**: SAS trusts the configured Registry to answer schema existence, revocation policy and authorization. Changes to the Registry implementation or binding change this trust boundary.
4. **SAS → resolver**: optional schema-specific external callbacks may reject issuance or revocation. Treat their code as untrusted, even if the schema owner selected them; consider reentrancy and gas exhaustion. A resolver rejection must not be converted to a successful attestation.
5. **SAS → Indexer**: index publication is a downstream side effect; the Indexer accepts trusted SAS callbacks, not arbitrary public writes. Strict versus non-strict indexing affects consistency/availability, not the validity of the SAS record.
6. **Off-chain SDK/JS → chain**: an untrusted RPC endpoint, local key store, or compromised frontend can feed misleading metadata; contract state and cryptographically verified signatures are the ultimate source of truth.

**Trusted roles:** Registry admin (upgrade, fee and treasury policy); SAS admin (upgrade, pause, fee and indexer binding); Indexer admin (upgrade); per-schema owner/approved multisig owners (schema management); attester (attestation issuance/revocation); delegated signer (registered/structurally matching Ed25519 key); recipient (subject, not necessarily issuer). Do not confuse transaction fee-payer and authorization principal.

**Critical assets:** admin/owner/issuer signing keys; source-account sequences; UID integrity; schema ownership and revocation permissions; fee token balances; delegation nonce high-water marks; index consistency; historic event integrity; TTL/rent budget; upgrade WASM hashes.

## 2. Entrypoint authorization matrix

All methods below are on-chain public entrypoints, not private helper functions. A slash-separated group enumerates the entrypoints in that group. “Read” does not imply trustworthiness of the caller's RPC provider.

### Schema Registry

| Entrypoints | Authorized actor and guard | Security-sensitive effect |
| --- | --- | --- |
| `sasreg`, `get_version`, `get_fee`, `get_treasury` | Public/read | Version and configuration |
| `init` | Supplied admin authorizes; initialization one-time | Initializes registry admin |
| `upgrade`, `set_fee`, `set_treasury`, `withdraw_fees` | Registry admin auth | Code changes, payment settings, fee movement |
| `register`, `register_with_ttl`, `register_with_max_ttl`, `register_with_policy`, `register_with_category` | Supplied owner requires auth | Creates unique content-addressed schema and policy; optional category is a separate searchable index |
| `register_with_value`, `register_with_value_and_ttl` | Owner auth; exact configured token/fee; treasury if payable | Registration and atomic token payment |
| `deprecate`, `deprecate_schema` | Schema creator/owner, configured owner set, or allowed admin pathway (as implemented) | Invalidates future schema use; not retroactive erasure |
| `add_delegate`, `remove_delegate` | Schema owner authority | Modifies authorized attesters |
| `transfer_schema_ownership`, `transfer_ownership` | Current owner authorization, subject to multisig guards | Immediate ownership transfer on applicable configuration |
| `propose_schema_owner`, `claim_schema_ownership`, `cancel_schema_ownership_transfer` | Old owner proposes/cancels; designated new owner claims | Two-step ownership handoff |
| `configure_owner_set`, `propose_ownership_transfer`, `approve_ownership_transfer`, `cancel_ownership_transfer` | Authorized owner-set members and threshold approval rules | Multisig membership/ownership changes |
| `get_owner_set`, `is_schema_owner`, `get_pending_schema_owner`, `get_pending_ownership_transfer`, `get_creator`, `is_delegate`, `is_authorized` | Public/read | Policy lookup |
| `get_schema`, `get_schema_by_content`, `validate_schema`, `get_schema_policy`, `get_revocation_policy`, `get_max_ttl`, `get_schema_max_ttl` | Public/read | Schema lookup and TTL/policy validation |
| `get_schemas`, `get_schemas_paginated`, `get_schemas_by_category`, `get_schema_category` | Public/read; bounded scanning | Discoverability and metadata |

**Registry caution:** `SchemaRecord` is a protocol storage format; category is stored under independent keys to avoid silently breaking already-issued schemas. A category is descriptive metadata, **not** an authorization namespace. Schema UIDs remain based on schema definition, resolver and revocability, not on category.

### SAS attestation contract

| Entrypoints | Authorized actor and guard | Security-sensitive effect |
| --- | --- | --- |
| `sasv1`, `admin`, `get_version`, `is_paused`, `get_indexer`, `get_treasury`, `get_fee`, `get_indexer_strict` | Public/read | Configuration |
| `init` | Supplied admin authorization; only once | Binds admin and registry |
| `upgrade`, `propose_admin`, `accept_admin` | Admin or designated accepting admin | Changes code/control |
| `pause`, `unpause` | SAS admin | Stops/resumes guarded state-changing paths |
| `set_indexer`, `set_indexer_strict`, `set_treasury`, `set_fee`, `clear_fee`, `withdraw_tokens` | SAS admin | Indexer policy and fee custody |
| `attest`, `multi_attest`, `attest_with_value` | Each attester `require_auth`; fee validation if payable | Issues content-addressed records |
| `attest_by_delegation`, `multi_attest_by_delegation` | Valid Ed25519 digest(s), key binding and strictly increasing nonce per issuer | Relayed issuance without an attester Soroban auth entry |
| `revoke`, `multi_revoke`, `revoke_by_authorizer`, `revoke_by_delegate` | Recorded attester / authorized actor / delegate, per endpoint | Revokes active revocable records |
| `revoke_by_delegation`, `multi_revoke_by_delegation` | Issuer signature, nonce and key validation | Relayed revocation |
| `replace_attestation`, `renew_attestation` | Original attester authority and relevant schema constraints | Controlled record lifecycle |
| `register_attester_key`, `rotate_attester_key`, `revoke_attester_key`, `invalidate_nonces`, `set_nonce_highwater_mark` | Attester authorization | Key rotation and replay floor |
| `invalidate_nonces_by_delegation` | Delegated issuer cryptographic authorization | Signed nonce invalidation |
| `hash_delegation_digest`, `verify_offchain_attestation`, `verify_attestation`, `verify_attestations`, `verify_all_attestations`, `verify_attestation_view`, `get_attestation`, `get_attestation_view`, `get_valid_from`, `get_delegation_nonce`, `get_nonce_highwater_mark`, `get_attester_key`, `get_issuance_timestamp`, `get_revocation_timestamp`, `verify_timestamp` | Public/read (some reads renew TTL) | Cryptographic and state verification |
| `bulk_reindex`, `reindex_attestation` | Reindexes already-issued records; bound Indexer is the only trusted storage writer | Repairs downstream indexes |
| `migrate_attestation`, `migrate_attestations` | Public migration paths with contract-enforced constraints | Upgrades stored attestation format |

### Indexer

| Entrypoints | Authorized actor and guard | Security-sensitive effect |
| --- | --- | --- |
| `sasv1`, `get_version`, `get_admin`, `get_sas` | Public/read | Configuration |
| `init` | Supplied admin authorization; SAS address bound once | Initializes indexer |
| `upgrade` | Indexer admin | Changes code/layout |
| `index_attestation`, `set_valid_from` | Bound SAS contract/callback source required | Writes UID/status/lookup metadata |
| `get_attestation_status`, `get_valid_from`, `has_recipient_attestation`, `get_recipient_attestation_count`, `get_count_by_recipient`, `get_count_by_schema`, `get_count_by_attester`, `get_count_by_issuer` | Public/read | Counts and status |
| `get_attestations_by_recipient`, `get_attestations_by_schema`, `get_attestations_by_attester`, `get_attestations_by_issuer` | Public/read | UID lookup |
| `get_atts_by_recipient_paginated`, `get_atts_by_schema_paginated`, `get_atts_by_attester_paginated`, `get_atts_by_issuer_paginated`, `get_atts_by_recipient_reverse`, `get_atts_by_schema_reverse`, `get_atts_by_attester_reverse` | Public/read; page bounds | Paginated traversal |
| `get_recipient_filtered`, `get_schema_filtered`, `get_attester_filtered`, `get_issuer_filtered`, `get_recipient_page_filtered`, `get_issuer_page_filtered` | Public/read | Revocation-aware filtering |

**Review requirement:** reconcile this matrix against the deployed WASM *and* emitted contract spec for every release; no documentation list replaces an authorization review in the code. Public entrypoints may charge resources even when they are read-only.

## 3. Security invariants (release gates)

- **S1 — Identity:** stored attestation UID equals the canonical hash of `(schema_uid, recipient, attester, data)`; no alternate caller-supplied UID accepted.
- **S2 — Issuer authorization:** non-delegated mutation requiring an attester cannot be performed by an unrelated transaction source.
- **S3 — Domain separation:** delegated signatures commit to the live network ID, SAS contract address, nonce and exact signed payload; changing any must fail verification.
- **S4 — Monotonic nonce:** a successful delegated operation advances the issuer's replay floor, and old/repeated nonce values never succeed.
- **S5 — Schema lifecycle:** an unregistered or deprecated schema cannot authorize a new attestation.
- **S6 — Revocation integrity:** irreversible records cannot be revoked; repeated revocation cannot create multiple state transitions.
- **S7 — Atomic batches:** any item failing in a multi-attest/revoke batch leaves **all** writes and nonce changes unapplied.
- **S8 — Fee conservation:** amount/token must match admin configuration; failures do not transfer tokens or store records.
- **S9 — Authority isolation:** upgrade/fee/treasury binding changes require the correct admin; ownership approval thresholds count *distinct* authorized participants.
- **S10 — Source authentication:** the Indexer cannot accept fabricated attestation callbacks from a third party.
- **S11 — Bounded computation:** page scans, batch sizes and payload sizes have protocol-enforced limits.
- **S12 — Storage survival:** metadata and records needed for verification receive TTL extensions, and expired metadata must fail closed rather than silently overwrite live indexes.
- **S13 — Index consistency:** a verified SAS record is the source of truth; an indexer miss or stale index may degrade discovery but cannot manufacture a valid attestation.
- **S14 — Upgrade compatibility:** a version/WASM swap must retain UID, record and authority interpretation; any failing swap reverts the transaction.

## 4. Attack paths and mitigations

| Threat | Attack/impact | Controls and remaining risk |
| --- | --- | --- |
| Transaction front-running / reordering | Another relayer submits an already-public signed payload first or reorders nonces | Unique content-addressed UID and monotonic nonce limit replay, but **not** ordering or front-running of a valid disclosed signature. Use submission deadlines, controlled relayers and explicit policy where needed. |
| Cross-network or cross-contract replay | Reuse of a signature outside intended deployment | Digest domain binds ledger network ID, SAS address and nonce; test tampered domains and stale nonces. |
| Resolver reentrancy | External callback recursively enters SAS during a half-completed operation | Guarded batch operations, atomic Soroban transactions and endpoint validation. Review *each* resolver boundary for single-call reentry; a guard on one endpoint is not proof of whole-contract immunity. |
| State exhaustion / rent griefing | Huge batches, categories, schemas or storage growth increase ledger cost | Bounded data, bounded scan budget, fees and TTL. Category enumeration is indexed and paginated, not a full arbitrary storage scan; monitor storage/rent. |
| Admin/issuer key compromise | Malicious registration, upgrades, token withdrawal or forged attestations | Hardware/offline custody, role separation, multisig owners, nonce invalidation, issuer key revocation/rotation, audited upgrades; chain cannot undo already finalized attestations. |
| Malicious RPC / chain simulation mismatch | Wrong account sequence, stale simulation or false success | Pin network passphrase and contract IDs; verify finalized transaction status on a trusted RPC, resync sequences and reconcile from chain. |
| Gas or indexer denial of service | Resolver/indexer traps prevent issuance or leave explorer incomplete | Explicit strict/non-strict index policy; bounded calls; monitor and reconcile. Never interpret an absent index as definitive absence from SAS. |
| Timestamp/expiry manipulation | Premature activation, backdated attestation or beyond-limit expiry | Check ledger timestamps, `valid_from`, expiration, schema maximum TTL and stored anchor verification. |
| Upgrade storage corruption | New WASM reads persistent state with incompatible layout | Explicit version gates, candidate hash checks, staged testnet migrations, read-after-upgrade regression tests and rollback/recovery plan. |
| Hashing parity divergence | JS, Rust and contract disagree on encoded XDR or integer width | Golden vectors and differential fuzzing across suites; special-case empty data, non-ASCII, 0/max u64 and contract/account addresses. |

**Hash algorithm note:** the existing SAS *v1 off-chain signing scheme* is EIP-712-**style** but uses SHA-256 and SAS-specific type tags; it is *not interchangeable* with standard Ethereum Keccak-256 `eth_signTypedData`. The separate generic `soroban-sas-common::eip712` module implements standard Keccak-256 typed struct hashing. Never conflate the two.

## 5. Emergency incident response and pause runbook

1. **Detect and preserve evidence:** alert on unauthorized admin events, unexpected nonce jumps, duplicate/rejected UIDs, fee transfers, failed resolver callbacks, anomalous upgrade hashes and index drift. Record network, contract IDs, block/ledger, tx hashes, suspected keys, and time.
2. **Classify and notify privately:** identify whether the fault is limited to a client/relayer, an issuer key, a schema owner, the Registry, Indexer or SAS itself. Use the private disclosure channel in [SECURITY.md](SECURITY.md). Never publish unrepaired exploitation steps or signing seeds.
3. **Contain SAS writes:** a valid **SAS admin** submits `pause()` against the verified SAS address, watches the transaction until finalized, and independently queries `is_paused()`. A failed or pending tx is **not** containment.
4. **Contain credentials:** revoke/rotate compromised issuer signing keys using the applicable attester-authorized paths and raise the delegation nonce floor. Rotate relayer/channel keys and suspend their funding. Transfer admin authority through the implemented propose/accept path if feasible and safe.
5. **Handle the other contracts separately:** Registry and Indexer do **not** expose an equivalent global pause switch in the current interface. Halt operational callers and funding; if a code fix is necessary, use audited and authenticated upgrade procedures. **Pausing SAS does not freeze Registry ownership/fee operations.**
6. **Assess state integrity:** snapshot affected schema UIDs and records; compare native SAS events and stored records to Indexer queries; identify stale or mismatched indexes, replayed signatures and schema registration anomalies. Preserve forensic artifacts.
7. **Remediate in isolation:** reproduce on local/testnet, add a regression test for each violated invariant, obtain independent review, pin the expected candidate WASM hash, verify storage-layout migrations and prepare a versioned deployment plan.
8. **Recover and verify:** apply approved fix, exercise representative read/write/revoke flows, reindex missing records only after SAS truth is established, ensure all privileged roles are correct, then SAS admin calls `unpause()` and confirms `is_paused() == false`.
9. **Post-incident:** issue coordinated disclosure, document the affected ranges and mitigations, rotate operational secrets, and add continuous monitoring/release checks.

**No emergency shortcuts:** do not attempt an unknown WASM upgrade hash, reset nonce floors, delete persistent records, or assume historical attestation events can be rolled back. Have multiple independent admin key custodians and validated restoration steps before mainnet.

## 6. Assurance checklist

- Inspect all `require_auth` paths and delegated signature verification against Soroban authorization guidance and test harness.
- Run `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`.
- Run each `cargo fuzz` target in the scheduled campaigns; retain reproducible corpus seeds and crash artifacts.
- Run signing/hash parity tests against the pinned TypeScript SDK and deployed contract client.
- Run upgrade preservation, TTL, malformed input, fee transfer, callback failure and multisig authorization tests.
- Capture baseline gas/fee and attestation throughput before/after patches; include chain/network and runner details.
- Require separate review of changes to storage keys, auth, hashing, nonces and resolver/indexer callback paths.
- Follow the [project vulnerability process](SECURITY.md), [deployment runbook](docs/DEPLOYMENT.md), and [upgrade runbook](docs/UPGRADE_RUNBOOK.md).

This model should be updated whenever contract entrypoints, key custody, resolver behavior or deployed WASM changes.
