# Soroban Mainnet Launch Preparation Runbook

This operational runbook establishes the comprehensive checklist, architecture verifications, key custody procedures, economic budgeting, and incident runbooks required for deploying and maintaining the Soroban Attestation Service (SAS) on the Stellar/Soroban Mainnet.

---

## 1. Mainnet Launch Phases

The launch execution is divided into five sequential phases:

```
[Phase 1: Pre-Flight Audits & Reproducibility]
       │
       ▼
[Phase 2: Key Custody & Multi-Sig Governance]
       │
       ▼
[Phase 3: Deployment & Deterministic Verification]
       │
       ▼
[Phase 4: Storage Rent & State TTL Budgeting]
       │
       ▼
[Phase 5: Telemetry, Observability & Incident Response]
```

---

## 2. Phase 1: Pre-Flight Audits and Reproducible WASM Builds

Prior to mainnet deployment, all contract bytecode must be deterministically built and independently verifiable against the Git commit hash.

### 2.1 Compiler and Toolchain Pinning
- **Rust Toolchain:** Pinned strictly via `rust-toolchain.toml` (`1.80.0` or later matching the Soroban protocol target).
- **Soroban SDK:** `soroban-sdk 21.7.7` / Protocol 21+ compatibility.
- **Optimization:** Use `stellar contract build --package <pkg>` followed by `soroban contract optimize` (or `wasm-opt -Oz`).

### 2.2 Deterministic WASM Hash Verification
1. Run reproducible build script:
   ```bash
   bash scripts/verify_wasm_hashes.sh
   ```
2. Compute cryptographic SHA-256 hashes of the target WASMs:
   ```bash
   sha256sum target/wasm32-unknown-unknown/release/*.wasm
   ```
3. Record all build hashes in the deployment announcement and commit to repository release tags.

---

## 3. Phase 2: Multi-Sig Key Custody and Governance Setup

Mainnet contract administration must **never** reside on a single private key.

### 3.1 Administrator Account Architecture
- **Admin Model:** Multi-signature Stellar account or a Soroban multisig smart contract.
- **Threshold Scheme:** Minimum 3-of-5 threshold across geographically and organizationally distributed keyholders.
- **Signer Key Types:** Hardware security modules (HSM) or Ledger hardware wallets.

### 3.2 Role Separation
- **Deployer Key:** Ephemeral deployment account with sufficient XLM for transaction fees and initial rent reserves.
- **Admin Account:** Multisig account controlling `init`, `set_admin`, `upgrade`, `set_fee`, `set_indexer`, and `set_paused`.
- **Treasury Account:** Distinct multisig account receiving protocol fees and handling fund withdrawals.

---

## 4. Phase 3: Contract Deployment and Initialization Sequence

Deploy the contracts in exact dependency order:

```bash
# 1. Upload Bytecode to Mainnet
REGISTRY_WASM_HASH=$(stellar contract install --wasm target/wasm32-unknown-unknown/release/schema_registry.wasm --network mainnet --source deployer-key)
SAS_WASM_HASH=$(stellar contract install --wasm target/wasm32-unknown-unknown/release/sas.wasm --network mainnet --source deployer-key)
INDEXER_WASM_HASH=$(stellar contract install --wasm target/wasm32-unknown-unknown/release/soroban_sas_indexer.wasm --network mainnet --source deployer-key)

# 2. Deploy Contract Instances
REGISTRY_ID=$(stellar contract deploy --wasm-hash $REGISTRY_WASM_HASH --network mainnet --source deployer-key)
SAS_ID=$(stellar contract deploy --wasm-hash $SAS_WASM_HASH --network mainnet --source deployer-key)
INDEXER_ID=$(stellar contract deploy --wasm-hash $INDEXER_WASM_HASH --network mainnet --source deployer-key)

# 3. Initialize Schema Registry
stellar contract invoke --id $REGISTRY_ID --network mainnet --source deployer-key -- init --admin $MULTISIG_ADMIN

# 4. Initialize SAS Core
stellar contract invoke --id $SAS_ID --network mainnet --source deployer-key -- init --admin $MULTISIG_ADMIN --schema_registry $REGISTRY_ID

# 5. Initialize Indexer
stellar contract invoke --id $INDEXER_ID --network mainnet --source deployer-key -- init --admin $MULTISIG_ADMIN --sas_address $SAS_ID

# 6. Wire SAS to Indexer and Set Treasury
stellar contract invoke --id $SAS_ID --network mainnet --source admin-multisig -- set_indexer --indexer $INDEXER_ID
stellar contract invoke --id $SAS_ID --network mainnet --source admin-multisig -- set_treasury --treasury $MULTISIG_TREASURY
stellar contract invoke --id $REGISTRY_ID --network mainnet --source admin-multisig -- set_treasury --treasury $MULTISIG_TREASURY
```

---

## 5. Phase 4: Storage Rent & State TTL Budgeting

Soroban storage rent is calculated based on entry size and time-to-live (TTL) ledgers. Failure to maintain TTL leads to entry archiving.

### 5.1 Storage Footprint Optimization
- **Compact Attestation Struct:** SAS utilizes the packed `CompactAttestation` format, reducing per-attestation storage footprint by **>25%** compared to legacy representations (376 bytes vs 508 bytes per attestation).
- **Rent Savings:** At 10,000 attestations per ledger, `CompactAttestation` saves over 1.32 MB of persistent state writes per 10k batch, significantly lowering rent deposit and extension costs.

### 5.2 Automatic TTL Extension Policy
- **Instance Storage:** All contract entrypoints invoke `extend_instance_ttl(&env)`, refreshing the contract instance TTL to `LEDGERS_IN_ONE_YEAR` (approximately 6,307,200 ledgers at 5s/ledger) whenever `threshold < 30 days`.
- **Persistent Storage:** Attestation entries automatically extend their persistent TTL during issuance (`attest`), revocation (`revoke`), replacement, and manual migration (`migrate_attestation`).

### 5.3 Rent Reserve Monitoring
- Maintain an operational reserve of at least 5,000 XLM on each contract address to support auto-renewals and long-term ledger residency.
- Run cron monitors tracking contract XLM balances and TTL expiration horizons.

---

## 6. Phase 5: Monitoring, Telemetry and Alerting

Real-time indexing and event monitoring must be established immediately post-deployment.

### 6.1 RPC Event Filtering & Prometheus Telemetry
Operators must subscribe to Soroban RPC `getEvents` for the following topics:

| Contract | Event Topic | Criticality | Operational Action |
| :--- | :--- | :--- | :--- |
| `SAS` | `PAUSED` | Critical (P0) | Alert on-call immediately; protocol paused |
| `SAS` | `IDXFAIL` | High (P1) | Alert indexer outage; trigger fail-open reconciliation runbook |
| `SAS` | `ATTEST`, `REVOKE` | Medium (P2) | Ingest into analytics dashboard and query service |
| `SAS` | `WITHDRAW` | High (P1) | Audit fee withdrawals against treasury authorizations |
| `Registry` | `SCHEMA_REG` | Medium (P2) | Cache new schema definitions |

### 6.2 Health Probes
Expose automated health checks pinging:
1. RPC responsiveness: `sas.get_indexer()` and `sas.get_fee()`.
2. Parity check: Compare latest `AttestationIssued` events from SAS with latest records in `soroban_sas_indexer`.

---

## 7. Emergency Runbooks & Incident Response

### 7.1 Emergency Protocol Pause (`PAUSED`)
In case of critical vulnerability or severe network anomaly:
1. Multisig triggers `set_paused(true)`:
   ```bash
   stellar contract invoke --id $SAS_ID --network mainnet --source admin-multisig -- set_paused --paused true
   ```
2. When paused:
   - `attest`, `attest_by_delegation`, `multi_attest`, `replace_attestation`, and `renew_attestation` immediately abort with `SASError::ContractPaused`.
   - Read-only operations (`get_attestation`, `verify_attestation_view`) remain accessible.
   - Revocation operations (`revoke`, `multi_revoke`) remain operational to protect participants.
3. Unpausing is executed via `set_paused(false)` after remediation.

### 7.2 Indexer Outage Recovery
If the Indexer falls behind or traps:
1. SAS continues operating in fail-open mode, emitting `IndexFailed(uid)`.
2. Follow the [Reconciliation Runbook](reconciliation.md) to query missed events and replay with `reindex_attestation(uid)` or `bulk_reindex(uids)`.

### 7.3 Contract Upgrade Runbook
Upgrades must follow [UPGRADE_RUNBOOK.md](UPGRADE_RUNBOOK.md), retaining storage layout compatibility and executing migration functions if state formats evolve.
