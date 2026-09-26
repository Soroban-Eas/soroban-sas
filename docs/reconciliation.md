# Indexer Operational Runbook: Reconciliation & Recovery

This operational runbook documents the fail-open recovery procedure for the Soroban Attestation Service (SAS) Indexer.

When the Indexer is unavailable, traps, or encounters network partitions under fail-open mode (`set_indexer_strict(false)`, the default), the core SAS contract still issues attestations to preserve system availability. For each attestation whose push to the Indexer fails, SAS emits an `IndexFailed(uid)` event (topic `IDXFAIL`). Operators use `SAS::reindex_attestation` to restore consistency between the SAS contract's attestation records and the Indexer lookup tables.

---

## 1. Detection

Operators must monitor the contract event stream for `IndexFailed` events. In healthy operations, every `AttestationIssued` event is accompanied by successful indexing. When indexing fails, an `IndexFailed` event is emitted containing the missed attestation UID.

### Event Signatures

| Event | Topic 0 | Topic 1 (`uid`) | Data | Description |
|---|---|---|---|---|
| **IndexFailed** | `symbol_short!("IDXFAIL")` | `BytesN<32>` (attestation UID) | `(uid,)` | Emitted when downstream Indexer push fails in fail-open mode |
| **Reindexed** | `symbol_short!("REINDEX")` | `BytesN<32>` (attestation UID) | `(uid,)` | Emitted when a missed attestation is successfully re-indexed |
| **AttestationIssued** | `symbol_short!("ATTEST")` | `BytesN<32>` (attestation UID) | `(schema_uid, recipient, attester)` | Emitted on attestation creation |

---

## 2. Enumeration: Identifying Unreconciled UIDs

An attestation requires reconciliation if an `IndexFailed` (`IDXFAIL`) event was emitted for its UID, but no subsequent `Reindexed` (`REINDEX`) event has succeeded.

### Shell / RPC Pipeline

You can enumerate unreconciled UIDs using the Stellar CLI / Soroban RPC `getEvents` endpoint paired with `jq`:

```bash
#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${SOROBAN_RPC_URL:-https://soroban-testnet.stellar.org:443}"
SAS_CONTRACT_ID="${SAS_CONTRACT_ID:?SAS_CONTRACT_ID must be set}"
START_LEDGER="${START_LEDGER:-1000}"

# Query IDXFAIL and REINDEX events emitted by the SAS contract
curl -s -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getEvents",
    "params": {
      "startLedger": '"$START_LEDGER"',
      "filters": [
        {
          "type": "contract",
          "contractIds": ["'"$SAS_CONTRACT_ID"'"]
        }
      ],
      "limit": 10000
    }
  }' | jq -r '
    .result.events // [] |
    # Collect all failed UIDs and successfully reindexed UIDs
    {
      failed: [ .[] | select(.topic[0] == "AAAABAAAAAdJRFhGQUlMAAA=" or .topic[0] == "IDXFAIL") | .topic[1] ],
      reindexed: [ .[] | select(.topic[0] == "AAAABAAAAAdSRUlOREVYAAA=" or .topic[0] == "REINDEX") | .topic[1] ]
    } |
    # Unreconciled = failed UIDs that do not appear in reindexed list
    (.failed - .reindexed) | unique[]
  ' > unreconciled_uids.txt

echo "Found $(wc -l < unreconciled_uids.txt) unreconciled attestation(s)."
```

---

## 3. Invocation: Calling `reindex_attestation`

`reindex_attestation` is permissionless. It reads the authentic attestation stored in SAS persistent storage, verifies its existence, and pushes it to the bound Indexer. It cannot fabricate or alter attestation data.

### CLI Invocation

To reconcile a single UID via the Stellar CLI:

```bash
stellar contract invoke \
  --id "$SAS_CONTRACT_ID" \
  --source-account "$OPERATOR_IDENTITY" \
  --rpc-url "$RPC_URL" \
  --network-passphrase "$NETWORK_PASSPHRASE" \
  -- reindex_attestation \
  --uid "$UID_HEX"
```

To reconcile all UIDs listed in `unreconciled_uids.txt`:

```bash
while IFS= read -r uid; do
  [[ -z "$uid" ]] && continue
  echo "Reindexing attestation UID: $uid"
  stellar contract invoke \
    --id "$SAS_CONTRACT_ID" \
    --source-account "$OPERATOR_IDENTITY" \
    --rpc-url "$RPC_URL" \
    --network-passphrase "$NETWORK_PASSPHRASE" \
    -- reindex_attestation \
    --uid "$uid" || echo "Failed to reindex $uid, will retry"
done < unreconciled_uids.txt
```

### SDK Usage for Automated Background Service

For automated reconciliation in a daemon or microservice, use `SASClient` (or the Soroban SDK client):

```typescript
import { Contract, Keypair, rpc } from "@stellar/stellar-sdk";

async function reconcileAttestation(
  server: rpc.Server,
  sasContractId: string,
  operatorKey: Keypair,
  uidBytes: Buffer
): Promise<boolean> {
  const sas = new Contract(sasContractId);

  try {
    const tx = await sas.call("reindex_attestation", {
      uid: uidBytes,
    });
    const response = await server.sendTransaction(tx);
    console.log(`Reindexed ${uidBytes.toString("hex")}: tx hash ${response.hash}`);
    return true;
  } catch (error: any) {
    if (error.message?.includes("IndexerUnavailable")) {
      console.warn(`Indexer still unavailable while reindexing ${uidBytes.toString("hex")}. Queuing retry.`);
      return false;
    }
    throw error;
  }
}
```

In Rust backend services:

```rust
use soroban_sas_sdk::SASClient;
use soroban_sdk::{Address, BytesN, Env};

pub fn run_reconciliation(
    env: &Env,
    sas_client: &SASClient,
    unreconciled_uids: &[BytesN<32>],
) -> Vec<BytesN<32>> {
    let mut failed_retries = Vec::new();
    for uid in unreconciled_uids {
        match sas_client.try_reindex_attestation(uid) {
            Ok(Ok(())) => {
                // Successfully reindexed; SAS contract emitted REINDEX event
            }
            Ok(Err(_err)) | Err(_) => {
                // Indexer still unhealthy or call failed; queue for backoff retry
                failed_retries.push(uid.clone());
            }
        }
    }
    failed_retries
}
```

---

## 4. Verification: Health Check Pattern

Once `reindex_attestation` executes, verify that the UID is now queryable from the Indexer:

1. **Check Reverse Lookup by Recipient:**
   Call `Indexer::get_attestations_by_recipient` with the attestation recipient address:
   ```bash
   stellar contract invoke \
     --id "$INDEXER_CONTRACT_ID" \
     --rpc-url "$RPC_URL" \
     --network-passphrase "$NETWORK_PASSPHRASE" \
     -- get_attestations_by_recipient \
     --recipient "$RECIPIENT_ADDRESS"
   ```
   Assert that the previously missing UID is present in the returned list.

2. **Check Status Entry:**
   Call `Indexer::get_attestation_status`:
   ```bash
   stellar contract invoke \
     --id "$INDEXER_CONTRACT_ID" \
     --rpc-url "$RPC_URL" \
     --network-passphrase "$NETWORK_PASSPHRASE" \
     -- get_attestation_status \
     --uid "$UID_HEX"
   ```
   The result should be `Active` (or `None`, indicating active legacy status).

3. **Verify On-Chain Event:**
   Confirm that a `REINDEX` event (`topics: [symbol!("REINDEX"), uid]`) was emitted in the transaction receipt.

---

## 5. Unhealthy Indexer & Retry Strategy

If `reindex_attestation` returns `SASError::IndexerUnavailable`, the indexer is either unreachable, not yet deployed/initialized, or out of resources.

### Recommended Retry Policy:
- **Exponential Backoff with Jitter:** Start with a 5-second backoff, doubling up to a maximum interval of 5 minutes (`interval = min(5 * 2^attempt + jitter, 300)`).
- **Circuit Breaker:** If 5 consecutive reconciliation attempts fail with `IndexerUnavailable`, pause the reconciliation queue and alert on-call operators.
- **Contract Rotation (Failover):** If the Indexer contract cannot be restored, SAS admin should deploy a new Indexer contract and execute `SAS::set_indexer(new_indexer_address)`. Once updated, run reconciliation over all historic `unreconciled_uids.txt` to populate the new Indexer.
