# Migrating from Ethereum EAS to Soroban SAS

This guide walks through migrating historical attestations from an EVM EAS
deployment (Ethereum, Base, Arbitrum, etc.) to a Soroban SAS deployment using
the `sas migrate eas` command.

## Prerequisites

- Rust toolchain (1.75+) and cargo.
- Access to an EVM JSON-RPC endpoint for the source chain (Alchemy, Infura, Quicknode,
  or a self-hosted node).
- The EAS contract address on the source chain.
- A deployed Soroban SAS contract and a funded Stellar account for submitting
  transaction envelopes.

## Step 1 - Build the CLI

```bash
cargo build --release -p soroban-sas-cli
```

The binary is available at `target/release/sas`.

## Step 2 - Run a dry export

Before submitting any transactions, export and translate a small block range:

```bash
sas migrate eas \
  --rpc "https://sepolia.infura.io/v3/<your-key>" \
  --contract 0x420000000000000000000000000000000000000000000000000000000000000 \
  --from-block 1000000 \
  --to-block 1001000 \
  --output-dir ./sas-migration
```

This produces:

- ./sas-migration/audit.csv - source UID -> destination UID mapping.
- ./sas-migration/envelopes/batch-*.json - Soroban transaction envelopes.
- ./sas-migration/checkpoint.json - resume checkpoint.
- ./sas-migration/reconciliation.json - summary report.

## Step 3 - Resume after rate limiting

If the source RPC rate-limits the export, the CLI will retry with exponential
backoff and persist a checkpoint every 25 attestations. Resume with:

```bash
sas migrate eas \
  --rpc "${ETHEREUM_RPC}" \
  --contract "${EAS_CONTRACT}" \
  --from-block 1000000 \
  --output-dir ./sas-migration \
  --resume \
  --max-retries 10
```

The command will resume from the last persisted attestation index and append to
the existing audit log.

## Step 4 - Review the reconciliation report

After a complete run, inspect `reconciliation.json`. It contains:

- `attestations_discovered` - total attestations found in the block range.
- `attestations_migrated` - attestations successfully translated.
- `schemas_migrated` - unique schemas translated.
- `batches_emitted` -  number of transaction envelopes generated.
- `status` - `complete` or `partial`.

## Step 5 - Submit envelopes to Soroban

Each file in `envelopes/` is a JSON document with an `operations` array. Each
operation invokes `attest` on the SAS contract with the translated data. Submit
them using the Soroban CLI or the SDK batch runner:

```bash
for env in ./sas-migration/envelopes/*.json; do
  stellar contract invoke \
    --id SAS \
    --source ${STELLAR_SECRET} \
    --network testnet \
    --fee true \
    --send yes \
    --json "$env"
done
```

Note: the envelope format is designed to be consumed programmatically. Wrap the
.json files in a script that calls the Soroban CLI or the `SASclient` from the
soroban-sas-sdk for full automation.

## Schema type mapping

| EVM EAS type | Soroban SAS type |
|--------------|------------------|
| uint8        | u32              |
| uint16       | u32              |
| uint32       | u32              |
| uint64       | u64              |
| uint128      | u128             |
| uint256      | u256             |
| int8         | i32              |
| int32        | i32              |
| int64        | i64              |
| int256       | i256             |
| address      | address           |
| bytes32       | bytes32           |
| bytes         | bytes             |
| string        | string            |
| bool          | bool              |

## Troubleshooting

- `RPC error -32005` - the source RPC rate-limited you. Re-run with `--resume` and
  increase `--retry-delay-ms`.
- `unsupported schema type` - the source schema uses a type that has no Soroban
  equivalent. Extend `packages/soroban-sas-cli/src/migrate/schema.rs` with a new mapping.
- `attestation result too short` - the source contract did not return a valid
  EAS attestation struct. Verify the contract address and network.
