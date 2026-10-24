# Automated issuer service — channel-account parallelism (#497)

This is a **real-network transaction submitter**, using the repository's `soroban-sas-sdk` to build content-addressed attestations, sign transactions, recover source sequences, and wait for ledger settlement. It is not a simulated TPS benchmark.

## Channel architecture and authorizations

A Stellar channel account is an independently funded classic account with its **own transaction sequence number**. This service assigns one worker/ordered queue per channel; workers run concurrently across distinct channel accounts. A shared SDK `SequenceManager` reserves sequences and resyncs failed reservations; on-chain sequence monotonicity is protected even if a channel is accidentally reused.

**Important protocol constraint:** `SAS::attest` requires `attestation.attester.require_auth()`, so the channel signer must **also be the attester** of its transactions. The Registry requires the attester to be the schema owner or an explicitly approved delegate. Configure *each* channel account as a Registry delegate (using `add_delegate` authorized by the schema creator) before the run. Simply signing as a fee-payer on behalf of the schema owner cannot bypass authorization.

The alternative `attest_by_delegation` requires strictly increasing nonces **per original issuer**; it is not safe to submit multiple delegated attestations from the *same* issuer with concurrent, out-of-order settlement. This service deliberately uses independently authorized channel attesters for true concurrency. Consumers needing a single visible issuer identity must use a serially ordered delegated path rather than claim equivalent parallel throughput.

Each channel's public address is computed from its 32-byte Ed25519 secret seed. Keys are loaded from private environment configuration, are never printed, and are not embedded in the image.

## Run the local demonstration

1. From the repository root, run `docker compose -f examples/automated_issuer_service/docker-compose.yml up -d stellar` to start the pinned standalone node. Build/deploy the Registry and SAS contracts against this same network using the existing `make deploy-local` workflow and the [deployment instructions](../../docs/DEPLOYMENT.md).
2. Register a schema and capture its **32-byte UID**, then authorize all channel addresses as delegates using the Registry `add_delegate` entrypoint. Fund channel accounts in the local standalone network (e.g. through the quickstart Friendbot; do not fund production keys from a local-only service). Confirm each channel's balance and Registry authorization on-chain. Use a recipient **different from all channel accounts**.
3. Copy `.env.example` to `.env` in this directory and set `SAS_CONTRACT_ID`, `SCHEMA_UID`, `RECIPIENT` and comma-separated `CHANNEL_SEEDS_HEX` (each exactly 64 hex characters). Match `NETWORK_PASSPHRASE` to the standalone node and never commit the secrets.
4. Run `docker compose -f examples/automated_issuer_service/docker-compose.yml --profile issuer up --build --abort-on-container-exit --exit-code-from issuer`.

Alternatively, with an existing reachable Soroban RPC:

```sh
export RPC_URL=https://soroban-testnet.stellar.org
export NETWORK_PASSPHRASE='Test SDF Network ; September 2015'
# Set SAS_CONTRACT_ID, SCHEMA_UID, RECIPIENT, CHANNEL_SEEDS_HEX
cargo run --release --example automated_issuer_service
```

The project leaves schema creation, schema delegate authorization and contract deployment explicit rather than silently deploying or granting rights with unreviewed credentials.

## Configuration

| Variable | Meaning |
| --- | --- |
| `RPC_URL` | Stellar Soroban RPC (standalone default if omitted) |
| `NETWORK_PASSPHRASE` | Exact target-network passphrase |
| `SAS_CONTRACT_ID` | Already deployed SAS contract strkey |
| `SCHEMA_UID` | Already registered schema UID, 32 bytes as hex |
| `RECIPIENT` | G... or C... address distinct from every channel |
| `CHANNEL_SEEDS_HEX` | Comma-separated independently funded 32-byte raw hex secret seeds |
| `MIN_CHANNEL_BALANCE_STROOPS` | Preflight account-balance threshold (default 1,000,000; not a per-tx fee estimate) |
| `JOBS` | Unique attestations per comparison phase (default 24) |
| `MODE` | `single`, `channels`, or `compare` (default) |

**Operational recovery:** a rejected bad-sequence submission is resynced and retried once by the SDK. Other uncertain errors (including timeout) are **not blindly resubmitted**, because the attestation may already have been finalized; inspect the emitted UID / transaction hash against SAS before retrying. On the next run, sequence preflight re-reads ledger state. Account funding and balances are checked before any submission.

## Performance metrics

The `compare` mode performs the same number of *unique* new attestations first using **one** channel, then across **all** configured channels. Output includes: successful and failed submissions; wall-time seconds; finalized transactions per second; and multi/single relative throughput. Only `SUCCESS` settlement counts as a successful attestation. A failed/unknown job causes a non-zero process exit.

Example log *shape* (illustrative only; no throughput values are pre-claimed):

```text
METRIC mode=single succeeded=<n> failed=<n> elapsed_seconds=<seconds> throughput_tps=<tps>
METRIC mode=channels succeeded=<n> failed=<n> elapsed_seconds=<seconds> throughput_tps=<tps>
METRIC relative_throughput=<ratio>x
```

Actual throughput depends on network capacity, fees, RPC availability, schema resolver, payload size and channel count. The service has no way to bypass Soroban's global throughput limits.

## Tests and safeguards

```sh
cargo test --example automated_issuer_service
cargo test --workspace
```

The local tests cover partition assignment, key input validation and correct throughput aggregation. End-to-end performance requires a funded live local/test network and a deployed/authorized registry+SAS suite, and must not be reported as measured without running it.
