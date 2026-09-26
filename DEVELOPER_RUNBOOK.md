# Developer Runbook

## Live-node integration tests (issue #247)

Every other test in this workspace runs against `soroban_sdk::Env`'s
in-process mock host (see `contracts/*/src/test*.rs`,
`packages/soroban-sas-common/src/test.rs`, etc.). That host never
serializes a transaction, never computes a real footprint, never charges a
fee, and never crosses the actual host/guest WASM boundary — it is fast and
deterministic, but it cannot catch a bug that only shows up in real RPC
encoding, fee estimation, or footprint/TTL handling.

`tests/integration/e2e_node_test.rs` closes that gap: it deploys fresh
instances of `schema-registry`, `sas`, `soroban-sas-indexer`, and a
purpose-built `permissive-resolver` contract (see
`contracts/permissive-resolver` — every schema needs *some* deployed
resolver, since `SAS::attest`/`revoke` always invoke it) to a real Soroban
RPC node, then drives them through `soroban-sas-sdk`'s `RpcClient`/
`SASClient` exactly as a real client would: build, simulate, sign, submit,
poll.

These tests are `#[ignore]`d by default, so a plain `cargo test` (or
`cargo test --workspace`) never runs them and stays fast. They require a
live node and a funded account, so they are opt-in and explicit.

### Prerequisites

- The `stellar` CLI (`cargo install --locked stellar-cli`) — used to deploy
  and initialize contracts, matching `scripts/deploy.sh`'s own conventions.
- The `wasm32-unknown-unknown` Rust target (`rustup target add
  wasm32-unknown-unknown`).
- Docker (or Podman), for running `stellar/quickstart` locally.

### 1. Start a local Soroban RPC node

```bash
docker compose up -d stellar-quickstart
```

This runs `stellar/quickstart:testing --standalone --enable-soroban-rpc`
(see `docker-compose.yml`), exposing Soroban RPC at
`http://localhost:8000/soroban/rpc` with network passphrase
`Standalone Network ; February 2017`. Wait for it to report healthy:

```bash
docker compose ps
# or poll directly:
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
  http://localhost:8000/soroban/rpc
```

### 2. Fund an account to deploy and pay with

Generate a keypair and fund it via the node's Friendbot:

```bash
stellar keys generate integration-test --network standalone \
  --rpc-url http://localhost:8000/soroban/rpc \
  --network-passphrase "Standalone Network ; February 2017" \
  --fund
stellar keys show integration-test   # prints the S... secret seed
```

(`tests/integration/e2e_node_test.rs` also best-effort Friendbot-funds the
account itself before deploying, so a pre-funded account is a convenience,
not a strict requirement.)

### 3. Run the integration tests

```bash
export SOROBAN_RPC_URL=http://localhost:8000/soroban/rpc
export NETWORK_PASSPHRASE="Standalone Network ; February 2017"
export STELLAR_SECRET_KEY="$(stellar keys show integration-test)"

cargo test --test integration -- --ignored
```

Each test independently builds the release WASM (skipped if already
built), deploys a fresh `schema-registry`/`sas`/`soroban-sas-indexer`/
`permissive-resolver` stack via the `stellar` CLI, wires them together
(`set_indexer`, etc.), and then exercises:

- `schema_registration_attest_revoke_and_indexer_lookup` — schema
  registration, attestation issuance, `get_attestation` readback, indexer
  reverse lookup by recipient, and revocation.
- `sac_fee_deduction_on_attest_with_value` — deploys the native XLM Stellar
  Asset Contract wrapper, configures a fee, calls `attest_with_value`, and
  asserts the SAS contract's SAC balance increased by exactly the
  configured amount.

Run a single test the same way any other Rust test is filtered:

```bash
cargo test --test integration schema_registration -- --ignored
```

### CI

`.github/workflows/integration.yml` runs the same flow on every push/PR
using `stellar/quickstart:testing` as a service container: it waits for RPC
readiness, generates and funds a fresh CI-only account, and runs
`cargo test --test integration -- --ignored --test-threads=1`
(serialized, since both tests deploy their own contract stack against the
same node and a single-threaded run keeps their `stellar` CLI invocations
from interleaving).

### Known limitations

This harness has been written against the actual `soroban-sas-sdk` API and
the `stellar` CLI's documented `contract deploy`/`contract invoke`/`keys`
subcommands, mirroring `scripts/deploy.sh`'s existing deploy/init sequence
as closely as possible — but it has not been run against a live
`stellar/quickstart` node in the environment this was authored in (no
Docker daemon available there). Before relying on it, run it once locally
per the steps above and adjust CLI flags if a `stellar-cli` version
mismatch surfaces a different argument shape.
