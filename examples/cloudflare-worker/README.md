# Cloudflare Worker: SAS attestations on the edge

A minimal [Cloudflare Worker](https://developers.cloudflare.com/workers/) that
reads a SAS attestation from a Soroban RPC node and returns it as JSON.

It exists to demonstrate that the Rust SDK works on
`wasm32-unknown-unknown` ([#553](../../issues/553)):

- the RPC transport is the `web-sys` `fetch` binding instead of the native
  `ureq` client, so no blocking sockets are needed inside the sandbox;
- attestations are decoded straight from the XDR wire format, because the
  Soroban *host* environment (`soroban_sdk::Env`) does not exist in a Worker.

## Routes

| Route                          | Description                                                  |
| ------------------------------ | ------------------------------------------------------------ |
| `GET /health`                  | Liveness probe, returns `ok`.                                 |
| `GET /attestation/{uid}`       | The attestation with the given hex UID, as JSON.              |
| `GET /attestation/{uid}` (404) | The UID was never issued (or has been garbage-collected).    |

Example response:

```json
{
  "uid": "5f2e...",
  "schema_uid": "9a13...",
  "time": 1700000000,
  "expiration_time": 0,
  "revocation_time": 0,
  "ref_uid": "0000...",
  "recipient": "GA...",
  "attester": "GB...",
  "revocable": true,
  "data": "eyJhbGciOiJIUzI1NiJ9...",
  "valid_from": 0
}
```

UIDs are lowercase hex; addresses are strkey; the attestation payload is
base64.

## Configuration

Set both variables in `wrangler.toml` (or as Worker secrets):

| Variable          | Meaning                                                  |
| ----------------- | -------------------------------------------------------- |
| `RPC_URL`         | Soroban RPC endpoint, e.g. `https://soroban-testnet.stellar.org`. |
| `SAS_CONTRACT_ID` | Strkey id (`C...`) of the deployed SAS contract.          |

## Prerequisites

- Rust with the `wasm32-unknown-unknown` target:
  `rustup target add wasm32-unknown-unknown`
- Node.js 18+ and [Wrangler](https://developers.cloudflare.com/workers/wrangler/):
  `npm install -g wrangler`

## Build and deploy

```bash
# Compile the Worker and generate the JavaScript shim.
cargo install -q worker-build --version ^0.1
worker-build --release

# Preview locally.
npx wrangler dev

# Deploy.
npx wrangler deploy
```

Wrangler runs the `[build]` command from `wrangler.toml` automatically, so
`npx wrangler deploy` alone is enough once the toolchain is installed.

## How it works

```rust
let rpc = RpcClient::new(rpc_url);
let record = attestation::fetch_attestation(&rpc, &contract_id, &uid).await?;
```

- `RpcClient::new` is target-agnostic; the transport differs. On
  `wasm32-unknown-unknown` with the `wasm` feature the SDK posts JSON-RPC
  requests through the runtime's global `fetch`.
- `attestation::fetch_attestation` simulates the contract's read-only
  `get_attestation_view` call and decodes the returned `ScVal` without a host
  environment, so it returns a plain, JSON-serializable
  `AttestationRecord`.
- The synchronous RPC methods (`simulate_transaction`,
  `get_ledger_entries`, ...) are unavailable on `wasm32`: they would block the
  Worker's event loop. Use the `*_async` variants instead.

## Local checks

```bash
# Type-check the Worker for the edge target.
cargo check --target wasm32-unknown-unknown
cargo clippy --target wasm32-unknown-unknown -- -D warnings
```

The repository's CI runs the equivalent check for the SDK itself
(`.github/workflows/ci.yml`, job `wasm-sdk`).
