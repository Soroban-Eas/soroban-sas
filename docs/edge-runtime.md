# Edge runtimes: running the Rust SDK on `wasm32-unknown-unknown`

The SDK can be compiled to WebAssembly and run inside serverless edge
runtimes — Cloudflare Workers, Fastly Compute, Deno Deploy, or a browser.
This page explains what changes on that target, how to build a Worker, and
what the platform does not support.

Related: [#553](https://github.com/Soroban-Eas/soroban-sas/issues/553),
[`examples/cloudflare-worker`](../examples/cloudflare-worker).

## The `wasm` feature

Enable the `wasm` feature to build the SDK for `wasm32-unknown-unknown`:

```toml
[dependencies]
soroban-sas-sdk = { path = "../../packages/soroban-sas-sdk", features = ["wasm"] }
```

The feature swaps the synchronous, native HTTP client (`ureq`) for a
`web-sys` `fetch` implementation. Every runtime listed above exposes the
WHATWG `fetch` API on the global object, and `wasm-bindgen-futures` turns the
returned promise into a Rust future, so an RPC call can be awaited directly
inside a Worker without blocking the event loop.

| Target                | Transport                                   | RPC methods                       |
| --------------------- | ------------------------------------------- | --------------------------------- |
| native (`x86_64`, …)  | `ureq` over the operating system's TLS     | synchronous and `*_async`          |
| `wasm32-unknown-unknown` | `web-sys` `fetch` (see `src/wasm_http.rs`) | `*_async` only                    |

### Synchronous methods are unavailable on `wasm32`

A Worker may not block its event loop, so the blocking RPC methods
(`simulate_transaction`, `get_ledger_entries`, `send_transaction`, …) return
a clear error on `wasm32-unknown-unknown`:

```text
SdkError::TransportError("synchronous RPC is not available on wasm32; use the *_async variant")
```

Use the asynchronous variants instead. They are `async fn`s on every target,
so the calling code looks the same:

```rust
use soroban_sas_sdk::rpc::RpcClient;

let rpc = RpcClient::new("https://soroban-testnet.stellar.org");
let result = rpc.simulate_transaction_async(&tx_xdr).await?;
```

### No host environment on `wasm32`

`soroban_sdk::Env` — the Soroban *host* environment — only exists on native
targets. Two consequences follow:

1. The typed helpers that round-trip values through the host `Val` bridge,
   `soroban_sas_sdk::encode_arg` and `soroban_sas_sdk::decode_result`, are
   compiled only for native targets. On `wasm32` the SDK exports
   `soroban_sas_sdk::decode_scval`, which decodes the same base64 XDR
   payload into a plain `ScVal`.
2. `soroban_sas_sdk::client::SASClient`, the host-backed client, is not
   available on `wasm32` either.

### Reading attestations without a host

The `soroban_sas_sdk::attestation` module decodes attestations straight from
the XDR wire format, so it works on every target:

```rust
use soroban_sas_sdk::attestation;

let uid = attestation::uid_from_hex("5f2e…")?;          // hex -> 32 bytes
let record = attestation::fetch_attestation(&rpc, &contract_id, &uid).await?;

if let Some(record) = record {
    println!("{} issued by {}", record.uid, record.attester);
    println!("valid at now: {}", record.is_valid_at(now));
}
```

`fetch_attestation` simulates the contract's read-only `get_attestation_view`
call, so it does not renew the entry's TTL and does not write to storage.

The returned [`AttestationRecord`] is JSON-serializable and renders the
on-chain data in the shapes edge runtimes usually want:

| Field                             | Rendering                |
| --------------------------------- | ------------------------ |
| `uid`, `schema_uid`, `ref_uid`    | lowercase hex           |
| `recipient`, `attester`           | strkey (`G…` / `C…`)    |
| `data`                            | base64                  |
| `time`, `expiration_time`, `revocation_time`, `valid_from` | unix seconds |

`AttestationRecord` also carries the two helpers the contract's own logic
uses: `is_revoked()`, `is_expired_at(now)` and `is_valid_at(now)`.

For the attestation model itself, see
[Attestation Lifecycle](attestations.md); for the SDK's native API, see the
[Getting Started guide](getting-started.md).

## Building a Cloudflare Worker

The repository ships a ready-to-deploy template in
[`examples/cloudflare-worker`](../examples/cloudflare-worker). It queries a
Soroban RPC node and answers `GET /attestation/{uid}` with the decoded
attestation.

```bash
cd examples/cloudflare-worker

# The Worker is built for the edge target.
rustup target add wasm32-unknown-unknown

# Compile and generate the JavaScript shim.
cargo install -q worker-build --version ^0.1
worker-build --release

# Preview locally, then deploy.
npx wrangler dev
npx wrangler deploy
```

The Worker reads two variables from `wrangler.toml` (or as Worker secrets):

```toml
[vars]
RPC_URL = "https://soroban-testnet.stellar.org"
SAS_CONTRACT_ID = "C…"
```

The example crate is intentionally **not** part of the repository workspace:
it carries its own `Cargo.lock`, so the Worker's dependencies never affect
the versions the contracts and the SDK are built and tested with.

## Other edge runtimes

The same SDK build works anywhere that provides `fetch` and
`wasm32-unknown-unknown`:

- **Deno** — run the module with `deno run --allow-net …`; `fetch` is part of
  the Deno runtime, and `js_sys::global()` resolves it.
- **Fastly Compute** — build with `cargo build --target wasm32-unknown-unknown
  --release` and link the module with `wasmtime`/`fastly` tooling; the
  runtime exposes `fetch` through the JS host API.
- **Browsers** — the same transport works, subject to the browser's CORS
  policy towards the RPC endpoint.

## CI

The `wasm-sdk` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
keeps the edge build working:

```bash
cargo check  -p soroban-sas-sdk --target wasm32-unknown-unknown --features wasm
cargo clippy -p soroban-sas-sdk --target wasm32-unknown-unknown --features wasm -- -D warnings
cargo check  --manifest-path examples/cloudflare-worker/Cargo.toml --target wasm32-unknown-unknown
```

If a change breaks the WebAssembly build, CI fails before the change reaches
`main`.

## Troubleshooting

**`this runtime does not provide a global fetch function`** — the runtime
does not expose `fetch` on the global object. Workers, Deno and browsers all
do; a bare `wasm32-unknown-unknown` binary does not.

**`synchronous RPC is not available on wasm32`** — call the `*_async` variant
of the RPC method.

**`failed to convert Val to host Val` / missing `encode_arg`** — the typed
host-bridge helpers are native-only. Use `decode_scval` and the
`attestation` module instead.

**A stale attestation** — `fetch_attestation` reads the current state of the
entry, but a revoked attestation is only observable after the revocation
transaction is included in a ledger the RPC node has closed.
