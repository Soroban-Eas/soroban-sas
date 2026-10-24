//! Cloudflare Worker template: reads SAS attestations from a Soroban RPC
//! node, from inside the edge runtime.
//!
//! The Worker is intentionally small — it exists to show that the Rust SDK
//! works on `wasm32-unknown-unknown` (#553):
//!
//! * the RPC transport is the `web-sys` `fetch` binding, not `ureq`, so no
//!   blocking sockets are needed inside the sandbox;
//! * attestations are decoded straight from XDR, without the Soroban host
//!   environment, which does not exist in a Worker.
//!
//! Routes:
//!
//! * `GET /health` — liveness probe.
//! * `GET /attestation/{uid}` — the attestation with the given hex UID, or
//!   `404` when the UID was never issued.
//!
//! Configuration (Worker variables, see `wrangler.toml`):
//!
//! * `RPC_URL` — the Soroban RPC endpoint, e.g.
//!   `https://soroban-testnet.stellar.org`.
//! * `SAS_CONTRACT_ID` — the SAS contract id (strkey `C...`).

use soroban_sas_sdk::attestation;
use soroban_sas_sdk::rpc::RpcClient;
use worker::{console_log, event, Context, Env, Error, Request, Response, Result};

/// The path prefix of the attestation route.
const ATTESTATION_PREFIX: &str = "/attestation/";

/// Body returned when an attestation was not found.
#[derive(serde::Serialize)]
struct NotFound {
    /// The UID that was looked up.
    uid: String,
    /// Always `false`; the attestation does not exist.
    found: bool,
}

/// Handles every request the Worker receives.
#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let path = req.url()?.path().to_string();
    console_log!("soroban-sas worker: {path}");

    if path == "/health" {
        return Response::ok("ok");
    }

    let Some(uid_hex) = path.strip_prefix(ATTESTATION_PREFIX) else {
        return Response::error("not found", 404);
    };

    let uid = attestation::uid_from_hex(uid_hex)
        .map_err(|err| Error::RustError(format!("invalid attestation uid: {err}")))?;

    let rpc_url = env.var("RPC_URL")?.to_string();
    let contract_id = env.var("SAS_CONTRACT_ID")?.to_string();
    let rpc = RpcClient::new(rpc_url);

    match attestation::fetch_attestation(&rpc, &contract_id, &uid).await {
        Ok(Some(record)) => Ok(Response::from_json(&record)?),
        Ok(None) => Ok(Response::from_json(&NotFound {
            uid: uid_hex.to_string(),
            found: false,
        })?
        .with_status(404)),
        Err(err) => {
            console_log!("soroban-sas worker: rpc error: {err}");
            Ok(Response::from_json(&serde_json::json!({
                "error": err.to_string(),
            }))?
            .with_status(502))
        }
    }
}
