//! Soroban RPC client.
//!
//! Builds well-typed JSON-RPC request bodies for the Soroban RPC methods the
//! SDK needs to submit and track transactions, sends them over HTTP via
//! `ureq`, and parses the matching JSON-RPC responses.

use std::time::Duration;

use crate::errors::SdkError;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use ureq::{Agent, AgentBuilder};

/// Per-request timeout applied by [`RpcClient`] unless overridden via
/// [`RpcClient::with_timeout`].
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// A Soroban RPC endpoint the SDK will submit requests to,
/// e.g. `https://soroban-testnet.stellar.org`.
///
/// Every request is bounded by a per-request timeout
/// ([`DEFAULT_RPC_TIMEOUT`] unless [`RpcClient::with_timeout`] overrides
/// it), so a slow or unreachable node cannot block the calling thread
/// indefinitely.
pub struct RpcClient {
    pub network_url: String,
    /// The effective per-request timeout. Kept alongside `agent` because
    /// `ureq`'s agent doesn't expose its configured timeout; readable via
    /// [`RpcClient::timeout`].
    timeout: Duration,
    /// HTTP agent preconfigured with `timeout`; every request goes through
    /// it so none can bypass the bound.
    agent: Agent,
}

impl RpcClient {
    pub fn new(network_url: impl Into<String>) -> Self {
        Self {
            network_url: network_url.into(),
            timeout: DEFAULT_RPC_TIMEOUT,
            agent: rpc_agent(DEFAULT_RPC_TIMEOUT),
        }
    }

    /// Overrides this client's per-request timeout, returning the configured
    /// client. Lets callers tune the bound without touching
    /// [`RpcClient::new`]'s signature, whose default stays
    /// [`DEFAULT_RPC_TIMEOUT`].
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use soroban_sas_sdk::rpc::RpcClient;
    ///
    /// let client = RpcClient::new("https://soroban-testnet.stellar.org")
    ///     .with_timeout(Duration::from_secs(30));
    /// ```
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.agent = rpc_agent(timeout);
        self
    }

    /// The per-request timeout applied to every request made by this client.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Builds the JSON-RPC request body for Soroban's `sendTransaction`.
    ///
    /// `tx_envelope_xdr` is the base64-encoded `TransactionEnvelope` to submit.
    pub fn build_send_transaction_request(
        &self,
        tx_envelope_xdr: &str,
    ) -> JsonRpcRequest<SendTransactionParams> {
        JsonRpcRequest::new(
            "sendTransaction",
            SendTransactionParams {
                transaction: tx_envelope_xdr.to_string(),
            },
        )
    }

    /// Builds the JSON-RPC request body for Soroban's `getTransaction`,
    /// used to poll for the result of a previously submitted transaction.
    pub fn build_get_transaction_request(
        &self,
        tx_hash: &str,
    ) -> JsonRpcRequest<GetTransactionParams> {
        JsonRpcRequest::new(
            "getTransaction",
            GetTransactionParams {
                hash: tx_hash.to_string(),
            },
        )
    }

    /// Parses a raw `sendTransaction` JSON-RPC response body.
    pub fn parse_send_transaction_response(
        &self,
        body: &str,
    ) -> Result<SendTransactionResult, SdkError> {
        parse_response(body)
    }

    /// Parses a raw `getTransaction` JSON-RPC response body.
    pub fn parse_get_transaction_response(
        &self,
        body: &str,
    ) -> Result<GetTransactionResult, SdkError> {
        parse_response(body)
    }

    /// Builds the JSON-RPC request body for Soroban's `simulateTransaction`,
    /// used for read-only contract calls (dry-run, no signature required).
    pub fn build_simulate_transaction_request(
        &self,
        tx_envelope_xdr: &str,
    ) -> JsonRpcRequest<SimulateTransactionParams> {
        JsonRpcRequest::new(
            "simulateTransaction",
            SimulateTransactionParams {
                transaction: tx_envelope_xdr.to_string(),
            },
        )
    }

    /// Parses a raw `simulateTransaction` JSON-RPC response body.
    pub fn parse_simulate_transaction_response(
        &self,
        body: &str,
    ) -> Result<SimulateTransactionResult, SdkError> {
        parse_response(body)
    }

    /// Simulates invoking a contract via `tx_envelope_xdr` (built by
    /// `soroban_sas_sdk::simulate::build_simulate_transaction_xdr` or
    /// `simulate::unsigned_envelope_xdr`) and parses the response. Returns
    /// `Ok` even when the simulation itself failed
    /// (check `SimulateTransactionResult::error`) — only transport/parsing
    /// failures are `Err`.
    pub fn simulate_transaction(
        &self,
        tx_envelope_xdr: &str,
    ) -> Result<SimulateTransactionResult, SdkError> {
        let request = self.build_simulate_transaction_request(tx_envelope_xdr);
        let body = self.post(&request)?;
        self.parse_simulate_transaction_response(&body)
    }

    /// Submits `tx_envelope_xdr` to this RPC endpoint's `sendTransaction`
    /// method and parses the response.
    pub fn send_transaction(
        &self,
        tx_envelope_xdr: &str,
    ) -> Result<SendTransactionResult, SdkError> {
        let request = self.build_send_transaction_request(tx_envelope_xdr);
        let body = self.post(&request)?;
        self.parse_send_transaction_response(&body)
    }

    /// Fetches the current status of `tx_hash` via this RPC endpoint's
    /// `getTransaction` method and parses the response.
    pub fn get_transaction(&self, tx_hash: &str) -> Result<GetTransactionResult, SdkError> {
        let request = self.build_get_transaction_request(tx_hash);
        let body = self.post(&request)?;
        self.parse_get_transaction_response(&body)
    }

    /// Builds the JSON-RPC request body for Soroban's `getLedgerEntries`.
    /// `keys` are base64-encoded `LedgerKey` XDR.
    pub fn build_get_ledger_entries_request(
        &self,
        keys: Vec<String>,
    ) -> JsonRpcRequest<GetLedgerEntriesParams> {
        JsonRpcRequest::new("getLedgerEntries", GetLedgerEntriesParams { keys })
    }

    /// Parses a raw `getLedgerEntries` JSON-RPC response body.
    pub fn parse_get_ledger_entries_response(
        &self,
        body: &str,
    ) -> Result<GetLedgerEntriesResult, SdkError> {
        parse_response(body)
    }

    /// Fetches the ledger entries for `keys` (base64-encoded `LedgerKey`
    /// XDR) and parses the response.
    pub fn get_ledger_entries(
        &self,
        keys: Vec<String>,
    ) -> Result<GetLedgerEntriesResult, SdkError> {
        let request = self.build_get_ledger_entries_request(keys);
        let body = self.post(&request)?;
        self.parse_get_ledger_entries_response(&body)
    }

    /// POSTs a JSON-RPC request body to this client's `network_url` and
    /// returns the raw response body.
    fn post<P: Serialize>(&self, request: &JsonRpcRequest<P>) -> Result<String, SdkError> {
        self.agent
            .post(&self.network_url)
            .send_json(request)
            .map_err(|err| SdkError::RpcError(err.to_string()))?
            .into_string()
            .map_err(|err| SdkError::RpcError(err.to_string()))
    }
}

/// Builds the `ureq` agent used for every [`RpcClient`] request, with
/// `timeout` bounding each request end-to-end (connect + send + read).
fn rpc_agent(timeout: Duration) -> Agent {
    AgentBuilder::new().timeout(timeout).build()
}

/// Decodes a JSON-RPC response envelope and unwraps either its `result`
/// or turns a JSON-RPC-level `error` (or malformed body) into an [`SdkError`].
fn parse_response<T: DeserializeOwned>(body: &str) -> Result<T, SdkError> {
    let response: JsonRpcResponse<T> =
        serde_json::from_str(body).map_err(|err| SdkError::RpcError(err.to_string()))?;
    match response {
        JsonRpcResponse::Result { result, .. } => Ok(result),
        JsonRpcResponse::Error { error, .. } => Err(SdkError::RpcError(format!(
            "{}: {}",
            error.code, error.message
        ))),
    }
}

#[derive(Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum JsonRpcResponse<T> {
    Result {
        #[allow(dead_code)]
        jsonrpc: String,
        #[allow(dead_code)]
        id: u32,
        result: T,
    },
    Error {
        #[allow(dead_code)]
        jsonrpc: String,
        #[allow(dead_code)]
        id: u32,
        error: JsonRpcError,
    },
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

/// The `result` payload of a Soroban `sendTransaction` response.
/// See <https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/sendTransaction>.
#[derive(Debug, Deserialize, PartialEq)]
pub struct SendTransactionResult {
    pub status: String,
    pub hash: String,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(rename = "errorResultXdr")]
    pub error_result_xdr: Option<String>,
}

/// The `result` payload of a Soroban `getTransaction` response.
/// See <https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getTransaction>.
#[derive(Debug, Deserialize, PartialEq)]
pub struct GetTransactionResult {
    pub status: String,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(rename = "envelopeXdr")]
    pub envelope_xdr: Option<String>,
    #[serde(rename = "resultXdr")]
    pub result_xdr: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct JsonRpcRequest<P: Serialize> {
    pub jsonrpc: &'static str,
    pub id: u32,
    pub method: &'static str,
    pub params: P,
}

impl<P: Serialize> JsonRpcRequest<P> {
    fn new(method: &'static str, params: P) -> Self {
        Self {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SendTransactionParams {
    pub transaction: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct GetTransactionParams {
    pub hash: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct SimulateTransactionParams {
    pub transaction: String,
}

/// The `result` payload of a Soroban `simulateTransaction` response.
/// See <https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/simulateTransaction>.
///
/// A simulation failure (e.g. the invoked contract traps) is reported via
/// `error`, not a JSON-RPC-level error — `results` is empty in that case.
/// Verified against live `soroban-testnet.stellar.org`: a well-formed call
/// to a nonexistent contract instance returns
/// `{"error": "HostError: Error(Storage, MissingValue)...", "latestLedger": ...}`
/// with no `results` field at all, which `#[serde(default)]` handles.
#[derive(Debug, Deserialize, PartialEq)]
pub struct SimulateTransactionResult {
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    pub error: Option<String>,
    #[serde(default)]
    pub results: Vec<SimulateHostFunctionResult>,
    /// Base64 `SorobanTransactionData` XDR, present only on success — the
    /// resource footprint/limits a real submission must carry in its
    /// `TransactionExt::V1` to be accepted by the network.
    #[serde(rename = "transactionData")]
    pub transaction_data: Option<String>,
    /// Stroops, present only on success — added to the classic per-operation
    /// fee to get a real submission's total `fee`.
    #[serde(rename = "minResourceFee")]
    pub min_resource_fee: Option<String>,
}

/// One entry of a successful simulation's `results` array — the return
/// value of the invoked function, base64-encoded `ScVal` XDR.
#[derive(Debug, Deserialize, PartialEq)]
pub struct SimulateHostFunctionResult {
    pub xdr: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct GetLedgerEntriesParams {
    pub keys: Vec<String>,
}

/// The `result` payload of a Soroban `getLedgerEntries` response.
/// See <https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getLedgerEntries>.
#[derive(Debug, Deserialize, PartialEq)]
pub struct GetLedgerEntriesResult {
    #[serde(default)]
    pub entries: Vec<LedgerEntryResult>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct LedgerEntryResult {
    pub key: String,
    /// Base64 `LedgerEntryData` XDR.
    pub xdr: String,
    #[serde(rename = "lastModifiedLedgerSeq")]
    pub last_modified_ledger_seq: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn builds_send_transaction_request() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_send_transaction_request("AAAAAgAAAAA=");

        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["method"], "sendTransaction");
        assert_eq!(value["params"]["transaction"], "AAAAAgAAAAA=");
    }

    #[test]
    fn builds_get_transaction_request() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_get_transaction_request("deadbeef");

        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["method"], "getTransaction");
        assert_eq!(value["params"]["hash"], "deadbeef");
    }

    #[test]
    fn parses_pending_send_transaction_response() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "status": "PENDING",
                "hash": "abcd1234",
                "latestLedger": 12345,
                "latestLedgerCloseTime": "1234567890"
            }
        }"#;

        let result = client.parse_send_transaction_response(body).unwrap();
        assert_eq!(result.status, "PENDING");
        assert_eq!(result.hash, "abcd1234");
        assert_eq!(result.latest_ledger, 12345);
        assert_eq!(result.error_result_xdr, None);
    }

    #[test]
    fn parses_successful_get_transaction_response() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "status": "SUCCESS",
                "latestLedger": 12345,
                "envelopeXdr": "AAAAAgAAAAA=",
                "resultXdr": "AAAAAQAAAAA="
            }
        }"#;

        let result = client.parse_get_transaction_response(body).unwrap();
        assert_eq!(result.status, "SUCCESS");
        assert_eq!(result.envelope_xdr.as_deref(), Some("AAAAAgAAAAA="));
    }

    #[test]
    fn maps_json_rpc_error_to_sdk_error() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32602, "message": "Invalid params" }
        }"#;

        let err = client.parse_send_transaction_response(body).unwrap_err();
        match err {
            SdkError::RpcError(msg) => assert!(msg.contains("Invalid params")),
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    #[test]
    fn builds_simulate_transaction_request() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_simulate_transaction_request("AAAAAgAAAAA=");

        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["method"], "simulateTransaction");
        assert_eq!(value["params"]["transaction"], "AAAAAgAAAAA=");
    }

    #[test]
    fn parses_successful_simulate_transaction_response() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": 3993006,
                "results": [
                    { "auth": [], "xdr": "AAAAAA==" }
                ]
            }
        }"#;

        let result = client.parse_simulate_transaction_response(body).unwrap();
        assert_eq!(result.latest_ledger, 3993006);
        assert_eq!(result.error, None);
        assert_eq!(result.results.len(), 1);
        assert_eq!(result.results[0].xdr, "AAAAAA==");
    }

    /// Captured verbatim (aside from truncating the diagnostic event log)
    /// from a real call to `soroban-testnet.stellar.org`, simulating an
    /// `InvokeHostFunction` against a syntactically valid but undeployed
    /// contract address — confirms this is really how a failed simulation
    /// is shaped on the wire, not just what the docs say.
    #[test]
    fn parses_a_failed_simulate_transaction_response_from_live_testnet() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "error": "HostError: Error(Storage, MissingValue)\n\nEvent log (newest first):\n   0: [Diagnostic Event] topics:[error, Error(Storage, MissingValue)], data:\"trying to get non-existing value for contract instance\"\n",
                "events": ["AAAAAA==", "AAAAAA=="],
                "latestLedger": 3993006
            }
        }"#;

        let result = client.parse_simulate_transaction_response(body).unwrap();
        assert_eq!(result.latest_ledger, 3993006);
        assert!(result.error.unwrap().contains("MissingValue"));
        assert!(result.results.is_empty());
    }

    #[test]
    fn builds_get_ledger_entries_request() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_get_ledger_entries_request(vec!["AAAAAA==".to_string()]);

        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["method"], "getLedgerEntries");
        assert_eq!(value["params"]["keys"][0], "AAAAAA==");
    }

    #[test]
    fn parses_get_ledger_entries_response() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "entries": [
                    { "key": "AAAAAA==", "xdr": "AAAAAA==", "lastModifiedLedgerSeq": 3993006 }
                ],
                "latestLedger": 3993006
            }
        }"#;

        let result = client.parse_get_ledger_entries_response(body).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].xdr, "AAAAAA==");
        assert_eq!(result.entries[0].last_modified_ledger_seq, 3993006);
    }

    #[test]
    fn maps_malformed_body_to_sdk_error() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let err = client
            .parse_get_transaction_response("not json")
            .unwrap_err();
        assert!(matches!(err, SdkError::RpcError(_)));
    }

    #[test]
    fn defaults_to_a_ten_second_timeout() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        assert_eq!(client.timeout(), DEFAULT_RPC_TIMEOUT);
    }

    #[test]
    fn with_timeout_overrides_the_default() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org")
            .with_timeout(Duration::from_secs(42));
        assert_eq!(client.timeout(), Duration::from_secs(42));
    }

    /// Issue #22 acceptance criterion: pointing the client at a port where
    /// nothing is listening must produce a transport-level
    /// `SdkError::RpcError` promptly instead of blocking the caller.
    #[test]
    fn unreachable_endpoint_fails_within_two_seconds_instead_of_hanging() {
        let client = RpcClient::new("http://127.0.0.1:1");

        let start = Instant::now();
        let err = client
            .get_ledger_entries(vec!["AAAAAA==".to_string()])
            .unwrap_err();
        let elapsed = start.elapsed();

        assert!(
            matches!(err, SdkError::RpcError(_)),
            "expected SdkError::RpcError, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "unreachable endpoint took {elapsed:?} to fail; the client hangs"
        );
    }

    /// A listener that accepts TCP connections but never writes anything:
    /// the only way the request below can finish is the configured timeout
    /// firing, proving the agent's bound really cuts off a hung node rather
    /// than merely relying on the OS refusing the connection.
    #[test]
    fn hung_node_is_cut_off_by_the_configured_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            // Hold every accepted socket open without ever responding.
            let mut held = Vec::new();
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => held.push(stream),
                    Err(_) => break,
                }
            }
        });

        let client = RpcClient::new(url.as_str()).with_timeout(Duration::from_millis(500));

        let start = Instant::now();
        let err = client.get_transaction("deadbeef").unwrap_err();
        let elapsed = start.elapsed();

        assert!(
            matches!(err, SdkError::RpcError(_)),
            "expected SdkError::RpcError, got {err:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(400),
            "returned after {elapsed:?}; the server never answers, so \
             nothing should succeed before the timeout fires"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "hung node took {elapsed:?} to fail; timeout not applied"
        );
    }

    /// Happy-path guard: with the timeout-wired agent in place, ordinary
    /// requests against the public testnet still round-trip. Ignored by
    /// default so the suite stays offline; run with
    /// `cargo test -p soroban-sas-sdk -- --ignored`.
    #[test]
    #[ignore = "requires network access to soroban-testnet.stellar.org"]
    fn live_testnet_request_succeeds_with_the_timeout_wired_agent() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let result = client.get_ledger_entries(vec![]);

        match result {
            Ok(response) => assert!(response.latest_ledger > 0),
            Err(SdkError::RpcError(message)) => {
                // The server may reject our request body outright; what
                // matters here is that the request round-tripped through
                // the timeout-wired agent instead of failing at transport.
                let lowered = message.to_lowercase();
                assert!(
                    !lowered.contains("timedout")
                        && !lowered.contains("timed out")
                        && !lowered.contains("connection refused")
                        && !lowered.contains("dns"),
                    "transport-level failure talking to live testnet: {message}"
                );
            }
            Err(err) => panic!("unexpected error kind from live testnet: {err:?}"),
        }
    }
}
