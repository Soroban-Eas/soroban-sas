//! Soroban RPC client.
//!
//! Builds well-typed JSON-RPC request bodies for the Soroban RPC methods the
//! SDK needs to submit and track transactions, sends them over HTTP via
//! `ureq`, and parses the matching JSON-RPC responses.

use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use crate::errors::SdkError;
use crate::limits::{rpc_response_limits, DEFAULT_MAX_RESPONSE_BYTES};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use soroban_sdk::xdr::{ReadXdr, TransactionEnvelope};
use ureq::{Agent, AgentBuilder};

// ─── Rate-limit retry policy ─────────────────────────────────────────────────

/// Default maximum number of retries on HTTP 429 responses.
pub const DEFAULT_RATE_LIMIT_MAX_RETRIES: u32 = 3;

/// Default base delay before the first retry (before jitter).
pub const DEFAULT_RATE_LIMIT_BASE_DELAY: Duration = Duration::from_millis(500);

/// Default upper bound on the computed backoff (before jitter).
pub const DEFAULT_RATE_LIMIT_MAX_DELAY: Duration = Duration::from_secs(30);

/// Methods that are safe to retry after a 429.
///
/// `sendTransaction` is **not** included because a duplicate submission may
/// incur fees or cause unexpected duplicate-entry errors; callers that want to
/// retry a send must do so explicitly after confirming the first attempt did
/// not reach the network.
pub const RETRYABLE_METHODS: &[&str] = &[
    "simulateTransaction",
    "getTransaction",
    "getLedgerEntries",
    "getLatestLedger",
    "getLedgers",
];

/// Opt-in policy for automatic retries on HTTP 429 Too Many Requests.
///
/// When attached to an [`RpcClient`] via
/// [`RpcClient::with_rate_limit_policy`], every request to a method listed in
/// [`RETRYABLE_METHODS`] that receives a 429 response is retried up to
/// `max_retries` times using exponential backoff with full jitter.
///
/// If the server returned a `Retry-After` header, that value overrides the
/// computed backoff for that attempt. Non-retryable methods (e.g.
/// `sendTransaction`) surface [`SdkError::RateLimited`] immediately without
/// any retry.
#[derive(Debug, Clone)]
pub struct RateLimitPolicy {
    /// Maximum number of retries after a 429 (0 = surface the error immediately).
    pub max_retries: u32,
    /// Base delay for the first retry, before jitter. Doubles each attempt.
    pub base_delay: Duration,
    /// Upper bound on the computed exponential delay, before jitter.
    pub max_delay: Duration,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_RATE_LIMIT_MAX_RETRIES,
            base_delay: DEFAULT_RATE_LIMIT_BASE_DELAY,
            max_delay: DEFAULT_RATE_LIMIT_MAX_DELAY,
        }
    }
}

impl RateLimitPolicy {
    /// Creates a policy with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of retries.
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Sets the base delay for exponential backoff.
    pub fn with_base_delay(mut self, delay: Duration) -> Self {
        self.base_delay = delay;
        self
    }

    /// Sets the upper bound on the computed backoff.
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Computes the backoff duration for attempt `n` (0-indexed) using
    /// full-jitter exponential backoff:
    ///
    /// ```text
    /// cap   = min(base_delay * 2^n, max_delay)
    /// sleep = random(0, cap)
    /// ```
    ///
    /// Uses a deterministic pseudo-random value derived from the attempt
    /// number so the function is pure (no OS randomness required), while
    /// still spreading retries across the allowed window.
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let factor = 1u64.saturating_shl(attempt);
        let cap_ms = (self.base_delay.as_millis() as u64)
            .saturating_mul(factor)
            .min(self.max_delay.as_millis() as u64);
        // Full jitter: use a simple LCG seeded on the attempt so the value
        // is deterministic in tests but spread across [0, cap].
        let jitter_ms = if cap_ms == 0 {
            0
        } else {
            // LCG constants from Numerical Recipes
            let seed = attempt as u64;
            let rand = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223) ^ (seed >> 16);
            rand % cap_ms
        };
        Duration::from_millis(jitter_ms)
    }

    /// Returns `true` when `method` is safe to retry after a 429.
    pub fn is_retryable(&self, method: &str) -> bool {
        RETRYABLE_METHODS.contains(&method)
    }
}

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
    /// Largest response body this client will buffer or decode, in bytes.
    /// A larger `Content-Length`, or more bytes on the wire, fails with
    /// [`SdkError::ResponseTooLarge`] before the body is fully read. Also
    /// bounds the `len` of every XDR decode of that body's contents.
    max_response_bytes: usize,
    /// HTTP agent preconfigured with `timeout`; every request goes through
    /// it so none can bypass the bound.
    agent: Agent,
    /// Monotonically-increasing JSON-RPC request ID.  Each request gets the
    /// next value so concurrent callers can correlate responses.
    next_id: AtomicU32,
    /// Optional rate-limit retry policy. When `Some`, 429 responses on
    /// retryable methods are automatically retried with exponential backoff
    /// and jitter up to `policy.max_retries` times. When `None` (default),
    /// a 429 surfaces immediately as [`SdkError::RateLimited`].
    rate_limit_policy: Option<RateLimitPolicy>,
}

impl RpcClient {
    pub fn new(network_url: impl Into<String>) -> Self {
        Self {
            network_url: network_url.into(),
            timeout: DEFAULT_RPC_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            agent: rpc_agent(DEFAULT_RPC_TIMEOUT),
            next_id: AtomicU32::new(1),
            rate_limit_policy: None,
        }
    }

    /// Attaches an opt-in rate-limit retry policy. When set, 429 responses
    /// on idempotent methods are automatically retried with exponential
    /// backoff and jitter. Non-idempotent methods (e.g. `sendTransaction`)
    /// always surface [`SdkError::RateLimited`] immediately regardless of
    /// this policy.
    ///
    /// ```no_run
    /// use soroban_sas_sdk::rpc::{RpcClient, RateLimitPolicy};
    ///
    /// let client = RpcClient::new("https://soroban-testnet.stellar.org")
    ///     .with_rate_limit_policy(RateLimitPolicy::new().with_max_retries(5));
    /// ```
    pub fn with_rate_limit_policy(mut self, policy: RateLimitPolicy) -> Self {
        self.rate_limit_policy = Some(policy);
        self
    }

    /// Returns the active rate-limit retry policy, if any.
    pub fn rate_limit_policy(&self) -> Option<&RateLimitPolicy> {
        self.rate_limit_policy.as_ref()
    }

    /// Overrides the largest response body this client will accept
    /// ([`DEFAULT_MAX_RESPONSE_BYTES`](crate::limits::DEFAULT_MAX_RESPONSE_BYTES)
    /// by default). Raise it for endpoints that legitimately return very
    /// large `getLedgerEntries` / `simulateTransaction` payloads.
    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// The largest response body, in bytes, this client will buffer or decode.
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
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
            self.next_id.fetch_add(1, Ordering::Relaxed),
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
            self.next_id.fetch_add(1, Ordering::Relaxed),
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
        expected_id: u32,
    ) -> Result<SendTransactionResult, SdkError> {
        parse_response(body, expected_id)
    }

    /// Parses a raw `getTransaction` JSON-RPC response body.
    pub fn parse_get_transaction_response(
        &self,
        body: &str,
        expected_id: u32,
    ) -> Result<GetTransactionResult, SdkError> {
        let result = parse_response(body, expected_id)?;
        validate_supported_transaction_envelope(&result, self.max_response_bytes)?;
        Ok(result)
    }

    /// Builds the JSON-RPC request body for Soroban's `simulateTransaction`,
    /// used for read-only contract calls (dry-run, no signature required).
    pub fn build_simulate_transaction_request(
        &self,
        tx_envelope_xdr: &str,
    ) -> JsonRpcRequest<SimulateTransactionParams> {
        JsonRpcRequest::new(
            self.next_id.fetch_add(1, Ordering::Relaxed),
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
        expected_id: u32,
    ) -> Result<SimulateTransactionResult, SdkError> {
        parse_response(body, expected_id)
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
        let id = request.id;
        let body = self.post(&request)?;
        self.parse_simulate_transaction_response(&body, id)
    }

    /// Submits `tx_envelope_xdr` to this RPC endpoint's `sendTransaction`
    /// method and parses the response.
    pub fn send_transaction(
        &self,
        tx_envelope_xdr: &str,
    ) -> Result<SendTransactionResult, SdkError> {
        let request = self.build_send_transaction_request(tx_envelope_xdr);
        let id = request.id;
        let body = self.post(&request)?;
        self.parse_send_transaction_response(&body, id)
    }

    /// Fetches the current status of `tx_hash` via this RPC endpoint's
    /// `getTransaction` method and parses the response.
    pub fn get_transaction(&self, tx_hash: &str) -> Result<GetTransactionResult, SdkError> {
        let request = self.build_get_transaction_request(tx_hash);
        let id = request.id;
        let body = self.post(&request)?;
        self.parse_get_transaction_response(&body, id)
    }

    /// Builds the JSON-RPC request body for Soroban's `getLedgerEntries`.
    /// `keys` are base64-encoded `LedgerKey` XDR.
    pub fn build_get_ledger_entries_request(
        &self,
        keys: Vec<String>,
    ) -> JsonRpcRequest<GetLedgerEntriesParams> {
        JsonRpcRequest::new(
            self.next_id.fetch_add(1, Ordering::Relaxed),
            "getLedgerEntries",
            GetLedgerEntriesParams { keys },
        )
    }

    /// Parses a raw `getLedgerEntries` JSON-RPC response body.
    pub fn parse_get_ledger_entries_response(
        &self,
        body: &str,
        expected_id: u32,
    ) -> Result<GetLedgerEntriesResult, SdkError> {
        parse_response(body, expected_id)
    }

    /// Fetches the ledger entries for `keys` (base64-encoded `LedgerKey`
    /// XDR) and parses the response.
    pub fn get_ledger_entries(
        &self,
        keys: Vec<String>,
    ) -> Result<GetLedgerEntriesResult, SdkError> {
        let request = self.build_get_ledger_entries_request(keys);
        let id = request.id;
        let body = self.post(&request)?;
        self.parse_get_ledger_entries_response(&body, id)
    }

    /// Fetches the RPC's view of the latest closed ledger via
    /// `getLatestLedger`.
    pub fn get_latest_ledger(&self) -> Result<GetLatestLedgerResult, SdkError> {
        let request = JsonRpcRequest::new(
            self.next_id.fetch_add(1, Ordering::Relaxed),
            "getLatestLedger",
            serde_json::Value::Null,
        );
        let id = request.id;
        let body = self.post(&request)?;
        parse_response(&body, id)
    }

    /// Returns the authoritative network wall-clock: the close time (unix
    /// seconds) of the RPC's latest ledger, plus that ledger's sequence.
    ///
    /// Uses `getLatestLedger` for the current sequence, then `getLedgers` for
    /// that ledger's close time. The per-request timeout on this client
    /// bounds both calls, so an unreachable node fails fast rather than
    /// hanging the caller (#172).
    pub fn get_latest_ledger_clock(&self) -> Result<LedgerClock, SdkError> {
        let latest = self.get_latest_ledger()?;
        let request = JsonRpcRequest::new(
            self.next_id.fetch_add(1, Ordering::Relaxed),
            "getLedgers",
            GetLedgersParams {
                start_ledger: latest.sequence,
                pagination: LedgersPagination { limit: 1 },
            },
        );
        let id = request.id;
        let body = self.post(&request)?;
        let result: GetLedgersResult = parse_response(&body, id)?;
        let close_time_str = result
            .ledgers
            .first()
            .map(|l| l.ledger_close_time.clone())
            .unwrap_or(result.latest_ledger_close_time);
        let close_time: u64 = close_time_str
            .parse()
            .map_err(|_| SdkError::RpcError(format!("invalid ledger close time: {close_time_str}")))?;
        Ok(LedgerClock {
            sequence: latest.sequence,
            close_time,
        })
    }

    /// POSTs a JSON-RPC request body to this client's `network_url` and
    /// returns the raw response body, refusing anything larger than
    /// [`RpcClient::max_response_bytes`] before it is fully buffered.
    ///
    /// When a rate-limit policy is attached and the request method is retryable,
    /// HTTP 429 responses trigger automatic retries with exponential backoff.
    /// Non-retryable methods surface [`SdkError::RateLimited`] immediately.
    fn post<P: Serialize>(&self, request: &JsonRpcRequest<P>) -> Result<String, SdkError> {
        let mut attempt = 0;
        loop {
            let response = self.agent.post(&self.network_url).send_json(request);
            
            match response {
                Ok(resp) => return read_body_bounded(resp, self.max_response_bytes),
                Err(ureq::Error::Status(429, resp)) => {
                    let retry_after_secs = resp
                        .header("Retry-After")
                        .and_then(|v| v.trim().parse::<u64>().ok());
                    
                    // Check if we should retry
                    if let Some(policy) = &self.rate_limit_policy {
                        if policy.is_retryable(request.method) && attempt < policy.max_retries {
                            let delay = retry_after_secs
                                .map(Duration::from_secs)
                                .unwrap_or_else(|| policy.backoff_for_attempt(attempt));
                            std::thread::sleep(delay);
                            attempt += 1;
                            continue;
                        }
                    }
                    
                    // No policy, non-retryable method, or retries exhausted
                    return Err(SdkError::RateLimited { retry_after_secs });
                }
                Err(err) => return Err(SdkError::TransportError(err.to_string())),
            }
        }
    }
}

/// Reads a `ureq` response body into a `String`, rejecting it with
/// [`SdkError::ResponseTooLarge`] if the announced `Content-Length` exceeds
/// `limit` or if the body turns out to be longer than `limit` on the wire
/// (covering chunked responses with no declared length).
fn read_body_bounded(response: ureq::Response, limit: usize) -> Result<String, SdkError> {
    if let Some(len) = response
        .header("Content-Length")
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        if len > limit {
            return Err(SdkError::ResponseTooLarge {
                limit,
                observed: Some(len),
            });
        }
    }

    // Read at most `limit + 1` bytes: the extra byte tells us the body was
    // over the limit without ever holding more than `limit + 1` in memory.
    let mut buf = Vec::new();
    let read = response
        .into_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|err| SdkError::TransportError(err.to_string()))?;
    if read > limit {
        return Err(SdkError::ResponseTooLarge {
            limit,
            observed: None,
        });
    }
    String::from_utf8(buf).map_err(|err| SdkError::TransportError(err.to_string()))
}

/// Builds the `ureq` agent used for every [`RpcClient`] request, with
/// `timeout` bounding each request end-to-end (connect + send + read).
fn rpc_agent(timeout: Duration) -> Agent {
    AgentBuilder::new().timeout(timeout).build()
}

/// Decodes a JSON-RPC response envelope and unwraps either its `result`
/// or turns a JSON-RPC-level `error` (or malformed body) into an [`SdkError`].
///
/// Validates that the response declares `jsonrpc == "2.0"` and carries the
/// expected request `id` before decoding the result payload.
fn parse_response<T: DeserializeOwned>(body: &str, expected_id: u32) -> Result<T, SdkError> {
    let response: JsonRpcResponse<T> =
        serde_json::from_str(body).map_err(|err| SdkError::RpcError(err.to_string()))?;
    match response {
        JsonRpcResponse::Result {
            jsonrpc,
            id,
            result,
        } => {
            if jsonrpc != "2.0" {
                return Err(SdkError::RpcError(format!(
                    "unsupported JSON-RPC version: expected \"2.0\", got \"{jsonrpc}\""
                )));
            }
            if id != expected_id {
                return Err(SdkError::RpcError(format!(
                    "response id mismatch: expected {expected_id}, got {id}"
                )));
            }
            Ok(result)
        }
        JsonRpcResponse::Error {
            jsonrpc,
            id,
            error,
        } => {
            if jsonrpc != "2.0" {
                return Err(SdkError::RpcError(format!(
                    "unsupported JSON-RPC version: expected \"2.0\", got \"{jsonrpc}\""
                )));
            }
            if id != expected_id {
                return Err(SdkError::RpcError(format!(
                    "response id mismatch: expected {expected_id}, got {id}"
                )));
            }
            Err(SdkError::RpcError(format!(
                "{}: {}",
                error.code, error.message
            )))
        }
    }
}

fn validate_supported_transaction_envelope(
    result: &GetTransactionResult,
    max_body_bytes: usize,
) -> Result<(), SdkError> {
    let Some(envelope_xdr) = &result.envelope_xdr else {
        return Ok(());
    };
    let envelope =
        TransactionEnvelope::from_xdr_base64(envelope_xdr, rpc_response_limits(max_body_bytes))
            .map_err(|err| {
                SdkError::DecodingError(format!("failed to decode envelopeXdr: {err:?}"))
            })?;
    match envelope {
        TransactionEnvelope::Tx(_) => Ok(()),
        other => Err(SdkError::DecodingError(format!(
            "unsupported transaction envelope variant: {}",
            other.name()
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
    /// The transaction hash. Absent in a raw `getTransaction` reply (which
    /// is queried *by* hash); the SDK fills it in from the preceding
    /// `sendTransaction` so callers — especially asynchronous ones — always
    /// have the hash to poll or record.
    #[serde(default)]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct JsonRpcRequest<P: Serialize> {
    pub jsonrpc: &'static str,
    pub id: u32,
    pub method: &'static str,
    pub params: P,
}

impl<P: Serialize> JsonRpcRequest<P> {
    fn new(id: u32, method: &'static str, params: P) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method,
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SendTransactionParams {
    pub transaction: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GetTransactionParams {
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
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
///
/// When an entry is **archived** the host returns an error containing
/// `"archived"` and, when the node can estimate it, a `restorePreamble`
/// with the rent fee and transaction data needed for a `restoreFootprint`
/// operation. The SDK surfaces this as `SdkError::RestorationRequired`.
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
    /// Present when the simulation failed because a footprint entry is
    /// archived. Carries the fee and footprint needed to restore it.
    #[serde(rename = "restorePreamble")]
    pub restore_preamble: Option<RestorePreamble>,
}

/// Preamble returned when simulation touches an archived entry. The
/// transaction must be preceded by a `restoreFootprint` operation built
/// from `transactionData` and funded by `minResourceFee`.
#[derive(Debug, Deserialize, PartialEq)]
pub struct RestorePreamble {
    #[serde(rename = "transactionData")]
    pub transaction_data: String,
    #[serde(rename = "minResourceFee")]
    pub min_resource_fee: String,
}

/// One entry of a successful simulation's `results` array — the return
/// value of the invoked function, base64-encoded `ScVal` XDR.
#[derive(Debug, Deserialize, PartialEq)]
pub struct SimulateHostFunctionResult {
    pub xdr: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
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

/// `getLatestLedger` takes no parameters; serializes as `{}`.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GetLatestLedgerParams {}

/// The `result` payload of a Soroban `getLatestLedger` response.
/// See <https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getLatestLedger>.
/// Notably does *not* include a close time — fetch that ledger's header via
/// [`RpcClient::get_ledgers`] for [`RpcClient::fetch_current_ledger_time`].
#[derive(Debug, Deserialize, PartialEq)]
pub struct GetLatestLedgerResult {
    pub id: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    pub sequence: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LedgerPaginationParams {
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GetLedgersParams {
    #[serde(rename = "startLedger")]
    pub start_ledger: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pagination: Option<LedgerPaginationParams>,
}

/// The `result` payload of a Soroban `getLedgers` response.
/// See <https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getLedgers>.
#[derive(Debug, Deserialize, PartialEq)]
pub struct GetLedgersResult {
    #[serde(default)]
    pub ledgers: Vec<LedgerInfoResult>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct LedgerInfoResult {
    pub sequence: u32,
    /// Unix timestamp (seconds), as a decimal string on the wire.
    #[serde(rename = "ledgerCloseTime")]
    pub ledger_close_time: String,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct LedgerEntryResult {
    pub key: String,
    /// Base64 `LedgerEntryData` XDR.
    pub xdr: String,
    #[serde(rename = "lastModifiedLedgerSeq")]
    pub last_modified_ledger_seq: u32,
    /// Ledger until which the entry is live. Present on Soroban entries;
    /// absent for classic entries. When `latestLedger >= liveUntilLedgerSeq`
    /// the entry is expiring / archived and needs TTL bump or restoration.
    #[serde(rename = "liveUntilLedgerSeq")]
    pub live_until_ledger_seq: Option<u32>,
}

/// The `result` payload of a Soroban `getLatestLedger` response.
#[derive(Debug, Deserialize, PartialEq)]
pub struct GetLatestLedgerResult {
    pub id: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    pub sequence: u32,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct GetLedgersParams {
    #[serde(rename = "startLedger")]
    pub start_ledger: u32,
    pub pagination: LedgersPagination,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct LedgersPagination {
    pub limit: u32,
}

/// The subset of a Soroban `getLedgers` response the SDK needs to read a
/// ledger close time. Close times are transmitted as decimal strings of unix
/// seconds.
#[derive(Debug, Deserialize, PartialEq)]
pub struct GetLedgersResult {
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(rename = "latestLedgerCloseTime")]
    pub latest_ledger_close_time: String,
    #[serde(default)]
    pub ledgers: Vec<LedgerInfo>,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct LedgerInfo {
    pub sequence: u32,
    #[serde(rename = "ledgerCloseTime")]
    pub ledger_close_time: String,
}

/// A network ledger's sequence and close time (unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerClock {
    pub sequence: u32,
    pub close_time: u64,
}

/// Why the network ledger time could not be used as-is for issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuanceTimeError {
    /// The ledger close time is more than `max_skew_secs` behind the local
    /// clock — the RPC node is lagging, or the local clock jumped forward.
    LedgerStale {
        close_time: u64,
        local_time: u64,
        max_skew_secs: u64,
    },
    /// The ledger close time is more than `max_skew_secs` ahead of the local
    /// clock.
    LedgerInFuture {
        close_time: u64,
        local_time: u64,
        max_skew_secs: u64,
    },
}

/// Deterministic issuance-time policy (#172): use the network ledger close
/// time, but refuse it when it disagrees with `local_time` by more than
/// `max_skew_secs` in either direction. A stale RPC and a forward-skewed
/// local clock both surface as an error the caller must handle (retry, pick a
/// different RPC, or explicitly opt into the local clock) rather than issuing
/// a timestamp that ledger-time validation may reject.
///
/// `local_time` is passed in rather than read from `SystemTime` here so tests
/// can inject a local/ledger disagreement deterministically.
pub fn resolve_issuance_time(
    ledger: &LedgerClock,
    local_time: u64,
    max_skew_secs: u64,
) -> Result<u64, IssuanceTimeError> {
    if ledger.close_time > local_time.saturating_add(max_skew_secs) {
        return Err(IssuanceTimeError::LedgerInFuture {
            close_time: ledger.close_time,
            local_time,
            max_skew_secs,
        });
    }
    if local_time.saturating_sub(ledger.close_time) > max_skew_secs {
        return Err(IssuanceTimeError::LedgerStale {
            close_time: ledger.close_time,
            local_time,
            max_skew_secs,
        });
    }
    Ok(ledger.close_time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::xdr::{
        FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        FeeBumpTransactionInnerTx, Limits, Memo, MuxedAccount, Preconditions, SequenceNumber,
        Transaction, TransactionExt, TransactionV0, TransactionV0Envelope, TransactionV0Ext,
        TransactionV1Envelope, Uint256, VecM, WriteXdr,
    };
    use std::time::Instant;

    /// A minimal, well-formed `Transaction` body used to assemble the
    /// envelope fixtures below. Its contents don't matter — the tests only
    /// care which `TransactionEnvelope` variant it is wrapped in.
    fn sample_transaction() -> Transaction {
        Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionExt::V0,
        }
    }

    /// Base64 XDR for a modern V1 (`TransactionEnvelope::Tx`) envelope — the
    /// only variant the SDK accepts from `getTransaction`.
    fn v1_envelope_xdr() -> String {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: sample_transaction(),
            signatures: VecM::default(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    /// Base64 XDR for a legacy V0 (`TransactionEnvelope::TxV0`) envelope,
    /// which the SDK must reject without panicking.
    fn v0_envelope_xdr() -> String {
        let tx = TransactionV0 {
            source_account_ed25519: Uint256([0u8; 32]),
            fee: 100,
            seq_num: SequenceNumber(0),
            time_bounds: None,
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionV0Ext::V0,
        };
        TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx,
            signatures: VecM::default(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    /// Base64 XDR for a fee-bump (`TransactionEnvelope::TxFeeBump`) envelope,
    /// which the SDK must reject without panicking.
    fn fee_bump_envelope_xdr() -> String {
        let inner = FeeBumpTransactionInnerTx::Tx(TransactionV1Envelope {
            tx: sample_transaction(),
            signatures: VecM::default(),
        });
        let tx = FeeBumpTransaction {
            fee_source: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 200,
            inner_tx: inner,
            ext: FeeBumpTransactionExt::V0,
        };
        TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx,
            signatures: VecM::default(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    #[test]
    fn builds_send_transaction_request() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_send_transaction_request("AAAAAgAAAAA=");

        let value = serde_json::to_value(request.clone()).unwrap();
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["method"], "sendTransaction");
        assert_eq!(value["params"]["transaction"], "AAAAAgAAAAA=");
        assert!(request.id >= 1);
    }

    #[test]
    fn builds_get_transaction_request() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_get_transaction_request("deadbeef");

        let value = serde_json::to_value(request.clone()).unwrap();
        assert_eq!(value["method"], "getTransaction");
        assert_eq!(value["params"]["hash"], "deadbeef");
        assert!(request.id >= 1);
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

        let result = client.parse_send_transaction_response(body, 1).unwrap();
        assert_eq!(result.status, "PENDING");
        assert_eq!(result.hash, "abcd1234");
        assert_eq!(result.latest_ledger, 12345);
        assert_eq!(result.error_result_xdr, None);
    }

    #[test]
    fn parses_successful_get_transaction_response() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let envelope_xdr = v1_envelope_xdr();
        let body = format!(
            r#"{{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {{
                "status": "SUCCESS",
                "latestLedger": 12345,
                "envelopeXdr": {envelope_xdr},
                "resultXdr": "AAAAAQAAAAA="
            }}
        }}"#,
            envelope_xdr = serde_json::to_string(&envelope_xdr).unwrap()
        );

        let result = client.parse_get_transaction_response(&body, 1).unwrap();
        assert_eq!(result.status, "SUCCESS");
        assert_eq!(result.envelope_xdr.as_deref(), Some(envelope_xdr.as_str()));
    }

    #[test]
    fn rejects_v0_get_transaction_envelope_without_panic() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = format!(
            r#"{{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {{
                "status": "SUCCESS",
                "latestLedger": 12345,
                "envelopeXdr": {v0_envelope_xdr}
            }}
        }}"#,
            v0_envelope_xdr = serde_json::to_string(&v0_envelope_xdr()).unwrap()
        );

        let err = client.parse_get_transaction_response(&body, 1).unwrap_err();
        match err {
            SdkError::DecodingError(msg) => {
                assert!(msg.contains("unsupported transaction envelope variant: TxV0"));
            }
            other => panic!("expected DecodingError, got {other:?}"),
        }
    }

    #[test]
    fn rejects_fee_bump_get_transaction_envelope_without_panic() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = format!(
            r#"{{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {{
                "status": "SUCCESS",
                "latestLedger": 12345,
                "envelopeXdr": {fee_bump_envelope_xdr}
            }}
        }}"#,
            fee_bump_envelope_xdr = serde_json::to_string(&fee_bump_envelope_xdr()).unwrap()
        );

        let err = client.parse_get_transaction_response(&body, 1).unwrap_err();
        match err {
            SdkError::DecodingError(msg) => {
                assert!(msg.contains("unsupported transaction envelope variant: TxFeeBump"));
            }
            other => panic!("expected DecodingError, got {other:?}"),
        }
    }

    #[test]
    fn maps_json_rpc_error_to_sdk_error() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32602, "message": "Invalid params" }
        }"#;

        let err = client.parse_send_transaction_response(body, 1).unwrap_err();
        match err {
            SdkError::RpcError(msg) => assert!(msg.contains("Invalid params")),
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    #[test]
    fn builds_simulate_transaction_request() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_simulate_transaction_request("AAAAAgAAAAA=");

        let value = serde_json::to_value(request.clone()).unwrap();
        assert_eq!(value["method"], "simulateTransaction");
        assert_eq!(value["params"]["transaction"], "AAAAAgAAAAA=");
        assert!(request.id >= 1);
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

        let result = client.parse_simulate_transaction_response(body, 1).unwrap();
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

        let result = client.parse_simulate_transaction_response(body, 1).unwrap();
        assert_eq!(result.latest_ledger, 3993006);
        assert!(result.error.unwrap().contains("MissingValue"));
        assert!(result.results.is_empty());
    }

    #[test]
    fn builds_get_ledger_entries_request() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_get_ledger_entries_request(vec!["AAAAAA==".to_string()]);

        let value = serde_json::to_value(request.clone()).unwrap();
        assert_eq!(value["method"], "getLedgerEntries");
        assert_eq!(value["params"]["keys"][0], "AAAAAA==");
        assert!(request.id >= 1);
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

        let result = client.parse_get_ledger_entries_response(body, 1).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].xdr, "AAAAAA==");
        assert_eq!(result.entries[0].last_modified_ledger_seq, 3993006);
    }

    #[test]
    fn maps_malformed_body_to_sdk_error() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let err = client
            .parse_get_transaction_response("not json", 1)
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
            matches!(err, SdkError::TransportError(_)),
            "expected SdkError::TransportError, got {err:?}"
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
            matches!(err, SdkError::TransportError(_)),
            "expected SdkError::TransportError, got {err:?}"
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

    // --- Issue #136: response bodies are bounded before JSON / XDR decode ---

    /// Serves one HTTP/1.1 response built from `status_line_extra_headers`
    /// (everything between the status line and the blank line, `\r\n`
    /// terminated) plus `body`. Lets a test forge a `Content-Length` or ship
    /// an over-large body.
    fn spawn_raw_http_server(headers: String, body: Vec<u8>) -> String {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                // Fully drain the request (headers + body) first: closing a
                // socket with unread bytes sends an RST that can wipe the
                // response mid-flight.
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    let read = reader.read_line(&mut line).unwrap_or(0);
                    if read == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut req_body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut req_body);

                let mut stream = stream;
                let _ = stream.write_all(
                    format!("HTTP/1.1 200 OK\r\n{headers}Connection: close\r\n\r\n").as_bytes(),
                );
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        url
    }

    #[test]
    fn default_max_response_bytes_matches_the_documented_limit() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        assert_eq!(
            client.max_response_bytes(),
            crate::limits::DEFAULT_MAX_RESPONSE_BYTES
        );
    }

    #[test]
    fn with_max_response_bytes_overrides_the_default() {
        let client =
            RpcClient::new("https://soroban-testnet.stellar.org").with_max_response_bytes(1024);
        assert_eq!(client.max_response_bytes(), 1024);
    }

    #[test]
    fn oversized_content_length_is_rejected_before_the_body_is_read() {
        // Announce a gigabyte but send almost nothing: a client that trusts
        // Content-Length would try to allocate 1 GiB.
        let url = spawn_raw_http_server(
            "Content-Type: application/json\r\nContent-Length: 1073741824\r\n".to_string(),
            b"{}".to_vec(),
        );
        let client = RpcClient::new(url).with_max_response_bytes(64 * 1024);
        let err = client.get_transaction("deadbeef").unwrap_err();
        match err {
            SdkError::ResponseTooLarge { limit, observed } => {
                assert_eq!(limit, 64 * 1024);
                assert_eq!(observed, Some(1_073_741_824));
            }
            other => panic!("expected ResponseTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn oversized_body_without_content_length_is_cut_off_at_the_limit() {
        let big = vec![b'a'; 200 * 1024];
        // Chunked-style: no Content-Length header at all.
        let url = spawn_raw_http_server("Content-Type: application/json\r\n".to_string(), big);
        let client = RpcClient::new(url).with_max_response_bytes(64 * 1024);
        let err = client.get_transaction("deadbeef").unwrap_err();
        assert!(
            matches!(
                err,
                SdkError::ResponseTooLarge {
                    limit: 65536,
                    observed: None
                }
            ),
            "expected ResponseTooLarge, got {err:?}"
        );
    }

    #[test]
    fn a_body_within_the_limit_still_parses_normally() {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"status":"SUCCESS","latestLedger":7,"envelopeXdr":{}}}}}"#,
            serde_json::to_string(&v1_envelope_xdr()).unwrap()
        )
        .into_bytes();
        let url = spawn_raw_http_server(
            format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ),
            body,
        );
        let client = RpcClient::new(url).with_max_response_bytes(64 * 1024);
        let result = client.get_transaction("deadbeef").unwrap();
        assert_eq!(result.status, "SUCCESS");
    }

    #[test]
    fn nested_xdr_past_the_configured_depth_is_rejected_not_recursed() {
        use soroban_sdk::xdr::{Limits as XdrLimits, ScVal, ScVec};

        // A modestly nested `ScVal::Vec` (shallow enough that *encoding* it
        // here doesn't overflow this test thread's own stack).
        let mut nested = ScVal::Vec(Some(ScVec(VecM::default())));
        for _ in 0..24 {
            nested = ScVal::Vec(Some(ScVec(vec![nested].try_into().unwrap())));
        }
        let deep_b64 = nested.to_xdr_base64(XdrLimits::none()).unwrap();

        // Unbounded / generous depth accepts it...
        assert!(ScVal::from_xdr_base64(&deep_b64, XdrLimits::none()).is_ok());
        assert!(ScVal::from_xdr_base64(&deep_b64, rpc_response_limits(1 << 20)).is_ok());
        // ...but a decoder whose depth ceiling sits below the nesting bails
        // with an error instead of recursing without bound.
        let shallow = XdrLimits {
            depth: 8,
            len: 1 << 20,
        };
        assert!(ScVal::from_xdr_base64(&deep_b64, shallow).is_err());
    }

    #[test]
    fn oversized_base64_xdr_is_rejected_by_the_finite_byte_limit() {
        use soroban_sdk::xdr::{Limits as XdrLimits, ScVal};

        // A big `ScVal::Bytes` blob: legal XDR, but larger than a tight
        // `len` ceiling, so the bounded decoder refuses it up front.
        let blob = ScVal::Bytes(vec![7u8; 200 * 1024].try_into().unwrap());
        let b64 = blob.to_xdr_base64(XdrLimits::none()).unwrap();
        assert!(ScVal::from_xdr_base64(&b64, XdrLimits::none()).is_ok());
        let tight = XdrLimits {
            depth: crate::limits::DEFAULT_XDR_DEPTH,
            len: 64 * 1024,
        };
        assert!(ScVal::from_xdr_base64(&b64, tight).is_err());
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
            // The server may reject our request body outright; what matters
            // here is that the request round-tripped through the
            // timeout-wired agent instead of failing at transport (which
            // would surface as `SdkError::TransportError`, not this).
            Err(SdkError::RpcError(_)) => {}
            Err(err) => panic!("unexpected error kind from live testnet: {err:?}"),
        }
    }

    // --- Issue #135: JSON-RPC version and response ID validation tests ---

    #[test]
    fn rejects_non_2_0_jsonrpc_version() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "1.0",
            "id": 1,
            "result": {
                "status": "PENDING",
                "hash": "abcd1234",
                "latestLedger": 12345,
                "latestLedgerCloseTime": "1234567890"
            }
        }"#;

        let err = client.parse_send_transaction_response(body, 1).unwrap_err();
        match err {
            SdkError::RpcError(msg) => {
                assert!(msg.contains("unsupported JSON-RPC version"));
                assert!(msg.contains("1.0"));
            }
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    #[test]
    fn rejects_response_with_wrong_id() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 99,
            "result": {
                "status": "PENDING",
                "hash": "abcd1234",
                "latestLedger": 12345,
                "latestLedgerCloseTime": "1234567890"
            }
        }"#;

        let err = client.parse_send_transaction_response(body, 1).unwrap_err();
        match err {
            SdkError::RpcError(msg) => {
                assert!(msg.contains("response id mismatch"));
                assert!(msg.contains("99"));
            }
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    #[test]
    fn rejects_error_response_with_wrong_id() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 42,
            "error": { "code": -32602, "message": "Invalid params" }
        }"#;

        let err = client.parse_send_transaction_response(body, 1).unwrap_err();
        match err {
            SdkError::RpcError(msg) => {
                assert!(msg.contains("response id mismatch"));
            }
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    #[test]
    fn rejects_error_response_with_wrong_jsonrpc_version() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{
            "jsonrpc": "1.0",
            "id": 1,
            "error": { "code": -32602, "message": "Invalid params" }
        }"#;

        let err = client.parse_send_transaction_response(body, 1).unwrap_err();
        match err {
            SdkError::RpcError(msg) => {
                assert!(msg.contains("unsupported JSON-RPC version"));
            }
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    // --- Issue #173: fetching current ledger time for client-side TTL checks ---

    #[test]
    fn builds_get_latest_ledger_request() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_get_latest_ledger_request();
        let value = serde_json::to_value(request.clone()).unwrap();
        assert_eq!(value["method"], "getLatestLedger");
        assert!(request.id >= 1);
    }

    #[test]
    fn parses_get_latest_ledger_response() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"id":"abcd","protocolVersion":21,"sequence":12345}}"#;
        let result = client.parse_get_latest_ledger_response(body, 1).unwrap();
        assert_eq!(result.sequence, 12345);
        assert_eq!(result.protocol_version, 21);
    }

    #[test]
    fn builds_get_ledgers_request_with_a_single_ledger_pagination_limit() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let request = client.build_get_ledgers_request(12345);
        let value = serde_json::to_value(request.clone()).unwrap();
        assert_eq!(value["method"], "getLedgers");
        assert_eq!(value["params"]["startLedger"], 12345);
        assert_eq!(value["params"]["pagination"]["limit"], 1);
    }

    #[test]
    fn parses_get_ledgers_response() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"ledgers":[{"sequence":12345,"ledgerCloseTime":"1700000000"}],"latestLedger":12345}}"#;
        let result = client.parse_get_ledgers_response(body, 1).unwrap();
        assert_eq!(result.ledgers.len(), 1);
        assert_eq!(result.ledgers[0].ledger_close_time, "1700000000");
    }

    /// Spawns a background thread that serially answers up to `responses.len()`
    /// HTTP requests, matching each incoming request's JSON-RPC `method` field
    /// (a plain substring search — good enough for a test double) against
    /// `responses` in order and replying with the paired body. Returns the
    /// URL an `RpcClient` should target.
    fn spawn_multi_call_mock_rpc_server(responses: Vec<(&'static str, String)>) -> String {
        use std::io::{BufRead, BufReader, Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for (expected_method, response_body) in responses {
                let Ok((stream, _)) = listener.accept() else {
                    break;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    let read = reader.read_line(&mut line).unwrap_or(0);
                    if read == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
                let request_body = String::from_utf8_lossy(&body);
                assert!(
                    request_body.contains(expected_method),
                    "expected request for {expected_method:?}, got: {request_body}"
                );

                let mut stream = stream;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        url
    }

    #[test]
    fn fetch_current_ledger_time_combines_get_latest_ledger_and_get_ledgers() {
        let url = spawn_multi_call_mock_rpc_server(vec![
            (
                "getLatestLedger",
                r#"{"jsonrpc":"2.0","id":1,"result":{"id":"abcd","protocolVersion":21,"sequence":555}}"#
                    .to_string(),
            ),
            (
                "getLedgers",
                r#"{"jsonrpc":"2.0","id":2,"result":{"ledgers":[{"sequence":555,"ledgerCloseTime":"1700000042"}],"latestLedger":555}}"#
                    .to_string(),
            ),
        ]);
        let client = RpcClient::new(url);
        let time = client.fetch_current_ledger_time().unwrap();
        assert_eq!(time, 1_700_000_042);
    }

    #[test]
    fn fetch_current_ledger_time_errors_when_getledgers_returns_no_header() {
        let url = spawn_multi_call_mock_rpc_server(vec![
            (
                "getLatestLedger",
                r#"{"jsonrpc":"2.0","id":1,"result":{"id":"abcd","protocolVersion":21,"sequence":555}}"#
                    .to_string(),
            ),
            (
                "getLedgers",
                r#"{"jsonrpc":"2.0","id":2,"result":{"ledgers":[],"latestLedger":555}}"#
                    .to_string(),
            ),
        ]);
        let client = RpcClient::new(url);
        let err = client.fetch_current_ledger_time().unwrap_err();
        assert!(matches!(err, SdkError::RpcError(_)));
    }

    #[test]
    fn request_ids_are_distinct_for_concurrent_calls() {
        let client = RpcClient::new("https://soroban-testnet.stellar.org");
        let r1 = client.build_send_transaction_request("AAAAAgAAAAA=");
        let r2 = client.build_send_transaction_request("AAAAAgAAAAA=");
        let r3 = client.build_send_transaction_request("AAAAAgAAAAA=");
        assert_ne!(r1.id, r2.id);
        assert_ne!(r2.id, r3.id);
    }
}

#[cfg(test)]
mod issuance_time_tests {
    use super::{resolve_issuance_time, IssuanceTimeError, LedgerClock};

    fn clock(close_time: u64) -> LedgerClock {
        LedgerClock {
            sequence: 100,
            close_time,
        }
    }

    #[test]
    fn uses_ledger_time_when_clocks_agree() {
        assert_eq!(resolve_issuance_time(&clock(1_000), 1_000, 300), Ok(1_000));
        // Small disagreement inside the skew budget is fine; ledger wins.
        assert_eq!(resolve_issuance_time(&clock(1_000), 1_200, 300), Ok(1_000));
        assert_eq!(resolve_issuance_time(&clock(1_000), 800, 300), Ok(1_000));
    }

    #[test]
    fn rejects_a_stale_rpc_ledger() {
        assert_eq!(
            resolve_issuance_time(&clock(1_000), 2_000, 300),
            Err(IssuanceTimeError::LedgerStale {
                close_time: 1_000,
                local_time: 2_000,
                max_skew_secs: 300,
            })
        );
    }

    #[test]
    fn rejects_a_ledger_from_the_future() {
        assert_eq!(
            resolve_issuance_time(&clock(5_000), 1_000, 300),
            Err(IssuanceTimeError::LedgerInFuture {
                close_time: 5_000,
                local_time: 1_000,
                max_skew_secs: 300,
            })
        );
    }

    #[test]
    fn saturating_math_does_not_panic_at_the_extremes() {
        assert!(resolve_issuance_time(&clock(0), u64::MAX, 300).is_err());
        assert!(resolve_issuance_time(&clock(u64::MAX), 0, 300).is_err());
    }
}
