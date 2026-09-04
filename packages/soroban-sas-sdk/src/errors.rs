//! Specialized error handling for SDK

/// Failures that can occur while building, signing, submitting, or querying
/// through the SDK's RPC-backed clients.
#[derive(Debug)]
pub enum SdkError {
    /// A network/HTTP-level failure talking to the RPC endpoint — the
    /// endpoint is unreachable, the connection times out, or the response
    /// body can't be read.
    TransportError(String),
    /// The invoked contract trapped (panicked) during `simulateTransaction`.
    SimulationError(String),
    /// The contract rejected the call with a specific on-chain `SASError`
    /// code.
    ContractError(u32),
    /// An XDR / `ScVal` / host `Val` conversion failed while building a
    /// request or decoding a response.
    DecodingError(String),
    /// A JSON-RPC-level error (or any other RPC failure that doesn't fit
    /// one of the more specific variants above).
    RpcError(String),
    /// A validation error where the simulated transaction's structure,
    /// contents, or ledger data did not match expected values before signing
    /// or key exposure.
    ValidationError(String),
    /// The requested ledger entry is archived and must be restored via
    /// `restoreFootprint` before it can be read. The inner string is the
    /// host's diagnostic (contains "archived") and should be surfaced to
    /// operators. When available, `min_resource_fee` / `transaction_data`
    /// from the simulation's `restorePreamble` are included.
    Archived(String),
    /// Structured restoration requirement surfaced from `simulateTransaction`'s
    /// `restorePreamble`. Contains the host error plus the estimated rent
    /// fee and the base64 transaction data needed to build a restore
    /// transaction.
    RestorationRequired {
        message: String,
        min_resource_fee: Option<String>,
        transaction_data: Option<String>,
    },
    /// `sendTransaction` rejected the transaction outright (status `ERROR`,
    /// or `DUPLICATE` where that is fatal) before it ever entered the
    /// mempool. `error_result_xdr` is the base64 `TransactionResult` the
    /// node returned, when present.
    SubmissionRejected {
        status: String,
        error_result_xdr: Option<String>,
    },
    /// A transaction settled with a `FAILED` status on-chain. Contains the
    /// base64 `TransactionResult` XDR and ledger context so callers can
    /// diagnose the failure without having to inspect the raw status string.
    TransactionFailed {
        result_xdr: String,
        last_ledger: u32,
    },
    /// A blocking submission's poll cap or wall-clock deadline elapsed while
    /// the transaction was still `PENDING` / `NOT_FOUND`. Distinct from an
    /// RPC failure (the polling calls all succeeded) and from a terminal
    /// on-chain failure (which is an `Ok` result with a `FAILED` status).
    /// The transaction may still settle later — poll `hash` to find out.
    SettlementTimeout {
        hash: String,
        /// The last status seen before giving up.
        last_status: String,
        /// How many polls were performed.
        polls: u32,
    },
    /// An RPC endpoint returned (or announced via `Content-Length`) a
    /// response body larger than the client's configured limit. The reply
    /// is refused before it is fully buffered or decoded, so a hostile or
    /// misconfigured node cannot force unbounded allocation in the caller.
    ResponseTooLarge {
        /// The configured maximum, in bytes.
        limit: usize,
        /// The observed or announced size when known (from `Content-Length`
        /// or the number of bytes read before the limit tripped).
        observed: Option<usize>,
    },
    /// The RPC endpoint returned HTTP 429 Too Many Requests, signalling that
    /// the caller has exceeded its rate limit.
    ///
    /// When the node supplied a `Retry-After` header the value is preserved in
    /// `retry_after_secs` so callers can back off exactly as long as the node
    /// requests. `retry_after_secs` is `None` when the header was absent or
    /// unparseable (treat it as "back off at your discretion").
    ///
    /// This is intentionally distinct from [`SdkError::TransportError`] so
    /// callers can branch on it and apply a bounded retry loop without
    /// catching unrelated network failures.
    RateLimited {
        /// Parsed value of the `Retry-After` header (integer seconds), if
        /// the server sent one and it was a valid non-negative integer.
        retry_after_secs: Option<u64>,
    },
}

impl std::fmt::Display for SdkError {
    /// Renders a human-readable, single-line message for CLI output. Unlike
    /// `{:?}`, this doesn't leak the enum variant's Rust name — every
    /// variant's message is written to stand on its own (issue #171 /
    /// #175: "CLI prints actionable messages").
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::TransportError(msg) => write!(f, "network error: {msg}"),
            SdkError::SimulationError(msg) => write!(f, "simulation failed: {msg}"),
            SdkError::ContractError(code) => write!(f, "contract rejected the call (error {code})"),
            SdkError::DecodingError(msg) => write!(f, "{msg}"),
            SdkError::RpcError(msg) => write!(f, "RPC error: {msg}"),
            SdkError::ValidationError(msg) => write!(f, "{msg}"),
            SdkError::Archived(msg) => write!(f, "entry is archived and needs restoration: {msg}"),
            SdkError::RestorationRequired { message, .. } => {
                write!(f, "entry is archived and needs restoration: {message}")
            }
            SdkError::SubmissionRejected {
                status,
                error_result_xdr,
            } => match error_result_xdr {
                Some(xdr) => write!(f, "transaction submission rejected ({status}): {xdr}"),
                None => write!(f, "transaction submission rejected ({status})"),
            },
            SdkError::SettlementTimeout {
                hash,
                last_status,
                polls,
            } => write!(
                f,
                "transaction {hash} did not settle after {polls} polls (last status: {last_status})"
            ),
            SdkError::ResponseTooLarge { limit, observed } => match observed {
                Some(size) => write!(
                    f,
                    "RPC response of {size} bytes exceeds the {limit}-byte limit"
                ),
                None => write!(f, "RPC response exceeds the {limit}-byte limit"),
            },
            SdkError::RateLimited { retry_after_secs } => match retry_after_secs {
                Some(secs) => write!(
                    f,
                    "RPC endpoint returned 429 Too Many Requests; retry after {secs}s"
                ),
                None => write!(
                    f,
                    "RPC endpoint returned 429 Too Many Requests; no Retry-After provided"
                ),
            },
            SdkError::TransactionFailed {
                result_xdr,
                last_ledger,
            } => write!(
                f,
                "transaction failed (ledger {last_ledger}): {result_xdr}"
            ),
        }
    }
}

impl std::error::Error for SdkError {}

/// Attempt to extract a SAS error code from a simulation host error string.
///
/// Simulation errors from Soroban often follow the format:
/// `HostError: Error(<code>, <message>)` or contain a numeric code
/// within the diagnostic text. This function tries to extract that code
/// so it can be surfaced as a structured `SdkError::ContractError` instead
/// of an opaque `SdkError::SimulationError`.
///
/// Returns `Some(code)` if a known SAS error code was found, `None` otherwise.
pub fn extract_contract_error_code(error: &str) -> Option<u32> {
    // Try to find a pattern like "Error(<number>, ...)" in the error string.
    // Common Soroban host error format: "HostError: Error(<code>, <msg>)"
    let error_lower = error.to_lowercase();

    // Common SAS error codes and their typical textual representations
    // These are checked via substring matching on the error message
    let code_map = [
        (101, "invalidschema"),
        (102, "schemaalreadyexists"),
        (103, "schemasnotfound"),
        (201, "attestationnotfound"),
        (202, "alreadyrevoked"),
        (203, "notrevocable"),
        (204, "alreadyexpired"),
        (205, "duplicateattestation"),
        (301, "unauthorized"),
        (302, "invalidsignature"),
        (303, "delegationreplay"),
        (401, "invalidttl"),
        (402, "invalidrecipient"),
        (403, "invalidvalue"),
        (404, "incompatibledependency"),
        (405, "batchtoolarge"),
        (406, "attesterkeyalreadyregistered"),
        (407, "attesterkeynotfound"),
        (408, "attesterkeyrevoked"),
        (406, "feemismatch"),
        (407, "indexerunavailable"),
        (408, "countmetadataexpired"),
    ];

    // First, try to extract a number from "Error(<number>, ...)" pattern
    // This handles the case where the host returns "Error(101, InvalidSchema)"
    if let Some(pos) = error_lower.find("error(") {
        // Look for a number after "error("
        let after = &error_lower[pos + 6..];
        if let Some(num_end) = after.chars().position(|c| !c.is_ascii_digit()) {
            if let Ok(code) = after[..num_end].parse::<u32>() {
                // Verify it's a valid SAS error code range (100-500)
                if (100..=500).contains(&code) {
                    return Some(code);
                }
            }
        }
    }

    // Also check for known code words in the error message
    for (code, keyword) in &code_map {
        if error_lower.contains(*keyword) {
            return Some(*code);
        }
    }

    None
}
