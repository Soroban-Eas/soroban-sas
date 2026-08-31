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
        }
    }
}

impl std::error::Error for SdkError {}
