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
}
