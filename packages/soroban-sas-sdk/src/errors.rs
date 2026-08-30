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
}
