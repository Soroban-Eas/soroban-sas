//! Finite decode limits for data coming back from a Soroban RPC endpoint
//! (issue #136).
//!
//! Every value the SDK decodes from an RPC response — JSON bodies, and the
//! base64 XDR nested inside them — originates from a remote node the caller
//! does not control. Left unbounded (`Limits::none()`, `into_string()`), a
//! hostile or misconfigured endpoint can force the SDK process to allocate
//! or recurse without limit. These constants and helpers give every such
//! decode a documented, tunable ceiling.

use soroban_sdk::xdr::Limits;

/// Default cap on a single RPC HTTP response body, in bytes (4 MiB).
///
/// Soroban RPC replies are normally a few KiB; the largest legitimate ones
/// (`getLedgerEntries` over big contract data, `simulateTransaction` with a
/// heavy footprint) still sit well under this. Callers expecting more can
/// raise it with [`crate::rpc::RpcClient::with_max_response_bytes`].
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Default maximum XDR nesting depth accepted when decoding RPC payloads.
///
/// Matches the Stellar ecosystem default (`stellar-xdr`'s own tooling limit)
/// and is far deeper than any structure the SDK actually decodes
/// (`TransactionEnvelope`, `LedgerEntryData`, `ScVal`), so it rejects only
/// pathological, adversarial nesting.
pub const DEFAULT_XDR_DEPTH: u32 = 500;

/// XDR decode limits for untrusted RPC response payloads: bounded recursion
/// depth and a byte ceiling equal to `max_body_bytes` (the same limit the
/// HTTP layer already enforced on the enclosing body, so a base64 blob
/// inside it can never decode to more than the body that carried it).
pub fn rpc_response_limits(max_body_bytes: usize) -> Limits {
    Limits {
        depth: DEFAULT_XDR_DEPTH,
        len: max_body_bytes,
    }
}

/// [`rpc_response_limits`] with the default body ceiling — for decode sites
/// that are not wired to a specific [`crate::rpc::RpcClient`].
pub fn default_rpc_response_limits() -> Limits {
    rpc_response_limits(DEFAULT_MAX_RESPONSE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_finite() {
        let l = default_rpc_response_limits();
        assert_eq!(l.depth, DEFAULT_XDR_DEPTH);
        assert_eq!(l.len, DEFAULT_MAX_RESPONSE_BYTES);
        assert!(l.depth < u32::MAX && l.len < usize::MAX);
    }

    #[test]
    fn body_ceiling_is_propagated_to_xdr_len() {
        assert_eq!(rpc_response_limits(1234).len, 1234);
    }
}
