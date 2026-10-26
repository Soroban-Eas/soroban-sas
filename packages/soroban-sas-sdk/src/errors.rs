//! Specialized error handling for SDK

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE_CONTRACT_DIAGNOSTICS: AtomicBool = AtomicBool::new(false);

/// Controls whether structured contract errors include their full RPC trace.
pub fn set_verbose_contract_diagnostics(enabled: bool) {
    VERBOSE_CONTRACT_DIAGNOSTICS.store(enabled, Ordering::Relaxed);
}

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
    /// The contract rejected a simulation and the RPC provided its diagnostic
    /// trace. Keeping that trace lets CLI callers show it in verbose output.
    ContractErrorWithDiagnostics { code: u32, diagnostics: String },
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
    /// Input parameters provided to an SDK method were invalid or inappropriate
    /// for the operation (e.g. attempting to restore an entry that is not archived,
    /// or missing required configuration on the client).
    InvalidInput(String),
    /// The RPC endpoint returned HTTP 429 Too Many Requests, and retries were
    /// exhausted or not configured.
    RateLimited {
        /// Number of retry attempts made before giving up.
        retries: u32,
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
            SdkError::ContractError(code) => write_contract_error(f, *code, None),
            SdkError::ContractErrorWithDiagnostics { code, diagnostics } => {
                write_contract_error(f, *code, Some(diagnostics))
            }
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
            SdkError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            SdkError::RateLimited { retries } => {
                write!(
                    f,
                    "RPC endpoint returned 429 Too Many Requests (exhausted {retries} retries)"
                )
            }
            SdkError::TransactionFailed {
                result_xdr,
                last_ledger,
            } => write!(f, "transaction failed (ledger {last_ledger}): {result_xdr}"),
        }
    }
}

fn write_contract_error(
    f: &mut std::fmt::Formatter<'_>,
    code: u32,
    diagnostics: Option<&str>,
) -> std::fmt::Result {
    let summary = match contract_error_name(code) {
        Some(name) => format!(
            "contract rejected the call: SASError::{name} (code {code}). {}",
            contract_error_suggestion(code)
        ),
        None => format!("contract rejected the call (unknown custom error code {code})"),
    };
    match diagnostics {
        Some(details)
            if VERBOSE_CONTRACT_DIAGNOSTICS.load(Ordering::Relaxed)
                && !details.trim().is_empty() =>
        {
            write!(f, "{summary}\nSoroban RPC diagnostics:\n{details}")
        }
        _ => f.write_str(&summary),
    }
}

/// Maps every custom error code shared by the SAS and schema-registry contracts.
pub fn contract_error_name(code: u32) -> Option<&'static str> {
    Some(match code {
        1 => "AlreadyInitialized",
        2 => "NotInitialized",
        101 => "InvalidSchema",
        102 => "SchemaAlreadyExists",
        103 => "SchemaNotFound",
        105 => "EmptySchema",
        106 => "InvalidSchemaDefinition",
        201 => "AttestationNotFound",
        202 => "AlreadyRevoked",
        203 => "NotRevocable",
        204 => "AlreadyExpired",
        205 => "DuplicateAttestation",
        206 => "InvalidRevocability",
        301 => "Unauthorized",
        302 => "InvalidSignature",
        303 => "DelegationReplay",
        304 => "UnauthorizedAttester",
        401 => "InvalidTTL",
        402 => "InvalidRecipient",
        403 => "InvalidValue",
        404 => "IncompatibleDependency",
        405 => "BatchTooLarge",
        406 => "AttesterKeyAlreadyRegistered",
        407 => "AttesterKeyNotFound",
        408 => "AttesterKeyRevoked",
        409 => "ResolverRejected",
        410 => "FeeMismatch",
        411 => "IndexerUnavailable",
        412 => "CountMetadataExpired",
        413 => "InvalidRefUid",
        414 => "PayloadTooLarge",
        415 => "TreasuryNotSet",
        416 => "InvalidUID",
        417 => "LimitExceeded",
        418 => "InvalidTimeRange",
        419 => "InvalidExpirationTime",
        420 => "InvalidTimestamp",
        421 => "TimestampAnchorNotFound",
        422 => "SchemaQuarantined",
        423 => "CooldownActive",
        424 => "InvalidToken",
        425 => "RateLimitExceeded",
        426 => "AutoPruneDisabled",
        501 => "ContractPaused",
        502 => "Reentrancy",
        503 => "ProtocolPaused",
        504 => "InsufficientFee",
        505 => "DelegationScopeDenied",
        506 => "InvalidZKProof",
        507 => "NullifierAlreadyUsed",
        _ => return None,
    })
}

fn contract_error_suggestion(code: u32) -> &'static str {
    match code {
        1 | 2 => "Check whether the contract has already been initialized and that required setup has completed.",
        101..=106 => "Review the schema definition and confirm it is registered on this network.",
        201..=206 | 413 | 416 | 419..=421 => "Check the attestation UID, lifecycle state, timestamps, and schema policy.",
        301..=304 | 406..=408 | 505 => "Verify the signing account, authorization, and delegation scope for this operation.",
        401..=405 | 414 | 417..=418 => "Validate the supplied values and stay within the documented limits.",
        409 => "Inspect the configured resolver contract and its diagnostic events.",
        410..=411 | 415 | 424 | 504 => "Check the fee configuration, treasury, allowlist, and required token balance.",
        422..=423 | 501..=503 => "Check the protocol pause state, schema quarantine, and resolver or indexer re-entrancy.",
        425..=426 => "Wait for the configured ledger window or enable pruning with the protocol administrator.",
        506..=507 => "Verify the proof inputs and confirm the nullifier has not already been consumed.",
        _ => "Inspect the contract diagnostic events for more context.",
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

    const CODES: &[u32] = &[
        1, 2, 101, 102, 103, 105, 106, 201, 202, 203, 204, 205, 206, 301, 302, 303, 304, 401, 402,
        403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 419, 420,
        421, 422, 423, 424, 425, 426, 501, 502, 503, 504, 505, 506, 507,
    ];

    // Soroban formats include both Error(409, ResolverRejected) and
    // Error(Contract, #409); accept either numeric representation.
    if let Some(error_pos) = error_lower.find("error(") {
        let after = &error_lower[error_pos + "error(".len()..];
        let candidate = after.split_once('#').map(|(_, rest)| rest).unwrap_or(after);
        let digits: String = candidate
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(code) = digits.parse::<u32>() {
            if contract_error_name(code).is_some() {
                return Some(code);
            }
        }
    }

    // Names can overlap (for example InvalidSchemaDefinition), so prefer the
    // longest matching variant name.
    CODES
        .iter()
        .filter_map(|code| contract_error_name(*code).map(|name| (*code, name)))
        .filter(|(_, name)| error_lower.contains(&name.to_ascii_lowercase()))
        .max_by_key(|(_, name)| name.len())
        .map(|(code, _)| code)
}

#[cfg(test)]
mod acl_error_code_tests {
    use super::{contract_error_name, extract_contract_error_code, SdkError};

    #[test]
    fn unauthorized_attester_is_distinct_from_unauthorized() {
        assert_eq!(
            extract_contract_error_code("HostError: UnauthorizedAttester"),
            Some(304)
        );
        assert_eq!(
            extract_contract_error_code("HostError: Unauthorized"),
            Some(301)
        );
    }

    #[test]
    fn numeric_unauthorized_attester_code_is_recognised() {
        assert_eq!(
            extract_contract_error_code("HostError: Error(304, UnauthorizedAttester)"),
            Some(304)
        );
    }

    #[test]
    fn all_sas_and_schema_registry_error_variants_are_named_and_extractable() {
        let codes = [
            1, 2, 101, 102, 103, 105, 106, 201, 202, 203, 204, 205, 206, 301, 302, 303, 304, 401,
            402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418,
            419, 420, 421, 422, 423, 424, 425, 426, 501, 502, 503, 504, 505, 506, 507,
        ];

        for code in codes {
            let name = contract_error_name(code).expect("every contract error needs a name");
            assert_eq!(extract_contract_error_code(name), Some(code), "{name}");
            let message = SdkError::ContractError(code).to_string();
            assert!(message.contains(&format!("SASError::{name}")), "{message}");
            assert!(message.contains(&format!("code {code}")), "{message}");
        }
    }

    #[test]
    fn extracts_contract_error_hash_format_and_rejects_unknown_codes() {
        assert_eq!(
            extract_contract_error_code("Error(Contract, #409)"),
            Some(409)
        );
        assert_eq!(extract_contract_error_code("Error(Contract, #999)"), None);
        assert_eq!(contract_error_name(999), None);
    }

    #[test]
    fn contract_error_display_keeps_rpc_diagnostics() {
        super::set_verbose_contract_diagnostics(true);
        let message = SdkError::ContractErrorWithDiagnostics {
            code: 409,
            diagnostics: "Event log: resolver rejected the schema".to_string(),
        }
        .to_string();

        assert!(message.contains("SASError::ResolverRejected"));
        assert!(message.contains("code 409"));
        assert!(message.contains("Event log: resolver rejected the schema"));
        super::set_verbose_contract_diagnostics(false);
    }
}
