//! Soroban RPC client.
//!
//! Builds well-typed JSON-RPC request bodies for the Soroban RPC methods the
//! SDK needs to submit and track transactions, sends them over HTTP via
//! `ureq`, and parses the matching JSON-RPC responses.

use crate::errors::SdkError;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use soroban_sdk::xdr::{Limits, ReadXdr, TransactionEnvelope};

/// A Soroban RPC endpoint the SDK will submit requests to,
/// e.g. `https://soroban-testnet.stellar.org`.
pub struct RpcClient {
    pub network_url: String,
}

impl RpcClient {
    pub fn new(network_url: impl Into<String>) -> Self {
        Self {
            network_url: network_url.into(),
        }
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
        let result = parse_response(body)?;
        validate_supported_transaction_envelope(&result)?;
        Ok(result)
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
        ureq::post(&self.network_url)
            .send_json(request)
            .map_err(|err| SdkError::RpcError(err.to_string()))?
            .into_string()
            .map_err(|err| SdkError::RpcError(err.to_string()))
    }
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

fn validate_supported_transaction_envelope(result: &GetTransactionResult) -> Result<(), SdkError> {
    let Some(envelope_xdr) = &result.envelope_xdr else {
        return Ok(());
    };
    let envelope = TransactionEnvelope::from_xdr_base64(envelope_xdr, Limits::none())
        .map_err(|err| SdkError::DecodingError(format!("failed to decode envelopeXdr: {err:?}")))?;
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
    use soroban_sdk::xdr::{
        DecoratedSignature, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        FeeBumpTransactionInnerTx, Memo, MuxedAccount, Operation, Preconditions, SequenceNumber,
        Signature, SignatureHint, Transaction, TransactionExt, TransactionV0,
        TransactionV0Envelope, TransactionV0Ext, TransactionV1Envelope, Uint256, VecM, WriteXdr,
    };

    fn v1_envelope_xdr() -> String {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: transaction_v1(),
            signatures: VecM::default(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    fn v0_envelope_xdr() -> String {
        TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: TransactionV0 {
                source_account_ed25519: Uint256([1u8; 32]),
                fee: 100,
                seq_num: SequenceNumber(1),
                time_bounds: None,
                memo: Memo::None,
                operations: VecM::default(),
                ext: TransactionV0Ext::V0,
            },
            signatures: VecM::default(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    fn fee_bump_envelope_xdr() -> String {
        TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: MuxedAccount::Ed25519(Uint256([2u8; 32])),
                fee: 200,
                inner_tx: FeeBumpTransactionInnerTx::Tx(TransactionV1Envelope {
                    tx: transaction_v1(),
                    signatures: VecM::default(),
                }),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: vec![DecoratedSignature {
                hint: SignatureHint([0; 4]),
                signature: Signature(vec![0u8; 64].try_into().unwrap()),
            }]
            .try_into()
            .unwrap(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    fn transaction_v1() -> Transaction {
        Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([3u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: VecM::<Operation, 100>::default(),
            ext: TransactionExt::V0,
        }
    }

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

        let result = client.parse_get_transaction_response(&body).unwrap();
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

        let err = client.parse_get_transaction_response(&body).unwrap_err();
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

        let err = client.parse_get_transaction_response(&body).unwrap_err();
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
}
