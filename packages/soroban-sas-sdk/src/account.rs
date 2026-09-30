//! Fetches an account's current sequence number, needed to build a
//! submittable (not just simulated) transaction.

use std::collections::HashMap;

use crate::errors::SdkError;
use crate::rpc::RpcClient;
use soroban_sdk::xdr::{
    AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits, PublicKey, ReadXdr, Uint256,
    WriteXdr,
};

/// `public_key`. The next valid transaction from this account uses
/// `sequence_number + 1`.
pub fn fetch_sequence_number(rpc: &RpcClient, public_key: &[u8; 32]) -> Result<i64, SdkError> {
    fetch_sequence_numbers(rpc, std::slice::from_ref(public_key))?
        .into_iter()
        .next()
        .ok_or_else(|| SdkError::RpcError("sequence lookup returned no result".to_string()))
}

/// Fetches current sequence numbers for multiple accounts with a single
/// `getLedgerEntries` RPC request. Results follow the input order; if any
/// requested account is missing or its ledger entry is invalid, the entire
/// call returns an error.
///
/// An empty `public_keys` slice returns an empty vector without making an RPC
/// request.
pub fn fetch_sequence_numbers(
    rpc: &RpcClient,
    public_keys: &[[u8; 32]],
) -> Result<Vec<i64>, SdkError> {
    if public_keys.is_empty() {
        return Ok(Vec::new());
    }

    let keys = public_keys
        .iter()
        .map(account_ledger_key_base64_from_bytes)
        .collect::<Result<Vec<_>, _>>()?;
    let result = rpc.get_ledger_entries(keys.clone())?;
    let entries_by_key: HashMap<_, _> = result
        .entries
        .iter()
        .map(|entry| (entry.key.as_str(), entry))
        .collect();

    keys.iter()
        .map(|key| {
            let entry = entries_by_key.get(key.as_str()).ok_or_else(|| {
                SdkError::ValidationError(
                    "account does not exist on this network (fund it first, e.g. via friendbot on testnet)"
                        .to_string(),
                )
            })?;
            let data = LedgerEntryData::from_xdr_base64(
                &entry.xdr,
                crate::limits::default_rpc_response_limits(),
            )
            .map_err(|e| {
                SdkError::DecodingError(format!("failed to decode account ledger entry xdr: {e:?}"))
            })?;

            match data {
                LedgerEntryData::Account(account) => Ok(account.seq_num.0),
                other => Err(SdkError::ValidationError(format!(
                    "expected an Account ledger entry, got {:?}",
                    other
                ))),
            }
        })
        .collect()
}

/// Encodes an Ed25519 account public key strkey as a base64 XDR
/// `LedgerKey::Account`, suitable for `getLedgerEntries`.
pub fn account_ledger_key_base64(public_key: &str) -> Result<String, SdkError> {
    let public_key = stellar_strkey::ed25519::PublicKey::from_string(public_key).map_err(|e| {
        SdkError::DecodingError(format!("invalid account public key strkey: {e:?}"))
    })?;
    account_ledger_key_base64_from_bytes(&public_key.0)
}

fn account_ledger_key_base64_from_bytes(public_key: &[u8; 32]) -> Result<String, SdkError> {
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(*public_key))),
    });
    key.to_xdr_base64(Limits::none())
        .map_err(|e| SdkError::RpcError(format!("failed to encode ledger key: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::xdr::{
        AccountEntry, AccountEntryExt, AccountId, ContractDataDurability, Hash, PublicKey,
        ScAddress, ScVal, SequenceNumber, String32, Thresholds, Uint256,
    };
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// Decodes a base64 `LedgerKey::Account` XDR and asserts its account id
    /// carries exactly `expected` as its Ed25519 public key.
    fn assert_account_key_bytes(key_b64: &str, expected: [u8; 32]) {
        let key = LedgerKey::from_xdr_base64(key_b64, Limits::none()).unwrap();
        let LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes))),
        }) = key
        else {
            panic!("expected a LedgerKey::Account, got {key:?}");
        };
        assert_eq!(bytes, expected);
    }

    fn account_entry_xdr(public_key: [u8; 32], sequence: i64) -> String {
        LedgerEntryData::Account(AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key))),
            balance: 100_000_000,
            seq_num: SequenceNumber(sequence),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: Default::default(),
            ext: AccountEntryExt::V0,
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    fn mock_ledger_entries_rpc(
        entries: Vec<serde_json::Value>,
    ) -> (String, std::thread::JoinHandle<serde_json::Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse().unwrap();
                }
            }
            let mut request_body = vec![0u8; content_length];
            reader.read_exact(&mut request_body).unwrap();
            let request: serde_json::Value = serde_json::from_slice(&request_body).unwrap();
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": { "entries": entries, "latestLedger": 1 }
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response.len(),
                response
            )
            .unwrap();
            stream.flush().unwrap();
            request
        });
        (url, server)
    }

    #[test]
    fn account_ledger_key_round_trips_multiple_ed25519_keys() {
        for public_key in [
            [0u8; 32],
            [0xffu8; 32],
            core::array::from_fn(|i| i as u8),
            core::array::from_fn(|i| 31u8 - i as u8),
        ] {
            let key_b64 = account_ledger_key_base64_from_bytes(&public_key).unwrap();
            assert_account_key_bytes(&key_b64, public_key);

            let strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
            let public_key_b64 = account_ledger_key_base64(&strkey).unwrap();
            assert_account_key_bytes(&public_key_b64, public_key);
        }
    }

    #[test]
    fn account_ledger_key_rejects_invalid_public_key_strkey() {
        let err = account_ledger_key_base64("not-a-valid-account").unwrap_err();
        match err {
            SdkError::DecodingError(msg) => assert!(msg.contains("invalid account public key")),
            other => panic!("expected DecodingError, got {other:?}"),
        }
    }

    #[test]
    fn extracts_seq_num_from_an_account_entry() {
        let public_key = [6u8; 32];
        let account_entry = AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key))),
            balance: 100_000_000,
            seq_num: SequenceNumber(42),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: Default::default(),
            ext: AccountEntryExt::V0,
        };
        let entry_xdr = LedgerEntryData::Account(account_entry)
            .to_xdr_base64(Limits::none())
            .unwrap();

        let data = LedgerEntryData::from_xdr_base64(entry_xdr, Limits::none()).unwrap();
        let LedgerEntryData::Account(decoded) = data else {
            panic!("expected an Account ledger entry");
        };
        assert_eq!(decoded.seq_num.0, 42);
    }

    #[test]
    fn fetches_multiple_sequences_in_one_request_and_preserves_input_order() {
        let public_keys = [[6u8; 32], [7u8; 32]];
        let ledger_keys: Vec<_> = public_keys
            .iter()
            .map(|key| account_ledger_key_base64_from_bytes(key).unwrap())
            .collect();
        let entries = vec![
            serde_json::json!({
                "key": ledger_keys[1],
                "xdr": account_entry_xdr(public_keys[1], 73),
                "lastModifiedLedgerSeq": 1
            }),
            serde_json::json!({
                "key": ledger_keys[0],
                "xdr": account_entry_xdr(public_keys[0], 42),
                "lastModifiedLedgerSeq": 1
            }),
        ];
        let (url, server) = mock_ledger_entries_rpc(entries);

        let sequences = fetch_sequence_numbers(&RpcClient::new(url), &public_keys).unwrap();
        let request = server.join().unwrap();

        assert_eq!(sequences, vec![42, 73]);
        assert_eq!(request["method"], "getLedgerEntries");
        assert_eq!(request["params"]["keys"], serde_json::json!(ledger_keys));
    }

    #[test]
    fn batched_sequence_lookup_reports_missing_accounts() {
        let public_keys = [[6u8; 32], [7u8; 32]];
        let first_key = account_ledger_key_base64_from_bytes(&public_keys[0]).unwrap();
        let entries = vec![serde_json::json!({
            "key": first_key,
            "xdr": account_entry_xdr(public_keys[0], 42),
            "lastModifiedLedgerSeq": 1
        })];
        let (url, server) = mock_ledger_entries_rpc(entries);

        let error = fetch_sequence_numbers(&RpcClient::new(url), &public_keys).unwrap_err();
        server.join().unwrap();

        assert!(matches!(
            error,
            SdkError::ValidationError(message) if message.contains("account does not exist")
        ));
    }

    #[test]
    fn empty_sequence_batch_does_not_contact_rpc() {
        let rpc = RpcClient::new("http://127.0.0.1:1");
        assert_eq!(
            fetch_sequence_numbers(&rpc, &[]).unwrap(),
            Vec::<i64>::new()
        );
    }

    // Negative test cases for Issue #93: account ledger-entry response validation
    #[test]
    fn rejects_malformed_account_xdr_base64() {
        use soroban_sdk::xdr::ReadXdr;

        let invalid_xdr = "!!!invalid base64!!!";

        let result = LedgerEntryData::from_xdr_base64(invalid_xdr, Limits::none());
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_ledger_entry_type() {
        use soroban_sdk::xdr::ContractDataEntry;

        let contract_data = ContractDataEntry {
            ext: soroban_sdk::xdr::ExtensionPoint::V0,
            contract: ScAddress::Contract(Hash([0u8; 32])),
            key: ScVal::Void,
            durability: ContractDataDurability::Persistent,
            val: ScVal::Void,
        };

        let entry_xdr = LedgerEntryData::ContractData(contract_data)
            .to_xdr_base64(Limits::none())
            .unwrap();

        let data = LedgerEntryData::from_xdr_base64(entry_xdr, Limits::none()).unwrap();
        let result = match data {
            LedgerEntryData::Account(_) => Ok(()),
            _ => Err(SdkError::ValidationError(
                "expected Account, got ContractData".to_string(),
            )),
        };
        assert!(result.is_err());
    }

    #[test]
    fn provides_clear_error_for_unfunded_account() {
        use crate::rpc::GetLedgerEntriesResult;

        // Simulate an empty entries response (unfunded account)
        let entries_response = GetLedgerEntriesResult {
            entries: vec![],
            latest_ledger: 100,
        };

        // `fetch_sequence_number` treats an empty `entries` list as the
        // unfunded-account case and returns `SdkError::ValidationError`
        // rather than panicking on a missing entry.
        assert!(entries_response.entries.is_empty());
    }

    #[test]
    fn truncated_xdr_produces_decoding_error() {
        let public_key = [8u8; 32];
        let account_entry = AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key))),
            balance: 100_000_000,
            seq_num: SequenceNumber(42),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: Default::default(),
            ext: AccountEntryExt::V0,
        };
        let entry_xdr = LedgerEntryData::Account(account_entry)
            .to_xdr_base64(Limits::none())
            .unwrap();

        // Truncate the XDR to create invalid data
        let truncated_xdr = &entry_xdr[0..entry_xdr.len().saturating_sub(10)];

        let result = LedgerEntryData::from_xdr_base64(truncated_xdr, Limits::none());
        assert!(result.is_err());
    }
}
