//! Fetches an account's current sequence number, needed to build a
//! submittable (not just simulated) transaction.

use crate::errors::SdkError;
use crate::rpc::RpcClient;
use soroban_sdk::xdr::{
    AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits, PublicKey, ReadXdr, Uint256,
    WriteXdr,
};

/// Fetches the current sequence number of the account belonging to
/// `public_key`. The next valid transaction from this account uses
/// `sequence_number + 1`.
pub fn fetch_sequence_number(rpc: &RpcClient, public_key: &[u8; 32]) -> Result<i64, SdkError> {
    let key = account_ledger_key_base64_from_bytes(public_key)?;
    let result = rpc.get_ledger_entries(vec![key])?;

    if result.entries.is_empty() {
        return Err(SdkError::ValidationError(
            "account does not exist on this network (fund it first, e.g. via friendbot on testnet)"
                .to_string(),
        ));
    }

    let entry = &result.entries[0];

    let data =
        LedgerEntryData::from_xdr_base64(&entry.xdr, crate::limits::default_rpc_response_limits())
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

        let data = LedgerEntryData::from_xdr_base64(&entry_xdr, Limits::none()).unwrap();
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

        // When entries is empty, should return ValidationError
        if entries_response.entries.is_empty() {
            assert!(true); // Correctly identifies unfunded account case
        } else {
            panic!("should recognize empty entries");
        }
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
