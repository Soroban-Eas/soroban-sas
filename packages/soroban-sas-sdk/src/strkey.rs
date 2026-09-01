//! Pre-host-conversion Stellar strkey validation (issue #171).
//!
//! `soroban_sdk::Address::from_string` converts a strkey to a host `Address`
//! by asking the host to decode it — a malformed, wrong-prefix, wrong-length,
//! or checksum-invalid strkey makes the host **trap**, which panics the
//! calling process instead of returning an error the SDK or CLI can report.
//! Every user-supplied address string must be validated with `stellar-strkey`
//! (which decodes off-host and returns `Result`) before it is ever handed to
//! `Address::from_string`.

use crate::errors::SdkError;
use soroban_sdk::{Address, Env, String as SorobanString};

/// The kind of Stellar address a given field accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    /// An `G...` ed25519 account strkey only.
    Account,
    /// A `C...` contract strkey only.
    Contract,
    /// Either a `G...` account or a `C...` contract strkey.
    Either,
}

impl AddressKind {
    fn expected_description(self) -> &'static str {
        match self {
            AddressKind::Account => "an account address (G...)",
            AddressKind::Contract => "a contract address (C...)",
            AddressKind::Either => "a G... account or C... contract address",
        }
    }
}

/// Validates `value` as a Stellar strkey of the given `kind`, without ever
/// invoking host address conversion. `field` names the input for the error
/// message (e.g. `"recipient"`, `"resolver"`).
///
/// Rejects malformed strkeys, wrong-prefix strkeys (e.g. a `C...` value where
/// an account is required), wrong-length payloads, and checksum failures —
/// every case `stellar_strkey` itself rejects — with a
/// [`SdkError::DecodingError`] instead of letting a later
/// `Address::from_string` trap the host.
pub fn validate_strkey(value: &str, kind: AddressKind, field: &str) -> Result<(), SdkError> {
    let is_account = stellar_strkey::ed25519::PublicKey::from_string(value).is_ok();
    let is_contract = stellar_strkey::Contract::from_string(value).is_ok();

    let ok = match kind {
        AddressKind::Account => is_account,
        AddressKind::Contract => is_contract,
        AddressKind::Either => is_account || is_contract,
    };

    if ok {
        Ok(())
    } else {
        Err(SdkError::DecodingError(format!(
            "{field}: {value:?} is not a valid Stellar strkey; expected {}",
            kind.expected_description()
        )))
    }
}

/// Validates `value` against `kind` and, only on success, converts it to a
/// host [`Address`]. Never panics on malformed input.
pub fn parse_address(
    env: &Env,
    value: &str,
    kind: AddressKind,
    field: &str,
) -> Result<Address, SdkError> {
    validate_strkey(value, kind, field)?;
    Ok(Address::from_string(&SorobanString::from_str(env, value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_account() -> String {
        stellar_strkey::ed25519::PublicKey([1u8; 32]).to_string()
    }

    fn valid_contract() -> String {
        stellar_strkey::Contract([2u8; 32]).to_string()
    }

    /// Table-driven: (input, kind, should_be_ok).
    #[test]
    fn validates_every_combination_of_kind_and_input_shape() {
        let account = valid_account();
        let contract = valid_contract();
        let flipped_account = flip_last_char(&account);
        let flipped_contract = flip_last_char(&contract);

        let cases: Vec<(&str, AddressKind, bool)> = vec![
            // Well-formed, matching kind.
            (account.as_str(), AddressKind::Account, true),
            (contract.as_str(), AddressKind::Contract, true),
            (account.as_str(), AddressKind::Either, true),
            (contract.as_str(), AddressKind::Either, true),
            // Wrong kind for an otherwise well-formed strkey.
            (contract.as_str(), AddressKind::Account, false),
            (account.as_str(), AddressKind::Contract, false),
            // Malformed: empty, garbage, truncated, non-strkey text.
            ("", AddressKind::Either, false),
            ("not-a-strkey", AddressKind::Either, false),
            ("G", AddressKind::Account, false),
            ("C", AddressKind::Contract, false),
            // Wrong-prefix strkeys (valid strkey grammar, wrong type byte):
            // a secret seed (S...) presented where an address is expected.
            (
                "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF7U",
                AddressKind::Either,
                false,
            ),
            // Wrong length: truncate a valid account strkey by one char.
            (&account[..account.len() - 1], AddressKind::Account, false),
            // Checksum-invalid: flip the last character of a valid strkey.
            (flipped_account.as_str(), AddressKind::Account, false),
            (flipped_contract.as_str(), AddressKind::Contract, false),
        ];

        for (input, kind, expect_ok) in cases {
            let result = validate_strkey(input, kind, "field");
            assert_eq!(
                result.is_ok(),
                expect_ok,
                "validate_strkey({input:?}, {kind:?}) = {result:?}, expected ok={expect_ok}"
            );
        }
    }

    fn flip_last_char(s: &str) -> String {
        let mut chars: Vec<char> = s.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        chars.into_iter().collect()
    }

    #[test]
    fn parse_address_never_panics_on_malformed_input_and_returns_decoding_error() {
        let env = Env::default();
        let err = parse_address(&env, "not-a-strkey", AddressKind::Either, "recipient")
            .expect_err("malformed strkey must be rejected, not panic");
        match err {
            SdkError::DecodingError(msg) => {
                assert!(msg.contains("recipient"));
            }
            other => panic!("expected DecodingError, got {other:?}"),
        }
    }

    #[test]
    fn parse_address_accepts_a_well_formed_matching_strkey() {
        let env = Env::default();
        let account = valid_account();
        let addr = parse_address(&env, &account, AddressKind::Account, "recipient").unwrap();
        assert_eq!(
            addr,
            Address::from_string(&SorobanString::from_str(&env, &account))
        );
    }

    #[test]
    fn parse_address_rejects_the_wrong_address_kind() {
        let env = Env::default();
        let contract = valid_contract();
        let err = parse_address(&env, &contract, AddressKind::Account, "resolver")
            .expect_err("a contract strkey must not satisfy an account-only field");
        assert!(matches!(err, SdkError::DecodingError(_)));
    }
}
