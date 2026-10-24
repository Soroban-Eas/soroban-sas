//! Host-free decoding of SAS attestations from raw XDR.
//!
//! `soroban_sas_common::Attestation` is a `#[contracttype]`, so materialising
//! one requires the Soroban host environment (`soroban_sdk::Env`). That
//! environment only exists on native targets: inside a WebAssembly sandbox
//! (Cloudflare Workers, Deno, browsers) the SDK runs with the `wasm` feature
//! enabled and has no host to talk to (#553).
//!
//! This module decodes the very same on-chain data straight from the XDR wire
//! format, so edge runtimes can read attestations without an `Env`. The
//! decoded [`AttestationRecord`] is a plain, JSON-serializable view of the
//! on-chain struct: UIDs as lowercase hex, addresses as strkey, and the
//! attestation payload as base64.
//!
//! On native targets [`crate::client::SASClient::get_attestation`] remains
//! available and returns the fully typed
//! `soroban_sas_common::Attestation`; this module is the portable
//! counterpart that works everywhere.

use serde::{Deserialize, Serialize};
use soroban_sdk::xdr::{
    AccountId, BytesM, PublicKey, ScAddress, ScBytes, ScMap, ScVal, ScVec, Uint256, VecM,
};

use crate::errors::SdkError;
use crate::rpc::RpcClient;

/// The fields of the on-chain `Attestation` struct, in declaration order.
///
/// The host encodes a `#[contracttype]` struct as a map keyed by the field
/// names, so the field names are part of the wire format. The positional
/// order is kept as well, for the (legacy) vector encoding.
const ATTESTATION_FIELDS: [&[u8]; 11] = [
    b"uid",
    b"schema_uid",
    b"time",
    b"expiration_time",
    b"revocation_time",
    b"ref_uid",
    b"recipient",
    b"attester",
    b"revocable",
    b"data",
    b"valid_from",
];

/// Length of a UID / schema UID, in bytes.
const UID_LEN: usize = 32;

/// The SAS contract function that reads an attestation without touching
/// storage, so the call can be simulated safely (no TTL renewal, no writes).
const GET_ATTESTATION_VIEW: &str = "get_attestation_view";

/// A decoded attestation, in a host-free and JSON-friendly shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRecord {
    /// Content-addressed attestation id, lowercase hex.
    pub uid: String,
    /// UID of the schema the attestation was issued under, lowercase hex.
    pub schema_uid: String,
    /// Issuance time, in unix seconds.
    pub time: u64,
    /// Expiration time, in unix seconds. `0` means "never expires".
    pub expiration_time: u64,
    /// Revocation time, in unix seconds. `0` means "not revoked".
    pub revocation_time: u64,
    /// UID of the referenced attestation, lowercase hex.
    pub ref_uid: String,
    /// Address the attestation was issued to, as strkey.
    pub recipient: String,
    /// Address that issued the attestation, as strkey.
    pub attester: String,
    /// Whether the attestation may be revoked by its attester.
    pub revocable: bool,
    /// The attestation payload, base64-encoded.
    pub data: String,
    /// Earliest time the attestation is valid from, in unix seconds.
    pub valid_from: u64,
}

impl AttestationRecord {
    /// Whether the attestation has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revocation_time != 0
    }

    /// Whether the attestation is expired at `now` (unix seconds).
    ///
    /// An `expiration_time` of `0` means the attestation never expires.
    #[must_use]
    pub fn is_expired_at(&self, now: u64) -> bool {
        self.expiration_time != 0 && self.expiration_time <= now
    }

    /// Whether the attestation is valid at `now` (unix seconds): not revoked,
    /// not expired, and past its `valid_from` timestamp.
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        !self.is_revoked() && !self.is_expired_at(now) && self.valid_from <= now
    }
}

/// Encodes a 32-byte UID as the `ScVal` the SAS contract expects as an
/// argument.
///
/// A `UID` is a `#[contracttype]` newtype, so its wire format is a
/// single-element vector wrapping the 32 raw bytes.
#[must_use]
pub fn uid_scval(uid: &[u8; UID_LEN]) -> ScVal {
    let bytes = BytesM::try_from(uid.to_vec())
        .expect("a 32-byte UID always fits into the XDR byte-string limit");
    let values = VecM::try_from(vec![ScVal::Bytes(ScBytes(bytes))])
        .expect("a single-element vector always fits into the XDR vector limit");
    ScVal::Vec(Some(ScVec(values)))
}

/// Decodes the `Option<Attestation>` returned by the SAS contract.
///
/// Returns `Ok(None)` for the `None` case (an attestation that was never
/// issued, or has been garbage-collected).
pub fn decode_optional_attestation(val: &ScVal) -> Result<Option<AttestationRecord>, SdkError> {
    match val {
        // `None` is encoded as a void value.
        ScVal::Void => Ok(None),
        // `Option<T>` may also be encoded as a zero- or one-element vector.
        ScVal::Vec(Some(ScVec(values))) => match values.len() {
            0 => Ok(None),
            1 => decode_attestation(&values[0]).map(Some),
            len => Err(SdkError::DecodingError(format!(
                "expected an optional attestation (0 or 1 elements), got {len}"
            ))),
        },
        // `Some(attestation)` is encoded as the attestation itself.
        other => decode_attestation(other).map(Some),
    }
}

/// Decodes an on-chain attestation from its `ScVal` representation.
///
/// The host encodes a `#[contracttype]` struct as a map keyed by the field
/// names; the older positional vector encoding is accepted as well.
pub fn decode_attestation(val: &ScVal) -> Result<AttestationRecord, SdkError> {
    match val {
        ScVal::Map(Some(map)) => decode_attestation_fields(
            &ATTESTATION_FIELDS
                .iter()
                .map(|name| map_get(map, name).cloned())
                .collect::<Result<Vec<_>, _>>()?,
        ),
        ScVal::Vec(Some(ScVec(values))) if values.len() == ATTESTATION_FIELDS.len() => {
            decode_attestation_fields(values.as_slice())
        }
        other => Err(SdkError::DecodingError(format!(
            "expected an attestation with {} fields, got {:?}",
            ATTESTATION_FIELDS.len(),
            other
        ))),
    }
}

/// Reads an attestation by UID, through a read-only simulation of the SAS
/// contract's `get_attestation_view`.
///
/// This is the portable counterpart of
/// [`crate::client::SASClient::get_attestation`]: it needs no host `Env`, so
/// it works on native targets and inside WebAssembly sandboxes alike.
///
/// Returns `Ok(None)` when the UID was never issued. Fails when the entry has
/// been archived (the simulation traps) — restore it first, exactly like the
/// native client does.
pub async fn fetch_attestation(
    rpc: &RpcClient,
    contract_id: &str,
    uid: &[u8; UID_LEN],
) -> Result<Option<AttestationRecord>, SdkError> {
    let tx_xdr = crate::simulate::build_simulate_transaction_xdr(
        contract_id,
        GET_ATTESTATION_VIEW,
        vec![uid_scval(uid)],
    )?;
    let result = rpc.simulate_transaction_async(&tx_xdr).await?;
    if let Some(error) = result.error {
        if let Some(code) = crate::errors::extract_contract_error_code(&error) {
            return Err(SdkError::ContractError(code));
        }
        return Err(SdkError::SimulationError(error));
    }
    let first = result
        .results
        .first()
        .ok_or_else(|| SdkError::RpcError("simulation returned no results".to_string()))?;
    let sc_val = crate::simulate::decode_scval(&first.xdr)?;
    decode_optional_attestation(&sc_val)
}

/// Decodes the attestation fields, in declaration order.
fn decode_attestation_fields(fields: &[ScVal]) -> Result<AttestationRecord, SdkError> {
    if fields.len() != ATTESTATION_FIELDS.len() {
        return Err(SdkError::DecodingError(format!(
            "expected an attestation with {} fields, got {}",
            ATTESTATION_FIELDS.len(),
            fields.len()
        )));
    }
    Ok(AttestationRecord {
        uid: decode_uid(&fields[0])?,
        schema_uid: decode_uid(&fields[1])?,
        time: decode_u64(&fields[2])?,
        expiration_time: decode_u64(&fields[3])?,
        revocation_time: decode_u64(&fields[4])?,
        ref_uid: decode_uid(&fields[5])?,
        recipient: decode_address(&fields[6])?,
        attester: decode_address(&fields[7])?,
        revocable: decode_bool(&fields[8])?,
        data: decode_bytes(&fields[9])?,
        valid_from: decode_u64(&fields[10])?,
    })
}

/// Looks a field up in a contracttype map, by its symbol key.
fn map_get<'a>(map: &'a ScMap, key: &[u8]) -> Result<&'a ScVal, SdkError> {
    map.0
        .iter()
        .find(|entry| matches!(&entry.key, ScVal::Symbol(sym) if sym.0.as_slice() == key))
        .map(|entry| &entry.val)
        .ok_or_else(|| {
            SdkError::DecodingError(format!(
                "attestation is missing the `{}` field",
                String::from_utf8_lossy(key)
            ))
        })
}

/// Parses a 32-byte UID from its hex representation.
///
/// Edge runtimes usually receive UIDs as hex (a URL path segment, a query
/// parameter, a JSON body), so this is the counterpart of the hex rendering
/// used by [`AttestationRecord::uid`].
pub fn uid_from_hex(hex: &str) -> Result<[u8; UID_LEN], SdkError> {
    let trimmed = hex.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() != UID_LEN * 2 {
        return Err(SdkError::DecodingError(format!(
            "expected a {}-character hex UID, got {}",
            UID_LEN * 2,
            bytes.len()
        )));
    }
    let mut uid = [0u8; UID_LEN];
    for (index, byte) in uid.iter_mut().enumerate() {
        let high = hex_digit(bytes[index * 2])?;
        let low = hex_digit(bytes[index * 2 + 1])?;
        *byte = (high << 4) | low;
    }
    Ok(uid)
}

/// Decodes a single hex digit.
fn hex_digit(byte: u8) -> Result<u8, SdkError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(SdkError::DecodingError(format!(
            "invalid hex character `{}`",
            byte as char
        ))),
    }
}

/// Decodes a UID (a `#[contracttype]` newtype) into lowercase hex.
fn decode_uid(val: &ScVal) -> Result<String, SdkError> {
    // A newtype wraps its single field in a one-element vector; accept the
    // unwrapped shape too so the decoder is not tied to that detail.
    let bytes = match val {
        ScVal::Vec(Some(ScVec(values))) if values.len() == 1 => decode_raw_bytes(&values[0])?,
        other => decode_raw_bytes(other)?,
    };
    if bytes.len() != UID_LEN {
        return Err(SdkError::DecodingError(format!(
            "expected a {UID_LEN}-byte UID, got {} bytes",
            bytes.len()
        )));
    }
    Ok(to_hex(&bytes))
}

/// Decodes a byte string into base64.
fn decode_bytes(val: &ScVal) -> Result<String, SdkError> {
    let bytes = decode_raw_bytes(val)?;
    Ok(base64::encode_config(&bytes, base64::STANDARD))
}

/// Decodes a byte string into its raw bytes.
fn decode_raw_bytes(val: &ScVal) -> Result<Vec<u8>, SdkError> {
    match val {
        ScVal::Bytes(ScBytes(bytes)) => Ok(bytes.as_slice().to_vec()),
        other => Err(SdkError::DecodingError(format!(
            "expected a byte string, got {:?}",
            other
        ))),
    }
}

/// Decodes a `u64` field.
fn decode_u64(val: &ScVal) -> Result<u64, SdkError> {
    match val {
        ScVal::U64(value) => Ok(*value),
        other => Err(SdkError::DecodingError(format!(
            "expected a u64, got {:?}",
            other
        ))),
    }
}

/// Decodes a `bool` field.
fn decode_bool(val: &ScVal) -> Result<bool, SdkError> {
    match val {
        ScVal::Bool(value) => Ok(*value),
        other => Err(SdkError::DecodingError(format!(
            "expected a bool, got {:?}",
            other
        ))),
    }
}

/// Decodes an address field into its strkey representation.
fn decode_address(val: &ScVal) -> Result<String, SdkError> {
    match val {
        ScVal::Address(address) => address_to_strkey(address),
        other => Err(SdkError::DecodingError(format!(
            "expected an address, got {:?}",
            other
        ))),
    }
}

/// Renders an `ScAddress` as strkey (`G...` for accounts, `C...` for
/// contracts).
fn address_to_strkey(address: &ScAddress) -> Result<String, SdkError> {
    match address {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key)))) => {
            Ok(stellar_strkey::ed25519::PublicKey(*key).to_string())
        }
        ScAddress::Contract(hash) => Ok(stellar_strkey::Contract(hash.0).to_string()),
    }
}

/// Lowercase hex encoding of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Bytes, BytesN, Env};

    /// Builds the positional (`ScVal::Vec`) encoding of a contracttype
    /// struct: a vector of its fields.
    fn struct_val(fields: Vec<ScVal>) -> ScVal {
        ScVal::Vec(Some(ScVec(
            VecM::try_from(fields).expect("test vectors are small enough to fit"),
        )))
    }

    fn bytes_val(bytes: &[u8]) -> ScVal {
        ScVal::Bytes(ScBytes(
            BytesM::try_from(bytes.to_vec()).expect("test byte strings are small enough to fit"),
        ))
    }

    /// `soroban_sdk::Address` renders as a `soroban_sdk::String`, which has no
    /// `Display` impl; copy the strkey out of it for comparison.
    fn address_strkey(address: &Address) -> String {
        let soroban_string = address.to_string();
        let len = soroban_string.len() as usize;
        let mut buf = [0u8; 64];
        soroban_string.copy_into_slice(&mut buf[..len]);
        std::str::from_utf8(&buf[..len])
            .expect("a strkey is valid UTF-8")
            .to_string()
    }

    fn account_val() -> (ScVal, String) {
        let env = Env::default();
        let address = Address::generate(&env);
        let strkey = address_strkey(&address);
        let sc = crate::simulate::encode_arg(&env, &address).unwrap();
        (sc, strkey)
    }

    #[test]
    fn decodes_a_hand_built_attestation() {
        let (recipient, recipient_strkey) = account_val();
        let (attester, attester_strkey) = account_val();

        let uid = [7u8; UID_LEN];
        let schema_uid = [9u8; UID_LEN];
        let ref_uid = [11u8; UID_LEN];

        let val = struct_val(vec![
            uid_scval(&uid),
            uid_scval(&schema_uid),
            ScVal::U64(1_700_000_000),
            ScVal::U64(1_800_000_000),
            ScVal::U64(0),
            uid_scval(&ref_uid),
            recipient,
            attester,
            ScVal::Bool(true),
            bytes_val(b"payload"),
            ScVal::U64(1_699_000_000),
        ]);

        let record = decode_attestation(&val).unwrap();
        assert_eq!(record.uid, to_hex(&uid));
        assert_eq!(record.schema_uid, to_hex(&schema_uid));
        assert_eq!(record.ref_uid, to_hex(&ref_uid));
        assert_eq!(record.time, 1_700_000_000);
        assert_eq!(record.expiration_time, 1_800_000_000);
        assert_eq!(record.revocation_time, 0);
        assert_eq!(record.recipient, recipient_strkey);
        assert_eq!(record.attester, attester_strkey);
        assert!(record.revocable);
        assert_eq!(
            record.data,
            base64::encode_config(b"payload", base64::STANDARD)
        );
        assert_eq!(record.valid_from, 1_699_000_000);
        assert!(!record.is_revoked());
        assert!(!record.is_expired_at(1_700_000_000));
        assert!(record.is_valid_at(1_700_000_000));
    }

    #[test]
    fn decodes_the_none_case() {
        assert!(decode_optional_attestation(&ScVal::Void).unwrap().is_none());
        let none = ScVal::Vec(Some(ScVec(VecM::try_from(Vec::<ScVal>::new()).unwrap())));
        assert!(decode_optional_attestation(&none).unwrap().is_none());
    }

    #[test]
    fn decodes_the_some_case() {
        let uid = [3u8; UID_LEN];
        let (recipient, _) = account_val();
        let (attester, _) = account_val();
        let attestation = struct_val(vec![
            uid_scval(&uid),
            uid_scval(&uid),
            ScVal::U64(1),
            ScVal::U64(0),
            ScVal::U64(2),
            uid_scval(&uid),
            recipient,
            attester,
            ScVal::Bool(false),
            bytes_val(b""),
            ScVal::U64(0),
        ]);
        let some = ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![attestation]).expect("single element fits"),
        )));
        let decoded = decode_optional_attestation(&some).unwrap().unwrap();
        assert_eq!(decoded.uid, to_hex(&uid));
        assert!(decoded.is_revoked());
        // `expiration_time == 0` means "never expires".
        assert!(!decoded.is_expired_at(u64::MAX));
    }

    #[test]
    fn rejects_a_struct_with_the_wrong_number_of_fields() {
        let val = struct_val(vec![ScVal::U64(1)]);
        assert!(decode_attestation(&val).is_err());
    }

    #[test]
    fn rejects_a_uid_of_the_wrong_length() {
        let val = struct_val(vec![bytes_val(&[1u8; 8])]);
        assert!(decode_uid(&val).is_err());
    }

    /// The decoder must agree with the encoding the host produces for
    /// `soroban_sas_common::Attestation`, otherwise edge runtimes would read
    /// different data than the contract stored.
    #[test]
    fn matches_the_host_encoding_of_a_real_attestation() {
        use soroban_sas_common::{Attestation, UID};

        let env = Env::default();
        let recipient = Address::generate(&env);
        let attester = Address::generate(&env);
        let attestation = Attestation {
            uid: UID(BytesN::from_array(&env, &[5u8; UID_LEN])),
            schema_uid: UID(BytesN::from_array(&env, &[2u8; UID_LEN])),
            time: 42,
            expiration_time: 84,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[3u8; UID_LEN])),
            recipient: recipient.clone(),
            attester: attester.clone(),
            revocable: true,
            data: Bytes::from_slice(&env, b"hello"),
            valid_from: 21,
        };

        let sc_val = crate::simulate::encode_arg(&env, &attestation).unwrap();
        let record = decode_attestation(&sc_val).unwrap();

        assert_eq!(record.time, 42);
        assert_eq!(record.expiration_time, 84);
        assert_eq!(record.revocation_time, 0);
        assert_eq!(record.valid_from, 21);
        assert!(record.revocable);
        assert_eq!(record.recipient, address_strkey(&recipient));
        assert_eq!(record.attester, address_strkey(&attester));
        assert_eq!(
            record.data,
            base64::encode_config(b"hello", base64::STANDARD)
        );
        assert_eq!(record.uid, to_hex(&[5u8; UID_LEN]));
        assert_eq!(record.schema_uid, to_hex(&[2u8; UID_LEN]));
        assert_eq!(record.ref_uid, to_hex(&[3u8; UID_LEN]));
    }

    /// The `Option<Attestation>` shape the host produces must decode to
    /// `Some(..)` / `None` exactly like the host does.
    #[test]
    fn matches_the_host_encoding_of_an_optional_attestation() {
        use soroban_sas_common::{Attestation, UID};

        let env = Env::default();
        let attestation = Attestation {
            uid: UID(BytesN::from_array(&env, &[4u8; UID_LEN])),
            schema_uid: UID(BytesN::from_array(&env, &[2u8; UID_LEN])),
            time: 1,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0u8; UID_LEN])),
            recipient: Address::generate(&env),
            attester: Address::generate(&env),
            revocable: false,
            data: Bytes::new(&env),
            valid_from: 0,
        };

        let some = crate::simulate::encode_arg(&env, &Some(attestation)).unwrap();
        let decoded = decode_optional_attestation(&some).unwrap().unwrap();
        assert_eq!(decoded.uid, to_hex(&[4u8; UID_LEN]));

        let none = crate::simulate::encode_arg(&env, &Option::<Attestation>::None).unwrap();
        assert!(decode_optional_attestation(&none).unwrap().is_none());
    }

    /// The `UID` argument must be encoded exactly like the host encodes it,
    /// or the contract rejects the call.
    #[test]
    fn builds_the_uid_argument_the_host_expects() {
        use soroban_sas_common::UID;

        let env = Env::default();
        let uid = BytesN::from_array(&env, &[8u8; UID_LEN]);
        let sc_val = crate::simulate::encode_arg(&env, &UID(uid)).unwrap();
        assert_eq!(sc_val, uid_scval(&[8u8; UID_LEN]));
    }

    #[test]
    fn hex_encoding_is_lowercase_and_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(to_hex(&[]), "");
    }

    #[test]
    fn parses_uids_from_hex() {
        let uid = [0x0au8; UID_LEN];
        let hex = to_hex(&uid);
        assert_eq!(uid_from_hex(&hex).unwrap(), uid);
        // Uppercase and surrounding whitespace are accepted.
        assert_eq!(uid_from_hex(&hex.to_uppercase()).unwrap(), uid);
        assert_eq!(uid_from_hex(&format!("  {hex}  ")).unwrap(), uid);
        // Wrong length and non-hex characters are rejected.
        assert!(uid_from_hex("abcd").is_err());
        assert!(uid_from_hex(&"z".repeat(UID_LEN * 2)).is_err());
    }
}
