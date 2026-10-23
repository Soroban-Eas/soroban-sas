//! Decode the concatenated Soroban XDR values used by attestation payloads.

use serde_json::Value;
use soroban_sdk::xdr::{Hash, Limited, Limits, ReadXdr, ScAddress, ScVal};
use std::fmt;
use std::io::{Cursor, Read};

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedField {
    pub name: String,
    pub field_type: String,
    pub value: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

fn parse_schema(schema: &str) -> Result<Vec<(&str, &str)>, DecodeError> {
    schema
        .split(',')
        .map(|part| {
            let (name, ty) = part.split_once(' ').ok_or_else(|| {
                DecodeError(format!(
                    "invalid schema field {part:?}: expected `name Type`"
                ))
            })?;
            let ty = ty.trim();
            if name.is_empty() || ty.is_empty() {
                return Err(DecodeError(format!(
                    "invalid schema field {part:?}: expected `name Type`"
                )));
            }
            Ok((name, ty))
        })
        .collect()
}

fn normalized_type(ty: &str) -> String {
    ty.trim().to_ascii_lowercase()
}

fn json_u128(value: u128) -> Value {
    if value <= i64::MAX as u128 {
        Value::from(value as u64)
    } else {
        Value::String(value.to_string())
    }
}

fn json_i128(value: i128) -> Value {
    if let Ok(value) = i64::try_from(value) {
        Value::from(value)
    } else {
        Value::String(value.to_string())
    }
}

fn decode_address(address: ScAddress) -> Value {
    match address {
        ScAddress::Account(account) => match account.0 {
            soroban_sdk::xdr::PublicKey::PublicKeyTypeEd25519(key) => {
                Value::String(stellar_strkey::ed25519::PublicKey(key.0).to_string())
            }
        },
        ScAddress::Contract(Hash(hash)) => {
            Value::String(stellar_strkey::contract::Contract(hash).to_string())
        }
    }
}

fn decode_value(field: &str, ty: &str, value: ScVal) -> Result<Value, DecodeError> {
    let mismatch = |actual: &str| {
        DecodeError(format!(
            "field {field}: schema type {ty:?} does not match XDR value {actual}"
        ))
    };
    match (normalized_type(ty).as_str(), value) {
        ("bool", ScVal::Bool(value)) => Ok(Value::Bool(value)),
        ("u32" | "uint32", ScVal::U32(value)) => Ok(Value::from(value)),
        ("i32" | "int32", ScVal::I32(value)) => Ok(Value::from(value)),
        ("u64" | "uint64", ScVal::U64(value)) => Ok(Value::from(value)),
        ("i64" | "int64", ScVal::I64(value)) => Ok(Value::from(value)),
        ("u128" | "uint128", ScVal::U128(value)) => Ok(json_u128(
            (u128::from(value.hi) << 64) | u128::from(value.lo),
        )),
        ("i128" | "int128", ScVal::I128(value)) => Ok(json_i128(
            (i128::from(value.hi) << 64) | i128::from(value.lo),
        )),
        ("string" | "str", ScVal::String(value)) => value
            .0
            .to_utf8_string()
            .map(Value::String)
            .map_err(|_| DecodeError(format!("field {field}: string is not valid UTF-8"))),
        ("bytes", ScVal::Bytes(value)) => Ok(Value::String(format!("0x{value}"))),
        ("address", ScVal::Address(value)) => Ok(decode_address(value)),
        (
            "bool" | "u32" | "uint32" | "i32" | "int32" | "u64" | "uint64" | "i64" | "int64"
            | "u128" | "uint128" | "i128" | "int128" | "string" | "str" | "bytes" | "address",
            _,
        ) => Err(mismatch("different primitive")),
        _ => Err(DecodeError(format!(
            "field {field}: unsupported schema type {ty:?}"
        ))),
    }
}

/// Decode one XDR value per schema field. Each value is read independently so
/// malformed, truncated, trailing, and type-mismatched payloads are rejected.
pub fn decode_payload(schema: &str, payload: &[u8]) -> Result<Vec<DecodedField>, DecodeError> {
    let fields = parse_schema(schema)?;
    let mut cursor = Cursor::new(payload);
    let mut decoded = Vec::with_capacity(fields.len());

    for (name, ty) in fields {
        let start = cursor.position();
        let mut limited = Limited::new(&mut cursor, Limits::none());
        let value = ScVal::read_xdr(&mut limited).map_err(|error| {
            DecodeError(format!(
                "field {name}: invalid or truncated XDR at byte {start}: {error}"
            ))
        })?;
        let value = decode_value(name, ty, value)?;
        decoded.push(DecodedField {
            name: name.to_string(),
            field_type: ty.to_string(),
            value,
        });
    }

    let mut trailing = Vec::new();
    cursor
        .read_to_end(&mut trailing)
        .map_err(|error| DecodeError(format!("could not inspect payload remainder: {error}")))?;
    if !trailing.is_empty() {
        return Err(DecodeError(format!(
            "payload has {} trailing byte(s) after decoding {} field(s)",
            trailing.len(),
            decoded.len()
        )));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::xdr::WriteXdr;

    fn xdr(value: ScVal) -> Vec<u8> {
        value.to_xdr(Limits::none()).unwrap()
    }

    #[test]
    fn decodes_mixed_schema() {
        let mut payload = xdr(ScVal::Bool(true));
        payload.extend(xdr(ScVal::U32(42)));
        payload.extend(xdr(ScVal::String("bob".parse().unwrap())));
        payload.extend(xdr(ScVal::Bytes(vec![1, 2].try_into().unwrap())));
        let fields = decode_payload(
            "verified bool, count u32, label String, raw Bytes",
            &payload,
        )
        .unwrap();
        assert_eq!(fields[0].value, Value::Bool(true));
        assert_eq!(fields[1].value, Value::from(42));
        assert_eq!(fields[2].value, Value::from("bob"));
        assert_eq!(fields[3].value, Value::from("0x0102"));
    }

    #[test]
    fn rejects_corrupt_and_mismatched_payloads() {
        assert!(decode_payload("ok bool", &[0, 0, 0, 0]).is_err());
        assert!(decode_payload("count u64", &xdr(ScVal::U32(1)))
            .unwrap_err()
            .to_string()
            .contains("does not match"));
        let mut payload = xdr(ScVal::Bool(true));
        payload.push(0);
        assert!(decode_payload("ok bool", &payload)
            .unwrap_err()
            .to_string()
            .contains("trailing"));
    }

    #[test]
    fn decodes_integer_and_address_layouts() {
        let mut payload = xdr(ScVal::I32(-3));
        payload.extend(xdr(ScVal::U64(9)));
        payload.extend(xdr(ScVal::I128(soroban_sdk::xdr::Int128Parts {
            hi: -1,
            lo: u64::MAX - 6,
        })));
        payload.extend(xdr(ScVal::Address(ScAddress::Contract(Hash([7; 32])))));
        let fields =
            decode_payload("delta i32, total u64, signed i128, owner Address", &payload).unwrap();
        assert_eq!(fields[0].value, Value::from(-3));
        assert_eq!(fields[1].value, Value::from(9));
        assert_eq!(fields[2].value, Value::from(-7));
        assert!(fields[3].value.as_str().unwrap().starts_with('C'));
    }
}
