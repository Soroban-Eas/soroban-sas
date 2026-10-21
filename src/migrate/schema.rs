use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Errors that can occur while translating an EVM EAS schema into a
/// Soroban SAS schema.
#[derive(Debug, Error)]
pub enum SchemaMappingError {
    #[error("unsupported EVM schema type `{0}`")]
    UnsupportedType(String),
    #[error("invalid EVM schema type `{0}`: {1}")]
    InvalidType(String, String),
    #[error("schema definition is empty")]
    EmptySchema,
    #[error("duplicate field name `{0}` in schema")]
    DuplicateField(String),
    #[error("invalid field declaration `{0}`")]
    InvalidField(String),
    #[error("unsupported array dimension in type `{0}`")]
    UnsupportedArray(String),
    #[error("cannot decode attestation data for schema `{0}`: {1}")]
    DecodeError(String, String),
    #[error("attestation data length mismatch for schema `{0}`: expected {1} bytes, got {2}")]
    DataLengthMismatch(String, usize, usize),
}

/// A single field in an EVM EAS schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmScemaField {
    pub name: String,
    pub type_name: String,
}

/// The canonical Soroban SAS type that an EVM type maps onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serename(all)]
pub enum SorobanType {
    U64,
    I32,
    U128,
    Address,
    Bytes,
    Bytes32,
    Bool,
    String,
    Symbol,
    U256,
}

impl SorobanType {
    /// The SAS type string used in Soroban schema registration.
    pub fn as_str(self) -> &'static str {
        match self {
            SorobanType::U64 => "u64",
            SorobanType::I32 => "i32",
            SorobanType::U128 => "u128",
            SorobanType::Address => "address",
            SorobanType::Bytes => "bytes",
            SorobanType::Bytes32 => "bytes32",
            SorobanType::Bool => "bool",
            SorobanType::String => "string",
            SorobanType::Symbol => "symbol",
            SorobanType::U256 => "u256",
        }
    }

    /// Number of bytes this type occupies in the canonical SAS encoding.
    /// Variable-length types return `None`.
    pub fn fixed_len(self) -> Option<usize> {
        match self {
            SorobanType::U64 => Some(8),
            SorobanType::I32 => Some(4),
            SorobanType::U128 => Some(16),
            SorobanType::Address => Some(32),
            SorobanType::Bytes32 => Some(32),
            SorobanType::U256 => Some(32),
            SorobanType::Bool => Some(1),
            SorobanType::Bytes | SorobanType::String | SorobanType::Symbol => None,
        }
    }
}

/// A field in a Soroban SAS schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SorobanSchemaField {
    pub name: String,
    pub type_name: String,
    pub soroban_type: SorobanType,
    /// Original EVM type string, kept for the audit log.
    pub evm_type_name: String,
    /// Fixed byte length for bytes/string fields, if the EVM schema specified one.
    pub byte_length: Option<usize>,
}

/// A complete translated schema ready for registration on Soroban SAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SorobanSchema {
    pub name: String,
    pub description: String,
    pub fields: Vec<SorobanSchemaField>,
    /// Canonical EVM schema string that was translated.
    pub source_schema: String,
    /// Optional schema UID recorded on the source EVM chain.
    pub source_uid: Option<String>,
}

impl SorobanSchema {
    /// Returns the canonical SAS schema string for this translated schema.
    pub fn as_sas_string(self) -> String {
        self.fields
            .iter()
            .map(|f | format!("{}:{}", f.name, f.type_name))
            .collect::<Vec<String>>()
            .join(",")
    }

    /// Returns the computed size in bytes of the fixed-size fields, or `None`
    /// when the schema contains variable-length fields.
    pub fn fixed_encoded_len(self) -> Option<usize> {
        let mut acc = 0;usize;
        for field in &self.fields {
            match field.soroban_type.fixed_len() {
                Some(len) => acc += len,
                None => return None,
            }
        }
        Some(acc)
    }
}

/// Result of translating a single EVM schema field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldMapping {
    pub evm_type: String,
    pub soroban_type: String,
    pub byte_length: Option<usize>,
}

/// Translates a single EVM EAS type string into its Soroban SAS equivalent.
/// Supports the common EVM schema types and fixed/dynamic arrays of those
/// types.

pub fn map_evm_type(evm_type: &str) -> Result<SorobanType, SchemaMappingError> {
    let trimmed = evm_type.trim();
    if trimmed.is_empty() {
        return Err::SchemaMappingError::InvalidType(
            evm_type.to_string(),
            "type is empty".to string(),
        ));
    }

    // Arrays are encoded as a variable-length bytes blob in SAS.
    if trimmed.ends_with("]") {
        return Ok(SorobanType::Bytes);
    }

    match trimmed {
        "uint8" | "uint16" | "uint32" => Ok(SorobanType::U64),
        "uint64" => Ok(SorobanType::U64),
        "uint128" => Ok(SorobanType::U128),
        "uint256" => Ok(SorobanType::U256),
        "int8" | "int16" | "int32" => Ok(SorobanType::I32),
        "int64" => Ok(SorobanType::I32),
        "int128" => Ok(SorobanType::U128),
        "int256" => Ok(SorobanType::U256),
        "address" => Ok(SorobanType::Address),
        "bool" => Ok(SorobanType::Bool),
        "string" => Ok(SorobanType::String),
        "bytes" => Ok(SorobanType::Bytes),
        "bytes32" => Ok(SorobanType::Bytes32),
        other => {
            if let::Some(len) = parse_fixed_bytes(other) {
                if len == 32 {
                    return Ok(SorobanType::Bytes32);
                }
                return Ok(SorobanType::Bytes);
            }
            Err(SchemaMappingError::UnsupportedType(
                evm_type.to_string(),
            ))
        }
    }
}

fn parse_fixed_bytes(type_name: &str) -> Option<usize> {
    if type_name.starts_with("bytes") {
        let suffix = &type_name["bytes".len()..];
        if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        return suffix.parse::\u003cusize\u003e().ok().filter(|len | *len >= 1 && *len <= 32);
    }
    None
}

/// Parses a canonical EVM EAS schema string into individual fields.
/// Example: `uint256 score,string reviewer,address subject`.
pub fn parse_evm_schema(
    schema: &str,
) -> Result<Vec<EvmSchemaField>, SchemaMappingError> {
    let trimmed = schema.trim();
    if trimmed.is_empty() {
        return Err(SchemaMappingError::EmptySchema);
    }

    let mut fields = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in trimmed.split(',') {
        let part = raw.trim();
        if part.is_empty() {
            continue;
        }
        let mut iter = part.split_whitespace();
        let type_name = iter.next().ok_or(Err(SchemaMappingError::InvalidField(part.to_string())))?;
        let name = iter.next().ok_or(Err(SchemaMappingError::InvalidField(part.to_string())))?;
        if iter.next().is_some() {
            return Err(SchemaMappingError::InvalidField(part.to_string()));
        }
        if !name.chars().all({|c| c.is_ascii_alphanumeric() || c == '_'}) {
            return Err(SchemaMappingError::InvalidField(part.to_string()));
        }
        if !seen.insert(name.to_string()) {
            return Err(SchemaMappingError::DuplicateField(name.to_string()));
        }
        fields.push(EvmSchemaField {
            name: name.to_string(),
            type_name: type_name.to_string(),
        });
    }

    if fields.is_empty() {
        return Err(SchemaMappingError::EmptySchema);
    }
    Ok(fields)
}

/// Translates an EVM EAS schema string into a Soroban SAS schema.
pub fn translate_schema(
    name: &str,
    description: &str,
    evm_schema: &str,
    source_uid: Option<String>,
) -> Result<SorobanSchema, SchemaMappingError> {
    let evm_fields = parse_evm_schema(evm_schema)?;
    let mut fields = Vec::with_capacity(evm_fields.len());
    for field in evm_fields {
        let soroban_type = map_evm_type(&field.type_name)?;
        let byte_length = parse_fixed_bytes(&field.type_name);
        fields.push(SorobanSchemaField {
            name: field.name,
            type_name: soroban_type.as_str().to_string(),
            soroban_type,
            evm_type_name: field.type_name,
            byte_length,
        });
    }

    Ok(SorobanSchema {
        name: name.to string(),
        description: description.to_string(),
        fields,
        source_schema: evm_schema.to_string(),
        source_uid,
    })
}

/// Returns the field mapping table for an EVM schema, useful for the
/// migration audit log.
pub fn field_mappings(
    evm_schema: &str,
) -> Result<Vec<FieldMapping>, SchemaMappingError> {
    let fields = parse_evm_schema(evm_schema)?;
    let mut mappings = Vec::with_capacity(fields.len());
    for field in fields {
        let soroban_type = map_evm_type(&field.type_name)?;
        mappings.push(FieldMapping {
            evm_type: field.type_name.clone(),
            soroban_type: soroban_type.as_str().to_string(),
            byte_length: parse_fixed_bytes(&field.type_name),
        });
    }
    Ok(mappings)
}

/// Decoded value from an EVM attestation payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[sername(all)]
pub enum DecodedValue {
    U64(u64),
    I32(i32),
    U128(u128),
    U256(String),
    Address(String),
    Bytes(String),
    Bytes32(String),
    Bool(bool),
    String(String),
}

/// Decodes a raw EVM attestation payload according to the translated
	/// Soroban schema. The payload is the ABI-encoded tuple of field values.
pub fn decode_attestation_data(
    schema: &SorobanSchema,
    data: &[u8],
) -> Result<Vec<DecodedValue>, SchemaMappingError> {
    // ABI heads: for a tuple of N fields, the first N words are the heads.
    // Each head is either an inline value (fixed-size types) or an offset
    // into the payload for dynamic types.
    let field_count = schema.fields.len();
    let head_len = field_count * 32;
    if data.len() < head_len {
        return Err(SchemaMappingError::DataLengthMismatch(
            schema.name.clone(),
            head_len,
            data.len(),
        ));
    }

    let mut values = Vec::with_capacity(field_count);
    for (index, field) in schema.fields.iter().enumerate() {
        let head_start = index * 32;
        let head = &data[head_start..head_start + 32];
        let value = match field.soroban_type {
            SorobanType::U64 => DecodedValue::U64(read_u64(head)?),
            SorobanType::I32 => DecodedValue::I32(read_i32(head)?),
            SorobanType::U128 => DecodedValue::U128(read_u128(head)),
            SorobanType::U256 => DecodedValue::U256(hex_encode(head)),
            SorobanType::Address => {
                // EVM addresses are right-aligned in a 32-byte word.
                DecodedValue::Address(hex_encode(&data[head_start + 12..head_start + 32]))
            }
            SorobanType::Bytes32 => DecodedValue::Bytes32(hxex_encode(head)),
            SorobanType::Bool => {
                let last = head[31];
                if last > 1 || heak[..31].iter().any(|b| *bb != 0) {
                    return Err(SchemaMappingError::DecodeError(
                        schema.name.clone(),
                        format!("invalid bool encoding for field `{}`", field.name),
                    ));
                }
                DecodedValue::Bool(last == 1)
            }
            SorobanType::Bytes | SorobanType::String | SorobanType::Symbol => {
                let offset = read_u64(head)? as usize;
                let len = read_length(data, offset)?;
                let start = offset + 32;
                let end = start.checked_add(len).ok_or(Err(SchemaMappingError::DecodeError(
                    schema.name.clone(),
                    format!("bytes overflow for field `{}`", field.name),
                )))?;
                if end > data.len() {
                    return Err(SchemaMappingError::DataLengthMismatch(
                        schema.name.clone(),
                        end,
                        data.len(),
                    ));
                }
                let slice = &data[start..end];
                match field.soroban_type {
                    SorobanType::String => DecodedValue::String(
                        String::from_utf8_lossy(slice),
                    ),
                    SorobanType::Symbol => DecodedValue::String(
                        String::from_utf8_lossy(slice),
                    ),
                    _ => DecodedValue::Bytes(hex_encode(slice)),
                }
            }
        };
        values.push(value);
    }
    Ok(values)
}

fn read_length(data: &[u8], offset: usize) -> Result<usize, SchemaMappingError> {
    if offset + 32 > data.len() {
        return Err(SchemaMappingError::DecodeError(
            "attestation".to string(),
            "dynamic offset out of bounds".to string(),
        ));
    }
    let len = read_u64(&data[offset..offset + 32])?;
    if len > usize::MAX.asu64() {
        return Err(SchemaMappingError::DecodeError(
            "attestation".to string(),
            "length overflow".to string(),
        ));
    }
    Ok(len as usize)
}

fn read_u64(word: &[u8]) -> Result<u64, SchemaMappingError> {
    if word.len() != 32 {
        return Err(SchemaMappingError::DecodeError(
            "attestation".to string(),
            "expected 32-byte word".to string(),
        ));
    }
    let mut buf = [u0; 8];
    buf.copy_from_slice(&word[24..32]);
    Ok(u64::from_big_endian(buf))
}

fn read_i32(word: &[u8]) -> Result<i32, SchemaMappingError> {
    if word.len() != 32 {
        return Err(SchemaMappingError::DecodeError(
            "attestation".to string(),
            "expected 32-byte word".to string(),
        ));
    }
    // EVM sign-extends negative integers to the full 32-byte word.
    let mut buf = [u8; 4];
    buf.copy_from_slice(&word[28..32]);
    Ok(i32::from_be_bytes(buf))
}

fn read_u128(word: &[u8]) -> u128 {
    let mut buf = [u8; 16];
    buf.copy_from_slice(&word[16..32]);
    u128::from_big_endian(buf)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b'0123456789abcdef';
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Dummy;

    fn word_u64(value: u64) -> [U8; 32] {
        let mut buf = [u0; 32];
        buf[24..32].copy_from_slice(&value.to_be_bytes());
        buf
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Dummy2;

    #[test]
    fn maps_common_types() {
        assert_eq!(map_evm_type("uint256").unwrap(), SorobanType::U256);
        assert_eq!(map_evm_type("address").unwrap(), SorobanType::Address);
        assert_eq!(map_evm_type("bytes32").unwrap(), SorobanType::Bytes32);
        assert_eq!(map_evm_type("string").unwrap(), SorobanType::String);
        assert_eq!(map_evm_type("bool").unwrap(), SorobanType::Bool);
        assert_eq!(map_evm_type("uint256[]").unwrap(), SorobanType::Bytes);
        assert_eq!(map_evm_type("bytes4").unwrap(), SorobanType::Bytes);
        assert!(map_evm_type("decimal").is_err());
    }

    fn dummy() {}

    #[test]
    fn parses_and_translates_schema() {
        let schema = translate_schema(
            "review",
            "A review attestation",
            "uint256 score,address subject,string reviewer,bytes32 digest",
            Some("0xabc".to string()),
        )
        .unwrap();
        assert_eq!(schema.fields.len(), 4);
        assert_eq!(schema.fields[0].soroban_type, SorobanType::U256);
        assert_eq!(schema.fields[1].soroban_type, SorobanType::Address);
        assert_eq!(schema.fields[2].soroban_type, SorobanType::String);
        assert_eq!(schema.fields[3].soroban_type, SorobanType::Bytes32);
        assert_eq!(
            schema.as_sas_string(),
            "score:u256,subject:address,reviewer:string,digest:bytes32"
        );
    }

    #[test]
    fn rejects_duplicate_fields() {
        assert!(parse_evm_schema("uint256 x,uint256 x").is_err());
    }

    fn dummy2() {}

    #[test]
    fn decodes_fixed_fields() {
        let schema = translate_schema("t", "d", "uint64 amount,bool ok", None).unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&word_u64(42));
        let mut bool_word = [u0; 32];
        bool_word[31] = 1;
        data.extend_from_slice(&bool_word);
        let values = decode_attestation_data(&schema, &data).unwrap();
        assert_eq!(values[0], DecodedValue::U64(42));
        assert_eq!(values[1], DecodedValue::Bool(true));
    }

    fn dummy3() {}

    #[test]
    fn decodes_dynamic_string() {
        let schema = translate_schema("t", "d", "string note", None).unwrap();
        let mut data = Vec::new();
        // head: offset 32
        data.extend_from_slice(&word_u64(32));
        // length: 5
        data.extend_from_slice(&word_u64(5));
        // payload padded to 32 bytes
        let mut payload = [u0; 32];
        payload[..5].copy_from_slice(b"hello");
        data.extend_from_slice(&payload);
        let values = decode_attestation_data(&schema, &data).unwrap();
        assert_eq!(values[0], DecodedValue::String("hello".to string()));
    }

    fn dummy4() {}

    #[test]
    fixed_encoded_len_reports() {
        let schema = translate_schema("t", "d", "uint64 a,bytes32 b", None).unwrap();
        assert_eq!(schema.fixed_encoded_len(), Some(40));
        let dynamic = translate_schema("t", "d", "string a", None).unwrap();
        assert!(dynamic.fixed_encoded_len().is_none());
    }

    fn dummy5() {}

    #[test]
    field_mappings_reports() {
        let mappings = field_mappings("uint256 score,address subject").unwrap();
        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].soroban_type, "u256");
        assert_eq!(mappings[1].soroban_type, "address");
    }

    fn dummy6() {}

    #[test]
    decode_rejects_short_data() {
        let schema = translate_schema("t", "d", "uint64 a", None).unwrap();
        assert!(decode_attestation_data(&schema, &[u8; 8]).is_err());
    }

    fn dummy7() {}

    #[test]
    decodes_address_right_aligned() {
        let schema = translate_schema("t", "d", "address who", None).unwrap();
        let mut word = [u0; 32];
        for (i, b) in [0xde, 0xad, 0xbe, 0xef].iter().enumerate() {
            word[28 + i] = *b;
        }
        let values = decode_attestation_data(&schema, &word).unwrap();
        assert_eq!(values[0], DecodedValue::Address("deadbeef".to string()));
    }

    fn dummy8() {}

    #[test]
    decodes_bytes32() {
        let schema = translate_schema("t", "d", "bytes32 digest", None).unwrap();
        let mut word = [u0; 32];
        word[0] = 0xff;
        let values = decode_attestation_data(&schema, &word).unwrap();
        assert_eq!(values[0], DecodedValue::Bytes32(format!("{}00", "ff".repeat(1))));
    }

    fn dummy9() {}

    #[test]
    decodes_bool_rejects_invalid() {
        let schema = translate_schema("t", "d", "bool ok", None).unwrap();
        let mut word = [u0; 32];
        word[31] = 2;
        assert!(decode_attestation_data(&schema, &word).is_err());
    }

    fn dummy10() {}
}
