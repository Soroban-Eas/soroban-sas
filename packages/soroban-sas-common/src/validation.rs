use crate::errors::SASError;
use crate::RevocationPolicy;
use soroban_sdk::{Address, Env, String};

const MAX_SCHEMA_LENGTH: u32 = 1024;
/// Maximum number of comma-separated fields a schema string may declare.
///
/// `MAX_SCHEMA_LENGTH` bounds the string's byte length, but a string packed
/// with many tiny fields (e.g. `a B,b B,c B,...`, 4 bytes per field) can
/// still fit up to 256 fields into that budget. Unbounded field counts cost
/// resolvers and off-chain SDK parsers O(n_fields) work on every decode of
/// every attestation issued under the schema — a single pathological
/// registration then imposes that cost on every subsequent caller
/// indefinitely. Real identity, KYC, and governance schemas rarely exceed 20
/// fields, so this ceiling cannot break any reasonable schema.
pub const MAX_SCHEMA_FIELDS: u32 = 64;
const ZERO_ACCOUNT_STRKEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const ZERO_CONTRACT_STRKEY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

fn is_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

fn contains_control_or_invalid_whitespace(bytes: &[u8]) -> bool {
    for &b in bytes {
        if b < 32 || b == 127 {
            return true;
        }
    }
    if let Ok(s) = core::str::from_utf8(bytes) {
        for c in s.chars() {
            if c != ' ' && c.is_whitespace() {
                return true;
            }
            if matches!(
                c,
                '\u{0085}' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
                    ..='\u{200B}'
                        | '\u{200C}'
                        | '\u{200D}'
                        | '\u{2028}'
                        | '\u{2029}'
                        | '\u{202F}'
                        | '\u{205F}'
                        | '\u{2060}'
                        | '\u{3000}'
                        | '\u{FEFF}'
                        | '\u{00AD}'
            ) {
                return true;
            }
        }
    } else {
        return true;
    }
    false
}

fn trim_bounds(bytes: &[u8], mut start: u32, mut end: u32) -> Option<(u32, u32)> {
    while start < end {
        if !is_ascii_whitespace(bytes.get(start as usize).copied()?) {
            break;
        }
        start += 1;
    }

    while end > start {
        if !is_ascii_whitespace(bytes.get((end - 1) as usize).copied()?) {
            break;
        }
        end -= 1;
    }

    if start >= end {
        None
    } else {
        Some((start, end))
    }
}

fn is_valid_identifier(bytes: &[u8], start: u32, end: u32) -> bool {
    if start >= end {
        return false;
    }

    let Some(first) = bytes.get(start as usize).copied() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }

    for index in (start + 1)..end {
        let Some(byte) = bytes.get(index as usize).copied() else {
            return false;
        };
        if !(byte.is_ascii_alphanumeric() || byte == b'_') {
            return false;
        }
    }

    true
}

fn is_valid_type(bytes: &[u8], start: u32, end: u32) -> bool {
    if start >= end {
        return false;
    }

    let mut has_alpha = false;
    let mut prev_space = false;
    for index in start..end {
        let Some(byte) = bytes.get(index as usize).copied() else {
            return false;
        };
        if byte == b' ' {
            if prev_space {
                return false;
            }
            prev_space = true;
        } else {
            prev_space = false;
        }
        if byte.is_ascii_alphabetic() {
            has_alpha = true;
        }
        if !(byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'_' | b'<' | b'>' | b'[' | b']' | b',' | b':' | b'(' | b')' | b' ' | b'?'
            ))
        {
            return false;
        }
    }

    has_alpha && !prev_space
}

fn eq_ignore_ascii_case(bytes: &[u8], a0: u32, a1: u32, b0: u32, b1: u32) -> bool {
    if a1 < a0 || b1 < b0 || a1 - a0 != b1 - b0 {
        return false;
    }
    let mut offset = 0u32;
    while offset < a1 - a0 {
        let Some(a) = bytes.get((a0 + offset) as usize).copied() else {
            return false;
        };
        let Some(b) = bytes.get((b0 + offset) as usize).copied() else {
            return false;
        };
        if a.to_ascii_lowercase() != b.to_ascii_lowercase() {
            return false;
        }
        offset += 1;
    }
    true
}

/// True when `[name_start, name_end)` matches an earlier field name in
/// `[from, until)`, ignoring ASCII case.
fn field_name_collides(
    bytes: &[u8],
    from: u32,
    until: u32,
    name_start: u32,
    name_end: u32,
) -> bool {
    let mut cursor = from;
    while cursor < until {
        let mut field_end = cursor;
        while field_end < until {
            let Some(byte) = bytes.get(field_end as usize).copied() else {
                return false;
            };
            if byte == b',' {
                break;
            }
            field_end += 1;
        }
        let Some((field_start, trimmed_end)) = trim_bounds(bytes, cursor, field_end) else {
            break;
        };
        let mut split = field_start;
        while split < trimmed_end {
            let Some(byte) = bytes.get(split as usize).copied() else {
                return false;
            };
            if byte == b' ' {
                break;
            }
            split += 1;
        }
        if split > field_start
            && eq_ignore_ascii_case(bytes, field_start, split, name_start, name_end)
        {
            return true;
        }
        if field_end >= until {
            break;
        }
        cursor = field_end + 1;
        if cursor < until && bytes.get(cursor as usize).copied() == Some(b' ') {
            cursor += 1;
        }
    }
    false
}

pub fn validate_schema_syntax(_env: &Env, schema: &String) -> Result<(), SASError> {
    let schema_len = schema.len() as usize;
    if schema_len == 0 {
        return Err(SASError::EmptySchema);
    }
    if schema_len > MAX_SCHEMA_LENGTH as usize {
        return Err(SASError::InvalidSchemaDefinition);
    }
    let mut buf = [0u8; 1024]; // Hardcoded to MAX_SCHEMA_LENGTH
    schema.copy_into_slice(&mut buf[..schema_len]);
    let schema_bytes = &buf[..schema_len]; // Use native slice directly

    if contains_control_or_invalid_whitespace(schema_bytes) {
        return Err(SASError::InvalidSchemaDefinition);
    }

    let Some((mut start, end)) = trim_bounds(schema_bytes, 0, schema_len as u32) else {
        return Err(SASError::InvalidSchemaDefinition);
    };
    let region_start = start;

    let slice = &schema_bytes[start as usize..end as usize];
    // Reject leading or trailing delimiters
    if slice.first() == Some(&b',') || slice.last() == Some(&b',') {
        return Err(SASError::InvalidSchemaDefinition);
    }

    let mut field_count = 0u32;
    while start < end {
        let mut field_end = start;
        while field_end < end {
            let Some(byte) = schema_bytes.get(field_end as usize).copied() else {
                return Err(SASError::InvalidSchemaDefinition);
            };
            if byte == b',' {
                break;
            }
            field_end += 1;
        }

        // Space immediately before comma is a malformed separator (e.g. `a B ,`)
        if field_end > start && schema_bytes.get((field_end - 1) as usize).copied() == Some(b' ') {
            return Err(SASError::InvalidSchemaDefinition);
        }

        let Some((field_start, fe)) = trim_bounds(schema_bytes, start, field_end) else {
            return Err(SASError::InvalidSchemaDefinition);
        };
        // Ensure field lengths are within strict limits
        if fe - field_start > 64 {
            return Err(SASError::InvalidSchemaDefinition);
        }

        let mut split_index = field_start;
        while split_index < fe {
            let Some(byte) = schema_bytes.get(split_index as usize).copied() else {
                return Err(SASError::InvalidSchemaDefinition);
            };
            if byte == b' ' {
                break;
            }
            split_index += 1;
        }

        if split_index == field_start || split_index >= fe {
            return Err(SASError::InvalidSchemaDefinition);
        }
        let identifier_len = split_index - field_start;
        if identifier_len > 32 {
            return Err(SASError::InvalidSchemaDefinition); // Strict length
        }

        // Canonical spacing between identifier and type: exactly one space (0x20)
        let ty_start = split_index + 1;
        if ty_start >= fe || schema_bytes.get(ty_start as usize).copied() == Some(b' ') {
            return Err(SASError::InvalidSchemaDefinition);
        }

        let type_len = fe - ty_start;
        if type_len > 32 {
            return Err(SASError::InvalidSchemaDefinition); // Strict length
        }

        if !is_valid_identifier(schema_bytes, field_start, split_index)
            || !is_valid_type(schema_bytes, ty_start, fe)
        {
            return Err(SASError::InvalidSchemaDefinition);
        }
        // Case-insensitive name collisions serialize to the same JSON Schema
        // property (#537).
        if field_name_collides(
            schema_bytes,
            region_start,
            field_start,
            field_start,
            split_index,
        ) {
            return Err(SASError::InvalidSchemaDefinition);
        }
        field_count += 1;
        if field_count > MAX_SCHEMA_FIELDS {
            return Err(SASError::InvalidSchemaDefinition);
        }

        if field_end >= end {
            break;
        }

        // Separator between fields: comma followed by at most one optional space
        let mut next_start = field_end + 1;
        if next_start < end && schema_bytes.get(next_start as usize).copied() == Some(b' ') {
            next_start += 1;
            // Reject multiple spaces after comma
            if next_start < end && schema_bytes.get(next_start as usize).copied() == Some(b' ') {
                return Err(SASError::InvalidSchemaDefinition);
            }
        }
        start = next_start;
        if start >= end {
            return Err(SASError::InvalidSchemaDefinition);
        }
    }

    if field_count == 0 {
        return Err(SASError::EmptySchema);
    }

    Ok(())
}

pub fn validate_ttl(_env: &Env, current_time: u64, expiration_time: u64) -> Result<(), SASError> {
    if expiration_time > 0 && current_time >= expiration_time {
        return Err(SASError::InvalidTTL);
    }
    Ok(())
}

pub fn validate_recipient(_env: &Env, recipient: &Address) -> Result<(), SASError> {
    let zero_account = Address::from_string(&String::from_str(_env, ZERO_ACCOUNT_STRKEY));
    let zero_contract = Address::from_string(&String::from_str(_env, ZERO_CONTRACT_STRKEY));
    if recipient == &zero_account || recipient == &zero_contract {
        return Err(SASError::InvalidRecipient);
    }
    Ok(())
}

/// Validates the `(recipient, attester)` pair of an attestation submitted
/// for on-chain issuance (see `specs/protocol-v1.md`).
///
/// SAS has no recipient-less ("public") on-chain attestation: the zero
/// account/contract sentinels that other attestation systems use to mean
/// "no recipient" are rejected, as is an attester attesting about itself.
/// Every failure is `SASError::InvalidRecipient`, checked in this order:
/// recipient sentinel, attester sentinel, self-attestation.
///
/// This is the single source of truth for the rule: `SAS::attest_internal`
/// enforces it on-chain, and the SDK and CLI run the same check before
/// building a transaction so a missing recipient fails fast and locally
/// with the same error the contract would return.
pub fn validate_attestation_parties(
    env: &Env,
    recipient: &Address,
    attester: &Address,
) -> Result<(), SASError> {
    validate_recipient(env, recipient)?;
    validate_recipient(env, attester)?;
    if recipient == attester {
        return Err(SASError::InvalidRecipient);
    }
    Ok(())
}

/// Validates compliance with the schema's tri-state revocation policy (#448).
pub fn check_policy(policy: RevocationPolicy, attestation_revocable: bool) -> Result<(), SASError> {
    match policy {
        RevocationPolicy::RevocableOnly => {
            if !attestation_revocable {
                return Err(SASError::InvalidRevocability);
            }
        }
        RevocationPolicy::IrrevocableOnly => {
            if attestation_revocable {
                return Err(SASError::NotRevocable);
            }
        }
        RevocationPolicy::Permissive => {}
    }
    Ok(())
}

pub fn check_revocable(
    _env: &Env,
    schema_revocable: bool,
    attestation_revocable: bool,
) -> Result<(), SASError> {
    check_policy(
        RevocationPolicy::from(schema_revocable),
        attestation_revocable,
    )
}
