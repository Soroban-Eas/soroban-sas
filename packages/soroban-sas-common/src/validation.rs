use crate::errors::SASError;
use soroban_sdk::{Address, Bytes, Env, String};

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
    for index in start..end {
        let Some(byte) = bytes.get(index as usize).copied() else {
            return false;
        };
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

    has_alpha
}

pub fn validate_schema_syntax(env: &Env, schema: &String) -> Result<(), SASError> {
    let schema_len = schema.len() as usize;
    if schema_len == 0 || schema_len > MAX_SCHEMA_LENGTH as usize {
        return Err(SASError::InvalidSchema);
    }
    let mut buf = [0u8; 1024]; // Hardcoded to MAX_SCHEMA_LENGTH
    schema.copy_into_slice(&mut buf[..schema_len]);
    let schema_bytes = &buf[..schema_len]; // Use native slice directly

    let Some((mut start, end)) = trim_bounds(schema_bytes, 0, schema_len as u32) else {
        return Err(SASError::InvalidSchema);
    };

    for i in 0..schema_len {
        let byte = buf[i];
        if byte >= b'A' && byte <= b'Z' {
            return Err(SASError::InvalidSchemaFormat);
        }
    }
    
    let mut field_count = 0u32;
    while start < end {
        let mut field_end = start;
        while field_end < end {
            let Some(byte) = schema_bytes.get(field_end as usize).copied() else {
                return Err(SASError::InvalidSchema);
            };
            if byte == b',' {
                break;
            }
            field_end += 1;
        }

        let Some((field_start, fe)) = trim_bounds(schema_bytes, start, field_end) else {
            return Err(SASError::InvalidSchema);
        };
        // Ensure field lengths are within strict limits (Issue 287)
        if fe - field_start > 64 {
            return Err(SASError::InvalidSchema);
        }

        let mut split_index = field_start;
        while split_index < fe {
            let Some(byte) = schema_bytes.get(split_index as usize).copied() else {
                return Err(SASError::InvalidSchema);
            };
            if is_ascii_whitespace(byte) {
                break;
            }
            split_index += 1;
        }

        if split_index == field_start || split_index >= fe {
            return Err(SASError::InvalidSchema);
        }
        let identifier_len = split_index - field_start;
        if identifier_len > 32 {
            return Err(SASError::InvalidSchema); // Strict length
        }

        let mut ty_start = split_index;
        while ty_start < fe {
            let Some(byte) = schema_bytes.get(ty_start as usize).copied() else {
                return Err(SASError::InvalidSchema);
            };
            if !is_ascii_whitespace(byte) {
                break;
            }
            ty_start += 1;
        }

        let type_len = fe - ty_start;
        if type_len > 32 {
            return Err(SASError::InvalidSchema); // Strict length
        }

        if ty_start >= fe
            || !is_valid_identifier(schema_bytes, field_start, split_index)
            || !is_valid_type(schema_bytes, ty_start, fe)
        {
            return Err(SASError::InvalidSchema);
        }
        field_count += 1;
        if field_count > MAX_SCHEMA_FIELDS {
            return Err(SASError::InvalidSchema);
        }

        if field_end >= end {
            break;
        }
        start = field_end + 1;
        while start < end {
            let Some(byte) = schema_bytes.get(start as usize).copied() else {
                return Err(SASError::InvalidSchema);
            };
            if !is_ascii_whitespace(byte) {
                break;
            }
            start += 1;
        }
        if start >= end {
            return Err(SASError::InvalidSchema);
        }
    }

    if field_count == 0 {
        return Err(SASError::InvalidSchema);
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

pub fn check_revocable(
    _env: &Env,
    schema_revocable: bool,
    attestation_revocable: bool,
) -> Result<(), SASError> {
    if !schema_revocable && attestation_revocable {
        return Err(SASError::NotRevocable);
    }
    Ok(())
}
