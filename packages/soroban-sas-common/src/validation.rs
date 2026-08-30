use crate::errors::SASError;
use soroban_sdk::{Address, Bytes, Env, String};

const MAX_SCHEMA_LENGTH: u32 = 1024;
const ZERO_ACCOUNT_STRKEY: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const ZERO_CONTRACT_STRKEY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

fn is_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

fn trim_bounds(bytes: &Bytes, mut start: u32, mut end: u32) -> Option<(u32, u32)> {
    while start < end {
        if !is_ascii_whitespace(bytes.get(start)?) {
            break;
        }
        start += 1;
    }

    while end > start {
        if !is_ascii_whitespace(bytes.get(end - 1)?) {
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

fn is_valid_identifier(bytes: &Bytes, start: u32, end: u32) -> bool {
    if start >= end {
        return false;
    }

    let Some(first) = bytes.get(start) else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }

    for index in (start + 1)..end {
        let Some(byte) = bytes.get(index) else {
            return false;
        };
        if !(byte.is_ascii_alphanumeric() || byte == b'_') {
            return false;
        }
    }

    true
}

fn is_valid_type(bytes: &Bytes, start: u32, end: u32) -> bool {
    if start >= end {
        return false;
    }

    let mut has_alpha = false;
    for index in start..end {
        let Some(byte) = bytes.get(index) else {
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
        let schema_bytes = Bytes::from_slice(env, &buf[..schema_len]);

        let Some((mut start, end)) = trim_bounds(&schema_bytes, 0, schema_bytes.len()) else {
            return Err(SASError::InvalidSchema);
        };

        let mut field_count = 0u32;
        while start < end {
            let mut field_end = start;
            while field_end < end {
                let Some(byte) = schema_bytes.get(field_end) else {
                    return Err(SASError::InvalidSchema);
                };
                if byte == b',' {
                    break;
                }
                field_end += 1;
            }

            let Some((field_start, field_end)) = trim_bounds(&schema_bytes, start, field_end)
            else {
                return Err(SASError::InvalidSchema);
            };

            let mut split_index = field_start;
            while split_index < field_end {
                let Some(byte) = schema_bytes.get(split_index) else {
                    return Err(SASError::InvalidSchema);
                };
                if is_ascii_whitespace(byte) {
                    break;
                }
                split_index += 1;
            }

            if split_index == field_start || split_index >= field_end {
                return Err(SASError::InvalidSchema);
            }

            let mut ty_start = split_index;
            while ty_start < field_end {
                let Some(byte) = schema_bytes.get(ty_start) else {
                    return Err(SASError::InvalidSchema);
                };
                if !is_ascii_whitespace(byte) {
                    break;
                }
                ty_start += 1;
            }

            if ty_start >= field_end
                || !is_valid_identifier(&schema_bytes, field_start, split_index)
                || !is_valid_type(&schema_bytes, ty_start, field_end)
            {
                return Err(SASError::InvalidSchema);
            }
            field_count += 1;

            if field_end >= end {
                break;
            }
            start = field_end + 1;
            while start < end {
                let Some(byte) = schema_bytes.get(start) else {
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
