use crate::errors::SASError;
use soroban_sdk::{Address, Env, String};

const MAX_SCHEMA_LENGTH: u32 = 1024;

/// Validates the syntax of a schema string.
///
/// See `docs/schemas.md` for the schema syntax specification.
pub fn validate_schema_syntax(_env: &Env, schema: &String) -> Result<(), SASError> {
    if schema.len() == 0 {
        return Err(SASError::InvalidSchema);
    }
    if schema.len() > MAX_SCHEMA_LENGTH {
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

pub fn validate_recipient(_env: &Env, _recipient: &Address) -> Result<(), SASError> {
    // Implement robust recipient address validation logic
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
