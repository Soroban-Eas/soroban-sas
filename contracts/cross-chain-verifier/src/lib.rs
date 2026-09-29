#![allow(unexpected_cfgs)]
#![cfg_attr(not(test), no_std)]

use soroban_sas_common::{extend_instance_ttl, LEDGERS_IN_ONE_YEAR, UID};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env,
    IntoVal, String, Symbol,
};

/// A remote positive verdict is deliberately short-lived: revocations are
/// asynchronous, so an old approved message must not grant indefinite trust.
pub const MAX_VALIDITY_SECONDS: u64 = 24 * 60 * 60;
pub const STATUS_PAYLOAD_LEN: u32 = 50;
const MAX_CHAIN_LEN: u32 = 64;
const MAX_ADDRESS_LEN: u32 = 128;
const MAX_MESSAGE_ID_LEN: u32 = 128;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum CrossChainError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    InvalidConfig = 3,
    WrongSource = 4,
    InvalidPayload = 5,
    InvalidValidity = 6,
    StaleRevision = 7,
    MessageNotApproved = 8,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceConfig {
    pub admin: Address,
    pub gateway: Address,
    pub source_chain: String,
    pub source_address: String,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteAttestation {
    pub uid: UID,
    pub revision: u64,
    pub valid_until: u64,
    pub valid: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteAttestationUpdated {
    pub message_id: String,
    pub status: RemoteAttestation,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Config,
    Status(UID),
}

fn config(env: &Env) -> Result<SourceConfig, CrossChainError> {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .ok_or(CrossChainError::NotInitialized)
}

/// Fixed, cross-language wire format: version (1 byte), UID (32 bytes),
/// revision (u64 big endian), valid-until UNIX timestamp (u64 big endian),
/// validity flag (0 or 1). Exact length and flag values are mandatory.
fn decode_status(payload: &Bytes) -> Result<RemoteAttestation, CrossChainError> {
    if payload.len() != STATUS_PAYLOAD_LEN || payload.get(0) != Some(1) {
        return Err(CrossChainError::InvalidPayload);
    }
    let env = payload.env();
    let mut uid = [0u8; 32];
    for i in 0..32u32 {
        uid[i as usize] = payload.get(1 + i).ok_or(CrossChainError::InvalidPayload)?;
    }
    let mut revision = 0u64;
    let mut valid_until = 0u64;
    for i in 0..8u32 {
        revision = (revision << 8)
            | u64::from(payload.get(33 + i).ok_or(CrossChainError::InvalidPayload)?);
        valid_until = (valid_until << 8)
            | u64::from(payload.get(41 + i).ok_or(CrossChainError::InvalidPayload)?);
    }
    let valid = match payload.get(49) {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(CrossChainError::InvalidPayload),
    };
    Ok(RemoteAttestation {
        uid: UID(BytesN::from_array(env, &uid)),
        revision,
        valid_until,
        valid,
    })
}

#[contract]
pub struct CrossChainVerifier;

#[contractimpl]
impl CrossChainVerifier {
    /// Bind one remote sender to one Axelar gateway. Deploy a separate
    /// verifier for another source; these values cannot change after init.
    pub fn init(
        env: Env,
        admin: Address,
        gateway: Address,
        source_chain: String,
        source_address: String,
    ) -> Result<(), CrossChainError> {
        if env.storage().instance().has(&DataKey::Config) {
            return Err(CrossChainError::AlreadyInitialized);
        }
        admin.require_auth();
        if gateway == env.current_contract_address()
            || source_chain.is_empty()
            || source_chain.len() > MAX_CHAIN_LEN
            || source_address.is_empty()
            || source_address.len() > MAX_ADDRESS_LEN
        {
            return Err(CrossChainError::InvalidConfig);
        }
        env.storage().instance().set(
            &DataKey::Config,
            &SourceConfig {
                admin,
                gateway,
                source_chain,
                source_address,
            },
        );
        extend_instance_ttl(&env);
        Ok(())
    }

    pub fn get_source(env: Env) -> Result<SourceConfig, CrossChainError> {
        extend_instance_ttl(&env);
        config(&env)
    }

    /// Consume an Axelar-approved message and record its remote verdict.
    /// The caller may be any relayer; the gateway authenticates the message.
    pub fn execute(
        env: Env,
        source_chain: String,
        message_id: String,
        source_address: String,
        payload: Bytes,
    ) -> Result<RemoteAttestation, CrossChainError> {
        let trusted = config(&env)?;
        if source_chain != trusted.source_chain || source_address != trusted.source_address {
            return Err(CrossChainError::WrongSource);
        }
        if message_id.is_empty() || message_id.len() > MAX_MESSAGE_ID_LEN {
            return Err(CrossChainError::InvalidPayload);
        }
        let status = decode_status(&payload)?;
        let now = env.ledger().timestamp();
        if status.revision == 0
            || (status.valid
                && (status.valid_until <= now
                    || status.valid_until > now.saturating_add(MAX_VALIDITY_SECONDS)))
            || (!status.valid && status.valid_until != 0)
        {
            return Err(CrossChainError::InvalidValidity);
        }
        let key = DataKey::Status(status.uid.clone());
        if let Some(previous) = env.storage().persistent().get::<_, RemoteAttestation>(&key) {
            if status.revision <= previous.revision {
                return Err(CrossChainError::StaleRevision);
            }
        }

        // Axelar's Stellar gateway checks the destination contract, source
        // tuple and Keccak-256 payload hash, then consumes its approval.
        let payload_hash: BytesN<32> = env.crypto().keccak256(&payload).into();
        let args = soroban_sdk::vec![
            &env,
            env.current_contract_address().into_val(&env),
            source_chain.into_val(&env),
            message_id.clone().into_val(&env),
            source_address.into_val(&env),
            payload_hash.into_val(&env),
        ];
        match env.try_invoke_contract::<bool, soroban_sdk::Error>(
            &trusted.gateway,
            &Symbol::new(&env, "validate_message"),
            args,
        ) {
            Ok(Ok(true)) => {}
            _ => return Err(CrossChainError::MessageNotApproved),
        }

        env.storage().persistent().set(&key, &status);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        env.events().publish(
            (symbol_short!("rem_att"), status.uid.0.clone()),
            RemoteAttestationUpdated {
                message_id,
                status: status.clone(),
            },
        );
        extend_instance_ttl(&env);
        Ok(status)
    }

    /// Latest approved message, including a negative or expired verdict.
    pub fn get_status(env: Env, uid: UID) -> Option<RemoteAttestation> {
        extend_instance_ttl(&env);
        let key = DataKey::Status(uid);
        let status = env.storage().persistent().get(&key);
        if status.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        }
        status
    }

    /// Fail closed for unknown, invalid, or expired remote attestations.
    pub fn verify_remote(env: Env, uid: UID) -> bool {
        let Some(status) = Self::get_status(env.clone(), uid) else {
            return false;
        };
        status.valid && status.valid_until > env.ledger().timestamp()
    }
}

#[cfg(test)]
mod test;
