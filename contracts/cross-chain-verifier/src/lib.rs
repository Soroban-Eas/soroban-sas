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
/// V2 appends a 32-byte schema, 20-byte EVM recipient, a 56-byte Stellar
/// strkey, a two-byte data length, and the raw attestation data.
pub const PROOF_PAYLOAD_HEADER_LEN: u32 = STATUS_PAYLOAD_LEN + 32 + 20 + 56 + 2;
pub const MAX_PROOF_DATA_LEN: u32 = 1024;
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
    UnauthorizedEndpoint = 9,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Origin {
    pub src_eid: u32,
    pub sender: BytesN<32>,
    pub nonce: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LayerZeroConfig {
    pub endpoint: Address,
    pub src_eid: u32,
    pub sender: BytesN<32>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossChainAttestationReceived {
    pub guid: BytesN<32>,
    pub src_eid: u32,
    pub sender: BytesN<32>,
    pub uid: UID,
    pub revision: u64,
    pub valid: bool,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteProof {
    pub schema_uid: UID,
    pub evm_recipient: BytesN<20>,
    /// Explicit recipient mapping certified by the remote source. An EVM
    /// address alone cannot identify a Stellar account.
    pub recipient: Address,
    pub data: Bytes,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Config,
    Admin,
    LzConfig,
    Status(UID),
    Proof(UID),
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
    if (payload.get(0) == Some(1) && payload.len() != STATUS_PAYLOAD_LEN)
        || (payload.get(0) == Some(2) && payload.len() < PROOF_PAYLOAD_HEADER_LEN)
        || !matches!(payload.get(0), Some(1 | 2))
    {
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

fn decode_proof(payload: &Bytes) -> Result<Option<RemoteProof>, CrossChainError> {
    if payload.get(0) != Some(2) {
        return Ok(None);
    }
    let env = payload.env();
    let data_len = u32::from(payload.get(158).ok_or(CrossChainError::InvalidPayload)?) * 256
        + u32::from(payload.get(159).ok_or(CrossChainError::InvalidPayload)?);
    if data_len > MAX_PROOF_DATA_LEN || payload.len() != PROOF_PAYLOAD_HEADER_LEN + data_len {
        return Err(CrossChainError::InvalidPayload);
    }
    let mut schema = [0u8; 32];
    let mut evm = [0u8; 20];
    let mut strkey = [0u8; 56];
    let mut data = [0u8; MAX_PROOF_DATA_LEN as usize];
    for (i, byte) in schema.iter_mut().enumerate() {
        *byte = payload.get(50 + i as u32).unwrap();
    }
    for (i, byte) in evm.iter_mut().enumerate() {
        *byte = payload.get(82 + i as u32).unwrap();
    }
    for (i, byte) in strkey.iter_mut().enumerate() {
        *byte = payload.get(102 + i as u32).unwrap();
    }
    for (i, byte) in data.iter_mut().enumerate().take(data_len as usize) {
        *byte = payload.get(160 + i as u32).unwrap();
    }
    // Soroban validates the G/C strkey checksum and type here. Malformed
    // mappings trap, so they cannot be recorded as approved proofs.
    let recipient = Address::from_string_bytes(&Bytes::from_slice(env, &strkey));
    Ok(Some(RemoteProof {
        schema_uid: UID(BytesN::from_array(env, &schema)),
        evm_recipient: BytesN::from_array(env, &evm),
        recipient,
        data: Bytes::from_slice(env, &data[..data_len as usize]),
    }))
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
        let proof = decode_proof(&payload)?;
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
        let proof_key = DataKey::Proof(status.uid.clone());
        if let Some(proof) = proof {
            env.storage().persistent().set(&proof_key, &proof);
            env.storage().persistent().extend_ttl(
                &proof_key,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
        } else {
            // A newer status-only update must not leave older proof data
            // looking current.
            env.storage().persistent().remove(&proof_key);
        }
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

    /// Proof fields from the latest approved V2 update, if any.
    pub fn get_proof(env: Env, uid: UID) -> Option<RemoteProof> {
        extend_instance_ttl(&env);
        let key = DataKey::Proof(uid);
        let proof = env.storage().persistent().get(&key);
        if proof.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        }
        proof
    }

    /// Fail closed for unknown, invalid, or expired remote attestations.
    pub fn verify_remote(env: Env, uid: UID) -> bool {
        let Some(status) = Self::get_status(env.clone(), uid) else {
            return false;
        };
        status.valid && status.valid_until > env.ledger().timestamp()
    }

    /// Configure LayerZero V2 endpoint integration.
    /// Only the contract admin can set or update this configuration.
    pub fn set_lz_config(
        env: Env,
        caller: Address,
        endpoint: Address,
        src_eid: u32,
        sender: BytesN<32>,
    ) -> Result<(), CrossChainError> {
        caller.require_auth();
        let admin = if let Ok(conf) = config(&env) {
            conf.admin
        } else if let Some(admin) = env.storage().instance().get::<_, Address>(&DataKey::Admin) {
            admin
        } else {
            caller.clone()
        };
        if caller != admin {
            return Err(CrossChainError::UnauthorizedEndpoint);
        }
        if endpoint == env.current_contract_address() || src_eid == 0 {
            return Err(CrossChainError::InvalidConfig);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(
            &DataKey::LzConfig,
            &LayerZeroConfig {
                endpoint,
                src_eid,
                sender,
            },
        );
        extend_instance_ttl(&env);
        Ok(())
    }

    /// Retrieve the configured LayerZero V2 parameters.
    pub fn get_lz_config(env: Env) -> Result<LayerZeroConfig, CrossChainError> {
        extend_instance_ttl(&env);
        env.storage()
            .instance()
            .get(&DataKey::LzConfig)
            .ok_or(CrossChainError::NotInitialized)
    }

    /// LayerZero V2 endpoint callback. Authenticates caller is the configured
    /// endpoint, validates the source endpoint ID, sender contract address,
    /// and GUID, decodes the attestation payload, persists verified state, and
    /// publishes `CrossChainAttestationReceived`.
    pub fn lz_receive(
        env: Env,
        origin: Origin,
        guid: BytesN<32>,
        message: Bytes,
        _executor: Address,
        _extra_data: Bytes,
    ) -> Result<RemoteAttestation, CrossChainError> {
        let trusted = Self::get_lz_config(env.clone())?;
        trusted.endpoint.require_auth();
        if origin.src_eid != trusted.src_eid {
            return Err(CrossChainError::UnauthorizedEndpoint);
        }
        if origin.sender != trusted.sender {
            return Err(CrossChainError::WrongSource);
        }
        let zero_guid = BytesN::from_array(&env, &[0u8; 32]);
        if guid == zero_guid {
            return Err(CrossChainError::InvalidPayload);
        }

        let status = decode_status(&message)?;
        let proof = decode_proof(&message)?;
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

        env.storage().persistent().set(&key, &status);
        env.storage()
            .persistent()
            .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        let proof_key = DataKey::Proof(status.uid.clone());
        if let Some(proof) = proof {
            env.storage().persistent().set(&proof_key, &proof);
            env.storage().persistent().extend_ttl(
                &proof_key,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
        } else {
            env.storage().persistent().remove(&proof_key);
        }
        env.events().publish(
            (symbol_short!("lz_rcv"), status.uid.0.clone()),
            CrossChainAttestationReceived {
                guid,
                src_eid: origin.src_eid,
                sender: origin.sender,
                uid: status.uid.clone(),
                revision: status.revision,
                valid: status.valid,
            },
        );
        extend_instance_ttl(&env);
        Ok(status)
    }
}

#[cfg(test)]
mod test;
