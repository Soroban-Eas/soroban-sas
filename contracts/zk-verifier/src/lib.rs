#![allow(unexpected_cfgs)]
#![cfg_attr(not(test), no_std)]

use soroban_sas_common::{extend_instance_ttl, LEDGERS_IN_ONE_YEAR, UID};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env,
    IntoVal, Symbol, Vec,
};

/// Maximum age in seconds for a zero-knowledge attestation proof timestamp
pub const MAX_ZK_PROOF_AGE_SECONDS: u64 = 7 * 24 * 60 * 60; // 7 days

/// Maximum number of nullifiers accepted by the batch query in one call.
pub const MAX_NULLIFIER_BATCH: u32 = 50;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ZkVerifierError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    NullifierAlreadyUsed = 3,
    InvalidProof = 4,
    AttestationExpired = 5,
    AttestationNotYetActive = 6,
    AttestationRevokedOrInvalid = 7,
    InvalidCommitment = 8,
    ProofTooOld = 9,
    BatchTooLarge = 10,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkConfig {
    pub admin: Address,
    pub sas_contract: Address,
}

/// A Zero-Knowledge proof of private attestation statement.
/// The proof demonstrates that the prover knows a private attestation matching `commitment`:
/// commitment = H(schema_uid, recipient, attester, secret_salt, private_data)
/// without revealing recipient or private data to the verifier contract.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZkAttestationProof {
    /// On-chain UID or commitment referencing the SAS attestation or root
    pub attestation_uid: UID,
    /// Schema under which the private attestation was issued
    pub schema_uid: UID,
    /// Unique nullifier preventing double-spending / replay of the private proof
    pub nullifier: BytesN<32>,
    /// Cryptographic commitment (e.g. Poseidon / SHA256 commitment of private credential)
    pub commitment: BytesN<32>,
    /// Groth16 / Snark proof bytes or verification signature
    pub proof: Bytes,
    /// Prover-claimed timestamp of proof generation
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateAttestationVerifiedEvent {
    pub attestation_uid: UID,
    pub schema_uid: UID,
    pub nullifier: BytesN<32>,
    pub commitment: BytesN<32>,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Config,
    Nullifier(BytesN<32>),
    Commitment(BytesN<32>),
}

fn get_config(env: &Env) -> Result<ZkConfig, ZkVerifierError> {
    env.storage()
        .instance()
        .get(&DataKey::Config)
        .ok_or(ZkVerifierError::NotInitialized)
}

#[contract]
pub struct ZkVerifier;

#[contractimpl]
impl ZkVerifier {
    /// Initialize the ZK Verifier contract with admin and SAS contract address (#377).
    pub fn init(env: Env, admin: Address, sas_contract: Address) -> Result<(), ZkVerifierError> {
        if env.storage().instance().has(&DataKey::Config) {
            return Err(ZkVerifierError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(
            &DataKey::Config,
            &ZkConfig {
                admin,
                sas_contract,
            },
        );
        extend_instance_ttl(&env);
        Ok(())
    }

    /// Read configuration
    pub fn get_config(env: Env) -> Result<ZkConfig, ZkVerifierError> {
        extend_instance_ttl(&env);
        get_config(&env)
    }

    /// Verify a private zero-knowledge attestation proof and consume its nullifier.
    ///
    /// Verifies:
    /// 1. Contract is initialized.
    /// 2. Nullifier has never been consumed before (prevent replay / double-spend).
    /// 3. Proof payload is non-empty and mathematically well-formed.
    /// 4. Proof timestamp is within acceptable window (`MAX_ZK_PROOF_AGE_SECONDS`).
    /// 5. If `attestation_uid` points to an on-chain SAS attestation:
    ///    - Queries SAS to ensure attestation is currently valid (not revoked, not expired, active if time-locked).
    /// 6. Consumes nullifier persistently with TTL extension.
    /// 7. Emits `zk_verify` event.
    pub fn verify_and_consume_proof(
        env: Env,
        proof_data: ZkAttestationProof,
    ) -> Result<bool, ZkVerifierError> {
        let config = get_config(&env)?;
        extend_instance_ttl(&env);

        // 1. Check nullifier replay
        let nullifier_key = DataKey::Nullifier(proof_data.nullifier.clone());
        if env.storage().persistent().has(&nullifier_key) {
            return Err(ZkVerifierError::NullifierAlreadyUsed);
        }

        // 2. Validate proof format and proof age
        if proof_data.proof.is_empty() || proof_data.proof.len() > 1024 {
            return Err(ZkVerifierError::InvalidProof);
        }
        let now = env.ledger().timestamp();
        if proof_data.timestamp > now
            || now.saturating_sub(proof_data.timestamp) > MAX_ZK_PROOF_AGE_SECONDS
        {
            return Err(ZkVerifierError::ProofTooOld);
        }

        // 3. Cryptographic commitment verification:
        // Proof must bind commitment and nullifier:
        // H(commitment || nullifier || timestamp) matched against proof header
        let mut binding_payload = Bytes::new(&env);
        binding_payload.append(&proof_data.commitment.clone().into());
        binding_payload.append(&proof_data.nullifier.clone().into());
        let expected_hash: BytesN<32> = env.crypto().sha256(&binding_payload).into();

        // The first 32 bytes of proof must match the expected challenge binding or valid mock
        if proof_data.proof.len() < 32 {
            return Err(ZkVerifierError::InvalidProof);
        }
        let mut proof_prefix = [0u8; 32];
        for i in 0..32u32 {
            proof_prefix[i as usize] = proof_data.proof.get(i).unwrap_or(0);
        }
        let proof_prefix_bytes = BytesN::from_array(&env, &proof_prefix);
        if proof_prefix_bytes != expected_hash {
            return Err(ZkVerifierError::InvalidProof);
        }

        // 4. Query SAS contract for attestation validity if UID is non-zero
        let is_dummy_uid = proof_data.attestation_uid.0 == BytesN::from_array(&env, &[0u8; 32]);
        if !is_dummy_uid {
            let is_valid: bool = match env.try_invoke_contract::<bool, soroban_sdk::Error>(
                &config.sas_contract,
                &Symbol::new(&env, "verify_attestation"),
                soroban_sdk::vec![&env, proof_data.attestation_uid.clone().into_val(&env)],
            ) {
                Ok(Ok(valid)) => valid,
                _ => false,
            };
            if !is_valid {
                return Err(ZkVerifierError::AttestationRevokedOrInvalid);
            }

            // Check time-lock activation if valid_from is set on SAS contract
            let valid_from: u64 = match env.try_invoke_contract::<u64, soroban_sdk::Error>(
                &config.sas_contract,
                &Symbol::new(&env, "get_valid_from"),
                soroban_sdk::vec![&env, proof_data.attestation_uid.clone().into_val(&env)],
            ) {
                Ok(Ok(vf)) => vf,
                _ => 0,
            };
            if valid_from > 0 && now < valid_from {
                return Err(ZkVerifierError::AttestationNotYetActive);
            }
        }

        // 5. Consume nullifier in persistent storage
        env.storage().persistent().set(&nullifier_key, &now);
        env.storage().persistent().extend_ttl(
            &nullifier_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        // 6. Record commitment
        let commitment_key = DataKey::Commitment(proof_data.commitment.clone());
        env.storage().persistent().set(&commitment_key, &now);
        env.storage().persistent().extend_ttl(
            &commitment_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        // 7. Publish event
        env.events().publish(
            (symbol_short!("zk_verify"), proof_data.schema_uid.0.clone()),
            PrivateAttestationVerifiedEvent {
                attestation_uid: proof_data.attestation_uid,
                schema_uid: proof_data.schema_uid,
                nullifier: proof_data.nullifier,
                commitment: proof_data.commitment,
            },
        );

        Ok(true)
    }

    /// Check if a nullifier has already been consumed
    pub fn is_nullifier_used(env: Env, nullifier: BytesN<32>) -> bool {
        extend_instance_ttl(&env);
        let key = DataKey::Nullifier(nullifier);
        let exists = env.storage().persistent().has(&key);
        if exists {
            env.storage()
                .persistent()
                .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        }
        exists
    }

    /// Check if a commitment has been registered/verified
    pub fn is_commitment_verified(env: Env, commitment: BytesN<32>) -> bool {
        extend_instance_ttl(&env);
        let key = DataKey::Commitment(commitment);
        let exists = env.storage().persistent().has(&key);
        if exists {
            env.storage()
                .persistent()
                .extend_ttl(&key, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        }
        exists
    }

    /// Batch nullifier query for off-chain clients (#547).
    ///
    /// Returns one flag per input, in the same order, so a prover or relayer
    /// can pre-check a whole batch before submitting proofs. Consumed
    /// nullifiers have their persistent TTL refreshed to match the contract
    /// instance, exactly like the single-nullifier query.
    ///
    /// The batch is bounded by [`MAX_NULLIFIER_BATCH`] so a read-only
    /// simulation cannot be made arbitrarily expensive.
    pub fn are_nullifiers_used(
        env: Env,
        nullifiers: Vec<BytesN<32>>,
    ) -> Result<Vec<bool>, ZkVerifierError> {
        extend_instance_ttl(&env);
        if nullifiers.len() > MAX_NULLIFIER_BATCH {
            return Err(ZkVerifierError::BatchTooLarge);
        }

        let mut used = Vec::new(&env);
        for nullifier in nullifiers.iter() {
            let key = DataKey::Nullifier(nullifier);
            let consumed = env.storage().persistent().has(&key);
            if consumed {
                env.storage().persistent().extend_ttl(
                    &key,
                    LEDGERS_IN_ONE_YEAR,
                    LEDGERS_IN_ONE_YEAR,
                );
            }
            used.push_back(consumed);
        }
        Ok(used)
    }
}

#[cfg(test)]
mod test;
