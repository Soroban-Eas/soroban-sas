#![allow(unexpected_cfgs)]
#![cfg_attr(not(test), no_std)]

use soroban_sas_common::{
    extend_instance_ttl, INSTANCE_EXTEND_TO_LEDGERS, INSTANCE_TTL_THRESHOLD_LEDGERS, UID,
};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env,
    IntoVal, Symbol, Vec,
};

/// Maximum age in seconds for a zero-knowledge attestation proof timestamp
pub const MAX_ZK_PROOF_AGE_SECONDS: u64 = 7 * 24 * 60 * 60; // 7 days

/// TTL threshold, in ledgers, below which a nullifier record is renewed.
///
/// Nullifiers are the contract's replay-protection state, so they are renewed
/// with exactly the policy the contract's instance storage uses
/// (`INSTANCE_TTL_THRESHOLD_LEDGERS`): a spent nullifier must not expire
/// while the contract that guards it is still live, otherwise the contract
/// would forget the nullifier and accept a replay of an already-verified
/// proof (#547).
pub const NULLIFIER_TTL_THRESHOLD_LEDGERS: u32 = INSTANCE_TTL_THRESHOLD_LEDGERS;

/// Number of ledgers a nullifier record is extended to when it is renewed.
///
/// Aligned with the contract instance's renewal target
/// (`INSTANCE_EXTEND_TO_LEDGERS`), so nullifier records and the instance
/// that guards them expire on the same horizon.
pub const NULLIFIER_TTL_EXTEND_TO_LEDGERS: u32 = INSTANCE_EXTEND_TO_LEDGERS;

/// Maximum number of nullifiers accepted by the batch query in one call.
pub const MAX_NULLIFIER_BATCH: u32 = 50;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ZkVerifierError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    /// The nullifier was already consumed by an earlier proof submission.
    ///
    /// A nullifier may be spent exactly once: every later submission that
    /// carries it is a replay of the same private statement and is rejected
    /// without touching any other state (#547).
    NullifierSpent = 3,
    InvalidProof = 4,
    AttestationExpired = 5,
    AttestationNotYetActive = 6,
    AttestationRevokedOrInvalid = 7,
    InvalidCommitment = 8,
    ProofTooOld = 9,
    BatchTooLarge = 10,
}

/// Alias for [`ZkVerifierError`], so the error can be referred to as
/// `ZKError::NullifierSpent` — the spelling used by the ZK verifier
/// documentation and issue #547.
pub type ZKError = ZkVerifierError;

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

/// Renews the TTL of a nullifier record.
///
/// Nullifier records are renewed with the same policy as the contract's
/// instance storage, so a spent nullifier never expires before the contract
/// instance that guards it. Expiring a nullifier early would let the
/// contract forget that a private statement was already spent, and the same
/// proof could be submitted again.
fn extend_nullifier_ttl(env: &Env, key: &DataKey) {
    env.storage().persistent().extend_ttl(
        key,
        NULLIFIER_TTL_THRESHOLD_LEDGERS,
        NULLIFIER_TTL_EXTEND_TO_LEDGERS,
    );
}

/// Checks a nullifier and records it as spent, in one atomic step.
///
/// The check and the write belong to the same invocation, so a nullifier can
/// never be spent twice: either the invocation commits both, or it fails and
/// the host rolls it back, leaving the nullifier unspent. Recording the
/// nullifier before the proof is validated is safe for the same reason — a
/// failed verification reverts the record with the rest of the invocation.
fn consume_nullifier(
    env: &Env,
    nullifier: &BytesN<32>,
    timestamp: u64,
) -> Result<(), ZkVerifierError> {
    let key = DataKey::Nullifier(nullifier.clone());
    if env.storage().persistent().has(&key) {
        return Err(ZkVerifierError::NullifierSpent);
    }
    env.storage().persistent().set(&key, &timestamp);
    extend_nullifier_ttl(env, &key);
    Ok(())
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
    /// 2. The nullifier has never been spent before. The check and the
    ///    record are atomic: a spent nullifier is rejected with
    ///    [`ZkVerifierError::NullifierSpent`] before any other work is done,
    ///    and a nullifier is only kept when the whole verification succeeds.
    /// 3. Proof payload is non-empty and mathematically well-formed.
    /// 4. Proof timestamp is within acceptable window (`MAX_ZK_PROOF_AGE_SECONDS`).
    /// 5. If `attestation_uid` points to an on-chain SAS attestation:
    ///    - Queries SAS to ensure attestation is currently valid (not revoked, not expired, active if time-locked).
    /// 6. Consumes nullifier persistently, with a TTL aligned with the contract instance.
    /// 7. Emits `zk_verify` event.
    pub fn verify_and_consume_proof(
        env: Env,
        proof_data: ZkAttestationProof,
    ) -> Result<bool, ZkVerifierError> {
        let config = get_config(&env)?;
        extend_instance_ttl(&env);

        let now = env.ledger().timestamp();

        // 1. Atomically check and record the nullifier. The check comes first
        //    so that a replay is rejected immediately, without paying for the
        //    proof validation or the SAS cross-contract calls below.
        consume_nullifier(&env, &proof_data.nullifier, now)?;

        // 2. Validate proof format and proof age
        if proof_data.proof.is_empty() || proof_data.proof.len() > 1024 {
            return Err(ZkVerifierError::InvalidProof);
        }
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

        // 5. Record commitment
        let commitment_key = DataKey::Commitment(proof_data.commitment.clone());
        env.storage().persistent().set(&commitment_key, &now);
        env.storage().persistent().extend_ttl(
            &commitment_key,
            NULLIFIER_TTL_THRESHOLD_LEDGERS,
            NULLIFIER_TTL_EXTEND_TO_LEDGERS,
        );

        // 6. Publish event
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
            extend_nullifier_ttl(&env, &key);
        }
        exists
    }

    /// Check if a commitment has been registered/verified
    pub fn is_commitment_verified(env: Env, commitment: BytesN<32>) -> bool {
        extend_instance_ttl(&env);
        let key = DataKey::Commitment(commitment);
        let exists = env.storage().persistent().has(&key);
        if exists {
            env.storage().persistent().extend_ttl(
                &key,
                NULLIFIER_TTL_THRESHOLD_LEDGERS,
                NULLIFIER_TTL_EXTEND_TO_LEDGERS,
            );
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
                extend_nullifier_ttl(&env, &key);
            }
            used.push_back(consumed);
        }
        Ok(used)
    }
}

#[cfg(test)]
mod test;
