//! Selective payload disclosure via Merkle root attestations (#435).
//!
//! Putting a large or private payload on-chain is costly and exposes every
//! claim in it. Instead the attester commits to a 32-byte Merkle root as the
//! attestation's `data`; the holder keeps the leaves and discloses only the
//! ones a verifier needs, each with its proof. `SAS::verify_merkle_leaf` (and
//! the Keccak-256 sibling) check one disclosed leaf against the root of a
//! *live* attestation, without the other leaves ever touching the chain.
//!
//! The tree format and the hash-agnostic verifier live in
//! `soroban_sas_common::merkle`, shared with batch attestations (#179), so an
//! off-chain generator written once works for both.

use soroban_sas_common::{
    verify_proof_with, MerkleHash, MAX_ATTESTATION_DATA_BYTES, MAX_MERKLE_PROOF_DEPTH, UID,
};
use soroban_sdk::{Bytes, BytesN, Env, Vec};

/// A Merkle-root attestation carries exactly this many bytes of `data`.
pub const ROOT_LEN: u32 = 32;

/// `true` only when attestation `uid` is live (exists, not revoked, not
/// expired, valid) with a 32-byte `data` root and `leaf` plus `proof` rebuild
/// that root under `algo`.
///
/// Every failure is a plain `false`: a verifier gets one signal and no way to
/// tell a missing attestation from a bad proof by probing. The cheap
/// structural checks (proof depth, leaf size, root length) run before any
/// hashing so malformed input cannot make a call expensive.
pub fn verify_leaf(
    env: &Env,
    uid: &UID,
    leaf: &Bytes,
    proof: &Vec<BytesN<32>>,
    algo: MerkleHash,
) -> bool {
    if proof.len() > MAX_MERKLE_PROOF_DEPTH || leaf.len() > MAX_ATTESTATION_DATA_BYTES {
        return false;
    }

    let Some(attestation) = crate::read_attestation(env, uid) else {
        return false;
    };
    if attestation.data.len() != ROOT_LEN {
        return false;
    }

    // A revoked, expired or not-yet-valid attestation proves nothing.
    if !crate::verify_attestation_record(env, uid) {
        return false;
    }

    let mut raw = [0u8; 32];
    attestation.data.copy_into_slice(&mut raw);
    let root = BytesN::from_array(env, &raw);

    verify_proof_with(env, algo, &root, leaf, proof)
}
