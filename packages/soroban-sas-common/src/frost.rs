//! FROST (Flexible Round-Optimized Schnorr Threshold) signature support for
//! delegated attestations (#534).
//!
//! # Why FROST fits SAS
//!
//! FROST over Ed25519 lets `t` out of `n` signers jointly produce **one**
//! ordinary Ed25519 signature under a group public key. SAS does not need to
//! know the group size, the share identifiers, or the signing round: it
//! verifies the aggregate exactly as it verifies any delegated attestation,
//! with a single `Env::crypto().ed25519_verify` call. Consequently:
//!
//! * the on-chain verification cost is the same as a single-key delegated
//!   attestation (one Ed25519 verification),
//! * the calldata is byte-for-byte the same shape — a 64-byte signature and a
//!   32-byte public key, in the existing `attest_by_delegation` argument
//!   list,
//! * a signature that fewer than `t` shares contributed to is not a valid
//!   Ed25519 signature under the group public key, so it fails verification.
//!
//! # Verification specification (v1)
//!
//! Given a schema with a required [`FrostGroup`]:
//!
//! 1. The group public key `A` is the Ed25519 compressed point the DKG
//!    (or trusted dealer) produced. It is stored on-chain by
//!    `SchemaRegistry::set_schema_frost_group`; it is **never** supplied by the
//!    relayer.
//! 2. The message is the ordinary SAS delegated-attestation digest,
//!    `hash_offchain_attestation(attestation, domain)` (or
//!    `hash_delegated_revocation(uid, attester, domain)` for revocations).
//!    No FROST-specific prefix or domain separator is added, so the payload
//!    layout is unchanged from the single-signer protocol.
//! 3. The aggregate signature is `R || s`: a 32-byte compressed nonce point
//!    followed by a 32-byte little-endian scalar, exactly RFC 8032's encoding.
//! 4. Verification is plain Ed25519 verification of `(A, message, R || s)`,
//!    i.e. `[s]B = R + H(R || A || message) * A` with SHA-512 as `H`, as
//!    implemented by `Env::crypto().ed25519_verify`.
//!
//! The signing ceremony itself is off-chain. Compatible implementations are
//! `frost-ed25519` (Zcash Foundation) and any other FROST variant that emits
//! RFC 8032-compatible Ed25519 signatures; the group public key is generated
//! by a DKG, so no single member ever holds the group secret.
//!
//! [`FrostGroup::threshold`] and [`FrostGroup::max_signers`] are **declared**
//! metadata for clients/indexers: the chain cannot observe how many shares
//! participated, and does not need to — a signature under `A` is valid exactly
//! when at least `threshold` shares were combined at signing time. The fields
//! are validated for internal consistency when the group is configured.
//!
//! Golden vectors for 2-of-3 and 3-of-5 groups live in
//! `packages/soroban-sas-common/test_vectors/frost_threshold.tsv` and are
//! exercised by `contracts/sas/src/frost_test.rs`.
//!
//! # Operational notes
//!
//! * A group key is a *delegation* credential. It authorizes
//!   `attest_by_delegation`, `multi_attest_by_delegation`,
//!   `revoke_by_delegation`, `multi_revoke_by_delegation`, and
//!   `verify_offchain_attestation` for schemas that declare it; the attester's
//!   own account/registered key is not accepted for those schemas.
//! * Rotating a group key is an on-chain schema-owner action. Signatures made
//!   under the previous key stop verifying immediately, the same way
//!   `rotate_attester_key` invalidates earlier delegated signatures.
//! * Test-vector keys in this repository are public and **must never** be used
//!   for production groups.

use crate::errors::SASError;
use crate::typed_data::verify_offchain_signature;
use soroban_sdk::{contracttype, BytesN, Env};

/// Largest supported FROST signing group.
///
/// Share identifiers must fit in one byte for the common FROST encodings, so
/// `255` is the practical ceiling. The bound also keeps the declared metadata
/// unambiguous.
pub const MAX_FROST_SIGNERS: u32 = 255;

/// Smallest threshold a schema may declare.
///
/// A 1-of-n group is just a single signer with extra steps; the feature exists
/// for multi-party endorsement, so configurations that cannot express a real
/// threshold are rejected at registration time.
pub const MIN_FROST_THRESHOLD: u32 = 2;

/// Byte length of an aggregate Ed25519 signature (`R || s`).
pub const FROST_SIGNATURE_BYTES: u32 = 64;

/// Byte length of a compressed Ed25519 group public key.
pub const FROST_GROUP_PUBLIC_KEY_BYTES: u32 = 32;

/// A FROST signing group a schema requires for delegated signatures.
///
/// The group public key is the only security-relevant field: it is what the
/// contract verifies aggregate signatures against. `threshold` and
/// `max_signers` describe the group's signing policy so SDKs, indexers, and
/// auditors can display it, and are validated when the group is configured.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FrostGroup {
    /// Compressed Ed25519 public key of the group (`A` in the v1 spec above).
    /// The corresponding secret is never reconstructed on-chain and is not
    /// held by any single participant of a properly run DKG.
    pub group_public_key: BytesN<32>,
    /// Number of shares that must contribute to a valid aggregate signature.
    pub threshold: u32,
    /// Total number of shares the DKG distributed.
    pub max_signers: u32,
}

/// Checks that a declared group is internally consistent.
///
/// These checks are deliberately local and cheap: the contract cannot verify
/// that the DKG was run honestly, only that the configuration it is asked to
/// enforce makes sense. A group whose key is the all-zero point (never a valid
/// Ed25519 group key produced by a DKG) or whose threshold cannot be met is
/// rejected with [`SASError::InvalidValue`]; a group larger than
/// [`MAX_FROST_SIGNERS`] is rejected with [`SASError::LimitExceeded`].
pub fn validate_frost_group(group: &FrostGroup) -> Result<(), SASError> {
    if group.max_signers > MAX_FROST_SIGNERS {
        return Err(SASError::LimitExceeded);
    }
    if group.threshold < MIN_FROST_THRESHOLD
        || group.threshold > group.max_signers
        || group.group_public_key.to_array() == [0u8; FROST_GROUP_PUBLIC_KEY_BYTES as usize]
    {
        return Err(SASError::InvalidValue);
    }
    Ok(())
}

/// Verifies a FROST aggregate signature against the group public key.
///
/// The aggregate is a standard Ed25519 signature, so this is exactly one
/// `ed25519_verify` host call — the same cost as verifying a single-signer
/// delegated attestation. Traps with the host's Ed25519 error when the
/// signature is not valid under the group key, which includes any aggregate
/// produced with fewer than `threshold` shares.
pub fn verify_frost_aggregate_signature(
    env: &Env,
    payload_hash: &BytesN<32>,
    group: &FrostGroup,
    signature: &BytesN<64>,
) {
    verify_offchain_signature(env, payload_hash, &group.group_public_key, signature);
}
