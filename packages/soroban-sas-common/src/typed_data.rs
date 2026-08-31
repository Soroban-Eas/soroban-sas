//! EIP-712 style typed-data hashing and ed25519 signature verification for
//! off-chain attestations.
//!
//! An issuer signs `hash_offchain_attestation(attestation, domain)` with the
//! ed25519 key backing its Stellar account. The resulting signature can be
//! verified on-chain (via `Env::crypto().ed25519_verify`) or by any off-chain
//! verifier that reproduces the same deterministic byte layout.
//!
//! Replay protection: the signed digest commits to a domain separator that
//! includes the network identifier, the verifying contract address, and a
//! caller-chosen nonce, so a signature is only meaningful for one network,
//! one contract, and one nonce. `Attestation.revocation_time` is deliberately
//! excluded from the digest because it is mutated on-chain by revocation.

use crate::Attestation;
use soroban_sdk::{contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env};

/// # Off-chain verification example
///
/// An off-chain verifier can reproduce the exact digest an issuer signed
/// without calling the on-chain contract. This is useful for wallets,
/// relayers, and indexers that need to validate attestations before
/// or without interacting with the ledger.
///
/// ```rust,no_run
/// use soroban_sas_common::{
///     hash_offchain_attestation, Attestation, AttestationDomain, UID,
/// };
/// use soroban_sdk::{Address, BytesN, Env};
///
/// let env = Env::default();
///
/// // Build the domain separator binding this signature to one network,
/// // one SAS contract, and one caller-chosen nonce.
/// let domain = AttestationDomain {
///     network_id: BytesN::from_array(&env, &[0u8; 32]), // SHA-256 of passphrase
///     contract: Address::generate(&env),
///     nonce: 42,
/// };
///
/// // Construct the attestation (fields must match what the issuer signed).
/// let attestation = Attestation {
///     uid: UID(BytesN::from_array(&env, &[1u8; 32])),
///     schema_uid: UID(BytesN::from_array(&env, &[2u8; 32])),
///     time: 1_700_000_000,
///     expiration_time: 0,
///     revocation_time: 0,
///     ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
///     recipient: Address::generate(&env),
///     attester: Address::generate(&env),
///     revocable: true,
///     data: soroban_sdk::Bytes::new(&env),
/// };
///
/// // Reproduce the deterministic digest the issuer signed.
/// let digest = hash_offchain_attestation(&env, &attestation, &domain);
///
/// // Verify with the issuer's ed25519 public key and signature.
/// // verify_offchain_signature(&env, &digest, &public_key, &signature);
/// ```

/// Prefix distinguishing SAS off-chain payloads from other signed messages
/// (analogous to EIP-191's `\x19\x01` prefix).
pub const PAYLOAD_PREFIX: &[u8] = b"\x19SorobanSAS\x01";

/// Type tag mixed into the domain separator hash.
pub const DOMAIN_TYPE_TAG: &[u8] = b"SorobanSAS Domain v1(network_id,contract,nonce)";

/// Type tag mixed into the attestation struct hash.
pub const ATTESTATION_TYPE_TAG: &[u8] =
    b"SorobanSAS Attestation v1(uid,schema_uid,time,expiration_time,ref_uid,recipient,attester,revocable,data)";

/// Type tag for a delegated revocation. This differs from the attestation
/// tag so a signature for one action can never authorize the other.
pub const DELEGATED_REVOCATION_TYPE_TAG: &[u8] = b"SorobanSAS DelegatedRevocation v1(uid,attester)";

/// Domain separator binding a signature to one network, contract, and nonce.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationDomain {
    /// SHA-256 of the network passphrase (the Stellar network id).
    pub network_id: BytesN<32>,
    /// Address of the contract that will verify the attestation.
    pub contract: Address,
    /// Issuer-chosen nonce; a signature is only valid for this exact value.
    pub nonce: u64,
}

/// Hashes the domain separator.
pub fn hash_domain(env: &Env, domain: &AttestationDomain) -> BytesN<32> {
    let mut buf = Bytes::from_slice(env, DOMAIN_TYPE_TAG);
    buf.append(&Bytes::from_slice(env, &domain.network_id.to_array()));
    buf.append(&domain.contract.clone().to_xdr(env));
    buf.append(&Bytes::from_slice(env, &domain.nonce.to_be_bytes()));
    env.crypto().sha256(&buf)
}

/// Hashes an `Attestation` with a fixed, deterministic field layout.
///
/// Layout (all integers big-endian, addresses as ScVal XDR):
/// `TAG || uid || schema_uid || time || expiration_time || ref_uid ||
///  recipient || attester || revocable || sha256(data)`
pub fn hash_attestation_struct(env: &Env, attestation: &Attestation) -> BytesN<32> {
    let mut buf = Bytes::from_slice(env, ATTESTATION_TYPE_TAG);
    buf.append(&Bytes::from_slice(env, &attestation.uid.0.to_array()));
    buf.append(&Bytes::from_slice(
        env,
        &attestation.schema_uid.0.to_array(),
    ));
    buf.append(&Bytes::from_slice(env, &attestation.time.to_be_bytes()));
    buf.append(&Bytes::from_slice(
        env,
        &attestation.expiration_time.to_be_bytes(),
    ));
    buf.append(&Bytes::from_slice(env, &attestation.ref_uid.0.to_array()));
    buf.append(&attestation.recipient.clone().to_xdr(env));
    buf.append(&attestation.attester.clone().to_xdr(env));
    buf.append(&Bytes::from_slice(env, &[attestation.revocable as u8]));
    let data_hash = env.crypto().sha256(&attestation.data);
    buf.append(&Bytes::from_slice(env, &data_hash.to_array()));
    env.crypto().sha256(&buf)
}

/// Computes the digest an issuer signs for an off-chain attestation:
/// `sha256(PAYLOAD_PREFIX || hash_domain(domain) || hash_attestation_struct(attestation))`.
pub fn hash_offchain_attestation(
    env: &Env,
    attestation: &Attestation,
    domain: &AttestationDomain,
) -> BytesN<32> {
    let mut buf = Bytes::from_slice(env, PAYLOAD_PREFIX);
    buf.append(&Bytes::from_slice(
        env,
        &hash_domain(env, domain).to_array(),
    ));
    buf.append(&Bytes::from_slice(
        env,
        &hash_attestation_struct(env, attestation).to_array(),
    ));
    env.crypto().sha256(&buf)
}

/// Computes the digest for a delegated on-chain revocation. The domain binds
/// the action to one network, one SAS contract, and one nonce; the body binds
/// it to the exact attestation UID and its recorded attester.
pub fn hash_delegated_revocation(
    env: &Env,
    uid: &crate::UID,
    attester: &Address,
    domain: &AttestationDomain,
) -> BytesN<32> {
    let mut buf = Bytes::from_slice(env, DELEGATED_REVOCATION_TYPE_TAG);
    buf.append(&Bytes::from_slice(
        env,
        &hash_domain(env, domain).to_array(),
    ));
    buf.append(&Bytes::from_slice(env, &uid.0.to_array()));
    buf.append(&attester.clone().to_xdr(env));
    env.crypto().sha256(&buf)
}

/// Verifies an ed25519 signature over a payload digest.
///
/// Traps (host error) if the signature does not verify, matching the
/// semantics of `Env::crypto().ed25519_verify`.
pub fn verify_offchain_signature(
    env: &Env,
    payload_hash: &BytesN<32>,
    public_key: &BytesN<32>,
    signature: &BytesN<64>,
) {
    let message = Bytes::from_slice(env, &payload_hash.to_array());
    env.crypto().ed25519_verify(public_key, &message, signature);
}

/// ScVal XDR prefix of an ed25519 account address:
/// ScVal discriminant (SCV_ADDRESS = 18), ScAddress discriminant
/// (SC_ADDRESS_TYPE_ACCOUNT = 0), PublicKey discriminant
/// (PUBLIC_KEY_TYPE_ED25519 = 0), each as a 4-byte big-endian word,
/// followed by the 32-byte key.
const ACCOUNT_ADDRESS_XDR_PREFIX: [u8; 12] = [0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0];

/// Returns true when `public_key` is the ed25519 key of the `attester`
/// account address. Contract addresses never match: their id is a SHA-256
/// output, so an attacker cannot deploy a contract whose address equals a
/// chosen public key.
///
/// This is a structural check scoped to classic Ed25519 accounts: it only
/// recognizes the `ScAddress::Account` XDR shape this SDK's `stellar-xdr`
/// version defines. It intentionally cannot resolve any other address kind
/// (e.g. a future protocol version's multiplexed-account address) — there is
/// no supported way to derive an `Address` from a raw public key inside a
/// WASM contract to check structurally. Callers that need to support such
/// addresses should fall back to an explicit, `require_auth`-gated
/// registration of the signing key for that address (see
/// `contracts/sas::register_attester_key`) rather than extending this byte
/// layout by hand.
pub fn attester_matches_key(env: &Env, attester: &Address, public_key: &BytesN<32>) -> bool {
    let mut expected = Bytes::from_slice(env, &ACCOUNT_ADDRESS_XDR_PREFIX);
    expected.append(&Bytes::from_slice(env, &public_key.to_array()));
    attester.clone().to_xdr(env) == expected
}
