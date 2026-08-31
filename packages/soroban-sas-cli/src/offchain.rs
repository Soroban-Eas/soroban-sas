//! Off-chain attestation signing and verification.
//!
//! Hashing is delegated to `soroban_sas_common::typed_data` through a local
//! Soroban `Env`, so the digest signed here is byte-for-byte identical to the
//! digest the SAS contract verifies on-chain.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use soroban_sas_common::{
    hash_delegated_revocation, hash_offchain_attestation, Attestation, AttestationDomain, UID,
};
use soroban_sas_sdk::strkey::{parse_address, AddressKind};
use soroban_sdk::{Bytes, BytesN, Env};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationInput {
    /// 32-byte attestation UID, hex encoded.
    pub uid: String,
    /// 32-byte schema UID, hex encoded.
    pub schema_uid: String,
    pub time: u64,
    #[serde(default)]
    pub expiration_time: u64,
    /// 32-byte reference UID, hex encoded (all zeros for none).
    pub ref_uid: String,
    /// Recipient address (strkey, `G...` or `C...`).
    pub recipient: String,
    /// Attester account address (strkey, `G...`); must match the signing key.
    pub attester: String,
    pub revocable: bool,
    /// Arbitrary attestation data, hex encoded (may be empty).
    #[serde(default)]
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedOffchainAttestation {
    pub attestation: AttestationInput,
    pub nonce: u64,
    pub network_passphrase: String,
    /// Address of the SAS contract the signature is bound to (strkey `C...`).
    pub contract_id: String,
    /// Hex-encoded 32-byte payload digest that was signed.
    pub payload_hash: String,
    /// Hex-encoded 32-byte ed25519 public key of the attester.
    pub public_key: String,
    /// Hex-encoded 64-byte ed25519 signature over the payload digest.
    pub signature: String,
}

fn decode_hex32(field: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value.trim_start_matches("0x"))
        .map_err(|e| format!("invalid hex in {field}: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{field} must be exactly 32 bytes"))
}

/// Parses the CLI JSON representation into the contract's `Attestation`
/// type. Used by both off-chain signing and direct on-chain issuance.
pub fn parse_attestation(env: &Env, input: &AttestationInput) -> Result<Attestation, String> {
    let data = hex::decode(input.data.trim_start_matches("0x"))
        .map_err(|e| format!("invalid hex in data: {e}"))?;
    Ok(Attestation {
        uid: UID(BytesN::from_array(env, &decode_hex32("uid", &input.uid)?)),
        schema_uid: UID(BytesN::from_array(
            env,
            &decode_hex32("schema_uid", &input.schema_uid)?,
        )),
        time: input.time,
        expiration_time: input.expiration_time,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(
            env,
            &decode_hex32("ref_uid", &input.ref_uid)?,
        )),
        recipient: parse_address(env, &input.recipient, AddressKind::Either, "recipient")
            .map_err(|e| e.to_string())?,
        attester: parse_address(env, &input.attester, AddressKind::Either, "attester")
            .map_err(|e| e.to_string())?,
        revocable: input.revocable,
        data: Bytes::from_slice(env, &data),
    })
}

/// Derives a fresh 32-byte UID for a new attestation from its content plus
/// `entropy` (the issuing call's timestamp in nanoseconds), so the CLI's
/// `attest attest` subcommand can issue an attestation without requiring the
/// caller to pick a UID by hand. Not a content hash in the cryptographic
/// sense — `entropy` exists purely so two attestations with identical
/// content don't collide.
pub fn generate_uid(
    env: &Env,
    schema_uid: &[u8; 32],
    recipient: &str,
    attester: &str,
    data: &[u8],
    entropy: u128,
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(schema_uid);
    buf.extend_from_slice(recipient.as_bytes());
    buf.extend_from_slice(attester.as_bytes());
    buf.extend_from_slice(data);
    buf.extend_from_slice(&entropy.to_be_bytes());
    env.crypto()
        .sha256(&Bytes::from_slice(env, &buf))
        .to_array()
}

/// Computes the payload digest for `input` bound to the given network
/// passphrase, contract, and nonce. Matches the on-chain digest exactly.
pub fn compute_payload_hash(
    input: &AttestationInput,
    nonce: u64,
    network_passphrase: &str,
    contract_id: &str,
) -> Result<[u8; 32], String> {
    let env = Env::default();
    let attestation = parse_attestation(&env, input)?;
    let network_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, network_passphrase.as_bytes()));
    let domain = AttestationDomain {
        network_id,
        contract: parse_address(&env, contract_id, AddressKind::Contract, "contract_id")
            .map_err(|e| e.to_string())?,
        nonce,
    };
    let hash: BytesN<32> = hash_offchain_attestation(&env, &attestation, &domain);
    Ok(hash.to_array())
}

/// Signs an off-chain attestation with a 32-byte ed25519 seed.
pub fn sign_offchain_attestation(
    input: AttestationInput,
    nonce: u64,
    network_passphrase: &str,
    contract_id: &str,
    secret_seed: &[u8; 32],
) -> Result<SignedOffchainAttestation, String> {
    let signing_key = SigningKey::from_bytes(secret_seed);
    let public_key = signing_key.verifying_key().to_bytes();

    let expected_attester = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    if input.attester != expected_attester {
        return Err(format!(
            "attester {} does not match signing key account {}",
            input.attester, expected_attester
        ));
    }

    let payload_hash = compute_payload_hash(&input, nonce, network_passphrase, contract_id)?;
    let signature: Signature = signing_key.sign(&payload_hash);

    Ok(SignedOffchainAttestation {
        attestation: input,
        nonce,
        network_passphrase: network_passphrase.to_string(),
        contract_id: contract_id.to_string(),
        payload_hash: hex::encode(payload_hash),
        public_key: hex::encode(public_key),
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Verifies a signed off-chain attestation: recomputes the digest, checks the
/// public key belongs to the declared attester account, and verifies the
/// ed25519 signature.
pub fn verify_offchain_attestation(signed: &SignedOffchainAttestation) -> Result<(), String> {
    let public_key = decode_hex32("public_key", &signed.public_key)?;

    let expected_attester = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    if signed.attestation.attester != expected_attester {
        return Err(format!(
            "public key belongs to account {}, but attester is {}",
            expected_attester, signed.attestation.attester
        ));
    }

    let payload_hash = compute_payload_hash(
        &signed.attestation,
        signed.nonce,
        &signed.network_passphrase,
        &signed.contract_id,
    )?;
    if hex::encode(payload_hash) != signed.payload_hash.trim_start_matches("0x") {
        return Err("payload_hash does not match attestation contents".to_string());
    }

    let signature_bytes: [u8; 64] = hex::decode(signed.signature.trim_start_matches("0x"))
        .map_err(|e| format!("invalid hex in signature: {e}"))?
        .try_into()
        .map_err(|_| "signature must be exactly 64 bytes".to_string())?;

    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|e| format!("invalid public key: {e}"))?;
    verifying_key
        .verify(&payload_hash, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| "signature verification failed".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedDelegatedRevocation {
    /// 32-byte attestation UID being revoked, hex encoded.
    pub uid: String,
    /// Attester account address (strkey `G...`); must match the signing key.
    pub attester: String,
    pub nonce: u64,
    pub network_passphrase: String,
    /// Address of the SAS contract the signature is bound to (strkey `C...`).
    pub contract_id: String,
    /// Hex-encoded 32-byte ed25519 public key of the attester.
    pub public_key: String,
    /// Hex-encoded 64-byte ed25519 signature over the payload digest.
    pub signature: String,
}

/// Signs a delegated revocation with a 32-byte ed25519 seed, for later
/// submission via `SAS::revoke_by_delegation` by any relayer.
pub fn sign_delegated_revocation(
    uid_hex: &str,
    attester: &str,
    nonce: u64,
    network_passphrase: &str,
    contract_id: &str,
    secret_seed: &[u8; 32],
) -> Result<SignedDelegatedRevocation, String> {
    let signing_key = SigningKey::from_bytes(secret_seed);
    let public_key = signing_key.verifying_key().to_bytes();

    let expected_attester = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    if attester != expected_attester {
        return Err(format!(
            "attester {attester} does not match signing key account {expected_attester}"
        ));
    }

    let env = Env::default();
    let uid = UID(BytesN::from_array(&env, &decode_hex32("uid", uid_hex)?));
    let attester_address = parse_address(&env, attester, AddressKind::Either, "attester")
        .map_err(|e| e.to_string())?;
    let network_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, network_passphrase.as_bytes()));
    let domain = AttestationDomain {
        network_id,
        contract: parse_address(&env, contract_id, AddressKind::Contract, "contract_id")
            .map_err(|e| e.to_string())?,
        nonce,
    };
    let payload_hash = hash_delegated_revocation(&env, &uid, &attester_address, &domain);
    let signature: Signature = signing_key.sign(&payload_hash.to_array());

    Ok(SignedDelegatedRevocation {
        uid: uid_hex.trim_start_matches("0x").to_string(),
        attester: attester.to_string(),
        nonce,
        network_passphrase: network_passphrase.to_string(),
        contract_id: contract_id.to_string(),
        public_key: hex::encode(public_key),
        signature: hex::encode(signature.to_bytes()),
    })
}

pub fn parse_secret_seed(value: &str) -> Result<[u8; 32], String> {
    let trimmed = value.trim();
    if trimmed.starts_with('S') {
        let key = stellar_strkey::ed25519::PrivateKey::from_string(trimmed)
            .map_err(|e| format!("invalid secret seed strkey: {e:?}"))?;
        Ok(key.0)
    } else {
        decode_hex32("secret key", trimmed)
    }
}
