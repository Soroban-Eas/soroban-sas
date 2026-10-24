//! Off-chain delegation signature helpers.
//!
//! The SAS contract authenticates `attest_by_delegation` /
//! `revoke_by_delegation` from an ed25519 signature over a typed-data digest,
//! not from `require_auth()`. Wallets, dApps, and relayer services therefore
//! need to *produce* that signature, not merely submit it.
//!
//! These helpers compute the digest with the exact `soroban_sas_common`
//! functions the contract verifies against, sign it with the issuer's
//! ed25519 key, and re-verify a signature locally. That lets an integrator
//! drive the whole issuer side of delegated issuance and revocation from the
//! SDK, without the CLI or a hand-rolled re-implementation of the byte layout.
//!
//! ```rust,no_run
//! use soroban_sas_sdk::delegation::{sign_offchain_attestation, verify_offchain_attestation};
//! use soroban_sas_sdk::delegation::delegation_domain;
//! use soroban_sdk::Env;
//!
//! # fn example(env: &Env, attester_key: [u8; 32], attestation: soroban_sas_common::Attestation)
//! #     -> Result<(), soroban_sas_sdk::errors::SdkError> {
//! let contract_id = "C...SAS_CONTRACT";
//! let network = "Test SDF Network ; September 2015";
//! let signed = sign_offchain_attestation(env, &attester_key, &attestation, 1, network, contract_id)?;
//!
//! let domain = delegation_domain(env, network, contract_id, signed.nonce)?;
//! verify_offchain_attestation(
//!     env,
//!     &attestation,
//!     &domain,
//!     &signed.public_key,
//!     &signed.signature,
//! )?;
//! # Ok(())
//! # }
//! ```

use crate::errors::SdkError;
use crate::strkey::{parse_address, AddressKind};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use soroban_sas_common::{
    hash_delegated_revocation, hash_offchain_attestation, Attestation, AttestationDomain,
    MAX_ATTESTATION_DATA_BYTES, MAX_MULTI_ATTEST, UID,
};
use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env};

/// Derives the Soroban network id from a network passphrase:
/// `sha256(network_passphrase)`.
pub fn network_id(env: &Env, network_passphrase: &str) -> BytesN<32> {
    env.crypto()
        .sha256(&Bytes::from_slice(env, network_passphrase.as_bytes()))
        .into()
}

/// Builds the [`AttestationDomain`] a delegated signature is bound to: the
/// network id derived from `network_passphrase`, the SAS contract address
/// parsed from `contract_id`, and the caller-chosen `nonce`.
///
/// The contract reconstructs this same domain from the current ledger network
/// and its own address, so a signature made for one network or one contract
/// deployment never validates against another.
pub fn delegation_domain(
    env: &Env,
    network_passphrase: &str,
    contract_id: &str,
    nonce: u64,
) -> Result<AttestationDomain, SdkError> {
    Ok(AttestationDomain {
        network_id: network_id(env, network_passphrase),
        contract: parse_address(env, contract_id, AddressKind::Contract, "contract_id")?,
        nonce,
    })
}

/// Digest an issuer signs to authorize `attestation` under `domain`.
pub fn attestation_digest(
    env: &Env,
    attestation: &Attestation,
    domain: &AttestationDomain,
) -> [u8; 32] {
    hash_offchain_attestation(env, attestation, domain).to_array()
}

/// Digest an issuer signs to authorize revocation of `uid`, where `attester`
/// is the attestation's recorded attester.
pub fn revocation_digest(
    env: &Env,
    uid: &UID,
    attester: &Address,
    domain: &AttestationDomain,
) -> [u8; 32] {
    hash_delegated_revocation(env, uid, attester, domain).to_array()
}

/// A ready-to-submit delegated signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegationSignature {
    /// Nonce the signature is bound to; must be greater than the attester's
    /// current on-chain delegation high-watermark.
    pub nonce: u64,
    /// The issuer's ed25519 public key.
    pub public_key: [u8; 32],
    /// 64-byte ed25519 signature over [`DelegationSignature::digest`].
    pub signature: [u8; 64],
    /// The 32-byte payload digest that was signed. Surfaced so callers can
    /// transport or log it alongside the signature.
    pub digest: [u8; 32],
}

/// A batch of signatures and their matching attestations, ready to submit via
/// `SAS::multi_attest_by_delegation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedBatchSignaturePacket {
    pub attestations: Vec<Attestation>,
    pub nonces: Vec<u64>,
    pub signatures: Vec<[u8; 64]>,
    pub public_keys: Vec<[u8; 32]>,
    pub digests: Vec<[u8; 32]>,
}

impl DelegatedBatchSignaturePacket {
    /// Encodes the packet as JSON. Attestations are represented as hex-encoded
    /// XDR; signatures, public keys, and digests are lowercase hex strings.
    /// The XDR values can be decoded with `Attestation::from_xdr`.
    pub fn to_json(&self, env: &Env) -> serde_json::Result<String> {
        let attestations_xdr = self
            .attestations
            .iter()
            .map(|attestation| {
                let bytes = attestation.clone().to_xdr(env);
                let mut buf = vec![0u8; bytes.len() as usize];
                bytes.copy_into_slice(&mut buf);
                hex_encode(buf)
            })
            .collect::<Vec<_>>();

        serde_json::to_string(&serde_json::json!({
            "version": 1,
            "attestations_xdr": attestations_xdr,
            "nonces": self.nonces,
            "signatures": self.signatures.iter().map(hex_encode_array).collect::<Vec<_>>(),
            "public_keys": self.public_keys.iter().map(hex_encode_array).collect::<Vec<_>>(),
            "digests": self.digests.iter().map(hex_encode_array).collect::<Vec<_>>(),
        }))
    }
}

/// Offline signer for batches of delegated attestations.
///
/// Signing and packet serialization are local operations: neither requires
/// an RPC client or network access. The supplied `Env` is used only for the
/// same deterministic hashing and XDR encoding used by the SAS contract.
pub struct DelegatedBatchSigner {
    signing_key: SigningKey,
}

impl DelegatedBatchSigner {
    /// Creates a signer from an ed25519 secret seed.
    pub fn new(secret_seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret_seed),
        }
    }

    /// Returns the signer's ed25519 public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Signs attestations for offline relay through
    /// `SAS::multi_attest_by_delegation`.
    ///
    /// All attestations must name this signer's account, carry a valid
    /// content-addressed UID, have no revocation timestamp, and fit within
    /// the protocol payload limit. Nonces must be strictly increasing in
    /// batch order, matching the contract's per-attester high-watermark.
    pub fn sign_batch(
        &self,
        env: &Env,
        attestations: &[Attestation],
        nonces: &[u64],
        network_passphrase: &str,
        contract_id: &str,
    ) -> Result<DelegatedBatchSignaturePacket, SdkError> {
        if attestations.len() != nonces.len() {
            return Err(SdkError::ValidationError(format!(
                "attestations and nonces must have the same length ({} != {})",
                attestations.len(),
                nonces.len()
            )));
        }
        if attestations.len() > MAX_MULTI_ATTEST as usize {
            return Err(SdkError::ValidationError(format!(
                "batch contains {} items; the maximum is {MAX_MULTI_ATTEST}",
                attestations.len()
            )));
        }
        if nonces.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SdkError::ValidationError(
                "nonces must be strictly increasing".to_string(),
            ));
        }

        let public_key = self.public_key();
        let base_domain = delegation_domain(env, network_passphrase, contract_id, 0)?;
        let mut packet = DelegatedBatchSignaturePacket {
            attestations: attestations.to_vec(),
            nonces: nonces.to_vec(),
            signatures: Vec::with_capacity(attestations.len()),
            public_keys: Vec::with_capacity(attestations.len()),
            digests: Vec::with_capacity(attestations.len()),
        };

        for (attestation, nonce) in attestations.iter().zip(nonces.iter().copied()) {
            if attestation.revocation_time != 0 {
                return Err(SdkError::ValidationError(
                    "delegated attestation must have a zero revocation_time".to_string(),
                ));
            }
            if attestation.data.len() > MAX_ATTESTATION_DATA_BYTES {
                return Err(SdkError::ValidationError(format!(
                    "attestation data exceeds the {MAX_ATTESTATION_DATA_BYTES}-byte protocol limit"
                )));
            }

            let expected_uid = soroban_sas_common::attestation_uid(
                env,
                &attestation.schema_uid,
                &attestation.recipient,
                &attestation.attester,
                &attestation.data,
            );
            if expected_uid != attestation.uid {
                return Err(SdkError::ValidationError(
                    "attestation UID does not match its content".to_string(),
                ));
            }

            require_attester_key(env, &attestation.attester, &public_key)?;
            let domain = AttestationDomain {
                nonce,
                ..base_domain.clone()
            };
            let digest = attestation_digest(env, attestation, &domain);
            packet
                .signatures
                .push(self.signing_key.sign(&digest).to_bytes());
            packet.public_keys.push(public_key);
            packet.digests.push(digest);
        }

        Ok(packet)
    }
}

fn hex_encode_array<const N: usize>(bytes: &[u8; N]) -> String {
    hex_encode(bytes.to_vec())
}

fn hex_encode(bytes: Vec<u8>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Derives the ed25519 public key for `secret_seed`.
pub fn signer_public_key(secret_seed: &[u8; 32]) -> [u8; 32] {
    crate::signature::derive_public_key(secret_seed)
}

/// Signs an off-chain attestation so any funded relayer can submit it via
/// `SAS::attest_by_delegation` / `SAS::multi_attest_by_delegation`.
///
/// Fails with [`SdkError::ValidationError`] when `secret_seed`'s public key is
/// not the `attestation.attester` account, matching the contract's binding
/// check rather than producing a signature that can never be accepted.
pub fn sign_offchain_attestation(
    env: &Env,
    secret_seed: &[u8; 32],
    attestation: &Attestation,
    nonce: u64,
    network_passphrase: &str,
    contract_id: &str,
) -> Result<DelegationSignature, SdkError> {
    let signing_key = SigningKey::from_bytes(secret_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    require_attester_key(env, &attestation.attester, &public_key)?;

    let domain = delegation_domain(env, network_passphrase, contract_id, nonce)?;
    let digest = attestation_digest(env, attestation, &domain);
    Ok(DelegationSignature {
        nonce,
        public_key,
        signature: signing_key.sign(&digest).to_bytes(),
        digest,
    })
}

/// Signs a delegated revocation so any funded relayer can submit it via
/// `SAS::revoke_by_delegation` / `SAS::multi_revoke_by_delegation`.
///
/// `attester` must be the attestation's recorded attester and must match
/// `secret_seed`'s key, mirroring the contract's binding check.
pub fn sign_delegated_revocation(
    env: &Env,
    secret_seed: &[u8; 32],
    uid: &UID,
    attester: &Address,
    nonce: u64,
    network_passphrase: &str,
    contract_id: &str,
) -> Result<DelegationSignature, SdkError> {
    let signing_key = SigningKey::from_bytes(secret_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    require_attester_key(env, attester, &public_key)?;

    let domain = delegation_domain(env, network_passphrase, contract_id, nonce)?;
    let digest = revocation_digest(env, uid, attester, &domain);
    Ok(DelegationSignature {
        nonce,
        public_key,
        signature: signing_key.sign(&digest).to_bytes(),
        digest,
    })
}

/// Recomputes the attestation digest for `domain` and checks `signature`
/// against `public_key`. Off-chain counterpart to the on-chain check; does not
/// consult any ledger state (expiry, revocation, schema existence).
pub fn verify_offchain_attestation(
    env: &Env,
    attestation: &Attestation,
    domain: &AttestationDomain,
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), SdkError> {
    verify_digest(
        &attestation_digest(env, attestation, domain),
        public_key,
        signature,
    )
}

/// Recomputes the delegated-revocation digest for `domain` and checks
/// `signature` against `public_key`.
pub fn verify_delegated_revocation(
    env: &Env,
    uid: &UID,
    attester: &Address,
    domain: &AttestationDomain,
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), SdkError> {
    verify_digest(
        &revocation_digest(env, uid, attester, domain),
        public_key,
        signature,
    )
}

fn require_attester_key(
    env: &Env,
    attester: &Address,
    public_key: &[u8; 32],
) -> Result<(), SdkError> {
    let public_key = BytesN::from_array(env, public_key);
    if soroban_sas_common::attester_matches_key(env, attester, &public_key) {
        Ok(())
    } else {
        Err(SdkError::ValidationError(
            "signing key does not match the attester account".to_string(),
        ))
    }
}

fn verify_digest(
    digest: &[u8; 32],
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), SdkError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| SdkError::ValidationError(format!("invalid ed25519 public key: {e}")))?;
    verifying_key
        .verify(digest, &Signature::from_bytes(signature))
        .map_err(|_| SdkError::ValidationError("ed25519 signature verification failed".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::String as SorobanString;

    const NETWORK: &str = "Test SDF Network ; September 2015";
    const OTHER_NETWORK: &str = "Public Global Stellar Network ; September 2015";

    fn contract_id() -> String {
        stellar_strkey::Contract([1u8; 32]).to_string()
    }

    fn other_contract_id() -> String {
        stellar_strkey::Contract([2u8; 32]).to_string()
    }

    fn signing_key(seed: [u8; 32]) -> SigningKey {
        SigningKey::from_bytes(&seed)
    }

    fn attester(env: &Env, key: &SigningKey) -> Address {
        let strkey = stellar_strkey::ed25519::PublicKey(key.verifying_key().to_bytes()).to_string();
        Address::from_string(&SorobanString::from_str(env, &strkey))
    }

    fn fixture(env: &Env, attester: &Address, recipient: &Address) -> Attestation {
        let schema_uid = UID(BytesN::from_array(env, &[2u8; 32]));
        let data = Bytes::from_slice(env, b"payload");
        let uid = soroban_sas_common::attestation_uid(env, &schema_uid, recipient, attester, &data);
        Attestation {
            uid,
            schema_uid,
            time: 1_000,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
            recipient: recipient.clone(),
            attester: attester.clone(),
            revocable: true,
            data,
            valid_from: 0,
        }
    }

    #[test]
    fn signs_and_verifies_an_attestation_roundtrip() {
        let env = Env::default();
        let key = signing_key([41u8; 32]);
        let attester = attester(&env, &key);
        let attestation = fixture(&env, &attester, &Address::generate(&env));

        let signed = sign_offchain_attestation(
            &env,
            &key.to_bytes(),
            &attestation,
            7,
            NETWORK,
            &contract_id(),
        )
        .unwrap();
        assert_eq!(signed.public_key, key.verifying_key().to_bytes());
        assert_eq!(signed.nonce, 7);

        let domain = delegation_domain(&env, NETWORK, &contract_id(), 7).unwrap();
        assert!(verify_offchain_attestation(
            &env,
            &attestation,
            &domain,
            &signed.public_key,
            &signed.signature
        )
        .is_ok());
        assert_eq!(
            signed.digest,
            attestation_digest(&env, &attestation, &domain)
        );
    }

    #[test]
    fn batch_signer_creates_contract_compatible_packets_offline() {
        let env = Env::default();
        let key = signing_key([41u8; 32]);
        let attester = attester(&env, &key);
        let attestations = vec![
            fixture(&env, &attester, &Address::generate(&env)),
            fixture(&env, &attester, &Address::generate(&env)),
        ];
        let nonces = [7, 8];
        let signer = DelegatedBatchSigner::new(&key.to_bytes());

        let packet = signer
            .sign_batch(&env, &attestations, &nonces, NETWORK, &contract_id())
            .unwrap();

        assert_eq!(packet.attestations, attestations);
        assert_eq!(packet.nonces, nonces);
        assert_eq!(packet.public_keys, vec![signer.public_key(); 2]);
        assert_eq!(packet.signatures.len(), 2);
        assert_eq!(packet.digests.len(), 2);
        for index in 0..attestations.len() {
            let domain = delegation_domain(&env, NETWORK, &contract_id(), nonces[index]).unwrap();
            assert!(verify_offchain_attestation(
                &env,
                &attestations[index],
                &domain,
                &packet.public_keys[index],
                &packet.signatures[index],
            )
            .is_ok());
            assert_eq!(
                packet.digests[index],
                attestation_digest(&env, &attestations[index], &domain)
            );
        }

        let serialized: serde_json::Value =
            serde_json::from_str(&packet.to_json(&env).unwrap()).unwrap();
        assert_eq!(serialized["version"], 1);
        assert_eq!(serialized["nonces"], serde_json::json!([7, 8]));
        assert_eq!(serialized["attestations_xdr"].as_array().unwrap().len(), 2);
        assert_eq!(serialized["signatures"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn batch_signer_rejects_invalid_lengths_nonces_and_attestations() {
        let env = Env::default();
        let key = signing_key([41u8; 32]);
        let attester = attester(&env, &key);
        let attestation = fixture(&env, &attester, &Address::generate(&env));
        let signer = DelegatedBatchSigner::new(&key.to_bytes());

        assert!(matches!(
            signer.sign_batch(&env, &[attestation.clone()], &[], NETWORK, &contract_id()),
            Err(SdkError::ValidationError(_))
        ));
        assert!(matches!(
            signer.sign_batch(
                &env,
                &[attestation.clone(), attestation.clone()],
                &[3, 3],
                NETWORK,
                &contract_id()
            ),
            Err(SdkError::ValidationError(_))
        ));

        let mut revoked = attestation.clone();
        revoked.revocation_time = 1;
        assert!(matches!(
            signer.sign_batch(&env, &[revoked], &[4], NETWORK, &contract_id()),
            Err(SdkError::ValidationError(_))
        ));

        let mut invalid_uid = attestation;
        invalid_uid.uid = UID(BytesN::from_array(&env, &[9u8; 32]));
        assert!(matches!(
            signer.sign_batch(&env, &[invalid_uid], &[4], NETWORK, &contract_id()),
            Err(SdkError::ValidationError(_))
        ));
    }

    #[test]
    fn verification_rejects_a_tampered_attestation() {
        let env = Env::default();
        let key = signing_key([41u8; 32]);
        let attester = attester(&env, &key);
        let attestation = fixture(&env, &attester, &Address::generate(&env));

        let signed = sign_offchain_attestation(
            &env,
            &key.to_bytes(),
            &attestation,
            7,
            NETWORK,
            &contract_id(),
        )
        .unwrap();
        let domain = delegation_domain(&env, NETWORK, &contract_id(), 7).unwrap();

        let mut tampered = attestation.clone();
        tampered.data = Bytes::from_slice(&env, b"tampered");
        assert!(verify_offchain_attestation(
            &env,
            &tampered,
            &domain,
            &signed.public_key,
            &signed.signature
        )
        .is_err());
    }

    #[test]
    fn verification_rejects_a_wrong_nonce_or_network_or_contract() {
        let env = Env::default();
        let key = signing_key([41u8; 32]);
        let attester = attester(&env, &key);
        let attestation = fixture(&env, &attester, &Address::generate(&env));

        let signed = sign_offchain_attestation(
            &env,
            &key.to_bytes(),
            &attestation,
            7,
            NETWORK,
            &contract_id(),
        )
        .unwrap();

        for (network, contract, nonce) in [
            (NETWORK, contract_id(), 8),
            (OTHER_NETWORK, contract_id(), 7),
            (NETWORK, other_contract_id(), 7),
        ] {
            let domain = delegation_domain(&env, network, &contract, nonce).unwrap();
            assert!(
                verify_offchain_attestation(
                    &env,
                    &attestation,
                    &domain,
                    &signed.public_key,
                    &signed.signature
                )
                .is_err(),
                "a signature bound to (network={network}, contract={contract}, nonce={nonce}) must not verify elsewhere"
            );
        }
    }

    #[test]
    fn signing_rejects_a_key_that_is_not_the_attester() {
        let env = Env::default();
        let signer = signing_key([41u8; 32]);
        let other = signing_key([42u8; 32]);
        // The attestation names `other` as attester, but `signer` signs it.
        let attestation = fixture(&env, &attester(&env, &other), &Address::generate(&env));

        let err = sign_offchain_attestation(
            &env,
            &signer.to_bytes(),
            &attestation,
            1,
            NETWORK,
            &contract_id(),
        )
        .expect_err("a key that is not the attester must be rejected");
        assert!(matches!(err, SdkError::ValidationError(_)));
    }

    #[test]
    fn signing_rejects_a_malformed_contract_id() {
        let env = Env::default();
        let key = signing_key([41u8; 32]);
        let attester = attester(&env, &key);
        let attestation = fixture(&env, &attester, &Address::generate(&env));

        let err = sign_offchain_attestation(
            &env,
            &key.to_bytes(),
            &attestation,
            1,
            NETWORK,
            "not-a-contract",
        )
        .expect_err("a malformed contract id must be rejected without trapping");
        assert!(matches!(err, SdkError::DecodingError(_)));
    }

    #[test]
    fn signs_and_verifies_a_delegated_revocation_roundtrip() {
        let env = Env::default();
        let key = signing_key([41u8; 32]);
        let attester = attester(&env, &key);
        let attestation = fixture(&env, &attester, &Address::generate(&env));

        let signed = sign_delegated_revocation(
            &env,
            &key.to_bytes(),
            &attestation.uid,
            &attester,
            9,
            NETWORK,
            &contract_id(),
        )
        .unwrap();
        let domain = delegation_domain(&env, NETWORK, &contract_id(), 9).unwrap();

        assert!(verify_delegated_revocation(
            &env,
            &attestation.uid,
            &attester,
            &domain,
            &signed.public_key,
            &signed.signature
        )
        .is_ok());

        // A different UID is a different digest, so the same signature fails.
        let other_uid = UID(BytesN::from_array(&env, &[9u8; 32]));
        assert!(verify_delegated_revocation(
            &env,
            &other_uid,
            &attester,
            &domain,
            &signed.public_key,
            &signed.signature
        )
        .is_err());
    }
}
