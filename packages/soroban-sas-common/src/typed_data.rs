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

//! # Off-chain verification example
//!
//! An off-chain verifier can reproduce the exact digest an issuer signed
//! without calling the on-chain contract. This is useful for wallets,
//! relayers, and indexers that need to validate attestations before
//! or without interacting with the ledger.
//!
//! ```rust,no_run
//! use soroban_sas_common::{
//!     hash_offchain_attestation, Attestation, AttestationDomain, UID,
//! };
//! use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};
//!
//! let env = Env::default();
//!
//! // Build the domain separator binding this signature to one network,
//! // one SAS contract, and one caller-chosen nonce.
//! let domain = AttestationDomain {
//!     network_id: BytesN::from_array(&env, &[0u8; 32]), // SHA-256 of passphrase
//!     contract: Address::generate(&env),
//!     nonce: 42,
//! };
//!
//! // Construct the attestation (fields must match what the issuer signed).
//! let attestation = Attestation {
//!     uid: UID(BytesN::from_array(&env, &[1u8; 32])),
//!     schema_uid: UID(BytesN::from_array(&env, &[2u8; 32])),
//!     time: 1_700_000_000,
//!     expiration_time: 0,
//!     revocation_time: 0,
//!     ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
//!     recipient: Address::generate(&env),
//!     attester: Address::generate(&env),
//!     revocable: true,
//!     data: soroban_sdk::Bytes::new(&env),
//! };
//!
//! // Reproduce the deterministic digest the issuer signed.
//! let digest = hash_offchain_attestation(&env, &attestation, &domain);
//!
//! // Verify with the issuer's ed25519 public key and signature.
//! // verify_offchain_signature(&env, &digest, &public_key, &signature);
//! ```

use crate::Attestation;
use soroban_sdk::{contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env};

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
    env.crypto().sha256(&buf).into()
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
    env.crypto().sha256(&buf).into()
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
    env.crypto().sha256(&buf).into()
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
    env.crypto().sha256(&buf).into()
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

#[cfg(test)]
mod golden_vectors {
    //! Golden test vectors for off-chain signing (Issue #103).
    //!
    //! These tests pin the exact digest values produced by the v1 signing
    //! protocol, ensuring that:
    //! 1. Cross-language implementations can verify they produce identical hashes
    //! 2. The protocol version is locked and any change is a breaking change
    //! 3. Network/contract/nonce separation is cryptographically enforced
    //!
    //! Each test uses fixed inputs and asserts against a hardcoded expected
    //! digest, so any deviation in the hash computation surfaces as a test failure.

    use super::*;
    use crate::{Attestation, UID};
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use soroban_sdk::{Address, Bytes, BytesN, Env, String as SorobanString};

    fn testnet_passphrase() -> &'static str {
        "Test SDF Network ; September 2015"
    }

    fn mainnet_passphrase() -> &'static str {
        "Public Global Stellar Network ; September 2015"
    }

    fn network_id_from_passphrase(env: &Env, passphrase: &str) -> BytesN<32> {
        env.crypto()
            .sha256(&Bytes::from_slice(env, passphrase.as_bytes()))
            .into()
    }

    fn account_address(env: &Env, public_key: &[u8; 32]) -> Address {
        let strkey = stellar_strkey::ed25519::PublicKey(*public_key).to_string();
        Address::from_string(&SorobanString::from_str(env, &strkey))
    }

    fn contract_address(env: &Env, contract_id: &[u8; 32]) -> Address {
        let strkey = stellar_strkey::Contract(*contract_id).to_string();
        Address::from_string(&SorobanString::from_str(env, &strkey))
    }

    /// Golden vector #1: Testnet attestation with fixed inputs.
    ///
    /// This is the canonical reference vector for v1 off-chain signing.
    /// The expected digest was computed by the implementation at the time
    /// this test was written and is pinned here as the ground truth.
    #[test]
    fn golden_vector_1_testnet_attestation() {
        let env = Env::default();

        let attester_key = [0x11u8; 32];
        let recipient_key = [0x22u8; 32];
        let contract_id = [0x33u8; 32];

        let attestation = Attestation {
            uid: UID(BytesN::from_array(&env, &[0x01u8; 32])),
            schema_uid: UID(BytesN::from_array(&env, &[0x02u8; 32])),
            time: 1_700_000_000,
            expiration_time: 1_800_000_000,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0x00u8; 32])),
            recipient: account_address(&env, &recipient_key),
            attester: account_address(&env, &attester_key),
            revocable: true,
            data: Bytes::from_slice(&env, b"test data"),
        };

        let domain = AttestationDomain {
            network_id: network_id_from_passphrase(&env, testnet_passphrase()),
            contract: contract_address(&env, &contract_id),
            nonce: 1,
        };

        let digest = hash_offchain_attestation(&env, &attestation, &domain);

        // Expected digest computed by the v1 implementation
        let expected: [u8; 32] = [
            0x34, 0xb5, 0x1a, 0x63, 0xfb, 0xda, 0xc0, 0xca, 0x44, 0x39, 0xf6, 0x01, 0x75, 0x62,
            0x91, 0xf1, 0xfe, 0x89, 0x26, 0xec, 0x85, 0x0e, 0xad, 0xc8, 0xf0, 0xff, 0x23, 0xa8,
            0x37, 0x3b, 0x85, 0xca,
        ];

        assert_eq!(
            digest.to_array(),
            expected,
            "Golden vector #1 digest mismatch - v1 protocol may have changed"
        );
    }

    /// Golden vector #2: Same attestation as #1 but on Mainnet.
    ///
    /// Proves that network_id separation is enforced: changing only the
    /// network passphrase produces a completely different digest.
    #[test]
    fn golden_vector_2_mainnet_produces_different_digest() {
        let env = Env::default();

        let attester_key = [0x11u8; 32];
        let recipient_key = [0x22u8; 32];
        let contract_id = [0x33u8; 32];

        let attestation = Attestation {
            uid: UID(BytesN::from_array(&env, &[0x01u8; 32])),
            schema_uid: UID(BytesN::from_array(&env, &[0x02u8; 32])),
            time: 1_700_000_000,
            expiration_time: 1_800_000_000,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0x00u8; 32])),
            recipient: account_address(&env, &recipient_key),
            attester: account_address(&env, &attester_key),
            revocable: true,
            data: Bytes::from_slice(&env, b"test data"),
        };

        let domain = AttestationDomain {
            network_id: network_id_from_passphrase(&env, mainnet_passphrase()),
            contract: contract_address(&env, &contract_id),
            nonce: 1,
        };

        let digest = hash_offchain_attestation(&env, &attestation, &domain);

        let expected: [u8; 32] = [
            0x5d, 0x7e, 0xe3, 0x5c, 0xf9, 0xe3, 0x53, 0x82, 0x5c, 0xcd, 0xd9, 0xb6, 0x15, 0xa5,
            0x8f, 0x22, 0x10, 0x5b, 0x3d, 0x98, 0x8c, 0xb9, 0xd8, 0xca, 0x63, 0x77, 0xba, 0x13,
            0xd1, 0x83, 0x2a, 0xe4,
        ];

        assert_eq!(
            digest.to_array(),
            expected,
            "Golden vector #2 (Mainnet) digest mismatch"
        );

        // Prove the digests differ
        let testnet_domain = AttestationDomain {
            network_id: network_id_from_passphrase(&env, testnet_passphrase()),
            contract: contract_address(&env, &contract_id),
            nonce: 1,
        };
        let testnet_digest = hash_offchain_attestation(&env, &attestation, &testnet_domain);
        assert_ne!(digest.to_array(), testnet_digest.to_array());
    }

    /// Golden vector #3: Same attestation as #1 but different contract.
    ///
    /// Proves that contract separation is enforced: a signature for one
    /// contract cannot be replayed against a different contract.
    #[test]
    fn golden_vector_3_different_contract_produces_different_digest() {
        let env = Env::default();

        let attester_key = [0x11u8; 32];
        let recipient_key = [0x22u8; 32];
        let contract_id_a = [0x33u8; 32];
        let contract_id_b = [0x44u8; 32];

        let attestation = Attestation {
            uid: UID(BytesN::from_array(&env, &[0x01u8; 32])),
            schema_uid: UID(BytesN::from_array(&env, &[0x02u8; 32])),
            time: 1_700_000_000,
            expiration_time: 1_800_000_000,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0x00u8; 32])),
            recipient: account_address(&env, &recipient_key),
            attester: account_address(&env, &attester_key),
            revocable: true,
            data: Bytes::from_slice(&env, b"test data"),
        };

        let domain_b = AttestationDomain {
            network_id: network_id_from_passphrase(&env, testnet_passphrase()),
            contract: contract_address(&env, &contract_id_b),
            nonce: 1,
        };

        let digest = hash_offchain_attestation(&env, &attestation, &domain_b);

        let expected: [u8; 32] = [
            0x1e, 0x40, 0xbd, 0x48, 0x87, 0xc1, 0x0d, 0x27, 0x94, 0x0d, 0x33, 0xbe, 0xd6, 0xa6,
            0xb1, 0xf9, 0x30, 0x9c, 0x32, 0x36, 0x20, 0x4c, 0x8b, 0x75, 0xee, 0x03, 0xfd, 0x4a,
            0x8d, 0x79, 0xe7, 0x2b,
        ];

        assert_eq!(
            digest.to_array(),
            expected,
            "Golden vector #3 (different contract) digest mismatch"
        );

        // Prove the digests differ
        let domain_a = AttestationDomain {
            network_id: network_id_from_passphrase(&env, testnet_passphrase()),
            contract: contract_address(&env, &contract_id_a),
            nonce: 1,
        };
        let digest_a = hash_offchain_attestation(&env, &attestation, &domain_a);
        assert_ne!(digest.to_array(), digest_a.to_array());
    }

    /// Golden vector #4: Same attestation as #1 but different nonce.
    ///
    /// Proves that nonce separation is enforced: changing the nonce prevents
    /// replay of the same attestation content.
    #[test]
    fn golden_vector_4_different_nonce_produces_different_digest() {
        let env = Env::default();

        let attester_key = [0x11u8; 32];
        let recipient_key = [0x22u8; 32];
        let contract_id = [0x33u8; 32];

        let attestation = Attestation {
            uid: UID(BytesN::from_array(&env, &[0x01u8; 32])),
            schema_uid: UID(BytesN::from_array(&env, &[0x02u8; 32])),
            time: 1_700_000_000,
            expiration_time: 1_800_000_000,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0x00u8; 32])),
            recipient: account_address(&env, &recipient_key),
            attester: account_address(&env, &attester_key),
            revocable: true,
            data: Bytes::from_slice(&env, b"test data"),
        };

        let domain_nonce_42 = AttestationDomain {
            network_id: network_id_from_passphrase(&env, testnet_passphrase()),
            contract: contract_address(&env, &contract_id),
            nonce: 42,
        };

        let digest = hash_offchain_attestation(&env, &attestation, &domain_nonce_42);

        let expected: [u8; 32] = [
            0x00, 0x86, 0x2b, 0xac, 0x7c, 0x29, 0x44, 0x03, 0xc3, 0x3b, 0x36, 0x67, 0x93, 0xbe,
            0x60, 0x15, 0xbe, 0x91, 0xaa, 0xb4, 0xd7, 0x19, 0xdd, 0x31, 0x17, 0xe8, 0x9d, 0x9c,
            0xb8, 0xdf, 0xc0, 0x57,
        ];

        assert_eq!(
            digest.to_array(),
            expected,
            "Golden vector #4 (nonce=42) digest mismatch"
        );

        // Prove the digests differ
        let domain_nonce_1 = AttestationDomain {
            network_id: network_id_from_passphrase(&env, testnet_passphrase()),
            contract: contract_address(&env, &contract_id),
            nonce: 1,
        };
        let digest_1 = hash_offchain_attestation(&env, &attestation, &domain_nonce_1);
        assert_ne!(digest.to_array(), digest_1.to_array());
    }

    /// Golden vector #5: End-to-end signature verification.
    ///
    /// Proves that a signature produced with the golden inputs verifies
    /// against the expected digest using ed25519.
    #[test]
    fn golden_vector_5_signature_verification() {
        let env = Env::default();

        let seed = [0x55u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let attester_key = verifying_key.to_bytes();

        let recipient_key = [0x22u8; 32];
        let contract_id = [0x33u8; 32];

        let attestation = Attestation {
            uid: UID(BytesN::from_array(&env, &[0x01u8; 32])),
            schema_uid: UID(BytesN::from_array(&env, &[0x02u8; 32])),
            time: 1_700_000_000,
            expiration_time: 1_800_000_000,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0x00u8; 32])),
            recipient: account_address(&env, &recipient_key),
            attester: account_address(&env, &attester_key),
            revocable: true,
            data: Bytes::from_slice(&env, b"test data"),
        };

        let domain = AttestationDomain {
            network_id: network_id_from_passphrase(&env, testnet_passphrase()),
            contract: contract_address(&env, &contract_id),
            nonce: 7,
        };

        let digest = hash_offchain_attestation(&env, &attestation, &domain);

        // Expected digest for this configuration
        let expected: [u8; 32] = [
            0x3b, 0xc0, 0x39, 0xe2, 0xb2, 0xe7, 0x43, 0xf9, 0xd8, 0x4a, 0x75, 0xd8, 0x58, 0x80,
            0x82, 0x47, 0xd5, 0x12, 0xf7, 0x95, 0xc6, 0x01, 0x48, 0x21, 0x3a, 0x66, 0x25, 0x04,
            0x9f, 0x0c, 0x61, 0xf7,
        ];

        assert_eq!(
            digest.to_array(),
            expected,
            "Golden vector #5 digest mismatch"
        );

        // Sign the digest and verify
        let signature = signing_key.sign(&digest.to_array());
        assert!(verifying_key.verify(&digest.to_array(), &signature).is_ok());

        // Expected signature (deterministic with ed25519)
        let expected_sig: [u8; 64] = [
            0xed, 0x26, 0xfe, 0x73, 0x89, 0x4a, 0x29, 0x8c, 0x25, 0x63, 0x1c, 0x49, 0x93, 0x19,
            0x49, 0x93, 0xe8, 0x26, 0x89, 0x23, 0x1f, 0xd2, 0x7d, 0xae, 0x7b, 0x05, 0xaf, 0x91,
            0xa3, 0x9d, 0x0f, 0x8e, 0x41, 0x4c, 0x38, 0x81, 0x30, 0xcd, 0x56, 0xcd, 0x51, 0x20,
            0xbd, 0x6f, 0x49, 0x5a, 0x3b, 0xeb, 0x2c, 0xcf, 0x2c, 0x1c, 0x7b, 0x52, 0x74, 0xae,
            0x1d, 0x2d, 0x3c, 0x00, 0x70, 0x64, 0xc6, 0x0f,
        ];

        assert_eq!(
            signature.to_bytes(),
            expected_sig,
            "Golden vector #5 signature mismatch - ed25519 implementation may have changed"
        );
    }
}

#[cfg(test)]
mod field_mutations {
    use super::*;
    use crate::UID;
    use soroban_sdk::{
        xdr::{Hash, ScAddress},
        TryFromVal,
    };

    fn address(env: &Env, seed: u8) -> Address {
        Address::try_from_val(env, &ScAddress::Contract(Hash([seed; 32]))).unwrap()
    }

    fn fixture(env: &Env) -> (Attestation, AttestationDomain) {
        (
            Attestation {
                uid: UID(BytesN::from_array(env, &[1; 32])),
                schema_uid: UID(BytesN::from_array(env, &[2; 32])),
                time: 1_700_000_000,
                expiration_time: 1_800_000_000,
                revocation_time: 0,
                ref_uid: UID(BytesN::from_array(env, &[3; 32])),
                recipient: address(env, 4),
                attester: address(env, 5),
                revocable: true,
                data: Bytes::from_slice(env, b"fixed payload"),
            },
            AttestationDomain {
                network_id: BytesN::from_array(env, &[6; 32]),
                contract: address(env, 7),
                nonce: 42,
            },
        )
    }

    #[test]
    fn uid_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.uid = UID(BytesN::from_array(&env, &[8; 32]));
        assert_ne!(base.uid, changed.uid);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn schema_uid_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.schema_uid = UID(BytesN::from_array(&env, &[8; 32]));
        assert_ne!(base.schema_uid, changed.schema_uid);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn time_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.time = base.time + 1;
        assert_ne!(base.time, changed.time);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn expiration_time_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.expiration_time = base.expiration_time + 1;
        assert_ne!(base.expiration_time, changed.expiration_time);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn ref_uid_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.ref_uid = UID(BytesN::from_array(&env, &[8; 32]));
        assert_ne!(base.ref_uid, changed.ref_uid);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn recipient_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.recipient = address(&env, 8);
        assert_ne!(base.recipient, changed.recipient);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn attester_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.attester = address(&env, 8);
        assert_ne!(base.attester, changed.attester);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn revocable_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.revocable = !base.revocable;
        assert_ne!(base.revocable, changed.revocable);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn data_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.data = Bytes::from_slice(&env, b"fixed payloae");
        assert_ne!(base.data, changed.data);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn revocation_time_does_not_change_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = base.clone();
        changed.revocation_time = 123;
        assert_ne!(base.revocation_time, changed.revocation_time);
        assert_eq!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &changed, &domain)
        );
    }

    #[test]
    fn network_id_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = domain.clone();
        changed.network_id = BytesN::from_array(&env, &[8; 32]);
        assert_ne!(domain.network_id, changed.network_id);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &base, &changed)
        );
    }

    #[test]
    fn contract_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = domain.clone();
        changed.contract = address(&env, 8);
        assert_ne!(domain.contract, changed.contract);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &base, &changed)
        );
    }

    #[test]
    fn nonce_changes_digest() {
        let env = Env::default();
        let (base, domain) = fixture(&env);
        let mut changed = domain.clone();
        changed.nonce = domain.nonce + 1;
        assert_ne!(domain.nonce, changed.nonce);
        assert_ne!(
            hash_offchain_attestation(&env, &base, &domain),
            hash_offchain_attestation(&env, &base, &changed)
        );
    }
}
