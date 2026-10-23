//! Regression tests for #492: audit of signature malleability and replay
//! vectors across disparate Stellar networks.
//!
//! Off-chain delegated signatures are strictly bound to the verifying
//! contract address and the active network's passphrase hash via the
//! `AttestationDomain` mixed into every signed digest. These tests prove, at
//! the contract entry-point level, that:
//!
//! 1. **Cross-network replay fails closed** — a signature produced for the
//!    Testnet passphrase (`Test SDF Network ; September 2015`) is rejected on
//!    a simulated Mainnet instance (`Public Global Stellar Network ;
//!    September 2015`) and vice versa.
//! 2. **Cross-contract (cross-instance) replay fails closed** — a signature
//!    bound to one SAS contract address is rejected by every other instance,
//!    including one deployed at a different address on the same network.
//! 3. **Signature malleability fails closed** — Ed25519 signatures whose
//!    scalar half satisfies `S >= L` (where
//!    `L = 2^252 + 27742317777372353535851937790883648493` is the prime order
//!    of the ed25519 group) are rejected deterministically with the typed
//!    `SASError::InvalidSignature` before any host verification runs.
//!
//! Rejection surfaces: the canonical-`S` guard traps with
//! `SASError::InvalidSignature`; otherwise the Soroban host's
//! `ed25519_verify` (ed25519-dalek `verify_strict`) fails, which escalates
//! to a host trap and surfaces through a `try_` client as the non-contract
//! host error `Context/InvalidAction` in the test environment. Both are
//! fail-closed invalid-signature rejections; the invocation never commits
//! and no nonce is consumed.
//! `assert_invalid_signature_rejection` accepts either and nothing else.

use crate::{SASClient, SAS};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{
    hash_delegated_revocation, hash_offchain_attestation, Attestation, AttestationDomain, SASError,
    UID,
};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, BytesN, Env, InvokeError, String as SorobanString,
};

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// Ed25519 group order `L` in little-endian byte order (the encoding `S`
/// uses inside a 64-byte signature `R || S`). Same constant the contract
/// guard in `soroban_sas_common::verify_offchain_signature` embeds.
const ED25519_L_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[contract]
struct MockRegistry;

#[contractimpl]
impl MockRegistry {
    pub fn on_attest(_env: Env, _attestation: Attestation) {}

    pub fn on_revoke(_env: Env, _attestation: Attestation) {}

    pub fn is_authorized(_env: Env, _uid: UID, _attester: Address) -> bool {
        true
    }

    #[allow(non_snake_case)]
    pub fn SASREG(_env: Env) -> bool {
        true
    }

    pub fn get_schema(env: Env, uid: UID) -> Option<soroban_sas_common::SchemaRecord> {
        Some(soroban_sas_common::SchemaRecord {
            uid,
            resolver: env.current_contract_address(),
            revocable: true,
            schema: soroban_sdk::String::from_str(&env, "bool valid"),
            deprecated: false,
        })
    }
}

/// SHA-256 of a network passphrase — the Stellar network id that
/// `env.ledger().network_id()` reports and the signed domain binds to.
fn network_id_from_passphrase(env: &Env, passphrase: &str) -> BytesN<32> {
    env.crypto()
        .sha256(&Bytes::from_slice(env, passphrase.as_bytes()))
        .into()
}

/// Binds the test ledger to a network passphrase, simulating a deployment
/// on that Stellar network.
fn simulate_network(env: &Env, passphrase: &str) {
    let network_id = network_id_from_passphrase(env, passphrase);
    env.ledger()
        .with_mut(|li| li.network_id = network_id.to_array());
}

fn account_address(env: &Env, public_key: &[u8; 32]) -> Address {
    let strkey = stellar_strkey::ed25519::PublicKey(*public_key).to_string();
    Address::from_string(&SorobanString::from_str(env, &strkey))
}

fn public_key_of(env: &Env, signing_key: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &signing_key.verifying_key().to_bytes())
}

/// Signs `attestation` under `domain` with `signing_key`.
fn sign_attestation(
    env: &Env,
    signing_key: &SigningKey,
    attestation: &Attestation,
    domain: &AttestationDomain,
) -> BytesN<64> {
    let payload_hash = hash_offchain_attestation(env, attestation, domain);
    BytesN::from_array(env, &signing_key.sign(&payload_hash.to_array()).to_bytes())
}

/// Signs a delegated revocation of `uid` under `domain` with `signing_key`.
fn sign_revocation(
    env: &Env,
    signing_key: &SigningKey,
    uid: &UID,
    attester: &Address,
    domain: &AttestationDomain,
) -> BytesN<64> {
    let payload_hash = hash_delegated_revocation(env, uid, attester, domain);
    BytesN::from_array(env, &signing_key.sign(&payload_hash.to_array()).to_bytes())
}

/// Adds the group order `L` to the `S` half of `sig` (little-endian, no
/// wraparound). Honest signatures satisfy `S < L`, so `S + L < 2^253` always
/// fits in 32 bytes. The result `(R, S + L)` is the classic ed25519
/// malleability transformation: a naive verifier accepts both encodings.
fn malleate_s_add_group_order(sig: &BytesN<64>) -> [u8; 64] {
    let mut out = sig.to_array();
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = out[32 + i] as u16 + ED25519_L_LE[i] as u16 + carry;
        out[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S + L must fit in 256 bits for honest signatures");
    out
}

/// Asserts `res` is a fail-closed invalid-signature rejection: either the
/// typed `SASError::InvalidSignature` from the canonical-`S` guard, or the
/// host's rejection of a cryptographically invalid (but canonical) signature
/// — ed25519-dalek `verify_strict` failing escalates to a host trap, which
/// surfaces through a `try_` client as the non-contract host error
/// `Context/InvalidAction` in the test environment.
fn assert_invalid_signature_rejection<T: core::fmt::Debug>(
    res: Result<T, Result<soroban_sdk::Error, InvokeError>>,
    context: &str,
) {
    match res {
        // Typed rejection from the contract-level canonical-`S` guard (#492).
        Err(Ok(e)) if e == SASError::InvalidSignature.into() => {}
        // Host ed25519 verification rejection.
        Err(Ok(e))
            if e.is_type(soroban_sdk::xdr::ScErrorType::Context)
                && e.get_code() == soroban_sdk::xdr::ScErrorCode::InvalidAction as u32 => {}
        other => {
            panic!("{context}: expected fail-closed invalid-signature rejection, got {other:?}")
        }
    }
}

struct Fixture {
    env: Env,
    sas_id: Address,
    sas_client: SASClient<'static>,
    signing_key: SigningKey,
    attestation: Attestation,
}

fn setup() -> Fixture {
    let env = Env::default();
    let registry_id = env.register_contract(None, MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let signing_key = SigningKey::from_bytes(&[77u8; 32]);
    let attester = account_address(&env, &signing_key.verifying_key().to_bytes());

    let schema_uid = UID(BytesN::from_array(&env, &[2u8; 32]));
    let recipient = Address::generate(&env);
    let data = Bytes::from_slice(&env, &[1, 2, 3]);
    let uid = soroban_sas_common::attestation_uid(&env, &schema_uid, &recipient, &attester, &data);
    let attestation = Attestation {
        uid,
        schema_uid,
        time: 1000,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester,
        revocable: true,
        data,
    };

    Fixture {
        env,
        sas_id,
        sas_client,
        signing_key,
        attestation,
    }
}

impl Fixture {
    /// The domain a correctly configured issuer uses against this instance:
    /// bound to the active ledger's network id and this contract's address.
    fn honest_domain(&self, nonce: u64) -> AttestationDomain {
        AttestationDomain {
            network_id: self.env.ledger().network_id(),
            contract: self.sas_id.clone(),
            nonce,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-network replay
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn testnet_signature_rejected_on_simulated_mainnet_instance() {
    let f = setup();
    let nonce = 7;

    // Simulate a Mainnet deployment of the same contract code.
    simulate_network(&f.env, MAINNET_PASSPHRASE);

    // The issuer signed for Testnet: same attestation, same contract
    // address, same nonce — only the network passphrase differs.
    let testnet_domain = AttestationDomain {
        network_id: network_id_from_passphrase(&f.env, TESTNET_PASSPHRASE),
        contract: f.sas_id.clone(),
        nonce,
    };
    let signature = sign_attestation(&f.env, &f.signing_key, &f.attestation, &testnet_domain);
    let public_key = public_key_of(&f.env, &f.signing_key);

    let res =
        f.sas_client
            .try_attest_by_delegation(&f.attestation, &nonce, &signature, &public_key);
    assert_invalid_signature_rejection(res, "testnet -> mainnet replay");

    // Positive control: the same attestation signed for Mainnet (the
    // active network) succeeds — the rejection above is purely a
    // network-bound mismatch, not a broken fixture.
    let mainnet_domain = f.honest_domain(nonce);
    assert_eq!(
        mainnet_domain.network_id,
        network_id_from_passphrase(&f.env, MAINNET_PASSPHRASE)
    );
    let signature = sign_attestation(&f.env, &f.signing_key, &f.attestation, &mainnet_domain);
    assert_eq!(
        f.sas_client
            .attest_by_delegation(&f.attestation, &nonce, &signature, &public_key),
        f.attestation.uid
    );
}

#[test]
fn mainnet_signature_rejected_on_simulated_testnet_instance() {
    let f = setup();
    let nonce = 7;

    // Simulate a Testnet deployment.
    simulate_network(&f.env, TESTNET_PASSPHRASE);

    // Issuer signed for Mainnet; instance runs on Testnet.
    let mainnet_domain = AttestationDomain {
        network_id: network_id_from_passphrase(&f.env, MAINNET_PASSPHRASE),
        contract: f.sas_id.clone(),
        nonce,
    };
    let signature = sign_attestation(&f.env, &f.signing_key, &f.attestation, &mainnet_domain);
    let public_key = public_key_of(&f.env, &f.signing_key);

    let res =
        f.sas_client
            .try_attest_by_delegation(&f.attestation, &nonce, &signature, &public_key);
    assert_invalid_signature_rejection(res, "mainnet -> testnet replay");

    // Positive control on the Testnet instance.
    let testnet_domain = f.honest_domain(nonce);
    let signature = sign_attestation(&f.env, &f.signing_key, &f.attestation, &testnet_domain);
    assert_eq!(
        f.sas_client
            .attest_by_delegation(&f.attestation, &nonce, &signature, &public_key),
        f.attestation.uid
    );
}

#[test]
fn cross_network_replay_rejected_on_delegated_revocation() {
    let f = setup();
    simulate_network(&f.env, MAINNET_PASSPHRASE);

    // Issue via delegation on the (simulated) Mainnet instance.
    let issue_signature =
        sign_attestation(&f.env, &f.signing_key, &f.attestation, &f.honest_domain(1));
    let public_key = public_key_of(&f.env, &f.signing_key);
    f.sas_client
        .attest_by_delegation(&f.attestation, &1, &issue_signature, &public_key);

    // A Testnet-bound revocation signature must not revoke on Mainnet.
    let testnet_domain = AttestationDomain {
        network_id: network_id_from_passphrase(&f.env, TESTNET_PASSPHRASE),
        contract: f.sas_id.clone(),
        nonce: 2,
    };
    let signature = sign_revocation(
        &f.env,
        &f.signing_key,
        &f.attestation.uid,
        &f.attestation.attester,
        &testnet_domain,
    );
    let res =
        f.sas_client
            .try_revoke_by_delegation(&f.attestation.uid, &2, &signature, &public_key);
    assert_invalid_signature_rejection(res, "testnet -> mainnet revoke replay");
    assert!(f.sas_client.verify_attestation(&f.attestation.uid));

    // Positive control: Mainnet-bound revocation succeeds. Advance the
    // ledger first so the recorded `revocation_time` is non-zero (zero is
    // the "not revoked" sentinel).
    f.env.ledger().with_mut(|li| li.timestamp = 100);
    let signature = sign_revocation(
        &f.env,
        &f.signing_key,
        &f.attestation.uid,
        &f.attestation.attester,
        &f.honest_domain(2),
    );
    f.sas_client
        .revoke_by_delegation(&f.attestation.uid, &2, &signature, &public_key);
    assert!(!f.sas_client.verify_attestation(&f.attestation.uid));
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-contract (cross-instance) replay
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signature_bound_to_other_contract_instance_rejected() {
    let f = setup();

    // A second, independent SAS instance on the same network.
    let sas_b_id = f.env.register_contract(None, SAS);
    let sas_b = SASClient::new(&f.env, &sas_b_id);
    let admin = Address::generate(&f.env);
    let registry_id = f.env.register_contract(None, MockRegistry);
    f.env.mock_all_auths();
    sas_b.init(&admin, &registry_id);

    let nonce = 7;
    let public_key = public_key_of(&f.env, &f.signing_key);

    // Signature bound to instance A must be rejected by instance B even
    // though the network, attestation, attester key, and nonce all match.
    let domain_a = AttestationDomain {
        network_id: f.env.ledger().network_id(),
        contract: f.sas_id.clone(),
        nonce,
    };
    let signature = sign_attestation(&f.env, &f.signing_key, &f.attestation, &domain_a);

    let res = sas_b.try_attest_by_delegation(&f.attestation, &nonce, &signature, &public_key);
    assert_invalid_signature_rejection(res, "instance A -> instance B replay");

    // Positive control: instance B accepts its own bound signature with
    // the same nonce — the rejection above is purely a contract binding.
    let domain_b = AttestationDomain {
        network_id: f.env.ledger().network_id(),
        contract: sas_b_id.clone(),
        nonce,
    };
    let signature = sign_attestation(&f.env, &f.signing_key, &f.attestation, &domain_b);
    assert_eq!(
        sas_b.attest_by_delegation(&f.attestation, &nonce, &signature, &public_key),
        f.attestation.uid
    );

    // And instance A still accepts its own bound signature: the failed
    // cross-instance attempt consumed nothing on either instance.
    let signature = sign_attestation(&f.env, &f.signing_key, &f.attestation, &domain_a);
    assert_eq!(
        f.sas_client
            .attest_by_delegation(&f.attestation, &nonce, &signature, &public_key),
        f.attestation.uid
    );
}

#[test]
fn signature_for_fabricated_contract_address_rejected() {
    let f = setup();
    let nonce = 7;
    let public_key = public_key_of(&f.env, &f.signing_key);

    // A signature whose domain names a contract address that was never
    // deployed (e.g. captured from another deployment's docs) must not
    // verify against this instance.
    let fabricated = Address::from_string(&SorobanString::from_str(
        &f.env,
        &stellar_strkey::Contract([0x44u8; 32]).to_string(),
    ));
    let domain = AttestationDomain {
        network_id: f.env.ledger().network_id(),
        contract: fabricated,
        nonce,
    };
    let signature = sign_attestation(&f.env, &f.signing_key, &f.attestation, &domain);

    let res =
        f.sas_client
            .try_attest_by_delegation(&f.attestation, &nonce, &signature, &public_key);
    assert_invalid_signature_rejection(res, "fabricated contract address");
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature malleability (non-canonical scalar `S >= L`)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn malleated_s_plus_l_signature_rejected_with_invalid_signature() {
    let f = setup();
    let nonce = 7;
    let public_key = public_key_of(&f.env, &f.signing_key);
    let signature = sign_attestation(
        &f.env,
        &f.signing_key,
        &f.attestation,
        &f.honest_domain(nonce),
    );

    // (R, S + L): the classic ed25519 malleability transformation.
    let malleated = BytesN::from_array(&f.env, &malleate_s_add_group_order(&signature));
    let res =
        f.sas_client
            .try_attest_by_delegation(&f.attestation, &nonce, &malleated, &public_key);
    // Deterministic typed rejection from the contract-level guard.
    assert_eq!(res, Err(Ok(SASError::InvalidSignature.into())));

    // The failed malleated attempt must not consume the nonce: the
    // canonical original still attests exactly once.
    assert_eq!(
        f.sas_client
            .attest_by_delegation(&f.attestation, &nonce, &signature, &public_key),
        f.attestation.uid
    );
}

#[test]
fn malleated_scalar_at_group_order_boundary_rejected() {
    let f = setup();
    let nonce = 7;
    let public_key = public_key_of(&f.env, &f.signing_key);
    let valid = sign_attestation(
        &f.env,
        &f.signing_key,
        &f.attestation,
        &f.honest_domain(nonce),
    );

    // S = L exactly: the smallest non-canonical scalar.
    let mut at_order = valid.to_array();
    at_order[32..].copy_from_slice(&ED25519_L_LE);
    let at_order = BytesN::from_array(&f.env, &at_order);
    let res = f
        .sas_client
        .try_attest_by_delegation(&f.attestation, &nonce, &at_order, &public_key);
    assert_eq!(res, Err(Ok(SASError::InvalidSignature.into())));

    // S = 2^256 - 1: far outside the valid range.
    let mut max_s = valid.to_array();
    max_s[32..].fill(0xff);
    let max_s = BytesN::from_array(&f.env, &max_s);
    let res = f
        .sas_client
        .try_attest_by_delegation(&f.attestation, &nonce, &max_s, &public_key);
    assert_eq!(res, Err(Ok(SASError::InvalidSignature.into())));

    // S = L - 1: canonical (passes the guard) but cryptographically wrong,
    // so the host must still fail closed — pinning the exact S < L bound.
    let mut below_order = valid.to_array();
    below_order[32..].copy_from_slice(&ED25519_L_LE);
    below_order[32] -= 1;
    let below_order = BytesN::from_array(&f.env, &below_order);
    let res =
        f.sas_client
            .try_attest_by_delegation(&f.attestation, &nonce, &below_order, &public_key);
    assert_invalid_signature_rejection(res, "S = L - 1 boundary");
}

#[test]
fn malleated_signature_rejected_on_offchain_verification_view() {
    let f = setup();
    let nonce = 7;
    let public_key = public_key_of(&f.env, &f.signing_key);
    let signature = sign_attestation(
        &f.env,
        &f.signing_key,
        &f.attestation,
        &f.honest_domain(nonce),
    );

    // The read-only verifier applies the same guard as the write paths.
    let malleated = BytesN::from_array(&f.env, &malleate_s_add_group_order(&signature));
    let res = f.sas_client.try_verify_offchain_attestation(
        &f.attestation,
        &nonce,
        &public_key,
        &malleated,
    );
    assert_eq!(res, Err(Ok(SASError::InvalidSignature.into())));

    // Positive control: the canonical signature verifies.
    assert!(f.sas_client.verify_offchain_attestation(
        &f.attestation,
        &nonce,
        &public_key,
        &signature
    ));
}

#[test]
fn malleated_revocation_signature_rejected() {
    let f = setup();
    let public_key = public_key_of(&f.env, &f.signing_key);

    let issue_signature =
        sign_attestation(&f.env, &f.signing_key, &f.attestation, &f.honest_domain(1));
    f.sas_client
        .attest_by_delegation(&f.attestation, &1, &issue_signature, &public_key);

    // Malleate the revocation signature's scalar half.
    let signature = sign_revocation(
        &f.env,
        &f.signing_key,
        &f.attestation.uid,
        &f.attestation.attester,
        &f.honest_domain(2),
    );
    let malleated = BytesN::from_array(&f.env, &malleate_s_add_group_order(&signature));
    let res =
        f.sas_client
            .try_revoke_by_delegation(&f.attestation.uid, &2, &malleated, &public_key);
    assert_eq!(res, Err(Ok(SASError::InvalidSignature.into())));
    // Attestation untouched; nonce not consumed.
    assert!(f.sas_client.verify_attestation(&f.attestation.uid));

    // Positive control: the canonical revocation still works with nonce 2.
    // Advance the ledger so the recorded `revocation_time` is non-zero.
    f.env.ledger().with_mut(|li| li.timestamp = 100);
    f.sas_client
        .revoke_by_delegation(&f.attestation.uid, &2, &signature, &public_key);
    assert!(!f.sas_client.verify_attestation(&f.attestation.uid));
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain separator binding (audit confirmation)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn delegated_digest_binds_contract_address_and_network_id() {
    // Digest-level confirmation that the domain separator commits to both
    // `env.current_contract_address()` and `env.ledger().network_id()` as
    // mixed into the digest by every delegated entry point.
    let f = setup();
    let attestation = &f.attestation;

    let base = f.honest_domain(7);
    let base_digest = hash_offchain_attestation(&f.env, attestation, &base);

    // Changing only the contract binding changes the digest.
    let other_contract = AttestationDomain {
        contract: Address::from_string(&SorobanString::from_str(
            &f.env,
            &stellar_strkey::Contract([0x55u8; 32]).to_string(),
        )),
        ..base.clone()
    };
    assert_ne!(
        base_digest,
        hash_offchain_attestation(&f.env, attestation, &other_contract)
    );

    // Changing only the network binding changes the digest.
    let other_network = AttestationDomain {
        network_id: network_id_from_passphrase(&f.env, TESTNET_PASSPHRASE),
        ..base.clone()
    };
    // (On the default test ledger the active network id is all-zero, which
    // is distinct from the Testnet passphrase hash.)
    assert_ne!(base.network_id, other_network.network_id);
    assert_ne!(
        base_digest,
        hash_offchain_attestation(&f.env, attestation, &other_network)
    );

    // Changing only the nonce changes the digest.
    let other_nonce = AttestationDomain {
        nonce: 8,
        ..base.clone()
    };
    assert_ne!(
        base_digest,
        hash_offchain_attestation(&f.env, attestation, &other_nonce)
    );
}

#[test]
fn invalid_signature_rejection_surfaces_are_fail_closed() {
    // Pins the exact error surface of each rejection path so a change in
    // either the contract guard or the host's ed25519 semantics shows up as
    // a deliberate test update, not a silent behaviour drift.
    let f = setup();
    let nonce = 7;
    let public_key = public_key_of(&f.env, &f.signing_key);
    let signature = sign_attestation(
        &f.env,
        &f.signing_key,
        &f.attestation,
        &f.honest_domain(nonce),
    );

    // Path 1 — contract-level canonical-`S` guard: typed `InvalidSignature`.
    let malleated = BytesN::from_array(&f.env, &malleate_s_add_group_order(&signature));
    let res =
        f.sas_client
            .try_attest_by_delegation(&f.attestation, &nonce, &malleated, &public_key);
    assert_eq!(res, Err(Ok(SASError::InvalidSignature.into())));

    // Path 2 — host `verify_strict` rejection of a canonical but invalid
    // signature: non-contract host error (`Context/InvalidAction`).
    let mut wrong_s = signature.to_array();
    wrong_s[32] ^= 0x01; // flip one bit of S; still canonical (S << L)
    let wrong_s = BytesN::from_array(&f.env, &wrong_s);
    let res = f
        .sas_client
        .try_attest_by_delegation(&f.attestation, &nonce, &wrong_s, &public_key);
    match res {
        Err(Ok(e)) => {
            assert!(e.is_type(soroban_sdk::xdr::ScErrorType::Context));
            assert_eq!(
                e.get_code(),
                soroban_sdk::xdr::ScErrorCode::InvalidAction as u32
            );
        }
        other => panic!("expected host rejection, got {other:?}"),
    }

    // Both rejections are fail-closed: neither consumed the nonce, so the
    // honest signature still attests exactly once afterwards.
    assert_eq!(
        f.sas_client
            .attest_by_delegation(&f.attestation, &nonce, &signature, &public_key),
        f.attestation.uid
    );
}
