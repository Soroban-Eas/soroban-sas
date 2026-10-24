//! Local Soroban resolver for a JWT-encoded W3C Verifiable Credential.
//!
//! The wire payload is deliberately binary (bounded, cheap to parse on-chain).
//! JSON-LD remains inside the signed VC JWT; the client checks its semantics.
//! The resolver checks both JWT Ed25519 signature and an issuer-signed binding
//! to SAS schema/attester/recipient plus the issuer and subject did:key IDs.
//!
//! NOTE: This is a runnable educational example, not a general JSON-LD parser.
use soroban_sas_common::Attestation;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env};

const MAGIC: &[u8] = b"SASVC1";
const BIND_DOMAIN: &[u8] = b"SAS-VC-JWT-BIND-v1";
const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAX_JWT_LEN: u32 = 4096;

/// Compute a self-certifying did:key identifier. The multicodec prefix
/// [0xed, 0x01] denotes an Ed25519 public key, followed by base58btc encoding.
pub fn did_for_key(env: &Env, key: &BytesN<32>) -> Bytes {
    let mut input = [0u8; 34];
    input[0] = 0xed;
    input[1] = 0x01;
    input[2..].copy_from_slice(&key.to_array());
    let mut digits = [0u8; 48];
    let mut used = 0usize;
    for byte in input {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut().take(used) {
            let n = u32::from(*digit) * 256 + carry;
            *digit = (n % 58) as u8;
            carry = n / 58;
        }
        while carry > 0 {
            assert!(used < digits.len(), "base58 output exceeds bounds");
            digits[used] = (carry % 58) as u8;
            used += 1;
            carry /= 58;
        }
    }
    let mut did = Bytes::from_slice(env, b"did:key:z");
    for i in (0..used).rev() {
        did.push_back(ALPHABET[digits[i] as usize]);
    }
    did
}

/// A binding proof protects against taking a perfectly valid credential for
/// one DID or schema and reusing it for another SAS recipient/schema.
/// XDR encoding matches the protocol's own content-addressing conventions.
pub fn binding_hash(
    env: &Env,
    att: &Attestation,
    signing_input: &Bytes,
    issuer_did: &Bytes,
    subject_did: &Bytes,
) -> BytesN<32> {
    let mut preimage = Bytes::from_slice(env, BIND_DOMAIN);
    preimage.append(&att.schema_uid.clone().to_xdr(env));
    preimage.append(&att.attester.clone().to_xdr(env));
    preimage.append(&att.recipient.clone().to_xdr(env));
    preimage.append(issuer_did);
    preimage.append(subject_did);
    let signed_hash: BytesN<32> = env.crypto().sha256(signing_input).into();
    preimage.append(&signed_hash.to_xdr(env));
    env.crypto().sha256(&preimage).into()
}

fn byte(data: &Bytes, at: &mut u32) -> u8 {
    let result = data.get(*at).expect("malformed VC proof envelope");
    *at += 1;
    result
}
fn chunk(env: &Env, data: &Bytes, at: &mut u32, n: u32) -> Bytes {
    assert!(
        *at <= data.len() && n <= data.len() - *at,
        "truncated VC envelope"
    );
    let mut out = Bytes::new(env);
    for _ in 0..n {
        out.push_back(byte(data, at));
    }
    out
}
fn signature(env: &Env, data: &Bytes, at: &mut u32) -> BytesN<64> {
    let bytes = chunk(env, data, at, 64);
    let mut result = [0u8; 64];
    bytes.copy_into_slice(&mut result);
    BytesN::from_array(env, &result)
}

#[contract]
pub struct DidVcResolver;

#[contractimpl]
impl DidVcResolver {
    /// A DID controller opts into the binding of a Soroban account to its
    /// Ed25519 verification method. Production authorization is require_auth;
    /// the demo enables mock_all_auths() only in an in-memory test environment.
    pub fn bind_controller(env: Env, controller: Address, public_key: BytesN<32>) {
        controller.require_auth();
        // The key is a did:key; on-chain code recomputes that DID from its bytes.
        env.storage().persistent().set(&controller, &public_key);
    }

    /// Called by SAS when registering a credential against this schema.
    /// Refuse unknown controllers, non-matching DID subjects or bad signatures.
    pub fn on_attest(env: Env, att: Attestation) {
        let issuer_key: BytesN<32> = env
            .storage()
            .persistent()
            .get(&att.attester)
            .expect("issuer DID controller not registered");
        let subject_key: BytesN<32> = env
            .storage()
            .persistent()
            .get(&att.recipient)
            .expect("subject DID controller not registered");

        let data = &att.data;
        assert!(
            data.len() >= MAGIC.len() as u32 + 2 + 2 + 64 + 64,
            "short VC proof"
        );
        let mut cursor = 0;
        assert_eq!(
            chunk(&env, data, &mut cursor, MAGIC.len() as u32),
            Bytes::from_slice(&env, MAGIC),
            "wrong VC proof version"
        );

        let issuer_len = u32::from(byte(data, &mut cursor));
        let issuer_did = chunk(&env, data, &mut cursor, issuer_len);
        let subject_len = u32::from(byte(data, &mut cursor));
        let subject_did = chunk(&env, data, &mut cursor, subject_len);
        assert_eq!(
            issuer_did,
            did_for_key(&env, &issuer_key),
            "issuer DID/key mismatch"
        );
        assert_eq!(
            subject_did,
            did_for_key(&env, &subject_key),
            "subject DID/key mismatch"
        );

        let len_hi = u32::from(byte(data, &mut cursor));
        let len_lo = u32::from(byte(data, &mut cursor));
        let jwt_len = (len_hi << 8) | len_lo;
        assert!(jwt_len > 0 && jwt_len <= MAX_JWT_LEN, "invalid JWT length");
        let signing_input = chunk(&env, data, &mut cursor, jwt_len);
        let jwt_signature = signature(&env, data, &mut cursor);
        let binding_signature = signature(&env, data, &mut cursor);
        assert_eq!(cursor, data.len(), "trailing proof data");

        // JWT EdDSA signs the exact ASCII "base64url(header).base64url(payload)".
        env.crypto()
            .ed25519_verify(&issuer_key, &signing_input, &jwt_signature);
        // Separate domain-separated signature binds JWT and did:key subjects
        // to these exact SAS addresses and schema; it prevents substitution.
        let digest = binding_hash(&env, &att, &signing_input, &issuer_did, &subject_did);
        env.crypto().ed25519_verify(
            &issuer_key,
            &Bytes::from_array(&env, &digest.to_array()),
            &binding_signature,
        );
    }

    /// SAS performs revocation authorization and state tracking. No additional
    /// policy is needed here; issuer proof was checked before issuance.
    pub fn on_revoke(_env: Env, _att: Attestation) {}
}
