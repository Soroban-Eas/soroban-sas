//! Shared differential case generator for the libFuzzer target and the
//! TypeScript cross-language fixture exporter (#489).
//! The reference hash deliberately uses sha2 and explicit byte assembly
//! instead of delegating to the common Rust hashing function.
use sas::SASClient;
use sha2::{Digest, Sha256};
use soroban_sas_common::{
    typed_data::{ATTESTATION_TYPE_TAG, DOMAIN_TYPE_TAG, PAYLOAD_PREFIX},
    Attestation, AttestationDomain, UID,
};
use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env, String as SorobanString};

fn word(input: &[u8], start: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    let available = input.len().saturating_sub(start).min(32);
    if available > 0 {
        out[..available].copy_from_slice(&input[start..start + available]);
    }
    out
}

fn address(env: &Env, key: [u8; 32], contract: bool) -> Address {
    let encoded = if contract {
        stellar_strkey::Contract(key).to_string()
    } else {
        stellar_strkey::ed25519::PublicKey(key).to_string()
    };
    Address::from_string(&SorobanString::from_str(env, &encoded))
}

fn raw(input: &Bytes) -> Vec<u8> {
    let mut value = vec![0u8; input.len() as usize];
    input.copy_into_slice(&mut value);
    value
}

fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

/// Input is arbitrary bytes, including zero-length buffers and non-UTF8.
/// Layout deliberately crosses u64 extremes, zero keys, account/contract
/// addresses, revocable booleans, and data of arbitrary length.
pub fn from_bytes(env: &Env, sas_id: &Address, data: &[u8]) -> (Attestation, AttestationDomain) {
    let flags = data.first().copied().unwrap_or(0);
    let mut u64buf = [0u8; 8];
    for (offset, item) in u64buf.iter_mut().enumerate() {
        *item = data.get(offset + 1).copied().unwrap_or(0);
    }
    let time = if flags & 0x10 != 0 {
        u64::MAX
    } else {
        u64::from_be_bytes(u64buf)
    };
    for (offset, item) in u64buf.iter_mut().enumerate() {
        *item = data.get(offset + 9).copied().unwrap_or(0);
    }
    let nonce = if flags & 0x20 != 0 {
        u64::MAX
    } else {
        u64::from_be_bytes(u64buf)
    };
    let recipient = address(
        env,
        if flags & 0x40 != 0 {
            [0u8; 32]
        } else {
            word(data, 17)
        },
        flags & 1 != 0,
    );
    let attester = address(env, word(data, 49), false);
    let bytes = data.get(113..).unwrap_or(&[]);
    let attestation = Attestation {
        uid: UID(BytesN::from_array(env, &word(data, 81))),
        schema_uid: UID(BytesN::from_array(env, &word(data, 17))),
        time,
        expiration_time: if flags & 0x80 != 0 { u64::MAX } else { nonce },
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient,
        attester,
        revocable: flags & 2 != 0,
        data: Bytes::from_slice(env, bytes),
        valid_from: 0,
    };
    let domain = AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: sas_id.clone(),
        nonce,
    };
    (attestation, domain)
}

/// Implementation independent of soroban_sas_common::typed_data, matching
/// the explicit Node/TS SDK preimage recipe and XDR encoding.
pub fn reference_digest(
    env: &Env,
    attestation: &Attestation,
    domain: &AttestationDomain,
) -> [u8; 32] {
    let mut domain_preimage = DOMAIN_TYPE_TAG.to_vec();
    domain_preimage.extend_from_slice(&domain.network_id.to_array());
    domain_preimage.extend_from_slice(&raw(&domain.contract.clone().to_xdr(env)));
    domain_preimage.extend_from_slice(&domain.nonce.to_be_bytes());
    let domain_hash = digest(&domain_preimage);

    let mut body = ATTESTATION_TYPE_TAG.to_vec();
    body.extend_from_slice(&attestation.uid.0.to_array());
    body.extend_from_slice(&attestation.schema_uid.0.to_array());
    body.extend_from_slice(&attestation.time.to_be_bytes());
    body.extend_from_slice(&attestation.expiration_time.to_be_bytes());
    body.extend_from_slice(&attestation.ref_uid.0.to_array());
    body.extend_from_slice(&raw(&attestation.recipient.clone().to_xdr(env)));
    body.extend_from_slice(&raw(&attestation.attester.clone().to_xdr(env)));
    body.push(u8::from(attestation.revocable));
    body.extend_from_slice(&digest(&raw(&attestation.data)));

    let mut preimage = PAYLOAD_PREFIX.to_vec();
    preimage.extend_from_slice(&domain_hash);
    preimage.extend_from_slice(&digest(&body));
    digest(&preimage)
}

pub fn assert_parity(
    env: &Env,
    sas_id: &Address,
    attestation: &Attestation,
    domain: &AttestationDomain,
) -> [u8; 32] {
    let common = soroban_sas_common::hash_offchain_attestation(env, attestation, domain).to_array();
    let via_contract = SASClient::new(env, sas_id)
        .hash_delegation_digest(attestation, &domain.nonce)
        .to_array();
    let independent = reference_digest(env, attestation, domain);
    assert_eq!(
        common, via_contract,
        "Rust common and SAS contract diverged"
    );
    assert_eq!(
        common, independent,
        "Rust common and independent TS-port preimage diverged"
    );
    common
}
