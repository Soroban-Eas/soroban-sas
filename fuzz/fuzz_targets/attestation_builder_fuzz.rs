//! Fuzz test for
//! `soroban_sas_sdk::attestation_builder::AttestationRequestBuilder::build`.
//!
//! `AttestationRequestBuilder::build` is the SDK-side entry point that every
//! caller uses before submitting an attestation transaction.  It must:
//! - validate the recipient and attester strkeys **before** calling
//!   `Address::from_string` (which traps on malformed input),
//! - reject self-attestation and zero-address sentinels,
//! - derive a content-addressed UID.
//!
//! Properties verified on every input:
//! 1. Never panics, regardless of recipient/attester string content.
//! 2. On success the UID is non-zero and consistent between two calls with
//!    the same inputs (determinism).
//! 3. On success, `validate_attestation_parties` accepts the resulting
//!    `(recipient, attester)` pair.
#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::validate_attestation_parties;
use soroban_sas_sdk::attestation_builder::AttestationRequestBuilder;
use soroban_sdk::{Bytes, Env};

/// A well-formed ed25519 account strkey used as the attester when the fuzz
/// input's candidate is invalid, so we can exercise the recipient-validation
/// branch.
const VALID_ATTESTER: &str = "GBGJPCTLVNHCXIBDQNRIWANQLXRQDLDQPQPKJD7YTBRFZLKM5C7BFNW";
/// A well-formed ed25519 account strkey used as the recipient when the fuzz
/// input's candidate is invalid.
const VALID_RECIPIENT: &str = "GCRR6BBDFE3SVDFJHCKJXPKBZMUFXN6PZD3YYSIFXNBXCKJF5BKJQHD";

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let env = Env::default();
    let flags = data[0];
    let rest = &data[1..];

    // Split rest at first NUL: before = recipient candidate,
    // after first NUL = attester candidate, remainder = data payload.
    let (recipient_raw, after_recipient) = match rest.find(b'\0') {
        Some(pos) => (&rest[..pos], &rest[pos + 1..]),
        None => (rest, &[][..]),
    };
    let (attester_raw, payload_raw) = match after_recipient.find(b'\0') {
        Some(pos) => (
            &after_recipient[..pos],
            &after_recipient[pos + 1..],
        ),
        None => (after_recipient, &[][..]),
    };

    let recipient_str = std::str::from_utf8(recipient_raw)
        .map(str::trim)
        .unwrap_or(VALID_RECIPIENT);
    let attester_str = std::str::from_utf8(attester_raw)
        .map(str::trim)
        .unwrap_or(VALID_ATTESTER);

    // Use flag bits to drive optional fields.
    let revocable = flags & 0x01 != 0;
    let has_expiration = flags & 0x02 != 0;
    let expiration: u64 = if has_expiration {
        // Derive expiration from the first 8 bytes of payload.
        if payload_raw.len() >= 8 {
            u64::from_be_bytes(payload_raw[..8].try_into().unwrap())
        } else {
            0
        }
    } else {
        0
    };

    let schema_uid: [u8; 32] = if payload_raw.len() >= 32 {
        payload_raw[..32].try_into().unwrap()
    } else {
        [0xAB; 32]
    };

    let data_slice = if payload_raw.len() >= 32 {
        &payload_raw[32..]
    } else {
        payload_raw
    };
    let data_bytes = Bytes::from_slice(&env, data_slice);

    // ── Property 1: never panics ─────────────────────────────────────────────
    let result = AttestationRequestBuilder::new()
        .with_recipient(recipient_str)
        .with_attester(attester_str)
        .with_schema_uid(schema_uid)
        .with_data(data_bytes.clone())
        .with_revocable(revocable)
        .with_expiration(expiration)
        .build(&env);

    match result {
        Ok(attestation) => {
            // ── Property 2: non-zero UID & determinism ────────────────────────
            assert_ne!(
                attestation.uid.0.to_array(),
                [0u8; 32],
                "built attestation must have a non-zero UID"
            );
            // `revocation_time` must always be 0 for a freshly built attestation.
            assert_eq!(
                attestation.revocation_time, 0,
                "freshly built attestation must have revocation_time == 0"
            );

            let result2 = AttestationRequestBuilder::new()
                .with_recipient(recipient_str)
                .with_attester(attester_str)
                .with_schema_uid(schema_uid)
                .with_data(data_bytes)
                .with_revocable(revocable)
                .with_expiration(expiration)
                .build(&env);
            let att2 = result2.expect("second build with same inputs must also succeed");
            assert_eq!(
                attestation.uid.0.to_array(),
                att2.uid.0.to_array(),
                "AttestationRequestBuilder::build must be deterministic"
            );

            // ── Property 3: parties are valid ─────────────────────────────────
            assert!(
                validate_attestation_parties(
                    &env,
                    &attestation.recipient,
                    &attestation.attester
                )
                .is_ok(),
                "a successfully built attestation must have valid (recipient, attester) parties"
            );
        }
        Err(e) => {
            // Errors are fine — the strkeys may be malformed or parties invalid.
            assert!(
                !format!("{e:?}").is_empty(),
                "error from AttestationRequestBuilder::build must not be empty"
            );
        }
    }
});

trait SliceExt {
    fn find(&self, needle: u8) -> Option<usize>;
}

impl SliceExt for [u8] {
    fn find(&self, needle: u8) -> Option<usize> {
        self.iter().position(|&b| b == needle)
    }
}
