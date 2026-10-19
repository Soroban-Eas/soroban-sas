//! Fuzz test for the shared validation utilities in `soroban-sas-common`.
//!
//! Covers three pure functions that are reused by every contract and SDK
//! call site:
//!
//! - `validate_attestation_parties`: rejects zero-address sentinels and
//!   self-attestation.
//! - `validate_ttl`: rejects expiration timestamps that have already passed.
//! - `validate_recipient`: the inner single-address check (zero-address).
//!
//! None of these functions allocate or branch on heap state, so they make
//! ideal fast-path fuzz targets. The goal is to confirm they never panic,
//! and that the outcome of each check is consistent with the invariants the
//! protocol spec documents.
#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::{validate_attestation_parties, validate_recipient, validate_ttl};
use soroban_sdk::{testutils::Address as _, Address, Env, String as SorobanString};

/// Zero-address sentinels the validator must always reject.
const ZERO_ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const ZERO_CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

fuzz_target!(|data: &[u8]| {
    // Need at least one flag byte + two u64 timestamps (16 bytes).
    if data.len() < 17 {
        return;
    }

    let env = Env::default();

    let flags = data[0];
    let current_time = u64::from_be_bytes(data[1..9].try_into().unwrap());
    let expiration_time = u64::from_be_bytes(data[9..17].try_into().unwrap());

    // ── validate_ttl ─────────────────────────────────────────────────────────
    // Contract: returns Err(InvalidTTL) iff expiration_time > 0 AND
    //           current_time >= expiration_time. Must never panic.
    let ttl_result = validate_ttl(&env, current_time, expiration_time);
    if expiration_time == 0 {
        assert!(
            ttl_result.is_ok(),
            "expiration_time == 0 means 'never expires', must always pass"
        );
    } else if current_time >= expiration_time {
        assert!(
            ttl_result.is_err(),
            "past/equal expiration must be rejected"
        );
    } else {
        assert!(
            ttl_result.is_ok(),
            "future expiration must be accepted"
        );
    }

    // ── validate_recipient ────────────────────────────────────────────────────
    // The zero sentinels must always be rejected.
    let zero_account = Address::from_string(&SorobanString::from_str(&env, ZERO_ACCOUNT));
    let zero_contract = Address::from_string(&SorobanString::from_str(&env, ZERO_CONTRACT));
    assert!(
        validate_recipient(&env, &zero_account).is_err(),
        "zero account sentinel must always be rejected"
    );
    assert!(
        validate_recipient(&env, &zero_contract).is_err(),
        "zero contract sentinel must always be rejected"
    );

    // A randomly generated address must always be accepted.
    let random_addr = Address::generate(&env);
    assert!(
        validate_recipient(&env, &random_addr).is_ok(),
        "a randomly generated (non-zero) address must always be accepted"
    );

    // ── validate_attestation_parties ─────────────────────────────────────────
    // Use two genuinely independent addresses so neither is zero.
    let recipient = Address::generate(&env);
    let attester = Address::generate(&env);

    // Two distinct non-zero addresses: must always succeed.
    assert!(
        validate_attestation_parties(&env, &recipient, &attester).is_ok(),
        "two distinct non-zero addresses must always pass validate_attestation_parties"
    );

    // Self-attestation (recipient == attester): must always be rejected.
    assert!(
        validate_attestation_parties(&env, &recipient, &recipient).is_err(),
        "self-attestation must always be rejected"
    );

    // Zero recipient with any attester: must always be rejected.
    assert!(
        validate_attestation_parties(&env, &zero_account, &attester).is_err(),
        "zero-account recipient must always be rejected by validate_attestation_parties"
    );
    assert!(
        validate_attestation_parties(&env, &zero_contract, &attester).is_err(),
        "zero-contract recipient must always be rejected by validate_attestation_parties"
    );

    // Variant: flags drive which zero sentinel is used as the attester.
    let sentinel = if flags & 0x01 != 0 {
        zero_account.clone()
    } else {
        zero_contract.clone()
    };
    assert!(
        validate_attestation_parties(&env, &recipient, &sentinel).is_err(),
        "zero-address attester sentinel must always be rejected"
    );
});
