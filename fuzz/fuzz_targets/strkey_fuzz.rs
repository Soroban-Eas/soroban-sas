//! Fuzz test for `soroban_sas_sdk::strkey::validate_strkey` (issue #171).
//!
//! `validate_strkey` is the off-host guard that prevents a malformed strkey
//! from reaching `Address::from_string`, which would trap the host and panic
//! the process. It must be robust against every byte sequence an attacker
//! or a misconfigured client might supply.
//!
//! Properties verified on every input:
//! 1. The function never panics.
//! 2. If it returns `Ok`, then `stellar_strkey` actually accepts the string
//!    (cross-checking the implementation against the reference library).
//! 3. If it returns `Err`, the error message is non-empty.
//! 4. The result is consistent across multiple calls with the same input
//!    (determinism).
//! 5. The three `AddressKind` variants are mutually consistent:
//!    - `Either` accepts iff `Account` OR `Contract` accepts.
//!    - `Account` and `Contract` must be mutually exclusive for a given
//!      well-formed strkey.
#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_sdk::strkey::{validate_strkey, AddressKind};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    let account_res = validate_strkey(s, AddressKind::Account, "field");
    let contract_res = validate_strkey(s, AddressKind::Contract, "field");
    let either_res = validate_strkey(s, AddressKind::Either, "field");

    // ── Property 1: never panics (implicit — we reached here) ───────────────

    // ── Property 3: errors carry a message ───────────────────────────────────
    if let Err(ref e) = account_res {
        assert!(!format!("{e:?}").is_empty(), "error must not be empty");
    }
    if let Err(ref e) = contract_res {
        assert!(!format!("{e:?}").is_empty(), "error must not be empty");
    }
    if let Err(ref e) = either_res {
        assert!(!format!("{e:?}").is_empty(), "error must not be empty");
    }

    // ── Property 4: determinism ───────────────────────────────────────────────
    let account_res2 = validate_strkey(s, AddressKind::Account, "field");
    assert_eq!(
        account_res.is_ok(),
        account_res2.is_ok(),
        "validate_strkey must be deterministic"
    );

    // ── Property 5: AddressKind consistency ──────────────────────────────────
    let accepts_account = account_res.is_ok();
    let accepts_contract = contract_res.is_ok();
    let accepts_either = either_res.is_ok();

    // Either ⟺ Account ∨ Contract
    assert_eq!(
        accepts_either,
        accepts_account || accepts_contract,
        "AddressKind::Either must accept iff Account OR Contract accepts"
    );

    // A well-formed strkey cannot simultaneously be an account and a contract.
    if accepts_account && accepts_contract {
        panic!("a strkey was accepted as both an account and a contract: {s:?}");
    }

    // ── Property 2: cross-check with stellar_strkey reference ───────────────
    let strkey_says_account = stellar_strkey::ed25519::PublicKey::from_string(s).is_ok();
    let strkey_says_contract = stellar_strkey::Contract::from_string(s).is_ok();

    assert_eq!(
        accepts_account, strkey_says_account,
        "validate_strkey(Account) disagrees with stellar_strkey for {s:?}"
    );
    assert_eq!(
        accepts_contract, strkey_says_contract,
        "validate_strkey(Contract) disagrees with stellar_strkey for {s:?}"
    );
});
