//! Fuzz test for `soroban_sas_cli::bulk::parse_bulk_csv` (issue #335).
//!
//! `parse_bulk_csv` is the entry point for every `attest bulk` invocation.
//! It accepts operator-supplied CSV files, handles arbitrary byte sequences as
//! field content, and must never panic on any input — malformed, adversarial,
//! or well-formed. A panic here would crash the CLI and could hide parsing bugs
//! that silently produce wrong attestation payloads.
//!
//! Properties verified on every input:
//! 1. The function never panics.
//! 2. On success, every returned `BulkRow` respects structural invariants
//!    (`expiration >= 0`, `schema_uid` and `recipient` non-empty, line number
//!    is positive).
//! 3. Row count is within `[1, MAX_BULK_ROWS]`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_cli::bulk::{parse_bulk_csv, MAX_BULK_ROWS};

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytes as a UTF-8 string (valid or not). parse_bulk_csv
    // operates on &str, so we skip non-UTF-8 inputs rather than panicking
    // on the conversion — the fuzzer will still explore many valid UTF-8
    // prefixes.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    match parse_bulk_csv(s) {
        Ok(rows) => {
            // ── Invariant 2: structural correctness ──────────────────────────
            assert!(
                !rows.is_empty(),
                "a successful parse must return at least one row"
            );
            assert!(
                rows.len() <= MAX_BULK_ROWS,
                "row count must never exceed MAX_BULK_ROWS"
            );
            for row in &rows {
                assert!(
                    !row.schema_uid.is_empty(),
                    "schema_uid must never be empty in a successfully parsed row"
                );
                assert!(
                    !row.recipient.is_empty(),
                    "recipient must never be empty in a successfully parsed row"
                );
                assert!(
                    row.line > 0,
                    "source line must be 1-based (> 0)"
                );
                // expiration_time is a u64, so it is always >= 0 by type.
                let _ = row.expiration;
                let _ = row.revocable;
            }
        }
        Err(e) => {
            // An error is fine — we only require that the function does not
            // panic and that errors carry a non-empty message useful for an
            // operator to diagnose the problem.
            assert!(
                !e.is_empty(),
                "error messages must be non-empty"
            );
        }
    }
});
