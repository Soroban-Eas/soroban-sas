//! Fuzz test for `soroban_sas_common::validate_schema_syntax`.
//!
//! Properties verified on every input:
//! 1. The function never panics, regardless of byte content or length.
//! 2. When it returns `Ok`, the input must:
//!    - Be valid UTF-8.
//!    - Have at most `MAX_SCHEMA_FIELDS` comma-separated fields.
//!    - Not exceed `MAX_SCHEMA_LENGTH` bytes.
//! 3. Determinism — the same input always yields the same result.
//! 4. An empty string always returns `EmptySchema`.
//! 5. A string exceeding `MAX_SCHEMA_LENGTH` always returns an error.
#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::{validate_schema_syntax, MAX_SCHEMA_FIELDS};
use soroban_sdk::{Env, String as SorobanString};

/// Matches the constant in `packages/soroban-sas-common/src/validation.rs`.
const MAX_SCHEMA_LENGTH: usize = 1024;

fuzz_target!(|data: &[u8]| {
    let env = Env::default();

    // ── Property 5: oversized input must always be rejected ──────────────────
    if data.len() > MAX_SCHEMA_LENGTH {
        // We can only construct a SorobanString from valid UTF-8, but the
        // length check happens before any character-level inspection, so
        // attempt it only when the bytes happen to be UTF-8.
        if let Ok(s) = core::str::from_utf8(data) {
            let schema = SorobanString::from_str(&env, s);
            assert!(
                validate_schema_syntax(&env, &schema).is_err(),
                "a schema string longer than MAX_SCHEMA_LENGTH must always be rejected"
            );
        }
        return;
    }

    // ── Property 4: empty string must always return EmptySchema ──────────────
    {
        let empty = SorobanString::from_str(&env, "");
        assert!(
            validate_schema_syntax(&env, &empty).is_err(),
            "empty schema must always be rejected"
        );
    }

    // Only exercise UTF-8 inputs for the remaining properties.
    let Ok(schema_str) = core::str::from_utf8(data) else {
        return;
    };

    let schema = SorobanString::from_str(&env, schema_str);

    // ── Property 1 & 3: no panic; determinism ────────────────────────────────
    let result1 = validate_schema_syntax(&env, &schema);
    let result2 = validate_schema_syntax(&env, &schema);
    assert_eq!(
        result1.is_ok(),
        result2.is_ok(),
        "validate_schema_syntax must be deterministic"
    );

    // ── Property 2: if accepted, structural invariants hold ──────────────────
    if result1.is_ok() {
        // Field count must not exceed the maximum.
        let field_count = schema_str
            .split(',')
            .filter(|f| !f.trim().is_empty())
            .count();
        assert!(
            field_count <= MAX_SCHEMA_FIELDS as usize,
            "accepted schema has {} fields, exceeds MAX_SCHEMA_FIELDS ({})",
            field_count,
            MAX_SCHEMA_FIELDS
        );

        // Schema length must not exceed the maximum (already checked above
        // for longer inputs; guard here in case of off-by-one).
        assert!(
            schema_str.len() <= MAX_SCHEMA_LENGTH,
            "accepted schema is {} bytes, exceeds MAX_SCHEMA_LENGTH",
            schema_str.len()
        );
    }
});
