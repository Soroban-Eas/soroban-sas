//! Fuzz test for `soroban_sas_common::validate_schema_syntax`.
//!
//! Properties verified on every input:
//! 1. The function never panics, regardless of byte content or length.
//! 2. When it returns `Ok`, the input must:
//!    - Be valid UTF-8 and ASCII.
//!    - Contain no uppercase ASCII letters (the parser requires lowercase
//!      identifiers and types).
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
    let schema = SorobanString::from_bytes(&env, data);

    // ── Property 1: no panic on arbitrary byte inputs ─────────────────────────
    let result = validate_schema_syntax(&env, &schema);

    // ── Property 4 & 5: empty or oversized inputs must always be rejected ─────
    if data.is_empty() || data.len() > MAX_SCHEMA_LENGTH {
        assert!(
            result.is_err(),
            "empty schema or schema longer than MAX_SCHEMA_LENGTH must always be rejected"
        );
        return;
    }

    // ── Property 3: determinism ──────────────────────────────────────────────
    let result2 = validate_schema_syntax(&env, &schema);
    assert_eq!(
        result.is_ok(),
        result2.is_ok(),
        "validate_schema_syntax must be deterministic"
    );

    // ── Property 2: if accepted, structural invariants hold ──────────────────
    if result.is_ok() {
        assert!(data.is_ascii(), "accepted schema must be valid ASCII");
        assert!(
            !data.iter().any(|&b| b < 32 || b == 127),
            "accepted schema must not contain ASCII control characters"
        );
        assert!(!data.contains(&b'\t'), "accepted schema must not contain tabs");
        assert!(!data.contains(&b'\0'), "accepted schema must not contain null bytes");

        let schema_str = core::str::from_utf8(data).expect("accepted schema must be valid UTF-8");

        // No uppercase ASCII letters allowed in valid schemas.
        assert!(
            !schema_str.chars().any(|c| c.is_ascii_uppercase()),
            "a schema with uppercase letters must not be accepted: {:?}",
            schema_str
        );

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

        // Schema length must not exceed the maximum.
        assert!(
            schema_str.len() <= MAX_SCHEMA_LENGTH,
            "accepted schema is {} bytes, exceeds MAX_SCHEMA_LENGTH",
            schema_str.len()
        );

        let fields: Vec<&str> = schema_str.split(',').collect();
        assert!(fields.len() <= MAX_SCHEMA_FIELDS as usize);
        for f in fields {
            let f = f.trim_matches(' ');
            assert!(!f.is_empty() && f.len() <= 64);
            let mut it = f.splitn(2, ' ');
            let ident = it.next().unwrap();
            let ty = it.next().unwrap().trim_matches(' ');
            assert!(!ident.is_empty() && ident.len() <= 32);
            assert!(!ty.is_empty() && ty.len() <= 32);
        }
    }
});
