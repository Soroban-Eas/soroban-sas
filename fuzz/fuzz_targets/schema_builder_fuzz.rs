//! Fuzz test for `soroban_sas_sdk::schema_builder::SchemaBuilder::build`.
//!
//! `SchemaBuilder::build` is the SDK-side entry point that an application
//! calls before it has ever submitted a transaction: it validates the schema
//! string, resolves the resolver address, derives the content-addressed UID,
//! and returns a ready-to-submit `SchemaRecord`. Adversarial or malformed
//! input must never panic; it should produce a structured error instead.
//!
//! Properties verified on every input:
//! 1. Never panics, regardless of the schema/resolver strings.
//! 2. On success the returned `SchemaRecord` has a non-zero UID.
//! 3. Building the same record twice produces the same UID (determinism).
//! 4. A `SchemaRecord` produced by a successful build round-trips through
//!    `validate_schema_syntax` without error.
//!
//! Note: `SchemaBuilder::build` calls `Address::from_string` on the resolver
//! string, which traps the Soroban host on a malformed input.  The harness
//! therefore pre-validates the fuzz-derived resolver with
//! `validate_strkey` and falls back to the well-known `VALID_RESOLVER`
//! constant when the fuzz input does not provide a valid strkey, so the
//! schema-validation branch is still exercised.
#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::validate_schema_syntax;
use soroban_sas_sdk::strkey::{validate_strkey, AddressKind};
use soroban_sas_sdk::SchemaBuilder;
use soroban_sdk::{Env, String as SorobanString};

/// A well-formed contract address used when the fuzz input doesn't produce a
/// valid strkey, so we always exercise the schema-validation branch.
const VALID_RESOLVER: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };

    let env = Env::default();

    // Split the input at the first NUL byte: before is the schema string,
    // after (if non-empty) is a resolver address candidate.
    let (schema_part, resolver_candidate) = match raw.find('\0') {
        Some(pos) => (&raw[..pos], raw[pos + 1..].trim()),
        None => (raw, ""),
    };

    // Pre-validate the resolver: `Address::from_string` traps on malformed
    // strkeys, so we fall back to a known-good constant instead of passing
    // the fuzz bytes directly.
    let resolver = if validate_strkey(resolver_candidate, AddressKind::Contract, "resolver").is_ok()
    {
        resolver_candidate
    } else {
        VALID_RESOLVER
    };

    let revocable = data.first().copied().unwrap_or(0) & 1 != 0;

    // ── Property 1: never panics ─────────────────────────────────────────────
    let result = SchemaBuilder::new()
        .with_schema(schema_part)
        .with_resolver(resolver)
        .with_revocable(revocable)
        .build(&env);

    match result {
        Ok(record) => {
            // ── Property 2: non-zero UID ──────────────────────────────────────
            assert_ne!(
                record.uid.0.to_array(),
                [0u8; 32],
                "a successfully built SchemaRecord must have a non-zero UID"
            );

            // ── Property 3: determinism ───────────────────────────────────────
            let result2 = SchemaBuilder::new()
                .with_schema(schema_part)
                .with_resolver(resolver)
                .with_revocable(revocable)
                .build(&env);
            let record2 = result2.expect("second build with same inputs must also succeed");
            assert_eq!(
                record.uid.0.to_array(),
                record2.uid.0.to_array(),
                "SchemaBuilder::build must be deterministic"
            );

            // ── Property 4: round-trip schema syntax validation ────────────────
            let schema_str = SorobanString::from_str(&env, schema_part);
            assert!(
                validate_schema_syntax(&env, &schema_str).is_ok(),
                "a schema accepted by SchemaBuilder::build must also pass \
                 validate_schema_syntax"
            );
        }
        Err(e) => {
            // Errors are fine — the schema or resolver string may be malformed.
            assert!(
                !format!("{e:?}").is_empty(),
                "error from SchemaBuilder::build must not be empty"
            );
        }
    }
});
