//! Cross-contract fuzzing for the schema registry and SAS contracts (#324).
//!
//! Every other fuzz target in this crate either drives a single contract
//! (`indexer_*_fuzz`) or a pure function (`schema_fuzz`, `typed_data_fuzz`).
//! None of them wire the real `schema-registry` and `sas` crates together the
//! way `packages/soroban-sas-cli/tests/cli_e2e.rs` does for its fixture, so
//! the register -> attest cross-contract boundary — the registry's
//! `get_schema` / `is_authorized` calls SAS makes mid-`attest`, and the
//! revocability check that spans both contracts' state — was untested by
//! fuzzing. This target drives that boundary directly with the real
//! contracts (no mocks) and checks it never panics on adversarial input, and
//! that the invariants documented in `docs/schemas.md` hold: registration is
//! content-addressed and a duplicate registration is rejected with
//! `SchemaAlreadyExists` rather than silently duplicated or corrupting
//! state, an attestation can only be issued against a schema that was
//! actually registered, and a schema's `revocable` flag is the sole
//! authority over whether an attestation under it may claim
//! `revocable = true`.
// `no_main` only applies to the fuzzer binary: `cfg_attr` keeps it off the
// `cargo test` build of this same file, which needs the harness's own
// `main` (otherwise MSVC's linker rejects the binary with "entry point must
// be defined") so `#[cfg(test)] mod tests` below stays runnable.
#![cfg_attr(not(test), no_main)]
use libfuzzer_sys::fuzz_target;
use sas::{SASClient, SAS};
use schema_registry::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::{Attestation, SASError, UID};
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, Address, Bytes, BytesN, Env,
    String as SorobanString,
};

mod accept_all_resolver {
    use super::*;

    #[contract]
    pub struct AcceptAllResolver;

    #[contractimpl]
    impl AcceptAllResolver {
        pub fn on_attest(_env: Env, _attestation: Attestation) {}
        pub fn on_revoke(_env: Env, _attestation: Attestation) {}
    }
}

const MAX_SCHEMA_LEN: usize = 200;
const MAX_DATA_LEN: usize = 64;

/// One fuzzed case, parsed out of the raw byte stream. Keeping this as a
/// plain struct (rather than reading fields ad hoc inline) makes each fuzz
/// run's inputs reproducible from a single, named cursor position.
struct Case<'a> {
    schema_bytes: &'a [u8],
    schema_revocable: bool,
    attestation_revocable: bool,
    self_attest: bool,
    valid_schema_uid: bool,
    data: &'a [u8],
}

fn parse_case(data: &[u8]) -> Option<Case<'_>> {
    if data.len() < 4 {
        return None;
    }
    let flags = data[0];
    let schema_len =
        (data[1] as usize) % MAX_SCHEMA_LEN.min(data.len().saturating_sub(2) + 1).max(1);
    let schema_len = schema_len.min(data.len().saturating_sub(2));
    let (schema_bytes, rest) = data[2..].split_at(schema_len);
    let data_len = rest.len().min(MAX_DATA_LEN);
    let payload = &rest[..data_len];

    Some(Case {
        schema_bytes,
        schema_revocable: flags & 0b0001 != 0,
        attestation_revocable: flags & 0b0010 != 0,
        self_attest: flags & 0b0100 != 0,
        valid_schema_uid: flags & 0b1000 != 0,
        data: payload,
    })
}

/// A schema string built from `name Type` syntax the registry accepts, so
/// most fuzz cases exercise the register -> attest happy path rather than
/// bouncing off local syntax validation every time. Bytes that don't map to
/// an identifier character are folded into the alphabet rather than
/// discarded, so the string's length still tracks the input's.
fn canonical_schema_string(env: &Env, raw: &[u8]) -> SorobanString {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let mut s = std::string::String::from("f");
    for (i, b) in raw.iter().enumerate() {
        s.push(ALPHABET[(*b as usize + i) % ALPHABET.len()] as char);
    }
    s.push_str(" string");
    SorobanString::from_str(env, &s)
}

fuzz_target!(|data: &[u8]| {
    run_case(data);
});

/// The fuzz target's body, factored out so `cargo test` can exercise a
/// handful of crafted inputs directly (the fuzzer itself needs
/// `cargo fuzz`, which requires a nightly toolchain this workspace doesn't
/// otherwise depend on).
fn run_case(data: &[u8]) {
    let Some(case) = parse_case(data) else {
        return;
    };

    let env = Env::default();
    env.mock_all_auths();
    env.budget().reset_unlimited();

    let admin = Address::generate(&env);
    let registry_id = env.register_contract(None, SchemaRegistry);
    let registry = SchemaRegistryClient::new(&env, &registry_id);
    registry.init(&admin);

    let sas_id = env.register_contract(None, SAS);
    let sas = SASClient::new(&env, &sas_id);
    sas.init(&admin, &registry_id);

    let resolver = env.register_contract(None, accept_all_resolver::AcceptAllResolver);
    let owner = Address::generate(&env);
    let recipient = if case.self_attest {
        owner.clone()
    } else {
        Address::generate(&env)
    };

    let schema_str = canonical_schema_string(&env, case.schema_bytes);

    // Registration must be content-addressed: registering the exact same
    // (owner, schema, resolver, revocable) a second time must be rejected
    // with `SchemaAlreadyExists` — never silently duplicated, never a
    // different UID for the same identity, and never a panic
    // (docs/schemas.md, contracts/schema-registry/src/lib.rs `register_internal`).
    let first = registry.try_register(&owner, &schema_str, &resolver, &case.schema_revocable);
    let Ok(Ok(schema_uid)) = first else {
        // A schema the local CLI validator would also reject (e.g. this
        // fuzzed string happened to fail canonical-form checks) must fail
        // cleanly, not panic the host.
        return;
    };
    let second = registry.try_register(&owner, &schema_str, &resolver, &case.schema_revocable);
    assert_eq!(
        second,
        Err(Ok(SASError::SchemaAlreadyExists.into())),
        "re-registering an identical schema must be rejected as already existing, not silently duplicated"
    );

    let stored = registry.get_schema(&schema_uid);
    assert!(
        stored.is_some(),
        "a successfully registered schema must be readable back"
    );

    let attest_schema_uid = if case.valid_schema_uid {
        schema_uid.clone()
    } else {
        // An address-sized, never-registered UID: attest must reject it
        // through the real cross-contract `get_schema` lookup, not trap.
        UID(BytesN::from_array(&env, &[0xAA; 32]))
    };

    let payload = Bytes::from_slice(&env, case.data);
    let attestation_uid =
        soroban_sas_common::attestation_uid(&env, &attest_schema_uid, &recipient, &owner, &payload);
    let attestation = Attestation {
        uid: attestation_uid.clone(),
        schema_uid: attest_schema_uid.clone(),
        time: 0,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: owner.clone(),
        revocable: case.attestation_revocable,
        data: payload,
    };

    let result = sas.try_attest(&attestation);

    if case.self_attest {
        assert_eq!(
            result,
            Err(Ok(SASError::InvalidRecipient.into())),
            "self-attestation must be rejected with InvalidRecipient, not panic"
        );
        return;
    }

    if !case.valid_schema_uid {
        assert_eq!(
            result,
            Err(Ok(SASError::InvalidSchema.into())),
            "attesting against an unregistered schema must fail with InvalidSchema, not panic"
        );
        return;
    }

    if case.attestation_revocable && !case.schema_revocable {
        assert_eq!(
            result,
            Err(Ok(SASError::NotRevocable.into())),
            "a revocable attestation under a non-revocable schema must fail with NotRevocable"
        );
        return;
    }

    assert_eq!(
        result,
        Ok(Ok(attestation_uid.clone())),
        "a well-formed attestation against a registered schema, by its owner, \
         respecting the schema's revocability, must succeed"
    );

    let recorded = sas.get_attestation(&attestation_uid);
    assert_eq!(
        recorded.as_ref().map(|a| &a.schema_uid),
        Some(&attest_schema_uid),
        "a successfully issued attestation must be readable back with the schema it names"
    );
    assert!(
        sas.verify_attestation(&attestation_uid),
        "a freshly issued, unrevoked attestation must verify"
    );
}

#[cfg(test)]
mod tests {
    use super::run_case;

    /// A minimal but plausible happy-path input: no flags set (fresh
    /// non-revocable schema, non-revocable attestation, distinct recipient,
    /// registered schema UID used), one schema byte, empty payload.
    #[test]
    fn happy_path_does_not_panic() {
        run_case(&[0b0000_1000, 1, b'x']);
    }

    /// `schema_revocable` and `attestation_revocable` both set: a revocable
    /// schema permits a revocable attestation.
    #[test]
    fn revocable_schema_and_attestation_does_not_panic() {
        run_case(&[0b0000_1011, 1, b'y']);
    }

    /// `attestation_revocable` set without `schema_revocable`: must hit the
    /// `NotRevocable` branch, not panic.
    #[test]
    fn revocable_attestation_under_irrevocable_schema_does_not_panic() {
        run_case(&[0b0000_1010, 1, b'z']);
    }

    /// `self_attest` set: recipient == attester must be rejected cleanly.
    #[test]
    fn self_attestation_does_not_panic() {
        run_case(&[0b0000_1100, 1, b'w']);
    }

    /// `valid_schema_uid` unset: attest must reject the unregistered UID
    /// cleanly instead of trapping on the cross-contract `get_schema` call.
    #[test]
    fn unregistered_schema_uid_does_not_panic() {
        run_case(&[0b0000_0000, 1, b'v']);
    }

    /// A schema string built from raw non-ASCII-identifier bytes: register
    /// must reject it cleanly rather than panicking on validation.
    #[test]
    fn arbitrary_schema_bytes_do_not_panic() {
        run_case(&[0b0000_1000, 40, 0, 1, 2, 3, 255, 254, 253, 10, 32, 44]);
    }

    /// Too short to parse a case: must return without touching any
    /// contract.
    #[test]
    fn too_short_input_does_not_panic() {
        run_case(&[]);
        run_case(&[1, 2]);
    }
}
