#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::validate_schema_syntax;
use soroban_sdk::{Bytes, Env, String as SorobanString};

fuzz_target!(|data: &[u8]| {
    let env = Env::default();
    let bytes = Bytes::from_slice(&env, data);
    let schema = SorobanString::from_bytes(&bytes);
    let _ = validate_schema_syntax(&env, &schema);
});
