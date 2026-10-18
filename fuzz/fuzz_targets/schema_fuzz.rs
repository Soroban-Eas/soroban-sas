#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::validate_schema_syntax;
use soroban_sdk::{Env, String as SorobanString};

const MAX_LEN: usize = 1024;
const MAX_FIELDS: usize = 64; // = MAX_SCHEMA_FIELDS

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\n' | '\r' | '\t' | '\x0b' | '\x0c')
}

fuzz_target!(|data: &[u8]| {
    let env = Env::default();
    let schema = SorobanString::from_bytes(&env, data);

    // 1. Kada ya yi panic ko ya rataya, ko da input mara UTF-8 ne.
    let result = validate_schema_syntax(&env, &schema);

    // 2. Mara komai ko mai tsayi fiye da iyaka dole a ƙi shi.
    if data.is_empty() || data.len() > MAX_LEN {
        assert!(result.is_err());
    }

    // 3. Duk abin da aka karɓa dole ya bi ka'idojin schema.
    if result.is_ok() {
        assert!(data.is_ascii());
        let text = core::str::from_utf8(data).unwrap();
        let fields: Vec<&str> = text.split(',').collect();
        assert!(fields.len() <= MAX_FIELDS);
        for f in fields {
            let f = f.trim_matches(is_ws);
            assert!(!f.is_empty() && f.len() <= 64);
            let mut it = f.splitn(2, is_ws);
            let ident = it.next().unwrap();
            let ty = it.next().unwrap().trim_matches(is_ws);
            assert!(!ident.is_empty() && ident.len() <= 32);
            assert!(!ty.is_empty() && ty.len() <= 32);
        }
    }
});
