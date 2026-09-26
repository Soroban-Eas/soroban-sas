#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::validate_schema_syntax;
use soroban_sdk::{Bytes, Env, String as SorobanString};

fuzz_target!(|data: &[u8]| {
    let env = Env::default();
    
    // Test basic slice to String parsing
    let schema_res = core::str::from_utf8(data);
    if let Ok(schema_str) = schema_res {
        // Must fit within MAX_SCHEMA_LENGTH (1024)
        if schema_str.len() <= 1024 {
            let bytes = Bytes::from_slice(&env, data);
            let schema = SorobanString::from_bytes(&bytes);
            
            // Fuzz test should assert that it does not panic, 
            // and maybe if it returns Ok(), we do some manual assertions.
            match validate_schema_syntax(&env, &schema) {
                Ok(_) => {
                    // If it passed, it must not contain uppercase letters!
                    for byte in data {
                        assert!(!byte.is_ascii_uppercase(), "Accepted uppercase byte!");
                    }
                }
                Err(_) => {
                    // Valid rejection
                }
            }
        }
    }
});
