#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sdk::xdr::{Limits, ReadXdr, ScVal};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ScVal::from_xdr_base64(s, Limits::none());
    }
});
