#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_indexer::chunking_test_support::{check_chunking, MAX_INSERTIONS};

fuzz_target!(|data: &[u8]| {
    let pairs: Vec<([u8; 4], [u8; 32])> = data
        .chunks_exact(36)
        .take(MAX_INSERTIONS)
        .map(|record| {
            (
                record[..4].try_into().unwrap(),
                record[4..].try_into().unwrap(),
            )
        })
        .collect();
    check_chunking(&pairs);
});
