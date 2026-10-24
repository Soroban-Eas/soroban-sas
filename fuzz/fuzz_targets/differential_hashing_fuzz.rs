#![cfg_attr(not(test), no_main)]
use libfuzzer_sys::fuzz_target;
use sas::SAS;
use soroban_sdk::Env;
#[path = "../hash_parity.rs"]
mod hash_parity;

fuzz_target!(|data: &[u8]| {
    run_case(data);
});

fn run_case(data: &[u8]) {
    let env = Env::default();
    env.budget().reset_unlimited();
    let contract = env.register_contract(None, SAS);
    let (attestation, domain) = hash_parity::from_bytes(&env, &contract, data);
    hash_parity::assert_parity(&env, &contract, &attestation, &domain);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundary_cases() {
        for seed in [
            vec![],
            vec![0u8; 1],
            vec![0xff; 512],
            vec![0x10, 0, 0, 0, 0, 0, 0, 0, 0],
            "élève😃/مرحبا".as_bytes().to_vec(),
            (0..240).map(|v| v as u8).collect(),
        ] {
            run_case(&seed);
        }
    }
}
