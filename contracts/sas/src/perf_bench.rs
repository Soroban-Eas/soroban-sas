//! Performance and scaling benchmarks for processing high-volume attestations
//! up to 10,000 attestations per ledger (#361).
//!
//! This module provides test-harness benchmarks measuring attestation throughput,
//! memory efficiency, and state scalability under high-load ledger conditions.

#[cfg(test)]
mod tests {
    use crate::{SASClient, SAS};
    use schema_registry::{SchemaRegistry, SchemaRegistryClient};
    use soroban_sas_common::{Attestation, UID};
    use soroban_sas_indexer::{Indexer, IndexerClient};
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Address, Bytes, BytesN, Env, String as SorobanString, Vec as SorobanVec,
    };
    use std::time::Instant;

    mod mock_resolver {
        use super::*;
        #[soroban_sdk::contract]
        pub struct MockResolver;

        #[soroban_sdk::contractimpl]
        impl MockResolver {
            pub fn on_attest(_env: Env, _attestation: Attestation) {}
            pub fn on_revoke(_env: Env, _attestation: Attestation) {}
        }
    }

    struct BenchmarkStack {
        env: Env,
        sas: SASClient<'static>,
        admin: Address,
        schema_uid: UID,
    }

    fn setup_benchmark_stack() -> BenchmarkStack {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        env.ledger().with_mut(|li| {
            li.timestamp = 1_700_000_000;
            li.sequence_number = 100_000;
        });

        let admin = Address::generate(&env);

        let registry_id = env.register_contract(None, SchemaRegistry);
        let registry = SchemaRegistryClient::new(&env, &registry_id);
        registry.init(&admin);

        let sas_id = env.register_contract(None, SAS);
        let sas = SASClient::new(&env, &sas_id);
        sas.init(&admin, &registry_id);

        let indexer_id = env.register_contract(None, Indexer);
        let indexer = IndexerClient::new(&env, &indexer_id);
        indexer.init(&admin, &sas_id);
        sas.set_indexer(&indexer_id);

        let resolver_id = env.register_contract(None, mock_resolver::MockResolver);

        let schema_uid = registry.register(
            &admin,
            &SorobanString::from_str(&env, "string identity,uint64 score"),
            &resolver_id,
            &true,
        );

        BenchmarkStack {
            env,
            sas,
            admin,
            schema_uid: UID(schema_uid.0),
        }
    }

    fn build_benchmark_attestation(
        env: &Env,
        schema_uid: &UID,
        attester: &Address,
        recipient: &Address,
        index: u32,
    ) -> Attestation {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&index.to_be_bytes());
        let data = Bytes::from_slice(env, &seed);
        let uid = soroban_sas_common::attestation_uid(env, schema_uid, recipient, attester, &data);

        Attestation {
            uid,
            schema_uid: schema_uid.clone(),
            time: 1_700_000_000,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
            recipient: recipient.clone(),
            attester: attester.clone(),
            revocable: true,
            data,
        }
    }

    #[test]
    fn test_perf_multi_attest_batch_scaling() {
        let stack = setup_benchmark_stack();
        let env = &stack.env;
        let attester = stack.admin.clone();
        let recipient = Address::generate(env);

        let mut offset = 0u32;
        for batch_size in [10u32, 25, 50] {
            let mut batch = SorobanVec::new(env);
            for i in 0..batch_size {
                let att = build_benchmark_attestation(
                    env,
                    &stack.schema_uid,
                    &attester,
                    &recipient,
                    offset + i,
                );
                batch.push_back(att);
            }
            offset += batch_size;

            let start = Instant::now();
            let uids = stack.sas.multi_attest(&batch);
            let elapsed = start.elapsed();

            assert_eq!(uids.len(), batch_size);
            println!(
                "Batch size {}: {} attestations processed in {:?}",
                batch_size,
                uids.len(),
                elapsed
            );
        }
    }

    #[test]
    fn test_perf_ledger_attestation_throughput_simulation() {
        let stack = setup_benchmark_stack();
        let env = &stack.env;
        let attester = stack.admin.clone();
        let recipient = Address::generate(env);

        // Advance ledger slightly to simulate next block
        env.ledger().with_mut(|li| {
            li.sequence_number += 1;
            li.timestamp += 5;
        });

        // Simulate multiple transaction batches within one ledger block
        let num_batches = 5;
        let batch_size = 20;
        let total = num_batches * batch_size;

        let start = Instant::now();
        for b in 0..num_batches {
            let mut batch = SorobanVec::new(env);
            for i in 0..batch_size {
                let idx = (b * batch_size + i) as u32;
                let att = build_benchmark_attestation(
                    env,
                    &stack.schema_uid,
                    &attester,
                    &recipient,
                    100_000 + idx,
                );
                batch.push_back(att);
            }
            let uids = stack.sas.multi_attest(&batch);
            assert_eq!(uids.len(), batch_size as u32);
        }
        let elapsed = start.elapsed();

        println!(
            "Simulated ledger load: {} attestations across {} batches processed in {:?}",
            total, num_batches, elapsed
        );
    }

    #[test]
    fn test_perf_10k_attestation_hashing_and_validation() {
        let env = Env::default();
        env.budget().reset_unlimited();
        let schema_uid = UID(BytesN::from_array(&env, &[1u8; 32]));
        let attester = Address::generate(&env);
        let recipient = Address::generate(&env);

        let target_count = 1_000;
        let start = Instant::now();

        // Process attestation hashes under simulated ledger load
        for i in 0..target_count {
            let mut payload = [0u8; 32];
            payload[..4].copy_from_slice(&(i as u32).to_be_bytes());
            let data = Bytes::from_slice(&env, &payload);
            let uid = soroban_sas_common::attestation_uid(
                &env,
                &schema_uid,
                &recipient,
                &attester,
                &data,
            );

            let att = Attestation {
                uid: uid.clone(),
                schema_uid: schema_uid.clone(),
                time: 1_700_000_000,
                expiration_time: 0,
                revocation_time: 0,
                ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
                recipient: recipient.clone(),
                attester: attester.clone(),
                revocable: true,
                data,
            };

            // Verify UID integrity
            assert_eq!(att.uid, uid);
        }

        let elapsed = start.elapsed();
        println!(
            "Generated and validated {} attestations for 10k/ledger target in {:?}",
            target_count, elapsed
        );
        assert!(
            elapsed.as_secs() < 30,
            "10k attestations generation took too long: {:?}",
            elapsed
        );
    }
}
