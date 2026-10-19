//! Benchmarks for processing 10,000 attestations per ledger (#361).
//!
//! Measures attestation hashing, UID derivation, struct construction, and
//! batch processing throughput targeting 10k attestations per ledger block.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use soroban_sas_common::{attestation_uid, Attestation, UID};
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env};

fn make_test_attestation(
    env: &Env,
    schema_uid: &UID,
    attester: &Address,
    recipient: &Address,
    index: u32,
) -> Attestation {
    let mut payload = [0u8; 32];
    payload[..4].copy_from_slice(&index.to_be_bytes());
    let data = Bytes::from_slice(env, &payload);
    let uid = attestation_uid(env, schema_uid, recipient, attester, &data);

    Attestation {
        uid,
        schema_uid: schema_uid.clone(),
        time: 1_700_000_000,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data,
    }
}

/// Measures throughput of attestation UID derivation across batch sizes.
fn bench_attestation_uid_batch(c: &mut Criterion) {
    let env = Env::default();
    let schema_uid = UID(BytesN::from_array(&env, &[1u8; 32]));
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let mut group = c.benchmark_group("attestation_uid_derivation");
    for size in [100, 500, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &n| {
            let data = Bytes::from_array(&env, &[0x42u8; 32]);
            b.iter(|| {
                for _ in 0..n {
                    black_box(attestation_uid(
                        black_box(&env),
                        black_box(&schema_uid),
                        black_box(&recipient),
                        black_box(&attester),
                        black_box(&data),
                    ));
                }
            });
        });
    }
    group.finish();
}

/// Measures processing time for a 10,000-attestations workload (simulating 10k per ledger).
fn bench_10k_attestations_workload(c: &mut Criterion) {
    let env = Env::default();
    let schema_uid = UID(BytesN::from_array(&env, &[1u8; 32]));
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let mut group = c.benchmark_group("ledger_10k_attestations");
    group.sample_size(10);

    group.bench_function("generate_and_hash_10k_attestations", |b| {
        b.iter(|| {
            for i in 0..10_000 {
                let att = make_test_attestation(
                    black_box(&env),
                    black_box(&schema_uid),
                    black_box(&attester),
                    black_box(&recipient),
                    black_box(i),
                );
                black_box(att.uid);
            }
        });
    });

    group.finish();
}

/// Measures throughput for multi-attest batch sizes representing transaction units.
fn bench_multi_attest_batch_formation(c: &mut Criterion) {
    let env = Env::default();
    let schema_uid = UID(BytesN::from_array(&env, &[2u8; 32]));
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let mut group = c.benchmark_group("multi_attest_batches");
    for batch_size in [25, 50, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &n| {
                b.iter(|| {
                    let mut batch = Vec::with_capacity(n);
                    for i in 0..n {
                        batch.push(make_test_attestation(
                            &env,
                            &schema_uid,
                            &attester,
                            &recipient,
                            i as u32,
                        ));
                    }
                    black_box(batch);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_attestation_uid_batch,
    bench_10k_attestations_workload,
    bench_multi_attest_batch_formation,
);
criterion_main!(benches);
