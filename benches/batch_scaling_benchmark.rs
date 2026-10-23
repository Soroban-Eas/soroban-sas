//! Batch-attestation scaling benchmarks (#493).
//!
//! This harness establishes the batch-size matrix (10..=1,000) and will measure
//! direct attestations, delegated attestations and revocations as the contract
//! benchmark fixtures are wired in.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

const BATCH_SIZES: [usize; 8] = [10, 25, 50, 100, 250, 500, 750, 1_000];

fn bench_batch_scaling_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_attestation_scaling");
    for size in BATCH_SIZES {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &n| {
            b.iter(|| {
                let mut acc = 0usize;
                for i in 0..n {
                    acc = acc.wrapping_add(black_box(i));
                }
                black_box(acc);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_batch_scaling_matrix);
criterion_main!(benches);
