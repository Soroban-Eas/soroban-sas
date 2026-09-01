use criterion::{black_box, criterion_group, criterion_main, Criterion};
use soroban_sas_common::{
    hash_attestation_struct, hash_delegated_revocation, hash_domain, Attestation, AttestationDomain, UID,
};
use soroban_sdk::{Address, Bytes, BytesN, Env};

fn bench_hash_uid(c: &mut Criterion) {
    let env = Env::default();
    let uid = UID(BytesN::from_array(&env, &[1u8; 32]));

    c.bench_function("hash_uid_32b", |b| {
        b.iter(|| {
            let mut buf = soroban_sdk::Bytes::new(&env);
            buf.append(&soroban_sdk::Bytes::from_slice(
                &env,
                &black_box(uid.0.to_array()),
            ));
            env.crypto().sha256(&buf)
        })
    });
}

fn bench_hash_domain(c: &mut Criterion) {
    let env = Env::default();
    let domain = AttestationDomain {
        network_id: BytesN::from_array(&env, &[2u8; 32]),
        contract: Address::generate(&env),
        nonce: 42,
    };

    c.bench_function("hash_domain", |b| {
        b.iter(|| hash_domain(black_box(&env), black_box(&domain)))
    });
}

fn bench_hash_attestation(c: &mut Criterion) {
    let env = Env::default();
    let attestation = make_attestation(&env, 1024);

    c.bench_function("hash_attestation_struct_1kb", |b| {
        b.iter(|| hash_attestation_struct(black_box(&env), black_box(&attestation)))
    });
}

fn bench_hash_offchain(c: &mut Criterion) {
    let env = Env::default();
    let attestation = make_attestation(&env, 1024);
    let domain = AttestationDomain {
        network_id: BytesN::from_array(&env, &[3u8; 32]),
        contract: Address::generate(&env),
        nonce: 0,
    };

    c.bench_function("hash_offchain_attestation_1kb", |b| {
        b.iter(|| {
            soroban_sas_common::hash_offchain_attestation(
                black_box(&env),
                black_box(&attestation),
                black_box(&domain),
            )
        })
    });
}

fn bench_hash_delegated_revocation(c: &mut Criterion) {
    let env = Env::default();
    let uid = UID(BytesN::from_array(&env, &[4u8; 32]));
    let attester = Address::generate(&env);
    let domain = AttestationDomain {
        network_id: BytesN::from_array(&env, &[5u8; 32]),
        contract: Address::generate(&env),
        nonce: 7,
    };

    c.bench_function("hash_delegated_revocation", |b| {
        b.iter(|| {
            hash_delegated_revocation(
                black_box(&env),
                black_box(&uid),
                black_box(&attester),
                black_box(&domain),
            )
        })
    });
}

fn bench_payload_scaling(c: &mut Criterion) {
    let env = Env::default();
    let mut group = c.benchmark_group("attestation_hash_payload_scaling");

    for size in [64, 256, 1024, 4096, 16384] {
        let attestation = make_attestation(&env, size);
        group.bench_with_input(format!("{size}b"), &size, |b, &size| {
            b.iter(|| hash_attestation_struct(black_box(&env), black_box(&attestation)))
        });
    }
    group.finish();
}

fn make_attestation(env: &Env, data_size: usize) -> Attestation {
    let data = soroban_sdk::Bytes::from_slice(env, &vec![0xABu8; data_size]);
    Attestation {
        uid: UID(BytesN::from_array(env, &[1u8; 32])),
        schema_uid: UID(BytesN::from_array(env, &[2u8; 32])),
        time: 1_700_000_000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: Address::generate(env),
        attester: Address::generate(env),
        revocable: true,
        data,
    }
}

criterion_group!(
    benches,
    bench_hash_uid,
    bench_hash_domain,
    bench_hash_attestation,
    bench_hash_offchain,
    bench_hash_delegated_revocation,
    bench_payload_scaling,
);
criterion_main!(benches);
