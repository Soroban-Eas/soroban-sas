use criterion::{black_box, criterion_group, criterion_main, Criterion};
use soroban_sas_common::{
    encode_type, hash_attestation_struct, hash_delegated_revocation, hash_domain, hash_struct,
    hash_typed_data, Attestation, AttestationDomain, FieldDef, FieldType, FieldValue, StructDef,
    UID,
};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

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
        group.bench_with_input(format!("{size}b"), &size, |b, &_size| {
            b.iter(|| hash_attestation_struct(black_box(&env), black_box(&attestation)))
        });
    }
    group.finish();
}

// --- Generic EIP-712 structured-data hashing -------------------------------

const PERSON_FIELDS: [FieldDef; 2] = [
    FieldDef {
        name: "name",
        ty: FieldType::Str,
    },
    FieldDef {
        name: "wallet",
        ty: FieldType::Address,
    },
];
const PERSON: StructDef = StructDef {
    name: "Person",
    fields: &PERSON_FIELDS,
};

const MAIL_FIELDS: [FieldDef; 3] = [
    FieldDef {
        name: "from",
        ty: FieldType::Struct("Person"),
    },
    FieldDef {
        name: "to",
        ty: FieldType::Struct("Person"),
    },
    FieldDef {
        name: "contents",
        ty: FieldType::Str,
    },
];
const MAIL: StructDef = StructDef {
    name: "Mail",
    fields: &MAIL_FIELDS,
};

const MAIL_DEFS: [StructDef; 2] = [MAIL, PERSON];

const RECEIPT_FIELDS: [FieldDef; 3] = [
    FieldDef {
        name: "buyer",
        ty: FieldType::Struct("Person"),
    },
    FieldDef {
        name: "numbers",
        ty: FieldType::Array(&FieldType::Uint(64)),
    },
    FieldDef {
        name: "memo",
        ty: FieldType::Bytes,
    },
];
const RECEIPT: StructDef = StructDef {
    name: "Receipt",
    fields: &RECEIPT_FIELDS,
};

/// Measures the cost of deriving the canonical type string (the alphabetical
/// dependency walk plus every field name).
fn bench_eip712_encode_type(c: &mut Criterion) {
    let env = Env::default();

    c.bench_function("eip712_encode_type_mail", |b| {
        b.iter(|| encode_type(black_box(&env), black_box(&MAIL_DEFS), black_box("Mail")))
    });
}

/// Measures hashing a struct whose fields are a nested struct and two dynamic
/// values: three keccaks plus the outer struct hash.
fn bench_eip712_hash_struct_nested(c: &mut Criterion) {
    let env = Env::default();
    let values = mail_values();

    c.bench_function("eip712_hash_struct_mail", |b| {
        b.iter(|| {
            hash_struct(
                black_box(&env),
                black_box(&MAIL_DEFS),
                black_box("Mail"),
                black_box(&values),
            )
        })
    });
}

/// Measures hashing a struct containing a dynamic array of 64 words, the
/// worst case for the per-element encoding loop.
fn bench_eip712_hash_struct_array(c: &mut Criterion) {
    let env = Env::default();
    let elements = [FieldValue::from_u64(7); 64];
    let values = [
        FieldValue::Struct("Person", &PERSON_VALUES),
        FieldValue::List(&FieldType::Uint(64), &elements),
        FieldValue::Dynamic(b"receipt memo"),
    ];
    let defs = [RECEIPT, PERSON];

    c.bench_function("eip712_hash_struct_array_64", |b| {
        b.iter(|| {
            hash_struct(
                black_box(&env),
                black_box(&defs),
                black_box("Receipt"),
                black_box(&values),
            )
        })
    });
}

/// Measures the full EIP-712 digest, whose extra work over `hash_struct` is
/// the prefix and domain separator concatenation.
fn bench_eip712_hash_typed_data(c: &mut Criterion) {
    let env = Env::default();
    let values = mail_values();
    let domain_separator = BytesN::from_array(&env, &[9u8; 32]);

    c.bench_function("eip712_hash_typed_data_mail", |b| {
        b.iter(|| {
            hash_typed_data(
                black_box(&env),
                black_box(&MAIL_DEFS),
                black_box("Mail"),
                black_box(&values),
                black_box(&domain_separator),
            )
        })
    });
}

const PERSON_VALUES: [FieldValue<'static>; 2] =
    [FieldValue::Dynamic(b"Alice"), FieldValue::Word([0x11; 32])];

fn mail_values() -> [FieldValue<'static>; 3] {
    const TO: [FieldValue<'static>; 2] =
        [FieldValue::Dynamic(b"Bob"), FieldValue::Word([0x22; 32])];
    [
        FieldValue::Struct("Person", &PERSON_VALUES),
        FieldValue::Struct("Person", &TO),
        FieldValue::Dynamic(b"Hello, Bob"),
    ]
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
    bench_eip712_encode_type,
    bench_eip712_hash_struct_nested,
    bench_eip712_hash_struct_array,
    bench_eip712_hash_typed_data,
);
criterion_main!(benches);
