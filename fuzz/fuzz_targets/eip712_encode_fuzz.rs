#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::{
    encode_data, encode_type, hash_struct, hash_typed_data, type_hash, FieldDef, FieldType,
    FieldValue, StructDef,
};
use soroban_sdk::{BytesN, Env};

/// Struct set mirroring the shapes the encoder has to handle in one call:
/// a nested struct, a dynamic array, a dynamic byte string, and words.
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

const DEFS: [StructDef; 2] = [RECEIPT, PERSON];

fuzz_target!(|data: &[u8]| {
    let env = Env::default();

    // Whatever the input, the encoder must either produce a digest or report a
    // `SchemaError` — never panic, never hang.
    let seed = data.first().copied().unwrap_or(0);
    let (name_preimage, rest) = data.split_at(data.len() / 2);

    let mut numbers = [FieldValue::from_u64(0); 8];
    for (index, byte) in rest.iter().take(numbers.len()).enumerate() {
        numbers[index] = FieldValue::from_u64(u64::from(*byte));
    }

    let values = [
        FieldValue::Struct(
            "Person",
            &[
                FieldValue::Dynamic(name_preimage),
                FieldValue::Word([seed; 32]),
            ],
        ),
        FieldValue::List(&FieldType::Uint(64), &numbers),
        FieldValue::Dynamic(rest),
    ];

    // Type-string derivation must terminate and stay stable for arbitrary
    // definitions, including the reachability walk.
    let first_type = encode_type(&env, &DEFS, "Receipt");
    let second_type = encode_type(&env, &DEFS, "Receipt");
    assert_eq!(first_type, second_type, "encodeType must be deterministic");
    let _ = encode_type(&env, &DEFS, "Unknown");
    let _ = encode_type(&env, &DEFS, "");
    let _ = type_hash(&env, &DEFS, "Receipt");
    let _ = type_hash(&env, &DEFS, "Unknown");

    // The value list matches the declaration exactly, so encoding must
    // succeed and be reproducible.
    let encoded = encode_data(&env, &DEFS, "Receipt", &values);
    assert!(encoded.is_ok(), "well-formed values must encode");
    let struct_hash = hash_struct(&env, &DEFS, "Receipt", &values);
    assert!(struct_hash.is_ok());
    assert_eq!(
        struct_hash.as_ref().map(|hash| hash.to_array()),
        hash_struct(&env, &DEFS, "Receipt", &values)
            .as_ref()
            .map(|hash| hash.to_array()),
        "hashStruct must be deterministic"
    );

    // Mismatched values must be rejected, never silently encoded.
    assert_eq!(
        encode_data(&env, &DEFS, "Receipt", &values[0..2]).unwrap_err(),
        soroban_sas_common::SchemaError::ArityMismatch
    );
    assert_eq!(
        encode_data(&env, &DEFS, "Missing", &values).unwrap_err(),
        soroban_sas_common::SchemaError::UnknownStruct
    );

    let domain_separator = BytesN::from_array(&env, &[seed; 32]);
    let digest = hash_typed_data(&env, &DEFS, "Receipt", &values, &domain_separator);
    assert!(digest.is_ok());
    assert_ne!(
        digest.map(|value| value.to_array()),
        struct_hash.map(|value| value.to_array()),
        "the domain separator must be mixed into the final digest"
    );
});
