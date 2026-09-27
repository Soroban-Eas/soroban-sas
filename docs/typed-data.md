# Typed-Data Hashing

`packages/soroban-sas-common` exposes two digest schemes:

| Scheme | Module | Shape |
| --- | --- | --- |
| Off-chain attestation digest | `soroban_sas_common::typed_data` | One **fixed** layout for the `Attestation` struct, with golden vectors. |
| Generic typed data (this document) | `soroban_sas_common::eip712` | **Any** struct described by a `TypedDataSchema`, EIP-712 style. |

The generic scheme exists because SAS schemas are arbitrary. The fixed layout
covers attestations and nothing else: an issuer that wants a signature over a
schema-defined payload — a payment authorisation, a credential claim, a
"reimburse this invoice" intent — had no way to hash it. `eip712` implements the
general algorithm the fixed layout is one instance of.

Both schemes are **SHA-256** based and prefix-separated, so a digest from one is
never valid in the other.

## The algorithm

```text
encodeType(T)  = "T(fieldType fieldName,...)" ‖ referenced struct types
typeHash(T)    = sha256(encodeType(T))
hashStruct(s)  = sha256(typeHash(T) ‖ encodeData(s))
digest         = sha256(PREFIX ‖ domainSeparator ‖ hashStruct(message))

PREFIX = "\x19\x01soroban-sas/typed-data/v1"
```

`encodeData(s)` concatenates exactly one 32-byte word per field. Positions are
pinned by `encodeType`, boundaries by the fixed word width, so no two field
layouts can encode to the same bytes. Dynamic data collapses into one word
through a hash, exactly as EIP-712 does for `bytes`, `string`, structs, and
arrays.

`encodeType` for a struct lists its own definition first, then every struct type
it references — transitively, each once, **sorted by name**. Sorting is what
makes the encoding independent of how a schema's struct table happens to be
ordered, so two schemas that describe the same types produce the same
`typeHash`.

## Type mapping

| `TypedDataKind` | Solidity-style name | Word encoding |
| --- | --- | --- |
| `Bytes32` | `bytes32` | the 32 bytes verbatim |
| `U64` | `uint64` | big-endian, right-aligned (8 bytes of value, 24 of zero) |
| `I128` | `int128` | two's complement, sign-extended to 32 bytes |
| `Bool` | `bool` | `0` or `1` as the last byte |
| `Address` | `address` | `sha256(ScVal XDR of the address)` |
| `Bytes` | `bytes` | `sha256(contents)` |
| `String` | `string` | `sha256(UTF-8 contents)` |
| `Struct(n)` | the struct's name | `hashStruct(nested)` |
| `Array(t)` | `t` + `"[]"` | `sha256(concatenated element words)` |

Arrays hash their elements *individually* before hashing the concatenation, so
`["ab", "c"]` and `["a", "bc"]` produce different words. An empty array hashes
the empty byte string, which is well defined rather than an edge case.

## Domain separation

`TypedDataDomain` carries the EIP-712 `EIP712Domain`:

```rust
pub struct TypedDataDomain {
    pub name: String,               // application name, e.g. "Soroban SAS"
    pub version: String,            // signing-format version, e.g. "1"
    pub network_id: BytesN<32>,     // SHA-256 of the network passphrase
    pub verifying_contract: Address,
}
```

Its type string is fixed:

```text
EIP712Domain(string name,string version,bytes32 networkId,address verifyingContract)
```

A digest computed for one network, one verifying contract, one app name, or one
version is unusable anywhere else. Verifiers must know all four fields; a
verifier that guesses any of them will reject valid signatures or, worse, accept
signatures meant for a different deployment.

## Schema validation

`validate_typed_data_schema` runs before any hashing, and rejects:

| Condition | Error |
| --- | --- |
| No structs or no types | `EmptySchema` |
| Empty struct or field name | `EmptyName` |
| Name longer than `MAX_NAME_BYTES` (64) | `NameTooLong` |
| Two structs with the same name | `DuplicateStructName` |
| The same field name twice in one struct | `DuplicateFieldName` |
| A field's `type_index` outside the type table | `TypeIndexOutOfRange` |
| A `Struct` node's `reference` outside the struct table | `StructIndexOutOfRange` |
| An elementary node carrying a `reference` other than `NO_REFERENCE` | `UnexpectedReference` |
| A cycle in the type graph | `CyclicTypeReference` |
| More than `MAX_SCHEMA_STRUCTS` structs or `MAX_SCHEMA_TYPES` types | `SchemaTooLarge` |
| More than `MAX_STRUCT_FIELDS` fields in one struct | `StructTooLarge` |
| A `String` value longer than `MAX_STRING_VALUE_BYTES` (1024) | `StringValueTooLong` |
| A value whose variant does not match the declared kind | `TypeMismatch` |
| A struct value whose length does not match the field count | `ArityMismatch` |

Two of these are load-bearing for security rather than hygiene:

* **Unique field names.** EIP-712 requires them for the same reason: with a
  duplicate name, `encodeType` describes two different field layouts, so two
  distinct payloads could produce one digest and a signature could be replayed
  onto a payload the signer never saw. Name comparison is case sensitive, so
  `amount` and `Amount` are distinct fields.
* **Acyclic types.** A struct that reaches itself would make `encodeType` and
  `encodeData` recurse forever. The cycle check also covers arrays, since an
  array element can reference a struct that references the array back.

The size caps bound both the host cost of a call and the recursion depth of
hashing.

## Usage

```rust
use soroban_sas_common::{
    typed_data_digest, TypedDataDomain, TypedDataField, TypedDataKind, TypedDataSchema,
    TypedDataStruct, TypedDataType, TypedDataValue, NO_REFERENCE,
};
use soroban_sdk::{Address, BytesN, Env, String, Vec};

let env = Env::default();
let mut types = Vec::new(&env);
types.push_back(TypedDataType { kind: TypedDataKind::U64, reference: NO_REFERENCE });
types.push_back(TypedDataType { kind: TypedDataKind::String, reference: NO_REFERENCE });

let mut fields = Vec::new(&env);
fields.push_back(TypedDataField { name: String::from_str(&env, "amount"), type_index: 0 });
fields.push_back(TypedDataField { name: String::from_str(&env, "memo"), type_index: 1 });

let mut structs = Vec::new(&env);
structs.push_back(TypedDataStruct { name: String::from_str(&env, "Payment"), fields });
let schema = TypedDataSchema { types, structs };

let mut values = Vec::new(&env);
values.push_back(TypedDataValue::U64(1_000));
values.push_back(TypedDataValue::String(String::from_str(&env, "rent")));

let domain = TypedDataDomain {
    name: String::from_str(&env, "Soroban SAS"),
    version: String::from_str(&env, "1"),
    network_id: BytesN::from_array(&env, &[0u8; 32]),
    verifying_contract: Address::from_string(&String::from_str(
        &env,
        "CDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
    )),
};

let digest = typed_data_digest(
    &env,
    &schema,
    0,
    &TypedDataValue::Struct(values),
    &domain,
).unwrap();

// Sign with the issuer's ed25519 key and verify the same way the fixed
// attestation digest is verified:
// soroban_sas_common::verify_offchain_signature(&env, &digest, &public_key, &signature);
```

A schema's `PREFIX`, `encodeType`, `typeHash`, and word layout are all part of
the wire format. Changing any of them is a breaking change that invalidates
every previously issued signature, which is why the prefix carries a `v1` tag
and the encode rules are pinned by tests that reconstruct the expected bytes
independently of the implementation.

## Deviations from EIP-712

Implementations in other languages must reproduce these:

1. **SHA-256, not keccak-256.** SAS hashes with the host's SHA-256 everywhere,
   including the fixed attestation digest. `\x19\x01` is kept as a nod to
   EIP-191, but the payload is not EVM-verifiable.
2. **`address` is a hash.** A Soroban `Address` is 44 bytes of XDR and has no
   20-byte EVM equivalent, so it is `sha256(xdr(address))` rather than a
   left-padded word.
3. **Type names follow Solidity spelling** (`uint64`, `int128`, `bytes32`) so
   type strings read like EIP-712 ones, but the referenced-type ordering rule is
   the only part of EIP-712's `encodeType` grammar that matters here.
4. **Bounded names and values.** Names are raw UTF-8 capped at 64 bytes;
   `String` values are capped at 1024 bytes.
