//! Generic EIP-712 equivalent structured-data hashing (#299).
//!
//! [`crate::typed_data`] implements one *fixed* layout: a hand-written encoder
//! for exactly one struct ([`crate::Attestation`]) with its golden vectors.
//! That is enough for attestations, but SAS schemas are arbitrary — an issuer
//! that wants a signature over a schema-defined payload has no generic way to
//! hash it. This module implements the general algorithm those fixed layouts
//! are a special case of, so callers can hash any schema-shaped struct:
//!
//! ```text
//! encodeType(T)  = "T(typeName fieldName,...)" ‖ referenced struct types
//! typeHash(T)    = sha256(encodeType(T))
//! hashStruct(s)  = sha256(typeHash(T) ‖ encodeData(s))
//! digest         = sha256(PREFIX ‖ domainSeparator ‖ hashStruct(message))
//! ```
//!
//! `encodeData` concatenates one 32-byte word per field, so a struct's encoding
//! is unambiguous: field *positions* are pinned by `encodeType`, and field
//! *boundaries* are pinned by every field occupying exactly one word. Dynamic
//! data (`Bytes`, `String`, nested structs, arrays) collapses to a single word
//! through a hash, exactly as EIP-712 does for `bytes`, `string`, structs and
//! arrays. Array elements are hashed together (`sha256` of their concatenated
//! words), so `["ab", "c"]` and `["a", "bc"]` do not collide.
//!
//! Unlike the fixed attestation layout, the schema itself is part of the
//! signed digest: a signature can never be replayed against a schema whose
//! field types differ, because a different schema yields a different
//! `typeHash`.
//!
//! # Deliberate deviations from EIP-712
//!
//! These are part of the wire format, so a cross-language implementation must
//! reproduce them exactly:
//!
//! * **SHA-256, not keccak-256.** SAS hashes with the host's SHA-256
//!   (`Env::crypto().sha256`) everywhere, including the attestation digest.
//!   The `\x19\x01` prefix below is therefore *not* an EVM-compatible payload.
//! * **`address` is one hashed word.** A Soroban `Address` is 44 bytes of XDR
//!   and has no 20-byte EVM equivalent, so it is encoded as
//!   `sha256(ScVal XDR of the address)` instead of a left-padded word.
//! * **Type tags are raw UTF-8.** Struct and field names are encoded as their
//!   raw UTF-8 bytes; integer type names follow Solidity spelling (`uint64`,
//!   `int128`, `bytes32`) so the type strings read like EIP-712 ones.
//! * **Bounded inputs.** Name length, struct count, and field count are capped
//!   so that validation and hashing have a predictable cost envelope.
//!
//! # Domain separation
//!
//! [`TypedDataDomain`] carries the EIP-712 `EIP712Domain` fields: `name`,
//! `version`, the network id (SHA-256 of the Stellar network passphrase), and
//! the verifying contract. A digest computed for one network, one contract, one
//! version, or one app name is useless anywhere else.
//!
//! # Example
//!
//! ```rust,no_run
//! use soroban_sas_common::{
//!     typed_data_digest, TypedDataDomain, TypedDataField, TypedDataKind,
//!     TypedDataSchema, TypedDataStruct, TypedDataType, TypedDataValue, NO_REFERENCE,
//! };
//! use soroban_sdk::{Address, Bytes, BytesN, Env, String, Vec};
//!
//! let env = Env::default();
//! let mut types = Vec::new(&env);
//! types.push_back(TypedDataType { kind: TypedDataKind::U64, reference: NO_REFERENCE });
//! types.push_back(TypedDataType { kind: TypedDataKind::String, reference: NO_REFERENCE });
//!
//! let mut fields = Vec::new(&env);
//! fields.push_back(TypedDataField { name: String::from_str(&env, "amount"), type_index: 0 });
//! fields.push_back(TypedDataField { name: String::from_str(&env, "memo"), type_index: 1 });
//!
//! let mut structs = Vec::new(&env);
//! structs.push_back(TypedDataStruct { name: String::from_str(&env, "Payment"), fields });
//! let schema = TypedDataSchema { types, structs };
//!
//! let mut values = Vec::new(&env);
//! values.push_back(TypedDataValue::U64(1_000));
//! values.push_back(TypedDataValue::String(String::from_str(&env, "rent")));
//!
//! let domain = TypedDataDomain {
//!     name: String::from_str(&env, "Soroban SAS"),
//!     version: String::from_str(&env, "1"),
//!     network_id: BytesN::from_array(&env, &[0u8; 32]),
//!     verifying_contract: Address::from_string(&String::from_str(
//!         &env,
//!         "CDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
//!     )),
//! };
//!
//! let digest = typed_data_digest(
//!     &env,
//!     &schema,
//!     0,
//!     &TypedDataValue::Struct(values),
//!     &domain,
//! ).unwrap();
//! let _ = digest;
//! ```

use crate::errors::TypedDataError;
use soroban_sdk::{contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env, String, Vec};

/// Prefix of a generic typed-data digest, mirroring EIP-191's `\x19\x01`
/// version-and-version-specific byte pair and adding an application tag so a
/// typed-data digest can never be confused with an EIP-712 (keccak) payload or
/// with the fixed attestation digest in [`crate::typed_data`], which uses its
/// own `\x19SorobanSAS\x01` prefix.
pub const TYPED_DATA_PREFIX: &[u8] = b"\x19\x01soroban-sas/typed-data/v1";

/// Canonical `encodeType` of the domain struct, spelled the EIP-712 way with
/// the SAS network binding named `networkId`.
pub const DOMAIN_ENCODE_TYPE: &str =
    "EIP712Domain(string name,string version,bytes32 networkId,address verifyingContract)";

/// Longest accepted struct or field name, in bytes. Bounding names keeps the
/// cost of `encodeType` predictable and gives validation a fixed buffer to
/// copy into (Soroban's `String` has no slice accessor).
pub const MAX_NAME_BYTES: u32 = 64;

/// Longest accepted `String` field value, in bytes.
pub const MAX_STRING_VALUE_BYTES: u32 = 1_024;

/// Largest number of struct definitions a schema may contain. Also bounds the
/// recursion depth of hashing, which follows the (acyclic) struct graph.
pub const MAX_SCHEMA_STRUCTS: u32 = 32;

/// Largest number of fields a single struct may declare.
pub const MAX_STRUCT_FIELDS: u32 = 64;

/// Largest number of entries the type table may contain.
pub const MAX_SCHEMA_TYPES: u32 = 256;

/// `TypedDataType::reference` value for elementary (non-composite) types.
pub const NO_REFERENCE: u32 = u32::MAX;

/// The kind of a node in a schema's type table.
///
/// Elementary kinds each encode to exactly one 32-byte word; composite kinds
/// point at another entry through [`TypedDataType::reference`].
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum TypedDataKind {
    /// 32 raw bytes: schema/attestation UIDs, hashes, ed25519 public keys.
    Bytes32 = 0,
    /// `u64`, right-aligned in its word as 8 big-endian bytes.
    U64 = 1,
    /// `i128`, two's complement, sign-extended to 32 big-endian bytes.
    I128 = 2,
    /// `bool`, encoded as the word `0` or `1`.
    Bool = 3,
    /// Stellar `Address`, encoded as `sha256(xdr(address))`.
    Address = 4,
    /// Dynamic bytes, encoded as `sha256(contents)`.
    Bytes = 5,
    /// UTF-8 string, encoded as `sha256(contents)`.
    String = 6,
    /// A struct definition; `reference` is an index into `TypedDataSchema::structs`.
    Struct = 7,
    /// A homogeneous array; `reference` is an index into `TypedDataSchema::types`
    /// for the element type.
    Array = 8,
}

/// One node of a schema's type table.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedDataType {
    pub kind: TypedDataKind,
    /// `Struct`: index into [`TypedDataSchema::structs`].
    /// `Array`: index into [`TypedDataSchema::types`] (the element type).
    /// Elementary kinds: [`NO_REFERENCE`].
    pub reference: u32,
}

/// A named field of a struct definition.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedDataField {
    pub name: String,
    /// Index into [`TypedDataSchema::types`].
    pub type_index: u32,
}

/// A struct definition: the "type" half of an EIP-712 type declaration.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedDataStruct {
    pub name: String,
    pub fields: Vec<TypedDataField>,
}

/// A complete typed-data schema: the type table plus the struct definitions
/// that index it.
///
/// Struct entries are referenced *by index* from [`TypedDataType::Struct`], so
/// reordering the table means remapping those references. The encoding itself
/// does not depend on table position: [`typed_data_encode_type`] appends
/// referenced types in name order, so two schemas describing the same types and
/// field layout hash identically.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedDataSchema {
    pub types: Vec<TypedDataType>,
    pub structs: Vec<TypedDataStruct>,
}

/// The EIP-712 `EIP712Domain`: everything a verifier must agree on before a
/// signature means anything.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedDataDomain {
    /// Human-readable application name.
    pub name: String,
    /// Signing-format version, e.g. `"1"`.
    pub version: String,
    /// SHA-256 of the Stellar network passphrase.
    pub network_id: BytesN<32>,
    /// Address of the contract that will verify the digest.
    pub verifying_contract: Address,
}

/// A value to hash against a schema. The variant must match the schema's
/// declared [`TypedDataKind`] for that position; a mismatch is rejected rather
/// than coerced.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedDataValue {
    Bytes32(BytesN<32>),
    U64(u64),
    I128(i128),
    Bool(bool),
    Address(Address),
    Bytes(Bytes),
    String(String),
    /// Field values of a struct, positionally matching its declaration.
    Struct(Vec<TypedDataValue>),
    /// Elements of an array.
    Array(Vec<TypedDataValue>),
}

/// Copies the raw UTF-8 bytes of `source` out of the host, rejecting a string
/// longer than `max`.
///
/// `soroban_sdk::String` only exposes a length and a copy-into-slice that
/// requires an exactly-sized destination, so callers must know an upper bound
/// up front. That bound is what makes the length checks in
/// [`validate_typed_data_schema`] load-bearing.
fn raw_bytes(
    env: &Env,
    source: &String,
    max: u32,
    too_long: TypedDataError,
) -> Result<Bytes, TypedDataError> {
    let len = source.len();
    if len > max {
        return Err(too_long);
    }
    let mut buf = [0u8; MAX_STRING_VALUE_BYTES as usize];
    source.copy_into_slice(&mut buf[..len as usize]);
    Ok(Bytes::from_slice(env, &buf[..len as usize]))
}

/// Struct/field name bytes, bounded by [`MAX_NAME_BYTES`].
fn name_bytes(env: &Env, name: &String) -> Result<Bytes, TypedDataError> {
    raw_bytes(env, name, MAX_NAME_BYTES, TypedDataError::NameTooLong)
}

/// One word holding a `u64`, big-endian and right-aligned.
fn word_from_u64(env: &Env, value: u64) -> BytesN<32> {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&value.to_be_bytes());
    BytesN::from_array(env, &word)
}

/// One word holding an `i128`, two's complement and sign-extended.
fn word_from_i128(env: &Env, value: i128) -> BytesN<32> {
    let mut word = if value < 0 { [0xffu8; 32] } else { [0u8; 32] };
    word[16..32].copy_from_slice(&value.to_be_bytes());
    BytesN::from_array(env, &word)
}

/// One word holding a `bool`.
fn word_from_bool(env: &Env, value: bool) -> BytesN<32> {
    let mut word = [0u8; 32];
    word[31] = value as u8;
    BytesN::from_array(env, &word)
}

/// One word holding an address: `sha256(xdr(address))`.
fn word_from_address(env: &Env, value: &Address) -> BytesN<32> {
    env.crypto().sha256(&value.clone().to_xdr(env)).into()
}

/// Appends the type name of `type_index` to `out` (`"uint64"`, `"Payment"`,
/// `"uint64[]"`, ...).
fn append_type_name(
    env: &Env,
    schema: &TypedDataSchema,
    type_index: u32,
    out: &mut Bytes,
) -> Result<(), TypedDataError> {
    let node = schema
        .types
        .get(type_index)
        .ok_or(TypedDataError::TypeIndexOutOfRange)?;
    match node.kind {
        TypedDataKind::Bytes32 => out.append(&Bytes::from_slice(env, b"bytes32")),
        TypedDataKind::U64 => out.append(&Bytes::from_slice(env, b"uint64")),
        TypedDataKind::I128 => out.append(&Bytes::from_slice(env, b"int128")),
        TypedDataKind::Bool => out.append(&Bytes::from_slice(env, b"bool")),
        TypedDataKind::Address => out.append(&Bytes::from_slice(env, b"address")),
        TypedDataKind::Bytes => out.append(&Bytes::from_slice(env, b"bytes")),
        TypedDataKind::String => out.append(&Bytes::from_slice(env, b"string")),
        TypedDataKind::Struct => {
            let def = schema
                .structs
                .get(node.reference)
                .ok_or(TypedDataError::StructIndexOutOfRange)?;
            out.append(&name_bytes(env, &def.name)?);
        }
        TypedDataKind::Array => {
            append_type_name(env, schema, node.reference, out)?;
            out.append(&Bytes::from_slice(env, b"[]"));
        }
    }
    Ok(())
}

/// Appends `Name(type field,...)` for one struct definition.
fn append_struct_definition(
    env: &Env,
    schema: &TypedDataSchema,
    struct_index: u32,
    out: &mut Bytes,
) -> Result<(), TypedDataError> {
    let def = schema
        .structs
        .get(struct_index)
        .ok_or(TypedDataError::StructIndexOutOfRange)?;
    out.append(&name_bytes(env, &def.name)?);
    out.append(&Bytes::from_slice(env, b"("));
    for (position, field) in def.fields.iter().enumerate() {
        if position > 0 {
            out.append(&Bytes::from_slice(env, b","));
        }
        append_type_name(env, schema, field.type_index, out)?;
        out.append(&Bytes::from_slice(env, b" "));
        out.append(&name_bytes(env, &field.name)?);
    }
    out.append(&Bytes::from_slice(env, b")"));
    Ok(())
}

/// Collects the transitive set of struct types referenced by `struct_index`,
/// excluding `struct_index` itself.
fn collect_referenced_structs(
    schema: &TypedDataSchema,
    struct_index: u32,
    out: &mut Vec<u32>,
) -> Result<(), TypedDataError> {
    let def = schema
        .structs
        .get(struct_index)
        .ok_or(TypedDataError::StructIndexOutOfRange)?;
    for field in def.fields.iter() {
        let node = schema
            .types
            .get(field.type_index)
            .ok_or(TypedDataError::TypeIndexOutOfRange)?;
        if node.kind == TypedDataKind::Struct {
            if !out.contains(node.reference) {
                out.push_back(node.reference);
                collect_referenced_structs(schema, node.reference, out)?;
            }
        } else if node.kind == TypedDataKind::Array {
            collect_array_referenced_structs(schema, node.reference, out)?;
        }
    }
    Ok(())
}

/// Arrays may nest, so an array field can reference a struct indirectly.
fn collect_array_referenced_structs(
    schema: &TypedDataSchema,
    type_index: u32,
    out: &mut Vec<u32>,
) -> Result<(), TypedDataError> {
    let node = schema
        .types
        .get(type_index)
        .ok_or(TypedDataError::TypeIndexOutOfRange)?;
    match node.kind {
        TypedDataKind::Struct => {
            if !out.contains(node.reference) {
                out.push_back(node.reference);
                collect_referenced_structs(schema, node.reference, out)?;
            }
        }
        TypedDataKind::Array => {
            collect_array_referenced_structs(schema, node.reference, out)?;
        }
        _ => {}
    }
    Ok(())
}

/// Sorts struct indices by struct name (EIP-712's ordering for referenced
/// types), using insertion sort because `soroban_sdk::Vec` has no `sort`.
fn sort_structs_by_name(schema: &TypedDataSchema, indices: &mut Vec<u32>) {
    let len = indices.len();
    for i in 1..len {
        let key = indices.get_unchecked(i);
        let key_name = struct_name(schema, key);
        let mut j = i;
        while j > 0 {
            let previous = indices.get_unchecked(j - 1);
            if struct_name(schema, previous) <= key_name {
                break;
            }
            indices.set(j, previous);
            j -= 1;
        }
        indices.set(j, key);
    }
}

/// The name of a struct definition, or an empty string when the index is out
/// of range (only reachable from already-validated schemas).
fn struct_name(schema: &TypedDataSchema, struct_index: u32) -> String {
    match schema.structs.get(struct_index) {
        Some(def) => def.name,
        None => String::from_str(schema.structs.env(), ""),
    }
}

/// Returns the `encodeType` of `struct_index` as raw UTF-8 bytes.
///
/// This is the string EIP-712 calls `encodeType`: the struct's own definition
/// followed by every struct type it references, transitively, each once, sorted
/// by name.
pub fn typed_data_encode_type(
    env: &Env,
    schema: &TypedDataSchema,
    struct_index: u32,
) -> Result<Bytes, TypedDataError> {
    validate_typed_data_schema(schema)?;
    encode_type_validated(env, schema, struct_index)
}

fn encode_type_validated(
    env: &Env,
    schema: &TypedDataSchema,
    struct_index: u32,
) -> Result<Bytes, TypedDataError> {
    let mut out = Bytes::new(env);
    append_struct_definition(env, schema, struct_index, &mut out)?;

    let mut referenced = Vec::new(env);
    collect_referenced_structs(schema, struct_index, &mut referenced)?;
    sort_structs_by_name(schema, &mut referenced);
    for index in referenced.iter() {
        append_struct_definition(env, schema, index, &mut out)?;
    }
    Ok(out)
}

/// Returns `sha256(encodeType(struct_index))`.
pub fn typed_data_type_hash(
    env: &Env,
    schema: &TypedDataSchema,
    struct_index: u32,
) -> Result<BytesN<32>, TypedDataError> {
    validate_typed_data_schema(schema)?;
    type_hash_validated(env, schema, struct_index)
}

fn type_hash_validated(
    env: &Env,
    schema: &TypedDataSchema,
    struct_index: u32,
) -> Result<BytesN<32>, TypedDataError> {
    let encoded = encode_type_validated(env, schema, struct_index)?;
    Ok(env.crypto().sha256(&encoded).into())
}

/// Encodes one field value to exactly one 32-byte word.
fn encode_field(
    env: &Env,
    schema: &TypedDataSchema,
    type_index: u32,
    value: &TypedDataValue,
) -> Result<BytesN<32>, TypedDataError> {
    let node = schema
        .types
        .get(type_index)
        .ok_or(TypedDataError::TypeIndexOutOfRange)?;
    match (node.kind, value) {
        (TypedDataKind::Bytes32, TypedDataValue::Bytes32(inner)) => Ok(inner.clone()),
        (TypedDataKind::U64, TypedDataValue::U64(inner)) => Ok(word_from_u64(env, *inner)),
        (TypedDataKind::I128, TypedDataValue::I128(inner)) => Ok(word_from_i128(env, *inner)),
        (TypedDataKind::Bool, TypedDataValue::Bool(inner)) => Ok(word_from_bool(env, *inner)),
        (TypedDataKind::Address, TypedDataValue::Address(inner)) => {
            Ok(word_from_address(env, inner))
        }
        (TypedDataKind::Bytes, TypedDataValue::Bytes(inner)) => {
            Ok(env.crypto().sha256(inner).into())
        }
        (TypedDataKind::String, TypedDataValue::String(inner)) => {
            let raw = raw_bytes(
                env,
                inner,
                MAX_STRING_VALUE_BYTES,
                TypedDataError::StringValueTooLong,
            )?;
            Ok(env.crypto().sha256(&raw).into())
        }
        (TypedDataKind::Struct, _) => hash_struct_validated(env, schema, node.reference, value),
        (TypedDataKind::Array, TypedDataValue::Array(items)) => {
            let mut buffer = Bytes::new(env);
            for item in items.iter() {
                let word = encode_field(env, schema, node.reference, &item)?;
                buffer.append(&Bytes::from_slice(env, &word.to_array()));
            }
            Ok(env.crypto().sha256(&buffer).into())
        }
        _ => Err(TypedDataError::TypeMismatch),
    }
}

/// Returns `hashStruct(struct_index, value)`:
/// `sha256(typeHash ‖ encodeData(value))`.
pub fn typed_data_hash_struct(
    env: &Env,
    schema: &TypedDataSchema,
    struct_index: u32,
    value: &TypedDataValue,
) -> Result<BytesN<32>, TypedDataError> {
    validate_typed_data_schema(schema)?;
    hash_struct_validated(env, schema, struct_index, value)
}

fn hash_struct_validated(
    env: &Env,
    schema: &TypedDataSchema,
    struct_index: u32,
    value: &TypedDataValue,
) -> Result<BytesN<32>, TypedDataError> {
    let def = schema
        .structs
        .get(struct_index)
        .ok_or(TypedDataError::StructIndexOutOfRange)?;
    let values = match value {
        TypedDataValue::Struct(values) => values,
        _ => return Err(TypedDataError::TypeMismatch),
    };
    if values.len() != def.fields.len() {
        return Err(TypedDataError::ArityMismatch);
    }

    let mut buffer = Bytes::from_slice(
        env,
        &type_hash_validated(env, schema, struct_index)?.to_array(),
    );
    for (field, field_value) in def.fields.iter().zip(values.iter()) {
        let word = encode_field(env, schema, field.type_index, &field_value)?;
        buffer.append(&Bytes::from_slice(env, &word.to_array()));
    }
    Ok(env.crypto().sha256(&buffer).into())
}

/// Returns the domain separator: `hashStruct(EIP712Domain)` over
/// [`DOMAIN_ENCODE_TYPE`], with the field order that type string declares.
pub fn typed_data_domain_hash(
    env: &Env,
    domain: &TypedDataDomain,
) -> Result<BytesN<32>, TypedDataError> {
    domain_hash_validated(env, domain)
}

fn domain_hash_validated(
    env: &Env,
    domain: &TypedDataDomain,
) -> Result<BytesN<32>, TypedDataError> {
    let mut buffer = Bytes::from_slice(
        env,
        &env.crypto()
            .sha256(&Bytes::from_slice(env, DOMAIN_ENCODE_TYPE.as_bytes()))
            .to_array(),
    );

    let name = raw_bytes(
        env,
        &domain.name,
        MAX_STRING_VALUE_BYTES,
        TypedDataError::StringValueTooLong,
    )?;
    let version = raw_bytes(
        env,
        &domain.version,
        MAX_STRING_VALUE_BYTES,
        TypedDataError::StringValueTooLong,
    )?;

    buffer.append(&Bytes::from_slice(
        env,
        &env.crypto().sha256(&name).to_array(),
    ));
    buffer.append(&Bytes::from_slice(
        env,
        &env.crypto().sha256(&version).to_array(),
    ));
    buffer.append(&Bytes::from_slice(env, &domain.network_id.to_array()));
    buffer.append(&Bytes::from_slice(
        env,
        &word_from_address(env, &domain.verifying_contract).to_array(),
    ));

    Ok(env.crypto().sha256(&buffer).into())
}

/// The digest a signer signs for a typed-data message:
/// `sha256(PREFIX ‖ domainSeparator ‖ hashStruct(message))`.
///
/// `struct_index` selects the root struct in `schema.structs`; `value` must be
/// a [`TypedDataValue::Struct`] whose fields match that struct's declaration.
pub fn typed_data_digest(
    env: &Env,
    schema: &TypedDataSchema,
    struct_index: u32,
    value: &TypedDataValue,
    domain: &TypedDataDomain,
) -> Result<BytesN<32>, TypedDataError> {
    validate_typed_data_schema(schema)?;
    let struct_hash = hash_struct_validated(env, schema, struct_index, value)?;
    let domain_hash = domain_hash_validated(env, domain)?;

    let mut buffer = Bytes::from_slice(env, TYPED_DATA_PREFIX);
    buffer.append(&Bytes::from_slice(env, &domain_hash.to_array()));
    buffer.append(&Bytes::from_slice(env, &struct_hash.to_array()));
    Ok(env.crypto().sha256(&buffer).into())
}

/// Validates a schema's shape before it is hashed.
///
/// Checks, in order: non-empty type and struct tables within their size caps;
/// non-empty, bounded, unique struct names; non-empty, bounded, unique field
/// names per struct (EIP-712 requires unique names — duplicates make
/// `encodeType` ambiguous); in-range type and struct indices; elementary types
/// carrying [`NO_REFERENCE`]; and an acyclic type graph, since a cycle would
/// make `encodeType` and `encodeData` recurse forever.
pub fn validate_typed_data_schema(schema: &TypedDataSchema) -> Result<(), TypedDataError> {
    if schema.types.is_empty() || schema.structs.is_empty() {
        return Err(TypedDataError::EmptySchema);
    }
    if schema.structs.len() > MAX_SCHEMA_STRUCTS || schema.types.len() > MAX_SCHEMA_TYPES {
        return Err(TypedDataError::SchemaTooLarge);
    }

    let mut seen_structs = Vec::new(schema.structs.env());
    for def in schema.structs.iter() {
        if def.name.is_empty() {
            return Err(TypedDataError::EmptyName);
        }
        if def.name.len() > MAX_NAME_BYTES {
            return Err(TypedDataError::NameTooLong);
        }
        if seen_structs.contains(&def.name) {
            return Err(TypedDataError::DuplicateStructName);
        }
        seen_structs.push_back(def.name.clone());

        if def.fields.len() > MAX_STRUCT_FIELDS {
            return Err(TypedDataError::StructTooLarge);
        }
        let mut seen_fields = Vec::new(schema.structs.env());
        for field in def.fields.iter() {
            if field.name.is_empty() {
                return Err(TypedDataError::EmptyName);
            }
            if field.name.len() > MAX_NAME_BYTES {
                return Err(TypedDataError::NameTooLong);
            }
            if seen_fields.contains(&field.name) {
                return Err(TypedDataError::DuplicateFieldName);
            }
            seen_fields.push_back(field.name.clone());

            if field.type_index >= schema.types.len() {
                return Err(TypedDataError::TypeIndexOutOfRange);
            }
        }
    }

    for node in schema.types.iter() {
        match node.kind {
            TypedDataKind::Struct => {
                if node.reference >= schema.structs.len() {
                    return Err(TypedDataError::StructIndexOutOfRange);
                }
            }
            TypedDataKind::Array => {
                if node.reference >= schema.types.len() {
                    return Err(TypedDataError::TypeIndexOutOfRange);
                }
            }
            _ => {
                if node.reference != NO_REFERENCE {
                    return Err(TypedDataError::UnexpectedReference);
                }
            }
        }
    }

    detect_type_cycles(schema)
}

/// Depth-first cycle detection over the type table. `state` is indexed by type
/// index: `0` unvisited, `1` on the current path, `2` fully explored.
fn detect_type_cycles(schema: &TypedDataSchema) -> Result<(), TypedDataError> {
    let mut state = [0u8; MAX_SCHEMA_TYPES as usize];
    for index in 0..schema.types.len() {
        visit_type(schema, index, &mut state)?;
    }
    Ok(())
}

fn visit_type(
    schema: &TypedDataSchema,
    type_index: u32,
    state: &mut [u8; MAX_SCHEMA_TYPES as usize],
) -> Result<(), TypedDataError> {
    let current = state[type_index as usize];
    if current == 1 {
        return Err(TypedDataError::CyclicTypeReference);
    }
    if current == 2 {
        return Ok(());
    }
    state[type_index as usize] = 1;

    let node = schema
        .types
        .get(type_index)
        .ok_or(TypedDataError::TypeIndexOutOfRange)?;
    match node.kind {
        TypedDataKind::Array => visit_type(schema, node.reference, state)?,
        TypedDataKind::Struct => {
            let def = schema
                .structs
                .get(node.reference)
                .ok_or(TypedDataError::StructIndexOutOfRange)?;
            for field in def.fields.iter() {
                visit_type(schema, field.type_index, state)?;
            }
        }
        _ => {}
    }

    state[type_index as usize] = 2;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        xdr::{Hash, ScAddress, ToXdr},
        String, TryFromVal, Vec,
    };

    // -- builders ---------------------------------------------------------

    fn s(env: &Env, value: &str) -> String {
        String::from_str(env, value)
    }

    fn ty(kind: TypedDataKind, reference: u32) -> TypedDataType {
        TypedDataType { kind, reference }
    }

    fn field(env: &Env, name: &str, type_index: u32) -> TypedDataField {
        TypedDataField {
            name: s(env, name),
            type_index,
        }
    }

    fn struct_def(env: &Env, name: &str, fields: Vec<TypedDataField>) -> TypedDataStruct {
        TypedDataStruct {
            name: s(env, name),
            fields,
        }
    }

    fn contract_address(env: &Env, seed: u8) -> Address {
        Address::try_from_val(env, &ScAddress::Contract(Hash([seed; 32]))).unwrap()
    }

    /// A `Root` struct with one field of `kind`, for encoding-rule tests.
    fn single_field_schema(env: &Env, kind: TypedDataKind, field_name: &str) -> TypedDataSchema {
        let mut types = Vec::new(env);
        types.push_back(ty(kind, NO_REFERENCE));
        let mut fields = Vec::new(env);
        fields.push_back(field(env, field_name, 0));
        let mut structs = Vec::new(env);
        structs.push_back(struct_def(env, "Only", fields));
        TypedDataSchema { types, structs }
    }

    /// `Payment` exercising every elementary kind, a nested struct, and an
    /// array. Index 1 in `structs` is the root.
    fn payment_schema(env: &Env) -> TypedDataSchema {
        let mut types = Vec::new(env);
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE)); // 0
        types.push_back(ty(TypedDataKind::String, NO_REFERENCE)); // 1
        types.push_back(ty(TypedDataKind::Bytes32, NO_REFERENCE)); // 2
        types.push_back(ty(TypedDataKind::Address, NO_REFERENCE)); // 3
        types.push_back(ty(TypedDataKind::Bool, NO_REFERENCE)); // 4
        types.push_back(ty(TypedDataKind::Struct, 0)); // 5 -> Meta
        types.push_back(ty(TypedDataKind::Array, 1)); // 6 -> string[]

        let mut meta_fields = Vec::new(env);
        meta_fields.push_back(field(env, "note", 1));

        let mut payment_fields = Vec::new(env);
        payment_fields.push_back(field(env, "amount", 0));
        payment_fields.push_back(field(env, "memo", 1));
        payment_fields.push_back(field(env, "reference", 2));
        payment_fields.push_back(field(env, "asset", 3));
        payment_fields.push_back(field(env, "approved", 4));
        payment_fields.push_back(field(env, "meta", 5));
        payment_fields.push_back(field(env, "tags", 6));

        let mut structs = Vec::new(env);
        structs.push_back(struct_def(env, "Meta", meta_fields)); // 0
        structs.push_back(struct_def(env, "Payment", payment_fields)); // 1
        TypedDataSchema { types, structs }
    }

    const PAYMENT_ENCODE_TYPE: &str = concat!(
        "Payment(uint64 amount,string memo,bytes32 reference,address asset,",
        "bool approved,Meta meta,string[] tags)",
        "Meta(string note)"
    );

    // -- independent encoders (a verifier's implementation of the spec) ----

    fn word_u64(value: u64) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&value.to_be_bytes());
        word
    }

    fn word_i128(value: i128) -> [u8; 32] {
        let mut word = if value < 0 { [0xffu8; 32] } else { [0u8; 32] };
        word[16..32].copy_from_slice(&value.to_be_bytes());
        word
    }

    fn word_bool(value: bool) -> [u8; 32] {
        let mut word = [0u8; 32];
        word[31] = value as u8;
        word
    }

    fn sha_bytes(env: &Env, data: &Bytes) -> [u8; 32] {
        env.crypto().sha256(data).to_array()
    }

    fn sha_slice(env: &Env, data: &[u8]) -> [u8; 32] {
        env.crypto()
            .sha256(&Bytes::from_slice(env, data))
            .to_array()
    }

    fn sha_str(env: &Env, value: &str) -> [u8; 32] {
        sha_slice(env, value.as_bytes())
    }

    fn append_word(env: &Env, buffer: &mut Bytes, word: [u8; 32]) {
        buffer.append(&Bytes::from_slice(env, &word));
    }

    fn domain(env: &Env) -> TypedDataDomain {
        TypedDataDomain {
            name: s(env, "Soroban SAS"),
            version: s(env, "1"),
            network_id: BytesN::from_array(env, &[7u8; 32]),
            verifying_contract: contract_address(env, 9),
        }
    }

    fn payment_values(env: &Env) -> TypedDataValue {
        let mut meta = Vec::new(env);
        meta.push_back(TypedDataValue::String(s(env, "reimbursement")));

        let mut tags = Vec::new(env);
        tags.push_back(TypedDataValue::String(s(env, "ab")));
        tags.push_back(TypedDataValue::String(s(env, "c")));

        let mut values = Vec::new(env);
        values.push_back(TypedDataValue::U64(1_000));
        values.push_back(TypedDataValue::String(s(env, "rent")));
        values.push_back(TypedDataValue::Bytes32(BytesN::from_array(env, &[1u8; 32])));
        values.push_back(TypedDataValue::Address(contract_address(env, 5)));
        values.push_back(TypedDataValue::Bool(true));
        values.push_back(TypedDataValue::Struct(meta));
        values.push_back(TypedDataValue::Array(tags));
        TypedDataValue::Struct(values)
    }

    fn payment_message_hash(env: &Env) -> [u8; 32] {
        let mut buffer = Bytes::from_slice(env, &sha_str(env, PAYMENT_ENCODE_TYPE));

        append_word(env, &mut buffer, word_u64(1_000));
        append_word(env, &mut buffer, sha_str(env, "rent"));
        append_word(env, &mut buffer, [1u8; 32]);

        let mut asset = Bytes::new(env);
        asset.append(&contract_address(env, 5).to_xdr(env));
        append_word(env, &mut buffer, sha_bytes(env, &asset));

        append_word(env, &mut buffer, word_bool(true));

        // Nested `Meta(string note)` hashed as its own struct.
        let mut nested = Bytes::from_slice(env, &sha_str(env, "Meta(string note)"));
        append_word(env, &mut nested, sha_str(env, "reimbursement"));
        append_word(env, &mut buffer, sha_bytes(env, &nested));

        // Array of strings: hash of the concatenated element words.
        let mut elements = Bytes::new(env);
        append_word(env, &mut elements, sha_str(env, "ab"));
        append_word(env, &mut elements, sha_str(env, "c"));
        append_word(env, &mut buffer, sha_bytes(env, &elements));

        sha_bytes(env, &buffer)
    }

    fn domain_hash(env: &Env) -> [u8; 32] {
        let mut buffer = Bytes::from_slice(env, &sha_str(env, DOMAIN_ENCODE_TYPE));
        append_word(env, &mut buffer, sha_str(env, "Soroban SAS"));
        append_word(env, &mut buffer, sha_str(env, "1"));
        append_word(env, &mut buffer, [7u8; 32]);

        let mut contract = Bytes::new(env);
        contract.append(&contract_address(env, 9).to_xdr(env));
        append_word(env, &mut buffer, sha_bytes(env, &contract));

        sha_bytes(env, &buffer)
    }

    // -- encodeType -------------------------------------------------------

    #[test]
    fn encode_type_lists_fields_and_appends_referenced_structs() {
        let env = Env::default();
        let schema = payment_schema(&env);

        let encoded = typed_data_encode_type(&env, &schema, 1).unwrap();

        assert_eq!(
            encoded,
            Bytes::from_slice(&env, PAYMENT_ENCODE_TYPE.as_bytes())
        );
    }

    #[test]
    fn encode_type_sorts_referenced_structs_by_name() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::Struct, 1)); // Zeta
        types.push_back(ty(TypedDataKind::Struct, 2)); // Alpha
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE));

        let mut root_fields = Vec::new(&env);
        root_fields.push_back(field(&env, "z", 0));
        root_fields.push_back(field(&env, "a", 1));

        let mut alpha_fields = Vec::new(&env);
        alpha_fields.push_back(field(&env, "v", 2));
        let mut zeta_fields = Vec::new(&env);
        zeta_fields.push_back(field(&env, "v", 2));

        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Root", root_fields));
        structs.push_back(struct_def(&env, "Zeta", zeta_fields));
        structs.push_back(struct_def(&env, "Alpha", alpha_fields));
        let schema = TypedDataSchema { types, structs };

        let encoded = typed_data_encode_type(&env, &schema, 0).unwrap();

        // Referenced types are appended alphabetically, not in field order.
        assert_eq!(
            encoded,
            Bytes::from_slice(&env, b"Root(Zeta z,Alpha a)Alpha(uint64 v)Zeta(uint64 v)")
        );
    }

    #[test]
    fn encode_type_ignores_struct_table_order() {
        let env = Env::default();
        let schema = payment_schema(&env);
        let root = 1;

        // Same types and fields, but the struct table lists Payment before
        // Meta, so the index that `types[5]` uses to reach Meta becomes 1 and
        // the root moves to 0.
        let mut types = Vec::new(&env);
        for index in 0..schema.types.len() {
            let mut node = schema.types.get_unchecked(index);
            if node.kind == TypedDataKind::Struct {
                node.reference = 1;
            }
            types.push_back(node);
        }
        let mut structs = Vec::new(&env);
        structs.push_back(schema.structs.get_unchecked(1)); // Payment
        structs.push_back(schema.structs.get_unchecked(0)); // Meta
        let reordered = TypedDataSchema { types, structs };
        let reordered_root = 0;

        assert_eq!(
            typed_data_encode_type(&env, &schema, root).unwrap(),
            typed_data_encode_type(&env, &reordered, reordered_root).unwrap()
        );
        assert_eq!(
            typed_data_type_hash(&env, &schema, root).unwrap(),
            typed_data_type_hash(&env, &reordered, reordered_root).unwrap()
        );
        assert_eq!(
            typed_data_hash_struct(&env, &schema, root, &payment_values(&env)).unwrap(),
            typed_data_hash_struct(&env, &reordered, reordered_root, &payment_values(&env))
                .unwrap()
        );
    }

    #[test]
    fn type_hash_is_sha256_of_encode_type() {
        let env = Env::default();
        let schema = payment_schema(&env);

        let encoded = typed_data_encode_type(&env, &schema, 1).unwrap();
        let expected: BytesN<32> = env.crypto().sha256(&encoded).into();

        assert_eq!(typed_data_type_hash(&env, &schema, 1).unwrap(), expected);
    }

    // -- hashStruct -------------------------------------------------------

    #[test]
    fn hash_struct_matches_independent_encoding() {
        let env = Env::default();
        let schema = payment_schema(&env);

        let actual = typed_data_hash_struct(&env, &schema, 1, &payment_values(&env)).unwrap();

        assert_eq!(actual.to_array(), payment_message_hash(&env));
    }

    #[test]
    fn digest_matches_independent_encoding() {
        let env = Env::default();
        let schema = payment_schema(&env);
        let domain = domain(&env);

        let actual = typed_data_digest(&env, &schema, 1, &payment_values(&env), &domain).unwrap();

        let mut buffer = Bytes::from_slice(&env, TYPED_DATA_PREFIX);
        append_word(&env, &mut buffer, domain_hash(&env));
        append_word(&env, &mut buffer, payment_message_hash(&env));
        let expected = sha_bytes(&env, &buffer);

        assert_eq!(actual.to_array(), expected);
    }

    #[test]
    fn digest_is_deterministic() {
        let env = Env::default();
        let schema = payment_schema(&env);
        let domain = domain(&env);

        let first = typed_data_digest(&env, &schema, 1, &payment_values(&env), &domain).unwrap();
        let second = typed_data_digest(&env, &schema, 1, &payment_values(&env), &domain).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn elementary_kinds_match_independent_words() {
        let env = Env::default();

        let u64_schema = single_field_schema(&env, TypedDataKind::U64, "v");
        let mut values = Vec::new(&env);
        values.push_back(TypedDataValue::U64(u64::MAX));
        let value = TypedDataValue::Struct(values);
        let mut buffer = Bytes::from_slice(&env, &sha_str(&env, "Only(uint64 v)"));
        append_word(&env, &mut buffer, word_u64(u64::MAX));
        assert_eq!(
            typed_data_hash_struct(&env, &u64_schema, 0, &value)
                .unwrap()
                .to_array(),
            sha_bytes(&env, &buffer)
        );

        let i128_schema = single_field_schema(&env, TypedDataKind::I128, "v");
        let mut values = Vec::new(&env);
        values.push_back(TypedDataValue::I128(-1));
        let value = TypedDataValue::Struct(values);
        assert_eq!(word_i128(-1), [0xffu8; 32]);
        let mut buffer = Bytes::from_slice(&env, &sha_str(&env, "Only(int128 v)"));
        append_word(&env, &mut buffer, word_i128(-1));
        assert_eq!(
            typed_data_hash_struct(&env, &i128_schema, 0, &value)
                .unwrap()
                .to_array(),
            sha_bytes(&env, &buffer)
        );

        let bool_schema = single_field_schema(&env, TypedDataKind::Bool, "v");
        let mut values = Vec::new(&env);
        values.push_back(TypedDataValue::Bool(true));
        let value = TypedDataValue::Struct(values);
        let mut buffer = Bytes::from_slice(&env, &sha_str(&env, "Only(bool v)"));
        append_word(&env, &mut buffer, word_bool(true));
        assert_eq!(
            typed_data_hash_struct(&env, &bool_schema, 0, &value)
                .unwrap()
                .to_array(),
            sha_bytes(&env, &buffer)
        );
    }

    #[test]
    fn empty_array_hashes_to_sha256_of_no_bytes() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::Array, 1));
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "values", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Batch", fields));
        let schema = TypedDataSchema { types, structs };

        let mut values = Vec::new(&env);
        values.push_back(TypedDataValue::Array(Vec::new(&env)));
        let value = TypedDataValue::Struct(values);

        let mut buffer = Bytes::from_slice(&env, &sha_str(&env, "Batch(uint64[] values)"));
        append_word(&env, &mut buffer, sha_slice(&env, b""));

        assert_eq!(
            typed_data_hash_struct(&env, &schema, 0, &value)
                .unwrap()
                .to_array(),
            sha_bytes(&env, &buffer)
        );
    }

    #[test]
    fn array_elements_are_hashed_individually() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::Array, 1));
        types.push_back(ty(TypedDataKind::String, NO_REFERENCE));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "values", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Batch", fields));
        let schema = TypedDataSchema { types, structs };

        let hash_of = |first: &str, second: &str| {
            let mut items = Vec::new(&env);
            items.push_back(TypedDataValue::String(s(&env, first)));
            items.push_back(TypedDataValue::String(s(&env, second)));
            let mut values = Vec::new(&env);
            values.push_back(TypedDataValue::Array(items));
            typed_data_hash_struct(&env, &schema, 0, &TypedDataValue::Struct(values)).unwrap()
        };

        // A per-element hash keeps the boundary between elements: if raw
        // contents were concatenated instead, these two would collide.
        assert_ne!(hash_of("ab", "c"), hash_of("a", "bc"));
    }

    #[test]
    fn wrong_arity_is_rejected() {
        let env = Env::default();
        let schema = payment_schema(&env);

        let mut values = Vec::new(&env);
        values.push_back(TypedDataValue::U64(1));

        assert_eq!(
            typed_data_hash_struct(&env, &schema, 1, &TypedDataValue::Struct(values)),
            Err(TypedDataError::ArityMismatch)
        );
    }

    #[test]
    fn wrong_value_variant_is_rejected() {
        let env = Env::default();
        let schema = single_field_schema(&env, TypedDataKind::U64, "v");

        let mut values = Vec::new(&env);
        values.push_back(TypedDataValue::Bool(true));

        assert_eq!(
            typed_data_hash_struct(&env, &schema, 0, &TypedDataValue::Struct(values)),
            Err(TypedDataError::TypeMismatch)
        );
    }

    #[test]
    fn non_struct_root_value_is_rejected() {
        let env = Env::default();
        let schema = single_field_schema(&env, TypedDataKind::U64, "v");

        assert_eq!(
            typed_data_hash_struct(&env, &schema, 0, &TypedDataValue::U64(1)),
            Err(TypedDataError::TypeMismatch)
        );
    }

    #[test]
    fn array_value_must_use_the_array_variant() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::Array, 1));
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "values", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Batch", fields));
        let schema = TypedDataSchema { types, structs };

        let mut values = Vec::new(&env);
        values.push_back(TypedDataValue::U64(1));

        assert_eq!(
            typed_data_hash_struct(&env, &schema, 0, &TypedDataValue::Struct(values)),
            Err(TypedDataError::TypeMismatch)
        );
    }

    // -- domain separation -------------------------------------------------

    #[test]
    fn domain_binds_name_version_network_and_contract() {
        let env = Env::default();
        let schema = payment_schema(&env);
        let values = payment_values(&env);
        let base = domain(&env);

        let baseline = typed_data_digest(&env, &schema, 1, &values, &base).unwrap();

        let mut other_name = base.clone();
        other_name.name = s(&env, "Other App");
        let mut other_version = base.clone();
        other_version.version = s(&env, "2");
        let mut other_network = base.clone();
        other_network.network_id = BytesN::from_array(&env, &[8u8; 32]);
        let mut other_contract = base.clone();
        other_contract.verifying_contract = contract_address(&env, 10);

        for changed in [other_name, other_version, other_network, other_contract] {
            assert_ne!(
                baseline,
                typed_data_digest(&env, &schema, 1, &values, &changed).unwrap()
            );
        }
    }

    #[test]
    fn domain_hash_matches_independent_encoding() {
        let env = Env::default();
        let domain = domain(&env);

        assert_eq!(
            typed_data_domain_hash(&env, &domain).unwrap().to_array(),
            domain_hash(&env)
        );
    }

    #[test]
    fn typed_data_prefix_is_distinct_from_the_attestation_prefix() {
        assert_ne!(TYPED_DATA_PREFIX, crate::typed_data::PAYLOAD_PREFIX);
    }

    // -- validation --------------------------------------------------------

    #[test]
    fn validation_rejects_empty_schema() {
        let env = Env::default();
        let empty = TypedDataSchema {
            types: Vec::new(&env),
            structs: Vec::new(&env),
        };

        assert_eq!(
            validate_typed_data_schema(&empty),
            Err(TypedDataError::EmptySchema)
        );
    }

    #[test]
    fn validation_rejects_duplicate_field_names() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "amount", 0));
        fields.push_back(field(&env, "amount", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Payment", fields));
        let schema = TypedDataSchema { types, structs };

        assert_eq!(
            validate_typed_data_schema(&schema),
            Err(TypedDataError::DuplicateFieldName)
        );
    }

    #[test]
    fn validation_keeps_field_names_case_sensitive() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "amount", 0));
        fields.push_back(field(&env, "Amount", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Payment", fields));
        let schema = TypedDataSchema { types, structs };

        assert_eq!(validate_typed_data_schema(&schema), Ok(()));
    }

    #[test]
    fn validation_rejects_duplicate_struct_names() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE));
        let mut first_fields = Vec::new(&env);
        first_fields.push_back(field(&env, "a", 0));
        let mut second_fields = Vec::new(&env);
        second_fields.push_back(field(&env, "b", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Same", first_fields));
        structs.push_back(struct_def(&env, "Same", second_fields));
        let schema = TypedDataSchema { types, structs };

        assert_eq!(
            validate_typed_data_schema(&schema),
            Err(TypedDataError::DuplicateStructName)
        );
    }

    #[test]
    fn validation_rejects_empty_and_oversized_names() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "a", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "", fields));
        assert_eq!(
            validate_typed_data_schema(&TypedDataSchema {
                types: types.clone(),
                structs
            }),
            Err(TypedDataError::EmptyName)
        );

        let long_name = String::from_bytes(&env, &[b'n'; (MAX_NAME_BYTES + 1) as usize]);
        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE));
        let mut fields = Vec::new(&env);
        fields.push_back(TypedDataField {
            name: long_name,
            type_index: 0,
        });
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Payment", fields));
        assert_eq!(
            validate_typed_data_schema(&TypedDataSchema { types, structs }),
            Err(TypedDataError::NameTooLong)
        );
    }

    #[test]
    fn validation_rejects_out_of_range_indices() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::U64, NO_REFERENCE));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "a", 7));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Payment", fields));
        assert_eq!(
            validate_typed_data_schema(&TypedDataSchema {
                types: types.clone(),
                structs
            }),
            Err(TypedDataError::TypeIndexOutOfRange)
        );

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::Struct, 5));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "a", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Payment", fields));
        assert_eq!(
            validate_typed_data_schema(&TypedDataSchema { types, structs }),
            Err(TypedDataError::StructIndexOutOfRange)
        );
    }

    #[test]
    fn validation_rejects_elementary_types_carrying_a_reference() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::U64, 0));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "a", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Payment", fields));

        assert_eq!(
            validate_typed_data_schema(&TypedDataSchema { types, structs }),
            Err(TypedDataError::UnexpectedReference)
        );
    }

    #[test]
    fn validation_rejects_struct_cycles() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::Struct, 0));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "self", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Loop", fields));

        assert_eq!(
            validate_typed_data_schema(&TypedDataSchema { types, structs }),
            Err(TypedDataError::CyclicTypeReference)
        );
    }

    #[test]
    fn validation_rejects_self_referencing_arrays() {
        let env = Env::default();

        let mut types = Vec::new(&env);
        types.push_back(ty(TypedDataKind::Array, 0));
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "nested", 0));
        let mut structs = Vec::new(&env);
        structs.push_back(struct_def(&env, "Loop", fields));

        assert_eq!(
            validate_typed_data_schema(&TypedDataSchema { types, structs }),
            Err(TypedDataError::CyclicTypeReference)
        );
    }

    #[test]
    fn validation_rejects_oversized_string_values() {
        let env = Env::default();
        let schema = single_field_schema(&env, TypedDataKind::String, "v");

        let too_long = String::from_bytes(&env, &[b'a'; (MAX_STRING_VALUE_BYTES + 1) as usize]);
        let mut values = Vec::new(&env);
        values.push_back(TypedDataValue::String(too_long));

        assert_eq!(
            typed_data_hash_struct(&env, &schema, 0, &TypedDataValue::Struct(values)),
            Err(TypedDataError::StringValueTooLong)
        );
    }
}
