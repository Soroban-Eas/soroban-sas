//! Generic EIP-712 structured-data hashing.
//!
//! [`crate::typed_data`] implements the SAS-specific v1 signing scheme: three
//! hand-written type tags, a fixed field layout per action, and SHA-256
//! throughout. This module adds the *general* mechanism EIP-712 actually
//! specifies, so a caller can declare a struct once and get the canonical
//! type string, its type hash, and the struct hash without hand-writing any
//! byte layout:
//!
//! | EIP-712 concept | Function |
//! |-----------------|----------|
//! | `encodeType(typeName)` | [`encode_type`] |
//! | `typeHash = keccak256(encodeType(...))` | [`type_hash`] |
//! | `encodeData(struct)` | [`encode_data`] |
//! | `hashStruct(s) = keccak256(typeHash ‖ encodeData(s))` | [`hash_struct`] |
//! | `hashTypedData = keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(m))` | [`hash_typed_data`] |
//!
//! Unlike the v1 scheme the hash function is **keccak256**, matching Ethereum
//! tooling, so an off-chain signer written against `eth_signTypedData` /
//! `viem`'s `hashTypedData` can reproduce a digest computed on Soroban from
//! the same JSON schema and any cross-language consumer can verify it.
//!
//! # Declaring a struct
//!
//! ```rust
//! use soroban_sas_common::{
//!     encode_type, hash_struct, FieldDef, FieldType, FieldValue, StructDef,
//! };
//! use soroban_sdk::{Bytes, Env};
//!
//! // struct Person { string name; address wallet; }
//! static PERSON_FIELDS: [FieldDef; 2] = [
//!     FieldDef { name: "name", ty: FieldType::Str },
//!     FieldDef { name: "wallet", ty: FieldType::Address },
//! ];
//! static PERSON: StructDef = StructDef { name: "Person", fields: &PERSON_FIELDS };
//!
//! // struct Mail { Person from; Person to; string contents; }
//! static MAIL_FIELDS: [FieldDef; 3] = [
//!     FieldDef { name: "from", ty: FieldType::Struct("Person") },
//!     FieldDef { name: "to", ty: FieldType::Struct("Person") },
//!     FieldDef { name: "contents", ty: FieldType::Str },
//! ];
//! static MAIL: StructDef = StructDef { name: "Mail", fields: &MAIL_FIELDS };
//!
//! let env = Env::default();
//! let defs = [MAIL, PERSON];
//!
//! // The canonical EIP-712 type string, dependencies expanded and sorted.
//! assert_eq!(
//!     encode_type(&env, &defs, "Mail"),
//!     Bytes::from_slice(
//!         &env,
//!         b"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
//!     ),
//! );
//!
//! let contents = b"Hello, Bob";
//! let values = [
//!     FieldValue::Struct("Person", &[
//!         FieldValue::Dynamic(b"Alice"),
//!         FieldValue::Word([0x11; 32]),
//!     ]),
//!     FieldValue::Struct("Person", &[
//!         FieldValue::Dynamic(b"Bob"),
//!         FieldValue::Word([0x22; 32]),
//!     ]),
//!     FieldValue::Dynamic(contents),
//! ];
//! let _mail_hash = hash_struct(&env, &defs, "Mail", &values).unwrap();
//! ```
//!
//! # Encoding rules
//!
//! * Atomic types are written as one 32-byte big-endian word. Use
//!   [`FieldValue::from_u64`], [`FieldValue::from_u128`], [`FieldValue::from_i128`],
//!   [`FieldValue::from_bool`], [`FieldValue::from_bytes32`] or
//!   [`FieldValue::from_address`] to build the word; `address` is the 20-byte
//!   value in the *low* 20 bytes, which [`FieldValue::from_address`] does for
//!   you.
//! * `bytes` and `string` are represented by their pre-image
//!   ([`FieldValue::Dynamic`]) and encoded as `keccak256(pre-image)`.
//! * A nested struct is [`FieldValue::Struct`] and encodes as
//!   `hashStruct` of that struct.
//! * A dynamic array is [`FieldValue::List`] and encodes as
//!   `keccak256(concat(encodeData(element)))` over its elements.
//!
//! Every function here either succeeds or returns a [`SchemaError`]; nothing
//! silently drops a field, so a mismatch between a declaration and the values
//! handed to it can never produce a digest that looks valid but commits to
//! something other than what the caller passed.
//!
//! # Relationship to the v1 scheme
//!
//! [`v1`] declares the three existing v1 action schemas in this grammar so
//! their literal type tags can be checked against their real field lists —
//! see [`v1::tag_matches_defs`]. The v1 tags are deliberately *not* EIP-712
//! `encodeType` strings (they carry no field types, are namespaced
//! `SorobanSAS … v1(…)`, and hash with SHA-256), and the digests in
//! [`crate::typed_data`] are unchanged by this module: the v1 golden vectors
//! continue to pass byte for byte.

use soroban_sdk::{Bytes, BytesN, Env};

/// The EIP-712 `\x19\x01` domain-separation prefix.
pub const EIP712_PREFIX: [u8; 2] = [0x19, 0x01];

/// The struct name EIP-712 reserves for the domain separator.
pub const DOMAIN_STRUCT_NAME: &str = "EIP712Domain";

/// Why a declared schema and the values supplied for it do not line up.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaError {
    /// No [`StructDef`] with the requested name is present in the supplied
    /// definition set.
    UnknownStruct,
    /// The value list does not contain exactly one entry per declared field.
    ArityMismatch,
    /// A value's representation does not match its declared field type (for
    /// example a [`FieldValue::Word`] supplied for a `string` field, or a
    /// [`FieldValue::Struct`] whose name is not the declared struct).
    TypeMismatch,
}

/// One field type of the EIP-712 grammar.
///
/// The variants mirror EIP-712's type table; [`FieldType::write_name`] is the
/// single place that knows how each one is spelled in an `encodeType` string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldType {
    /// `uintN` for `N` a multiple of 8 in `8..=256`.
    Uint(u16),
    /// `intN` for `N` a multiple of 8 in `8..=256`.
    Int(u16),
    /// `bool`.
    Bool,
    /// `address`, a 20-byte value in the low 20 bytes of its word.
    Address,
    /// `bytes`, dynamic; its value is the pre-image that gets hashed.
    Bytes,
    /// `bytesN` for `N` in `1..=32`, statically sized.
    FixedBytes(u32),
    /// `string`, dynamic; its value is the UTF-8 pre-image that gets hashed.
    Str,
    /// A reference to another [`StructDef`] by name.
    Struct(&'static str),
    /// A dynamic array of the referenced element type.
    Array(&'static FieldType),
}

impl FieldType {
    /// Appends the canonical EIP-712 name of this type to `out`.
    ///
    /// For example `Uint(256)` writes `uint256`, `FixedBytes(32)` writes
    /// `bytes32`, `Array(&Str)` writes `string[]`, and `Struct("Person")`
    /// writes `Person`.
    pub fn write_name(&self, out: &mut Bytes) {
        match self {
            FieldType::Uint(bits) => {
                out.extend_from_slice(b"uint");
                write_u32(out, u32::from(*bits));
            }
            FieldType::Int(bits) => {
                out.extend_from_slice(b"int");
                write_u32(out, u32::from(*bits));
            }
            FieldType::Bool => out.extend_from_slice(b"bool"),
            FieldType::Address => out.extend_from_slice(b"address"),
            FieldType::Bytes => out.extend_from_slice(b"bytes"),
            FieldType::FixedBytes(size) => {
                out.extend_from_slice(b"bytes");
                write_u32(out, *size);
            }
            FieldType::Str => out.extend_from_slice(b"string"),
            FieldType::Struct(name) => out.extend_from_slice(name.as_bytes()),
            FieldType::Array(element) => {
                element.write_name(out);
                out.extend_from_slice(b"[]");
            }
        }
    }

    /// Whether EIP-712 hashes this type's pre-image instead of inlining it.
    ///
    /// True for `bytes`, `string` and arrays. A struct reference is not
    /// "dynamic" in the EIP-712 sense: it is encoded as the 32-byte
    /// `hashStruct` of that struct, which [`encode_field`] handles.
    pub fn is_dynamic(&self) -> bool {
        matches!(
            self,
            FieldType::Bytes | FieldType::Str | FieldType::Array(_)
        )
    }

    /// The struct name this type ultimately refers to, following array
    /// nesting; `None` for every atomic and dynamic type.
    pub fn referenced_struct(&self) -> Option<&'static str> {
        match self {
            FieldType::Struct(name) => Some(name),
            FieldType::Array(element) => element.referenced_struct(),
            _ => None,
        }
    }
}

/// One declared field: its name and its EIP-712 type, in declaration order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldDef {
    /// Field name as it appears in the `encodeType` string.
    pub name: &'static str,
    /// Field type.
    pub ty: FieldType,
}

/// A declared struct: its name and its fields in declaration order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructDef {
    /// Struct name as it appears in `encodeType`.
    pub name: &'static str,
    /// Fields in declaration order; the order is part of the type.
    pub fields: &'static [FieldDef],
}

/// One field's value, in the representation its [`FieldType`] calls for.
#[derive(Clone, Copy, Debug)]
pub enum FieldValue<'a> {
    /// An atomic value already widened to its 32-byte EIP-712 word.
    Word([u8; 32]),
    /// The pre-image of a `bytes` or `string` value; encoded as its keccak256.
    Dynamic(&'a [u8]),
    /// A nested struct: its declared name and its field values in declaration
    /// order. Encoded as `hashStruct` of that struct.
    Struct(&'static str, &'a [FieldValue<'a>]),
    /// A dynamic array: its declared element type and its elements in order.
    /// Encoded as `keccak256(concat(encodeData(element)))`.
    List(&'static FieldType, &'a [FieldValue<'a>]),
}

impl<'a> FieldValue<'a> {
    /// A `bool` as a word: `0` or `1`.
    pub fn from_bool(value: bool) -> Self {
        let mut word = [0u8; 32];
        word[31] = u8::from(value);
        Self::Word(word)
    }

    /// A `uintN` value as a big-endian word, zero-extended to 32 bytes.
    pub fn from_u64(value: u64) -> Self {
        let mut word = [0u8; 32];
        word[24..32].copy_from_slice(&value.to_be_bytes());
        Self::Word(word)
    }

    /// A `uintN` value as a big-endian word, zero-extended to 32 bytes.
    pub fn from_u128(value: u128) -> Self {
        let mut word = [0u8; 32];
        word[16..32].copy_from_slice(&value.to_be_bytes());
        Self::Word(word)
    }

    /// An `intN` value as a big-endian word, sign-extended to 32 bytes so the
    /// two's-complement representation matches Ethereum's.
    pub fn from_i128(value: i128) -> Self {
        let mut word = if value < 0 { [0xffu8; 32] } else { [0u8; 32] };
        word[16..32].copy_from_slice(&value.to_be_bytes());
        Self::Word(word)
    }

    /// A `bytes32` value as its word.
    pub fn from_bytes32(value: &BytesN<32>) -> Self {
        Self::Word(value.to_array())
    }

    /// An `address` value: `bytes` is the 20-byte address and occupies the
    /// **low** 20 bytes of the word, as EIP-712 requires.
    ///
    /// Returns `None` when `bytes` is longer than 32 bytes. (20 bytes is the
    /// EIP-712 `address` size; longer inputs are accepted so a chain that
    /// uses a wider account id can declare a `bytesN`-style address instead.)
    pub fn from_address(bytes: &[u8]) -> Option<Self> {
        Self::from_right_aligned(bytes)
    }

    /// Any value of at most 32 bytes, right-aligned into a word (so it lands
    /// in the low-order bytes). `None` when `bytes` is longer than 32 bytes.
    pub fn from_right_aligned(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > 32 {
            return None;
        }
        let mut word = [0u8; 32];
        word[32 - bytes.len()..].copy_from_slice(bytes);
        Some(Self::Word(word))
    }
}

/// Finds a declared struct by name.
pub fn find_struct<'a>(defs: &'a [StructDef], name: &str) -> Option<&'a StructDef> {
    defs.iter().find(|def| def.name == name)
}

/// Builds the EIP-712 `encodeType` string for `primary`, as UTF-8 bytes.
///
/// The primary struct is written first, followed by every struct reachable
/// from it through field references — transitively — in ascending
/// alphabetical order and without duplicates, which is exactly what EIP-712
/// prescribes. Reachability is depth-bounded by `defs.len()`, so definitions
/// that reference each other in a cycle still terminate instead of recursing
/// forever (EIP-712 forbids recursive structs; this reports the reachable set
/// rather than trapping).
///
/// An unknown `primary` produces an empty byte string; [`type_hash`] reports
/// that case as [`SchemaError::UnknownStruct`].
pub fn encode_type(env: &Env, defs: &[StructDef], primary: &str) -> Bytes {
    let mut out = Bytes::new(env);
    let Some(primary_def) = find_struct(defs, primary) else {
        return out;
    };
    write_struct_type(&mut out, primary_def);

    let budget = defs.len() + 1;
    let mut last: Option<&'static str> = None;
    loop {
        let mut next: Option<&'static str> = None;
        for def in defs.iter() {
            if def.name == primary || !references(defs, primary, def.name, budget) {
                continue;
            }
            if let Some(previous) = last {
                if def.name <= previous {
                    continue;
                }
            }
            next = match next {
                Some(current) if current <= def.name => Some(current),
                _ => Some(def.name),
            };
        }
        let Some(name) = next else { break };
        if let Some(def) = find_struct(defs, name) {
            write_struct_type(&mut out, def);
        }
        last = Some(name);
    }

    out
}

/// `typeHash = keccak256(encodeType(primary))`.
///
/// # Errors
/// [`SchemaError::UnknownStruct`] when `primary` is not in `defs`.
pub fn type_hash(env: &Env, defs: &[StructDef], primary: &str) -> Result<BytesN<32>, SchemaError> {
    if find_struct(defs, primary).is_none() {
        return Err(SchemaError::UnknownStruct);
    }
    Ok(keccak(env, &encode_type(env, defs, primary)))
}

/// `encodeData(struct)`: the concatenation of each field's 32-byte encoding,
/// in declaration order.
///
/// # Errors
/// [`SchemaError::UnknownStruct`] when `struct_name` is unknown,
/// [`SchemaError::ArityMismatch`] when `values` is not exactly one entry per
/// declared field, or [`SchemaError::TypeMismatch`] when a value does not
/// match its declared type.
pub fn encode_data(
    env: &Env,
    defs: &[StructDef],
    struct_name: &str,
    values: &[FieldValue],
) -> Result<Bytes, SchemaError> {
    let Some(def) = find_struct(defs, struct_name) else {
        return Err(SchemaError::UnknownStruct);
    };
    if def.fields.len() != values.len() {
        return Err(SchemaError::ArityMismatch);
    }

    let mut out = Bytes::new(env);
    for (field, value) in def.fields.iter().zip(values.iter()) {
        out.append(&encode_field(env, defs, field, value)?);
    }
    Ok(out)
}

/// `hashStruct(s) = keccak256(typeHash(s) ‖ encodeData(s))`.
///
/// # Errors
/// The same cases as [`encode_data`], plus [`SchemaError::UnknownStruct`]
/// when `struct_name` has no definition.
pub fn hash_struct(
    env: &Env,
    defs: &[StructDef],
    struct_name: &str,
    values: &[FieldValue],
) -> Result<BytesN<32>, SchemaError> {
    let encoded = encode_data(env, defs, struct_name, values)?;
    let mut buffer = Bytes::new(env);
    buffer.extend_from_slice(&type_hash(env, defs, struct_name)?.to_array());
    buffer.append(&encoded);
    Ok(keccak(env, &buffer))
}

/// The standard EIP-712 digest:
/// `keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(primary))`.
///
/// `domain_separator` is the [`hash_struct`] of a struct named
/// [`DOMAIN_STRUCT_NAME`] (`EIP712Domain`).
///
/// # Errors
/// The same cases as [`hash_struct`].
pub fn hash_typed_data(
    env: &Env,
    defs: &[StructDef],
    primary: &str,
    values: &[FieldValue],
    domain_separator: &BytesN<32>,
) -> Result<BytesN<32>, SchemaError> {
    hash_typed_data_with_prefix(env, &EIP712_PREFIX, defs, primary, values, domain_separator)
}

/// [`hash_typed_data`] with a caller-chosen domain-separation prefix.
///
/// EIP-712 fixes the prefix at `0x1901`; the override exists so an
/// application that already has its own signed-message namespace (for example
/// [`crate::typed_data::PAYLOAD_PREFIX`]) can keep that separation while
/// still using the generic type/struct hashing above.
///
/// # Errors
/// The same cases as [`hash_struct`].
pub fn hash_typed_data_with_prefix(
    env: &Env,
    prefix: &[u8],
    defs: &[StructDef],
    primary: &str,
    values: &[FieldValue],
    domain_separator: &BytesN<32>,
) -> Result<BytesN<32>, SchemaError> {
    let struct_hash = hash_struct(env, defs, primary, values)?;
    let mut buffer = Bytes::new(env);
    buffer.extend_from_slice(prefix);
    buffer.extend_from_slice(&domain_separator.to_array());
    buffer.extend_from_slice(&struct_hash.to_array());
    Ok(keccak(env, &buffer))
}

/// Checks that the comma-separated field list inside a hand-written type tag
/// is exactly `def`'s field list, in order.
///
/// The tag must contain one parenthesised group (`…(a,b,c)`); anything else,
/// or any name that is missing, extra, reordered or renamed, returns `false`.
/// This is the drift guard for tags like
/// [`crate::typed_data::ATTESTATION_TYPE_TAG`], which are literals embedded in
/// a hash pre-image: nothing else would notice if a field were added to the
/// struct but not to the tag, or vice versa.
pub fn tag_matches_defs(tag: &[u8], def: &StructDef) -> bool {
    let Some(open) = tag.iter().position(|byte| *byte == b'(') else {
        return false;
    };
    let Some(close) = tag.iter().rposition(|byte| *byte == b')') else {
        return false;
    };
    if close <= open {
        return false;
    }

    let mut index = 0usize;
    for name in tag[open + 1..close].split(|byte| *byte == b',') {
        if index >= def.fields.len() || name != def.fields[index].name.as_bytes() {
            return false;
        }
        index += 1;
    }
    index == def.fields.len()
}

/// The v1 off-chain signing schemas declared in the EIP-712 type grammar.
///
/// These declarations describe the layouts that
/// [`crate::typed_data::hash_attestation_struct`],
/// [`crate::typed_data::hash_domain`] and
/// [`crate::typed_data::hash_delegated_revocation`] actually encode, so
/// [`tag_matches_defs`] can prove the literal type tags still describe the
/// fields they are mixed into a hash with.
///
/// The declared types reflect the v1 encoding rather than a new one:
/// `uid`/`schema_uid`/`ref_uid`/`network_id` are 32 raw bytes
/// ([`FieldType::FixedBytes`]), `time`/`expiration_time`/`nonce` are `uint64`,
/// `revocable` is `bool`, and the addresses and `data` are appended as their
/// XDR/`sha256` pre-images ([`FieldType::Bytes`]).
pub mod v1 {
    use super::{FieldDef, FieldType, StructDef};
    use crate::typed_data::{ATTESTATION_TYPE_TAG, DELEGATED_REVOCATION_TYPE_TAG, DOMAIN_TYPE_TAG};

    /// Fields of the v1 domain separator, in hash order.
    pub const DOMAIN_FIELDS: [FieldDef; 3] = [
        FieldDef {
            name: "network_id",
            ty: FieldType::FixedBytes(32),
        },
        FieldDef {
            name: "contract",
            ty: FieldType::Bytes,
        },
        FieldDef {
            name: "nonce",
            ty: FieldType::Uint(64),
        },
    ];

    /// The v1 domain separator schema.
    pub const DOMAIN: StructDef = StructDef {
        name: "Domain",
        fields: &DOMAIN_FIELDS,
    };

    /// Fields of the v1 attestation struct hash, in hash order.
    pub const ATTESTATION_FIELDS: [FieldDef; 9] = [
        FieldDef {
            name: "uid",
            ty: FieldType::FixedBytes(32),
        },
        FieldDef {
            name: "schema_uid",
            ty: FieldType::FixedBytes(32),
        },
        FieldDef {
            name: "time",
            ty: FieldType::Uint(64),
        },
        FieldDef {
            name: "expiration_time",
            ty: FieldType::Uint(64),
        },
        FieldDef {
            name: "ref_uid",
            ty: FieldType::FixedBytes(32),
        },
        FieldDef {
            name: "recipient",
            ty: FieldType::Bytes,
        },
        FieldDef {
            name: "attester",
            ty: FieldType::Bytes,
        },
        FieldDef {
            name: "revocable",
            ty: FieldType::Bool,
        },
        FieldDef {
            name: "data",
            ty: FieldType::Bytes,
        },
    ];

    /// The v1 attestation schema. `revocation_time` is intentionally absent:
    /// it is excluded from the v1 digest by design.
    pub const ATTESTATION: StructDef = StructDef {
        name: "Attestation",
        fields: &ATTESTATION_FIELDS,
    };

    /// Fields of the v1 delegated-revocation struct hash, in hash order.
    pub const DELEGATED_REVOCATION_FIELDS: [FieldDef; 2] = [
        FieldDef {
            name: "uid",
            ty: FieldType::FixedBytes(32),
        },
        FieldDef {
            name: "attester",
            ty: FieldType::Bytes,
        },
    ];

    /// The v1 delegated-revocation schema.
    pub const DELEGATED_REVOCATION: StructDef = StructDef {
        name: "DelegatedRevocation",
        fields: &DELEGATED_REVOCATION_FIELDS,
    };

    /// Every v1 schema paired with the literal type tag it must describe.
    pub const TAGS: [(&[u8], &StructDef); 3] = [
        (DOMAIN_TYPE_TAG, &DOMAIN),
        (ATTESTATION_TYPE_TAG, &ATTESTATION),
        (DELEGATED_REVOCATION_TYPE_TAG, &DELEGATED_REVOCATION),
    ];

    /// True when all three v1 type tags list exactly the fields their
    /// declaration names, in order.
    pub fn tag_matches_defs() -> bool {
        TAGS.iter()
            .all(|(tag, def)| super::tag_matches_defs(tag, def))
    }
}

/// Appends `value` as decimal ASCII. `value` is at most `u32::MAX`, so at
/// most ten digits are needed.
fn write_u32(out: &mut Bytes, mut value: u32) {
    if value == 0 {
        out.push_back(b'0');
        return;
    }

    let mut digits = [0u8; 10];
    let mut length = 0usize;
    while value > 0 {
        digits[length] = b'0' + (value % 10) as u8;
        value /= 10;
        length += 1;
    }
    while length > 0 {
        length -= 1;
        out.push_back(digits[length]);
    }
}

/// Appends `Name(type1 field1,type2 field2,…)` for one struct.
fn write_struct_type(out: &mut Bytes, def: &StructDef) {
    out.extend_from_slice(def.name.as_bytes());
    out.push_back(b'(');
    let mut first = true;
    for field in def.fields.iter() {
        if !first {
            out.push_back(b',');
        }
        first = false;
        field.ty.write_name(out);
        out.push_back(b' ');
        out.extend_from_slice(field.name.as_bytes());
    }
    out.push_back(b')');
}

/// Whether `target` is reachable from `from` through struct references.
///
/// `budget` bounds the recursion so a cyclic set of definitions terminates.
fn references(defs: &[StructDef], from: &str, target: &str, budget: usize) -> bool {
    if budget == 0 {
        return false;
    }
    let Some(def) = find_struct(defs, from) else {
        return false;
    };
    for field in def.fields.iter() {
        if let Some(name) = field.ty.referenced_struct() {
            if name == target || references(defs, name, target, budget - 1) {
                return true;
            }
        }
    }
    false
}

/// Encodes one field according to its declared type.
fn encode_field(
    env: &Env,
    defs: &[StructDef],
    field: &FieldDef,
    value: &FieldValue,
) -> Result<Bytes, SchemaError> {
    let mut out = Bytes::new(env);
    match value {
        FieldValue::Word(word) => {
            if field.ty.referenced_struct().is_some() || field.ty.is_dynamic() {
                return Err(SchemaError::TypeMismatch);
            }
            out.extend_from_slice(word);
        }
        FieldValue::Dynamic(preimage) => {
            if !matches!(field.ty, FieldType::Bytes | FieldType::Str) {
                return Err(SchemaError::TypeMismatch);
            }
            out.extend_from_slice(&keccak_slice(env, preimage).to_array());
        }
        FieldValue::Struct(name, values) => {
            let FieldType::Struct(declared) = field.ty else {
                return Err(SchemaError::TypeMismatch);
            };
            if declared != *name {
                return Err(SchemaError::TypeMismatch);
            }
            out.extend_from_slice(&hash_struct(env, defs, name, values)?.to_array());
        }
        FieldValue::List(element, values) => {
            let FieldType::Array(declared) = field.ty else {
                return Err(SchemaError::TypeMismatch);
            };
            if declared != *element {
                return Err(SchemaError::TypeMismatch);
            }
            out.extend_from_slice(&encode_list(env, defs, element, values)?.to_array());
        }
    }
    Ok(out)
}

/// `keccak256(concat(encodeData(element)))` for a dynamic array.
fn encode_list(
    env: &Env,
    defs: &[StructDef],
    element: &FieldType,
    values: &[FieldValue],
) -> Result<BytesN<32>, SchemaError> {
    let field = FieldDef {
        name: "",
        ty: *element,
    };
    let mut buffer = Bytes::new(env);
    for value in values.iter() {
        buffer.append(&encode_field(env, defs, &field, value)?);
    }
    Ok(keccak(env, &buffer))
}

/// keccak256 of an assembled buffer.
fn keccak(env: &Env, preimage: &Bytes) -> BytesN<32> {
    env.crypto().keccak256(preimage).to_bytes()
}

/// keccak256 of a byte slice.
fn keccak_slice(env: &Env, preimage: &[u8]) -> BytesN<32> {
    keccak(env, &Bytes::from_slice(env, preimage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Bytes;

    // ---- The EIP-712 specification's own example -------------------------

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

    const DOMAIN_FIELDS: [FieldDef; 4] = [
        FieldDef {
            name: "name",
            ty: FieldType::Str,
        },
        FieldDef {
            name: "version",
            ty: FieldType::Str,
        },
        FieldDef {
            name: "chainId",
            ty: FieldType::Uint(256),
        },
        FieldDef {
            name: "verifyingContract",
            ty: FieldType::Address,
        },
    ];
    const MAIL_DOMAIN: StructDef = StructDef {
        name: DOMAIN_STRUCT_NAME,
        fields: &DOMAIN_FIELDS,
    };

    /// `MAIL_DOMAIN` is the standard EIP-712 domain; keep it separate from
    /// `MAIL`/`PERSON` so `encode_type("Mail")` resolves exactly like the
    /// specification's example (Person is the only dependency).
    const MAIL_DEFS: [StructDef; 2] = [MAIL, PERSON];

    /// Values of the two `Person` structs inside the `Mail` example, shared so
    /// the nested-struct test can re-encode a child both ways.
    const MAIL_FROM: [FieldValue<'static>; 2] =
        [FieldValue::Dynamic(b"Alice"), FieldValue::Word([0x11; 32])];
    const MAIL_TO: [FieldValue<'static>; 2] =
        [FieldValue::Dynamic(b"Bob"), FieldValue::Word([0x22; 32])];

    fn mail_values() -> [FieldValue<'static>; 3] {
        [
            FieldValue::Struct("Person", &MAIL_FROM),
            FieldValue::Struct("Person", &MAIL_TO),
            FieldValue::Dynamic(b"Hello, Bob"),
        ]
    }

    #[test]
    fn encode_type_matches_the_eip712_specification_example() {
        let env = Env::default();
        assert_eq!(
            encode_type(&env, &MAIL_DEFS, "Mail"),
            Bytes::from_slice(
                &env,
                b"Mail(Person from,Person to,string contents)Person(string name,address wallet)",
            ),
        );
        assert_eq!(
            encode_type(&env, &[MAIL_DOMAIN], DOMAIN_STRUCT_NAME),
            Bytes::from_slice(
                &env,
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            ),
        );
    }

    #[test]
    fn encode_type_orders_dependencies_alphabetically_without_duplicates() {
        let env = Env::default();

        const WALLET_FIELDS: [FieldDef; 1] = [FieldDef {
            name: "owner",
            ty: FieldType::Address,
        }];
        const WALLET: StructDef = StructDef {
            name: "Wallet",
            fields: &WALLET_FIELDS,
        };
        const GROUP_FIELDS: [FieldDef; 1] = [FieldDef {
            name: "members",
            ty: FieldType::Array(&FieldType::Struct("Person")),
        }];
        const GROUP: StructDef = StructDef {
            name: "Group",
            fields: &GROUP_FIELDS,
        };
        const ORDER_FIELDS: [FieldDef; 4] = [
            FieldDef {
                name: "buyer",
                ty: FieldType::Struct("Person"),
            },
            FieldDef {
                name: "seller",
                ty: FieldType::Struct("Person"),
            },
            FieldDef {
                name: "group",
                ty: FieldType::Struct("Group"),
            },
            FieldDef {
                name: "wallet",
                ty: FieldType::Struct("Wallet"),
            },
        ];
        const ORDER: StructDef = StructDef {
            name: "Order",
            fields: &ORDER_FIELDS,
        };

        // Deliberately declared out of order: the encoder must sort.
        let defs = [ORDER, WALLET, PERSON, GROUP];
        assert_eq!(
            encode_type(&env, &defs, "Order"),
            Bytes::from_slice(
                &env,
                b"Order(Person buyer,Person seller,Group group,Wallet wallet)\
Group(Person[] members)Person(string name,address wallet)Wallet(address owner)",
            ),
            "dependencies must be transitive, alphabetical, and listed once",
        );
    }

    #[test]
    fn encode_type_is_empty_and_type_hash_errors_for_an_unknown_struct() {
        let env = Env::default();
        assert_eq!(encode_type(&env, &MAIL_DEFS, "Receipt"), Bytes::new(&env));
        assert_eq!(
            type_hash(&env, &MAIL_DEFS, "Receipt").unwrap_err(),
            SchemaError::UnknownStruct,
        );
        assert!(type_hash(&env, &MAIL_DEFS, "Mail").is_ok());
    }

    #[test]
    fn encode_type_terminates_for_cyclic_definitions() {
        let env = Env::default();

        const PING_FIELDS: [FieldDef; 2] = [
            FieldDef {
                name: "value",
                ty: FieldType::Uint(64),
            },
            FieldDef {
                name: "pong",
                ty: FieldType::Struct("Pong"),
            },
        ];
        const PING: StructDef = StructDef {
            name: "Ping",
            fields: &PING_FIELDS,
        };
        const PONG_FIELDS: [FieldDef; 1] = [FieldDef {
            name: "ping",
            ty: FieldType::Struct("Ping"),
        }];
        const PONG: StructDef = StructDef {
            name: "Pong",
            fields: &PONG_FIELDS,
        };

        // A recursive pair would loop forever with an unbounded walk; the
        // reachability budget makes this a bounded, repeatable answer.
        assert_eq!(
            encode_type(&env, &[PING, PONG], "Ping"),
            Bytes::from_slice(&env, b"Ping(uint64 value,Pong pong)Pong(Ping ping)"),
        );
        assert_ne!(
            encode_type(&env, &[PING, PONG], "Ping"),
            Bytes::new(&env),
            "a cyclic definition must still produce a type string"
        );
    }

    // ---- Atomic word construction ---------------------------------------

    #[test]
    fn integer_and_bool_words_are_big_endian() {
        let one = FieldValue::from_u64(1);
        let expected_one = {
            let mut word = [0u8; 32];
            word[31] = 1;
            word
        };
        assert_eq!(max_word(&[one]), expected_one);

        // u64::MAX fills the low eight bytes.
        let max = FieldValue::from_u64(u64::MAX);
        assert_eq!(
            max_word(&[max]),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255,
                255, 255, 255, 255, 255, 255,
            ]
        );

        let low_u128 = FieldValue::from_u128(0xf0);
        assert_eq!(max_word(&[low_u128])[31], 0xf0);
        assert_eq!(max_word(&[low_u128])[16], 0x00);

        assert_eq!(
            max_word(&[FieldValue::from_bool(true)])[31],
            1,
            "true must encode as one"
        );
        assert_eq!(max_word(&[FieldValue::from_bool(false)]), [0u8; 32]);
    }

    #[test]
    fn signed_words_are_sign_extended() {
        let negative = FieldValue::from_i128(-1);
        assert_eq!(max_word(&[negative]), [0xffu8; 32]);

        let minus_two = max_word(&[FieldValue::from_i128(-2)]);
        assert_eq!(minus_two[16..31], [0xffu8; 15]);
        assert_eq!(minus_two[31], 0xfe);
        assert_eq!(minus_two[15], 0xff, "sign extension reaches the top word");

        let plus_two = max_word(&[FieldValue::from_i128(2)]);
        assert_eq!(plus_two[31], 2);
        assert_eq!(plus_two[0], 0);
    }

    #[test]
    fn addresses_are_right_aligned_into_their_word() {
        let twenty = [0xab_u8; 20];
        let value = FieldValue::from_address(&twenty).expect("20 bytes fits a word");
        let word = max_word(&[value]);
        assert_eq!(word[0..12], [0u8; 12], "the high 12 bytes stay zero");
        assert_eq!(word[12..32], twenty);

        assert!(
            FieldValue::from_address(&[0u8; 33]).is_none(),
            "longer than a word must be rejected rather than truncated"
        );
        assert_eq!(
            max_word(&[FieldValue::from_right_aligned(&[]).unwrap()]),
            [0u8; 32]
        );
    }

    #[test]
    fn bytes32_values_pass_through_unchanged() {
        let env = Env::default();
        let raw = [0x5au8; 32];
        let value = FieldValue::from_bytes32(&BytesN::from_array(&env, &raw));
        assert_eq!(max_word(&[value]), raw);
    }

    // ---- encodeData -----------------------------------------------------

    #[test]
    fn dynamic_fields_encode_as_the_keccak_of_their_pre_image() {
        let env = Env::default();

        const NOTE_FIELDS: [FieldDef; 2] = [
            FieldDef {
                name: "text",
                ty: FieldType::Str,
            },
            FieldDef {
                name: "blob",
                ty: FieldType::Bytes,
            },
        ];
        const NOTE: StructDef = StructDef {
            name: "Note",
            fields: &NOTE_FIELDS,
        };

        let text = b"hello";
        let blob = b"\x00\x01\x02";
        let encoded = encode_data(
            &env,
            &[NOTE],
            "Note",
            &[FieldValue::Dynamic(text), FieldValue::Dynamic(blob)],
        )
        .expect("well-formed values");

        let mut expected = Bytes::new(&env);
        expected.extend_from_slice(&keccak_slice(&env, text).to_array());
        expected.extend_from_slice(&keccak_slice(&env, blob).to_array());
        assert_eq!(encoded, expected);

        // A dynamic pre-image must not be inlined raw.
        let mut raw = Bytes::new(&env);
        raw.extend_from_slice(text);
        raw.extend_from_slice(blob);
        assert_ne!(encoded, raw);
    }

    #[test]
    fn arrays_encode_as_the_keccak_of_their_concatenated_elements() {
        let env = Env::default();

        const VECTOR_FIELDS: [FieldDef; 1] = [FieldDef {
            name: "numbers",
            ty: FieldType::Array(&FieldType::Uint(64)),
        }];
        const VECTOR: StructDef = StructDef {
            name: "Vector",
            fields: &VECTOR_FIELDS,
        };

        let elements = [FieldValue::from_u64(1), FieldValue::from_u64(2)];
        let encoded = encode_data(
            &env,
            &[VECTOR],
            "Vector",
            &[FieldValue::List(&FieldType::Uint(64), &elements)],
        )
        .expect("well-formed values");

        let mut inner = Bytes::new(&env);
        inner.extend_from_slice(&max_word(&[FieldValue::from_u64(1)]));
        inner.extend_from_slice(&max_word(&[FieldValue::from_u64(2)]));
        let mut expected = Bytes::new(&env);
        expected.extend_from_slice(&keccak(&env, &inner).to_array());
        assert_eq!(encoded, expected);

        // An empty array still hashes (the empty pre-image), rather than
        // vanishing from the encoding.
        let empty = encode_data(
            &env,
            &[VECTOR],
            "Vector",
            &[FieldValue::List(&FieldType::Uint(64), &[])],
        )
        .expect("empty arrays are legal");
        assert_eq!(empty, expected_empty_array(&env));
    }

    #[test]
    fn nested_structs_encode_as_their_struct_hash() {
        let env = Env::default();

        let values = mail_values();
        let encoded = encode_data(&env, &MAIL_DEFS, "Mail", &values).expect("well-formed mail");

        let mut expected = Bytes::new(&env);
        expected.extend_from_slice(
            &hash_struct(&env, &MAIL_DEFS, "Person", &MAIL_FROM)
                .expect("well-formed Person")
                .to_array(),
        );
        expected.extend_from_slice(
            &hash_struct(&env, &MAIL_DEFS, "Person", &MAIL_TO)
                .expect("well-formed Person")
                .to_array(),
        );
        expected.extend_from_slice(&keccak_slice(&env, b"Hello, Bob").to_array());
        assert_eq!(encoded, expected);
    }

    #[test]
    fn hash_struct_is_the_keccak_of_type_hash_then_encode_data() {
        let env = Env::default();
        let values = mail_values();

        let struct_hash = hash_struct(&env, &MAIL_DEFS, "Mail", &values).expect("well-formed mail");

        let mut buffer = Bytes::new(&env);
        buffer.extend_from_slice(&type_hash(&env, &MAIL_DEFS, "Mail").unwrap().to_array());
        buffer.append(&encode_data(&env, &MAIL_DEFS, "Mail", &values).unwrap());
        assert_eq!(struct_hash, keccak(&env, &buffer));

        // Field order is part of the type: reordering the declaration changes
        // `typeHash`, so the same values under a different field order must
        // not produce the same digest.
        const REORDERED_FIELDS: [FieldDef; 3] = [MAIL_FIELDS[2], MAIL_FIELDS[0], MAIL_FIELDS[1]];
        const REORDERED: StructDef = StructDef {
            name: "Mail",
            fields: &REORDERED_FIELDS,
        };
        let reordered_values = [values[2], values[0], values[1]];
        let reordered = hash_struct(&env, &[REORDERED, PERSON], "Mail", &reordered_values)
            .expect("the reordered values match the reordered declaration");
        assert_eq!(
            encode_type(&env, &[REORDERED, PERSON], "Mail"),
            Bytes::from_slice(
                &env,
                b"Mail(string contents,Person from,Person to)Person(string name,address wallet)",
            )
        );
        assert_ne!(reordered, struct_hash);
    }

    // ---- hashTypedData --------------------------------------------------

    #[test]
    fn hash_typed_data_uses_the_eip712_prefix_and_domain_separator() {
        let env = Env::default();
        let values = mail_values();

        let domain_values = [
            FieldValue::Dynamic(b"Ether Mail"),
            FieldValue::Dynamic(b"1"),
            FieldValue::from_u128(1),
            FieldValue::Word([0x11; 32]),
        ];
        let separator =
            hash_struct(&env, &[MAIL_DOMAIN], DOMAIN_STRUCT_NAME, &domain_values).unwrap();

        let digest =
            hash_typed_data(&env, &MAIL_DEFS, "Mail", &values, &separator).expect("well-formed");

        let mut manual = Bytes::new(&env);
        manual.extend_from_slice(&EIP712_PREFIX);
        manual.extend_from_slice(&separator.to_array());
        manual.extend_from_slice(
            &hash_struct(&env, &MAIL_DEFS, "Mail", &values)
                .unwrap()
                .to_array(),
        );
        assert_eq!(digest, keccak(&env, &manual));

        // A different domain separator must change the digest: the domain is
        // what binds a signature to one chain/verifying contract.
        let other_separator = BytesN::from_array(&env, &[0x99; 32]);
        let other = hash_typed_data(&env, &MAIL_DEFS, "Mail", &values, &other_separator).unwrap();
        assert_ne!(other, digest);

        // The custom prefix keeps an application namespace while reusing the
        // same struct hashing.
        let prefixed = hash_typed_data_with_prefix(
            &env,
            b"\x19SorobanSAS\x01",
            &MAIL_DEFS,
            "Mail",
            &values,
            &separator,
        )
        .unwrap();
        assert_ne!(prefixed, digest);
    }

    // ---- Failure modes --------------------------------------------------

    #[test]
    fn mismatched_values_are_rejected_instead_of_encoded() {
        let env = Env::default();
        let values = mail_values();

        assert_eq!(
            encode_data(&env, &MAIL_DEFS, "Receipt", &values).unwrap_err(),
            SchemaError::UnknownStruct,
        );

        // Too few, and too many, values.
        assert_eq!(
            encode_data(&env, &MAIL_DEFS, "Mail", &values[0..2]).unwrap_err(),
            SchemaError::ArityMismatch,
        );
        let mut extra = [FieldValue::Word([0u8; 32]); 4];
        extra[0] = values[0];
        extra[1] = values[1];
        extra[2] = values[2];
        assert_eq!(
            encode_data(&env, &MAIL_DEFS, "Mail", &extra).unwrap_err(),
            SchemaError::ArityMismatch,
        );

        // A word where a `string` is declared.
        assert_eq!(
            encode_data(
                &env,
                &[PERSON],
                "Person",
                &[FieldValue::Dynamic(b"Alice"), FieldValue::Word([0; 32])],
            )
            .map(|_| ()),
            Ok(()),
            "a well-formed Person must still encode",
        );
        assert_eq!(
            encode_data(
                &env,
                &[PERSON],
                "Person",
                &[FieldValue::Word([0; 32]), FieldValue::Word([0; 32])],
            )
            .unwrap_err(),
            SchemaError::TypeMismatch,
            "a word may not stand in for a string",
        );

        // A dynamic pre-image where an atomic type is declared.
        assert_eq!(
            encode_data(
                &env,
                &[PERSON],
                "Person",
                &[
                    FieldValue::Dynamic(b"Alice"),
                    FieldValue::Dynamic(b"wallet")
                ],
            )
            .unwrap_err(),
            SchemaError::TypeMismatch,
        );

        // The wrong nested struct name.
        assert_eq!(
            encode_data(
                &env,
                &MAIL_DEFS,
                "Mail",
                &[FieldValue::Struct("Wallet", &[]), values[1], values[2],],
            )
            .unwrap_err(),
            SchemaError::TypeMismatch,
        );

        // The wrong array element type.
        const VECTOR_FIELDS: [FieldDef; 1] = [FieldDef {
            name: "numbers",
            ty: FieldType::Array(&FieldType::Uint(64)),
        }];
        const VECTOR: StructDef = StructDef {
            name: "Vector",
            fields: &VECTOR_FIELDS,
        };
        assert_eq!(
            encode_data(
                &env,
                &[VECTOR],
                "Vector",
                &[FieldValue::List(&FieldType::Bool, &[])],
            )
            .unwrap_err(),
            SchemaError::TypeMismatch,
        );
    }

    // ---- v1 drift guard -------------------------------------------------

    #[test]
    fn v1_literal_tags_describe_their_declared_fields() {
        assert!(
            v1::tag_matches_defs(),
            "a v1 type tag no longer lists the fields of its declaration"
        );
        assert!(tag_matches_defs(
            crate::typed_data::ATTESTATION_TYPE_TAG,
            &v1::ATTESTATION
        ));
        assert!(tag_matches_defs(
            crate::typed_data::DOMAIN_TYPE_TAG,
            &v1::DOMAIN
        ));
        assert!(tag_matches_defs(
            crate::typed_data::DELEGATED_REVOCATION_TYPE_TAG,
            &v1::DELEGATED_REVOCATION
        ));

        // Renaming, reordering, dropping or adding a field must all fail.
        const RENAMED: [FieldDef; 2] = [
            FieldDef {
                name: "id",
                ty: FieldType::FixedBytes(32),
            },
            FieldDef {
                name: "attester",
                ty: FieldType::Bytes,
            },
        ];
        const RENAMED_DEF: StructDef = StructDef {
            name: "DelegatedRevocation",
            fields: &RENAMED,
        };
        const REORDERED: [FieldDef; 2] = [
            FieldDef {
                name: "attester",
                ty: FieldType::Bytes,
            },
            FieldDef {
                name: "uid",
                ty: FieldType::FixedBytes(32),
            },
        ];
        const REORDERED_DEF: StructDef = StructDef {
            name: "DelegatedRevocation",
            fields: &REORDERED,
        };
        const DROPPED: [FieldDef; 1] = [FieldDef {
            name: "uid",
            ty: FieldType::FixedBytes(32),
        }];
        const DROPPED_DEF: StructDef = StructDef {
            name: "DelegatedRevocation",
            fields: &DROPPED,
        };
        const ADDED: [FieldDef; 3] = [
            FieldDef {
                name: "uid",
                ty: FieldType::FixedBytes(32),
            },
            FieldDef {
                name: "attester",
                ty: FieldType::Bytes,
            },
            FieldDef {
                name: "nonce",
                ty: FieldType::Uint(64),
            },
        ];
        const ADDED_DEF: StructDef = StructDef {
            name: "DelegatedRevocation",
            fields: &ADDED,
        };

        let tag = crate::typed_data::DELEGATED_REVOCATION_TYPE_TAG;
        assert!(!tag_matches_defs(tag, &RENAMED_DEF));
        assert!(!tag_matches_defs(tag, &REORDERED_DEF));
        assert!(!tag_matches_defs(tag, &DROPPED_DEF));
        assert!(!tag_matches_defs(tag, &ADDED_DEF));

        // Malformed tags fail closed.
        assert!(!tag_matches_defs(b"no parens", &v1::DELEGATED_REVOCATION));
        assert!(!tag_matches_defs(b"empty()", &v1::DELEGATED_REVOCATION));
        assert!(!tag_matches_defs(b")(", &v1::DELEGATED_REVOCATION));
        assert!(!tag_matches_defs(b"", &v1::DELEGATED_REVOCATION));
    }

    #[test]
    fn v1_declarations_are_distinct_and_documented_as_v1() {
        // The three v1 type tags must stay pairwise distinct so a signature
        // for one action can never authorize another.
        let tags = v1::TAGS;
        for (left_index, (left, _)) in tags.iter().enumerate() {
            for (right_index, (right, _)) in tags.iter().enumerate() {
                if left_index != right_index {
                    assert_ne!(left, right, "v1 action tags must be distinct");
                }
            }
        }

        // `revocation_time` is excluded from the v1 digest on purpose.
        assert!(!v1::ATTESTATION_FIELDS
            .iter()
            .any(|field| field.name == "revocation_time"));
        assert_eq!(v1::ATTESTATION_FIELDS.len(), 9);
        assert_eq!(v1::DOMAIN_FIELDS.len(), 3);
        assert_eq!(v1::DELEGATED_REVOCATION_FIELDS.len(), 2);
    }

    #[test]
    fn v1_and_eip712_type_strings_are_deliberately_different() {
        let env = Env::default();

        // The v1 tag is a namespaced, versioned, type-less literal; the
        // EIP-712 `encodeType` carries field types. Making that difference
        // explicit here stops a future reader from "fixing" one to match the
        // other and silently changing every v1 digest.
        let eip712 = encode_type(&env, &[v1::ATTESTATION], "Attestation");
        assert_ne!(
            eip712,
            Bytes::from_slice(&env, crate::typed_data::ATTESTATION_TYPE_TAG)
        );
        assert!(
            eip712.len() > Bytes::from_slice(&env, crate::typed_data::ATTESTATION_TYPE_TAG).len()
        );
        assert_eq!(
            eip712,
            Bytes::from_slice(
                &env,
                b"Attestation(bytes32 uid,bytes32 schema_uid,uint64 time,uint64 expiration_time,\
bytes32 ref_uid,bytes recipient,bytes attester,bool revocable,bytes data)",
            )
        );
    }

    // ---- helpers --------------------------------------------------------

    /// Extracts the single `Word` from a one-element slice of `Word` values.
    fn max_word(values: &[FieldValue]) -> [u8; 32] {
        match values.first() {
            Some(FieldValue::Word(word)) => *word,
            other => panic!("expected a single Word value, got {other:?}"),
        }
    }

    fn expected_empty_array(env: &Env) -> Bytes {
        let mut out = Bytes::new(env);
        out.extend_from_slice(&keccak_slice(env, &[]).to_array());
        out
    }
}
