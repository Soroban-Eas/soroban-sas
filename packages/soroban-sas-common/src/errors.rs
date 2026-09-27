use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SASError {
    /// Lifecycle errors
    /// A contract's `init` was called on an already-initialized instance.
    AlreadyInitialized = 1,
    /// A privileged operation was called before `init` stored an admin.
    NotInitialized = 2,

    /// Schema validation errors
    InvalidSchema = 101,
    InvalidSchemaFormat = 104,
    EmptySchema = 105,
    SchemaAlreadyExists = 102,
    SchemaNotFound = 103,

    /// Attestation lifecycle errors
    AttestationNotFound = 201,
    AlreadyRevoked = 202,
    NotRevocable = 203,
    AlreadyExpired = 204,
    DuplicateAttestation = 205,

    /// Authorization errors
    Unauthorized = 301,
    InvalidSignature = 302,
    DelegationReplay = 303,

    /// Input validation errors
    InvalidTTL = 401,
    InvalidRecipient = 402,
    /// A fee/value amount was negative.
    InvalidValue = 403,
    /// The configured dependency does not implement the required interface.
    IncompatibleDependency = 404,
    /// The requested attestation batch exceeds the protocol limit.
    BatchTooLarge = 405,
    /// `register_attester_key` was called while a non-revoked key is
    /// already registered for the attester; use `rotate_attester_key`.
    AttesterKeyAlreadyRegistered = 406,
    /// A rotate/revoke operation was attempted with no registered key on
    /// file for the attester.
    AttesterKeyNotFound = 407,
    /// The registered key for this attester has already been revoked.
    AttesterKeyRevoked = 408,
    /// The schema's resolver rejected, trapped on, or does not implement the
    /// callback for this operation. Resolvers are authoritative: this aborts
    /// the whole call. See docs/schemas.md's "Resolver Failure Semantics".
    ResolverRejected = 409,
    /// `attest_with_value` was called with a token or amount that does not
    /// match the fee required by authenticated on-chain configuration (#164).
    FeeMismatch = 410,
    /// A bound Indexer could not be invoked and the contract is configured to
    /// fail closed on indexing errors (#161).
    IndexerUnavailable = 411,
    /// The count metadata expired while schema records still exist.
    CountMetadataExpired = 412,
    /// `ref_uid` self-references the attestation being issued, or points at
    /// a UID that was never issued (#159).
    InvalidRefUid = 413,
    /// The attestation's `data` payload exceeds `MAX_ATTESTATION_DATA_BYTES`
    /// (#157).
    PayloadTooLarge = 414,
    /// `register_with_value` was called while a registration fee is
    /// configured but no treasury address has been set to receive it (#1).
    TreasuryNotSet = 415,
    /// An attestation's `uid` does not match the content-addressed hash of
    /// its `schema_uid`, `recipient`, `attester`, and `data` fields (#215).
    InvalidUID = 416,
    /// Maximum queries per block limit exceeded.
    LimitExceeded = 417,

    /// Circuit breaker errors
    /// The contract is paused and write operations are not permitted (#255).
    ContractPaused = 501,
}

/// Errors raised while validating a typed-data schema or hashing typed data
/// (#299). Kept separate from [`SASError`] because typed-data hashing is a
/// library surface used by off-chain callers, the SDK, and (potentially)
/// multiple contracts, so its codes must not shift when a contract error is
/// renumbered.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TypedDataError {
    /// The schema declares no structs, or no types.
    EmptySchema = 1,
    /// A struct or field name is empty.
    EmptyName = 2,
    /// A struct or field name exceeds `MAX_NAME_BYTES`.
    NameTooLong = 3,
    /// Two struct definitions share a name.
    DuplicateStructName = 4,
    /// A struct declares the same field name twice. EIP-712 requires unique
    /// field names: duplicates make `encodeType` ambiguous, so two different
    /// payloads could hash to one digest.
    DuplicateFieldName = 5,
    /// A field's `type_index` is outside the type table.
    TypeIndexOutOfRange = 6,
    /// A `Struct` type node's `reference` is outside the struct table.
    StructIndexOutOfRange = 7,
    /// An elementary type node carries a `reference` other than
    /// `NO_REFERENCE`.
    UnexpectedReference = 8,
    /// The type graph contains a cycle, which would make encoding recurse
    /// forever.
    CyclicTypeReference = 9,
    /// The schema exceeds the struct or type table size caps.
    SchemaTooLarge = 10,
    /// A struct declares more fields than `MAX_STRUCT_FIELDS`.
    StructTooLarge = 11,
    /// A `String` value exceeds `MAX_STRING_VALUE_BYTES`.
    StringValueTooLong = 12,
    /// A value's variant does not match the kind the schema declares for that
    /// field.
    TypeMismatch = 13,
    /// The number of values supplied for a struct does not match its field
    /// count.
    ArityMismatch = 14,
}
