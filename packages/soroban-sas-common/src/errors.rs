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
    /// A schema definition string violated strict lexical rules: it contained
    /// control characters, invalid/invisible unicode whitespace, or malformed
    /// separators (trailing/leading delimiters, non-canonical spacing). See
    /// `validate_schema_lexical`.
    InvalidSchemaDefinition = 106,
    SchemaAlreadyExists = 102,
    SchemaNotFound = 103,

    /// Attestation lifecycle errors
    AttestationNotFound = 201,
    AlreadyRevoked = 202,
    NotRevocable = 203,
    AlreadyExpired = 204,
    DuplicateAttestation = 205,
    /// An attestation's revocability flag violated the schema's revocation
    /// policy: irrevocable attestation under `RevocableOnly` schema.
    InvalidRevocability = 206,

    /// Authorization errors
    Unauthorized = 301,
    InvalidSignature = 302,
    DelegationReplay = 303,
    /// The schema has a private attester access control list and the attester
    /// is neither the schema owner, an authorized delegate, nor a member of
    /// that list (#443).
    UnauthorizedAttester = 304,

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
    /// Invalid time range: valid_from >= expiration_time > 0 (#439).
    InvalidTimeRange = 418,
    /// Expiration time exceeds schema's max_ttl or perpetual attestation under capped schema (#441).
    InvalidExpirationTime = 419,
    /// A timestamp claim does not match the ledger anchor recorded for the
    /// attestation, or stored anchors are not monotonic (#436).
    InvalidTimestamp = 420,
    /// No issuance or revocation timestamp anchor exists for the UID (#436).
    TimestampAnchorNotFound = 421,
    /// A new attestation was attempted under a schema the protocol admin has quarantined (#539).
    SchemaQuarantined = 422,
    /// A time-window resolver rejected an attestation because the recipient's
    /// cooldown period has not elapsed yet (#549).
    CooldownActive = 423,
    /// The payment asset is not authorized by the protocol fee allowlist.
    InvalidToken = 424,
    /// The attester has exhausted their configured ledger-window quota.
    RateLimitExceeded = 425,
    /// `prune_expired` was called while the admin has not enabled
    /// auto-pruning via `set_auto_prune` (#432).
    AutoPruneDisabled = 426,

    /// Circuit breaker errors
    /// The contract is paused and write operations are not permitted (#255).
    ContractPaused = 501,
    /// Core protocol mutation blocked by the emergency circuit breaker (#530).
    ProtocolPaused = 503,
    /// The caller did not supply enough tokens for the payload-size fee (#526).
    InsufficientFee = 504,
    /// A delegated signature does not authorize this schema or permission (#527).
    DelegationScopeDenied = 505,
    /// The configured proof-verifier rejected the supplied credential proof (#531).
    InvalidZKProof = 506,
    /// A proof nullifier has already been consumed by this SAS deployment.
    NullifierAlreadyUsed = 507,

    /// Reentrancy errors
    /// A callback (resolver or indexer) re-entered `multi_attest` while the
    /// outer batch was still executing (#296).
    Reentrancy = 502,
}

impl SASError {
    pub const ReentrancyDetected: SASError = SASError::Reentrancy;
}
