use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SASError {
    /// Schema validation errors
    InvalidSchema = 101,
    SchemaAlreadyExists = 102,
    SchemaNotFound = 103,

    /// Attestation lifecycle errors
    AttestationNotFound = 201,
    AlreadyRevoked = 202,
    NotRevocable = 203,
    AlreadyExpired = 204,

    /// Authorization errors
    Unauthorized = 301,
    InvalidSignature = 302,

    /// Input validation errors
    InvalidTTL = 401,
    InvalidRecipient = 402,

    /// Protocol fee errors
    FeeNotConfigured = 501,
    TreasuryNotSet = 502,
    InvalidFeeAmount = 503,
}
