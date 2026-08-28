//! Utility for constructing `Attestation` values to submit via
//! `SASClient::attest`.

use crate::errors::SdkError;
use soroban_sas_common::{Attestation, UID};
use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env, String as SorobanString};

/// Fluent builder for SDK callers that need to construct an `Attestation`
/// value before handing it to `SASClient::attest`.
///
/// Every `Attestation` field is either set through a dedicated `with_*`
/// method or derived at [`AttestationRequestBuilder::build`] time:
///
/// - `recipient`, `schema_uid`, `data`, and `attester` are required, and
///   [`AttestationRequestBuilder::build`] returns `Err` when any is missing.
/// - `expiration_time` defaults to `0` (never expires), `revocable` to
///   `false`, and `ref_uid` to the zero UID (no reference) when unset.
/// - `uid` is derived via SHA-256 over the attestation content, `time` is
///   taken from the current ledger timestamp, and `revocation_time` is
///   always `0` for a freshly built attestation.
#[derive(Clone, Debug, Default)]
pub struct AttestationRequestBuilder {
    /// Recipient address as a strkey (`G...` or `C...`).
    recipient: Option<std::string::String>,
    /// 32-byte schema UID the attestation conforms to.
    schema_uid: Option<[u8; 32]>,
    /// Arbitrary attestation payload.
    data: Option<Bytes>,
    /// Unix-seconds expiration; `0` means the attestation never expires.
    expiration_time: u64,
    /// Whether the attestation may be revoked on-chain.
    revocable: bool,
    /// Optional reference to a related attestation UID; the zero UID means none.
    ref_uid: [u8; 32],
    /// Attester address as a strkey (`G...`); must be the account whose
    /// secret seed signs the submission (see `SASClient::attest`).
    attester: Option<std::string::String>,
}

impl AttestationRequestBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the attestation's recipient address (strkey `G...` or `C...`).
    pub fn with_recipient(mut self, addr: &str) -> Self {
        self.recipient = Some(addr.to_string());
        self
    }

    /// Sets the 32-byte schema UID the attestation conforms to.
    pub fn with_schema_uid(mut self, uid: [u8; 32]) -> Self {
        self.schema_uid = Some(uid);
        self
    }

    /// Sets the attestation payload. Pass `Bytes::new(env)` for an empty
    /// payload.
    pub fn with_data(mut self, data: Bytes) -> Self {
        self.data = Some(data);
        self
    }

    /// Sets the expiration time in Unix seconds. `0` (the default) means
    /// the attestation never expires.
    pub fn with_expiration(mut self, ts: u64) -> Self {
        self.expiration_time = ts;
        self
    }

    /// Sets whether the attestation can be revoked on-chain.
    pub fn with_revocable(mut self, flag: bool) -> Self {
        self.revocable = flag;
        self
    }

    /// Sets an optional reference to a related attestation UID. When unset,
    /// the zero UID is used (no reference).
    pub fn with_ref_uid(mut self, uid: [u8; 32]) -> Self {
        self.ref_uid = uid;
        self
    }

    /// Sets the attester address (strkey `G...`).
    ///
    /// `SASClient::attest` requires the attestation's `attester` to be the
    /// account that signs the submission, so this should be the address
    /// derived from the `secret_seed` passed to that call.
    pub fn with_attester(mut self, addr: &str) -> Self {
        self.attester = Some(addr.to_string());
        self
    }

    /// Validates that every required field is set and returns the resulting
    /// `Attestation`, deriving its UID as:
    ///
    /// ```text
    /// uid = sha256(
    ///     schema_uid       # 32 bytes
    ///     || ref_uid       # 32 bytes, zero UID when unset
    ///     || recipient     # ScVal XDR of the address
    ///     || sha256(data)  # 32 bytes
    /// )
    /// ```
    ///
    /// The preimage follows the byte layout the rest of the codebase uses
    /// when hashing attestation content (addresses as ScVal XDR, UIDs as raw
    /// 32 bytes, `data` folded in through its own SHA-256), so the UID is
    /// deterministic: identical builder inputs always produce the same UID,
    /// and changing any content field produces a different one.
    pub fn build(self, env: &Env) -> Result<Attestation, SdkError> {
        let recipient = self.recipient.ok_or_else(|| {
            SdkError::RpcError("attestation recipient address is required".to_string())
        })?;
        let attester = self.attester.ok_or_else(|| {
            SdkError::RpcError("attestation attester address is required".to_string())
        })?;
        let schema_uid = self
            .schema_uid
            .ok_or_else(|| SdkError::RpcError("attestation schema uid is required".to_string()))?;
        let data = self
            .data
            .ok_or_else(|| SdkError::RpcError("attestation data is required".to_string()))?;

        let recipient = Address::from_string(&SorobanString::from_str(env, &recipient));
        let attester = Address::from_string(&SorobanString::from_str(env, &attester));

        let mut payload = Bytes::new(env);
        payload.append(&Bytes::from_slice(env, &schema_uid));
        payload.append(&Bytes::from_slice(env, &self.ref_uid));
        payload.append(&recipient.clone().to_xdr(env));
        let data_hash = env.crypto().sha256(&data);
        payload.append(&Bytes::from_slice(env, &data_hash.to_array()));
        let uid = UID(BytesN::from_array(
            env,
            &env.crypto().sha256(&payload).to_array(),
        ));

        Ok(Attestation {
            uid,
            schema_uid: UID(BytesN::from_array(env, &schema_uid)),
            time: env.ledger().timestamp(),
            expiration_time: self.expiration_time,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &self.ref_uid)),
            recipient,
            attester,
            revocable: self.revocable,
            data,
        })
    }
}
