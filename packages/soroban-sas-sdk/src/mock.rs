//! In-memory mock SAS and Indexer client for unit testing downstream services without RPC.
#![allow(clippy::arc_with_non_send_sync)]

use crate::errors::SdkError;
use sha2::{Digest, Sha256};
use soroban_sas_common::{Attestation, SchemaRecord, UID};
use soroban_sdk::{Address, Bytes, BytesN, Env, String as SorobanString};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A recorded mock call for custom assertions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MockCall {
    RegisterSchema {
        schema: String,
        resolver: String,
        revocable: bool,
    },
    GetSchema {
        uid: [u8; 32],
    },
    Attest {
        recipient: String,
        schema_uid: [u8; 32],
        data: Vec<u8>,
    },
    Revoke {
        uid: [u8; 32],
        reason: Option<String>,
    },
    GetAttestation {
        uid: [u8; 32],
    },
    QueryRecipient {
        recipient: String,
    },
    QuerySchema {
        schema_uid: [u8; 32],
    },
}

/// Core SAS client trait covering schema and attestation operations.
pub trait SASClientTrait {
    fn register_schema(
        &mut self,
        schema: &str,
        resolver: &str,
        revocable: bool,
    ) -> Result<UID, SdkError>;

    fn get_schema(&self, uid: &[u8; 32]) -> Result<Option<SchemaRecord>, SdkError>;

    fn attest(
        &mut self,
        recipient: &str,
        schema_uid: &[u8; 32],
        data: &[u8],
    ) -> Result<UID, SdkError>;

    fn revoke(&mut self, uid: &[u8; 32], reason: Option<&str>) -> Result<(), SdkError>;

    fn get_attestation(&self, uid: &[u8; 32]) -> Result<Option<Attestation>, SdkError>;
}

/// Indexer client trait covering query operations.
pub trait IndexerClientTrait {
    fn get_attestations_by_recipient(&self, recipient: &str) -> Result<Vec<Attestation>, SdkError>;
    fn get_attestations_by_schema(
        &self,
        schema_uid: &[u8; 32],
    ) -> Result<Vec<Attestation>, SdkError>;
}

/// In-memory mock client implementing [`SASClientTrait`] and [`IndexerClientTrait`].
#[derive(Clone)]
pub struct MockSASClient {
    env: Env,
    schemas: Arc<Mutex<HashMap<[u8; 32], SchemaRecord>>>,
    attestations: Arc<Mutex<HashMap<[u8; 32], Attestation>>>,
    calls: Arc<Mutex<Vec<MockCall>>>,
    simulated_error: Arc<Mutex<Option<String>>>,
    next_nonce: Arc<Mutex<u64>>,
}

impl Default for MockSASClient {
    fn default() -> Self {
        Self {
            env: Env::default(),
            schemas: Arc::new(Mutex::new(HashMap::new())),
            attestations: Arc::new(Mutex::new(HashMap::new())),
            calls: Arc::new(Mutex::new(Vec::new())),
            simulated_error: Arc::new(Mutex::new(None)),
            next_nonce: Arc::new(Mutex::new(0)),
        }
    }
}

impl MockSASClient {
    /// Creates a new, empty in-memory mock client.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a reference to the mock client's Soroban environment.
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// Sets or clears a simulated error to return on subsequent operations.
    pub fn set_simulated_error(&self, error: Option<String>) {
        *self.simulated_error.lock().unwrap() = error;
    }

    /// Returns a list of all dispatched calls made to this mock client.
    pub fn calls(&self) -> Vec<MockCall> {
        self.calls.lock().unwrap().clone()
    }

    /// Clears the recorded call log.
    pub fn clear_calls(&self) {
        self.calls.lock().unwrap().clear();
    }

    /// Returns the number of registered schemas.
    pub fn schema_count(&self) -> usize {
        self.schemas.lock().unwrap().len()
    }

    /// Returns the number of issued attestations.
    pub fn attestation_count(&self) -> usize {
        self.attestations.lock().unwrap().len()
    }

    fn check_error(&self) -> Result<(), SdkError> {
        if let Some(msg) = self.simulated_error.lock().unwrap().clone() {
            return Err(SdkError::RpcError(msg));
        }
        Ok(())
    }

    fn generate_uid(&self, seed: &[u8]) -> UID {
        let mut nonce = self.next_nonce.lock().unwrap();
        *nonce += 1;
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(nonce.to_be_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        UID(BytesN::from_array(&self.env, &hash))
    }
}

impl SASClientTrait for MockSASClient {
    fn register_schema(
        &mut self,
        schema: &str,
        resolver: &str,
        revocable: bool,
    ) -> Result<UID, SdkError> {
        self.check_error()?;
        self.calls.lock().unwrap().push(MockCall::RegisterSchema {
            schema: schema.to_string(),
            resolver: resolver.to_string(),
            revocable,
        });

        let uid = self.generate_uid(schema.as_bytes());
        let resolver_addr = Address::from_string(&SorobanString::from_str(&self.env, resolver));
        let record = SchemaRecord {
            uid: uid.clone(),
            schema: SorobanString::from_str(&self.env, schema),
            resolver: resolver_addr,
            revocable,
            deprecated: false,
        };

        let mut raw_uid = [0u8; 32];
        uid.0.copy_into_slice(&mut raw_uid);
        self.schemas.lock().unwrap().insert(raw_uid, record);
        Ok(uid)
    }

    fn get_schema(&self, uid: &[u8; 32]) -> Result<Option<SchemaRecord>, SdkError> {
        self.check_error()?;
        self.calls
            .lock()
            .unwrap()
            .push(MockCall::GetSchema { uid: *uid });
        Ok(self.schemas.lock().unwrap().get(uid).cloned())
    }

    fn attest(
        &mut self,
        recipient: &str,
        schema_uid: &[u8; 32],
        data: &[u8],
    ) -> Result<UID, SdkError> {
        self.check_error()?;
        self.calls.lock().unwrap().push(MockCall::Attest {
            recipient: recipient.to_string(),
            schema_uid: *schema_uid,
            data: data.to_vec(),
        });

        let recipient_addr = Address::from_string(&SorobanString::from_str(&self.env, recipient));
        let attester_addr = Address::from_string(&SorobanString::from_str(
            &self.env,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        ));

        let uid = self.generate_uid(data);
        let schema_uid_obj = UID(BytesN::from_array(&self.env, schema_uid));
        let attestation = Attestation {
            uid: uid.clone(),
            schema_uid: schema_uid_obj,
            time: 1_000_000,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[0u8; 32])),
            recipient: recipient_addr,
            attester: attester_addr,
            revocable: true,
            data: Bytes::from_slice(&self.env, data),
            valid_from: 0,
        };

        let mut raw_uid = [0u8; 32];
        uid.0.copy_into_slice(&mut raw_uid);
        self.attestations
            .lock()
            .unwrap()
            .insert(raw_uid, attestation);
        Ok(uid)
    }

    fn revoke(&mut self, uid: &[u8; 32], reason: Option<&str>) -> Result<(), SdkError> {
        self.check_error()?;
        self.calls.lock().unwrap().push(MockCall::Revoke {
            uid: *uid,
            reason: reason.map(|s| s.to_string()),
        });

        let mut attestations = self.attestations.lock().unwrap();
        if let Some(attestation) = attestations.get_mut(uid) {
            attestation.revocation_time = 1_000_500;
            Ok(())
        } else {
            Err(SdkError::RpcError("attestation not found".to_string()))
        }
    }

    fn get_attestation(&self, uid: &[u8; 32]) -> Result<Option<Attestation>, SdkError> {
        self.check_error()?;
        self.calls
            .lock()
            .unwrap()
            .push(MockCall::GetAttestation { uid: *uid });
        Ok(self.attestations.lock().unwrap().get(uid).cloned())
    }
}

impl IndexerClientTrait for MockSASClient {
    fn get_attestations_by_recipient(&self, recipient: &str) -> Result<Vec<Attestation>, SdkError> {
        self.check_error()?;
        self.calls.lock().unwrap().push(MockCall::QueryRecipient {
            recipient: recipient.to_string(),
        });

        let recipient_addr = Address::from_string(&SorobanString::from_str(&self.env, recipient));
        let attestations = self.attestations.lock().unwrap();
        let matches = attestations
            .values()
            .filter(|a| a.recipient == recipient_addr)
            .cloned()
            .collect();
        Ok(matches)
    }

    fn get_attestations_by_schema(
        &self,
        schema_uid: &[u8; 32],
    ) -> Result<Vec<Attestation>, SdkError> {
        self.check_error()?;
        self.calls.lock().unwrap().push(MockCall::QuerySchema {
            schema_uid: *schema_uid,
        });

        let schema_uid_obj = UID(BytesN::from_array(&self.env, schema_uid));
        let attestations = self.attestations.lock().unwrap();
        let matches = attestations
            .values()
            .filter(|a| a.schema_uid == schema_uid_obj)
            .cloned()
            .collect();
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_client_schema_and_attestation_lifecycle() {
        let mut mock = MockSASClient::new();
        assert_eq!(mock.schema_count(), 0);
        assert_eq!(mock.attestation_count(), 0);

        let schema_uid = mock
            .register_schema(
                "bool is_valid",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                true,
            )
            .unwrap();
        assert_eq!(mock.schema_count(), 1);

        let mut raw_schema_uid = [0u8; 32];
        schema_uid.0.copy_into_slice(&mut raw_schema_uid);

        let schema = mock.get_schema(&raw_schema_uid).unwrap().unwrap();
        assert!(schema.revocable);

        let recipient = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCT4";
        let attestation_uid = mock
            .attest(recipient, &raw_schema_uid, b"sample payload")
            .unwrap();
        assert_eq!(mock.attestation_count(), 1);

        let mut raw_attestation_uid = [0u8; 32];
        attestation_uid.0.copy_into_slice(&mut raw_attestation_uid);

        let att = mock.get_attestation(&raw_attestation_uid).unwrap().unwrap();
        assert_eq!(att.revocation_time, 0);

        mock.revoke(&raw_attestation_uid, Some("fraud")).unwrap();
        let revoked_att = mock.get_attestation(&raw_attestation_uid).unwrap().unwrap();
        assert!(revoked_att.revocation_time > 0);

        // Verify indexer queries
        let by_recipient = mock.get_attestations_by_recipient(recipient).unwrap();
        assert_eq!(by_recipient.len(), 1);

        let by_schema = mock.get_attestations_by_schema(&raw_schema_uid).unwrap();
        assert_eq!(by_schema.len(), 1);

        // Verify recorded calls
        assert!(mock.calls().len() >= 6);
        mock.clear_calls();
        assert_eq!(mock.calls().len(), 0);

        // Verify simulated error
        mock.set_simulated_error(Some("simulated network outage".to_string()));
        let err = mock.get_schema(&raw_schema_uid).unwrap_err();
        match err {
            SdkError::RpcError(msg) => assert!(msg.contains("simulated network outage")),
            _ => panic!("unexpected error type"),
        }
    }
}
