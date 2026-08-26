//! Utility for constructing schema records.

use crate::errors::SdkError;
use soroban_sas_common::{SchemaRecord, UID};
use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env, String as SorobanString};

/// Fluent builder for SDK callers that need to construct a `SchemaRecord`.
#[derive(Clone, Debug, Default)]
pub struct SchemaBuilder {
    schema: std::string::String,
    resolver: Option<std::string::String>,
    revocable: bool,
}

impl SchemaBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the schema definition string.
    pub fn with_schema(mut self, definition: &str) -> Self {
        self.schema = definition.to_string();
        self
    }

    /// Sets the resolver contract address.
    pub fn with_resolver(mut self, addr: &str) -> Self {
        self.resolver = Some(addr.to_string());
        self
    }

    /// Sets whether attestations using this schema are revocable.
    pub fn with_revocable(mut self, flag: bool) -> Self {
        self.revocable = flag;
        self
    }

    /// Builds a `SchemaRecord`, deriving its UID from the schema definition.
    pub fn build(self, env: &Env) -> Result<SchemaRecord, SdkError> {
        if self.schema.is_empty() {
            return Err(SdkError::RpcError(
                "schema definition cannot be empty".to_string(),
            ));
        }

        let schema = SorobanString::from_str(env, &self.schema);
        let resolver = self
            .resolver
            .ok_or_else(|| SdkError::RpcError("resolver address is required".to_string()))?;
        let resolver = Address::from_string(&SorobanString::from_str(env, &resolver));

        let mut payload = Bytes::new(env);
        payload.append(&schema.clone().to_xdr(env));
        let uid = UID(BytesN::from_array(
            env,
            &env.crypto().sha256(&payload).to_array(),
        ));

        Ok(SchemaRecord {
            uid,
            resolver,
            revocable: self.revocable,
            schema,
        })
    }
}
