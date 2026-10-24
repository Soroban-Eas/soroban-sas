use serde::{Deserialize, Serialize};

/// Represents an individual field definition parsed from a schema string.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaField {
    pub name: String,
    pub field_type: String,
    pub is_metadata_uri: bool,
    pub description: String,
}

/// Structured documentable item representing a registered schema.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaDocItem {
    pub uid: String,
    pub raw_schema: String,
    pub resolver: String,
    pub revocable: bool,
    pub deprecated: bool,
    pub creator: Option<String>,
    pub metadata_uri: Option<String>,
    pub fields: Vec<SchemaField>,
}

/// Network configuration settings for Soroban RPC connectivity.
#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub name: String,
    pub rpc_url: String,
    pub network_passphrase: String,
}

impl NetworkConfig {
    pub fn for_network(name: &str, custom_rpc: Option<&str>) -> Self {
        let normalized = name.to_lowercase();
        match normalized.as_str() {
            "mainnet" | "public" => Self {
                name: "mainnet".to_string(),
                rpc_url: custom_rpc
                    .unwrap_or("https://soroban-rpc.mainnet.stellar.org")
                    .to_string(),
                network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
            },
            "localnet" | "standalone" => Self {
                name: "localnet".to_string(),
                rpc_url: custom_rpc
                    .unwrap_or("http://localhost:8000/soroban/rpc")
                    .to_string(),
                network_passphrase: "Standalone Network ; February 2017".to_string(),
            },
            _ => Self {
                name: "testnet".to_string(),
                rpc_url: custom_rpc
                    .unwrap_or("https://soroban-testnet.stellar.org")
                    .to_string(),
                network_passphrase: "Test SDF Network ; September 2015".to_string(),
            },
        }
    }
}
