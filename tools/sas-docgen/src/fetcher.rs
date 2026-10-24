use crate::models::{NetworkConfig, SchemaDocItem};
use crate::parser::build_schema_doc_item;
use anyhow::{Context, Result};
use soroban_sas_sdk::client::SASClient;
use soroban_sas_sdk::rpc::RpcClient;
use std::fs;
use std::path::Path;
use tracing::{info, warn};

/// Converts a soroban_sdk::String to a standard Rust String.
fn soroban_string_to_std(s: &soroban_sdk::String) -> String {
    let mut buf = vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Fetches registered schemas directly from the on-chain SchemaRegistry contract.
pub fn fetch_on_chain_schemas(
    network: &NetworkConfig,
    registry_contract_id: &str,
    start: u32,
    limit: u32,
) -> Result<Vec<SchemaDocItem>> {
    info!(
        "Connecting to Soroban RPC at {} to fetch schemas from registry {}",
        network.rpc_url, registry_contract_id
    );

    let rpc = RpcClient::new(network.rpc_url.clone());
    let client = SASClient::new(registry_contract_id.to_string());

    let records = client
        .get_schemas(&rpc, registry_contract_id, start, limit)
        .with_context(|| {
            format!(
                "Failed to retrieve schemas from registry contract {} on {}",
                registry_contract_id, network.name
            )
        })?;

    let mut doc_items = Vec::new();

    for record in records.iter() {
        let uid_bytes = record.uid.0.to_array();
        let uid_hex = hex::encode(uid_bytes);
        let raw_schema = soroban_string_to_std(&record.schema);
        let resolver_str = soroban_string_to_std(&record.resolver.to_string());
        let revocable = record.revocable;
        let deprecated = record.deprecated;

        // Query creator address if available; fail gracefully on missing creator
        let creator = match client.get_creator(&rpc, registry_contract_id, &uid_bytes) {
            Ok(Some(creator_addr)) => Some(soroban_string_to_std(&creator_addr.to_string())),
            Ok(None) => None,
            Err(e) => {
                warn!(
                    "Could not fetch creator for schema {}: {}. Proceeding with None.",
                    uid_hex, e
                );
                None
            }
        };

        let item = build_schema_doc_item(
            &uid_hex,
            &raw_schema,
            &resolver_str,
            revocable,
            deprecated,
            creator,
        );

        doc_items.push(item);
    }

    info!(
        "Successfully fetched {} schema(s) from on-chain",
        doc_items.len()
    );
    Ok(doc_items)
}

/// Loads schema document items from a local JSON fixture file.
pub fn load_schemas_from_file(path: &Path) -> Result<Vec<SchemaDocItem>> {
    info!("Loading schema definitions from file: {:?}", path);
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read input schema file: {:?}", path))?;

    let items: Vec<SchemaDocItem> = serde_json::from_str(&content)
        .with_context(|| "Failed to parse schema JSON input fixture")?;

    info!("Loaded {} schema(s) from fixture", items.len());
    Ok(items)
}
