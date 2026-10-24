use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{error, info};

mod examples;
mod fetcher;
mod generator;
mod models;
mod parser;

#[cfg(test)]
mod tests;

use generator::DocGenerator;
use models::{NetworkConfig, SchemaDocItem};

/// CLI arguments for sas-docgen.
#[derive(Parser, Debug)]
#[command(
    name = "sas-docgen",
    about = "Automated schema documentation generator producing Markdown sites for Soroban SAS",
    version = "0.1.0"
)]
struct Args {
    /// Target network (testnet, mainnet, localnet)
    #[arg(short, long, default_value = "testnet", env = "STELLAR_NETWORK")]
    network: String,

    /// Soroban RPC endpoint URL (overrides network default)
    #[arg(long, env = "SOROBAN_RPC_URL")]
    rpc_url: Option<String>,

    /// Schema Registry contract address (C...)
    #[arg(short, long, env = "SCHEMA_REGISTRY_CONTRACT_ID")]
    registry_contract_id: Option<String>,

    /// Output directory for generated Markdown documentation
    #[arg(short, long, default_value = "docs/schemas-generated")]
    output_dir: PathBuf,

    /// Load schema records from a local JSON fixture file instead of querying RPC
    #[arg(long)]
    from_file: Option<PathBuf>,

    /// Generate a sample schema JSON fixture at the specified path and exit
    #[arg(long)]
    sample_config: Option<PathBuf>,

    /// Starting index for on-chain schema pagination
    #[arg(long, default_value_t = 0)]
    start_index: u32,

    /// Maximum number of schemas to fetch from on-chain registry
    #[arg(long, default_value_t = 100)]
    limit: u32,
}

fn sample_fixture_data() -> Vec<SchemaDocItem> {
    vec![
        SchemaDocItem {
            uid: "3b08e2a1490226cfa877c8e9bda53243f721d092d6e4a2bc1d8c199209581f5c".to_string(),
            raw_schema: "name String, age u32, verified bool, metadata_uri String".to_string(),
            resolver: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".to_string(),
            revocable: true,
            deprecated: false,
            creator: Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string()),
            metadata_uri: Some("https://ipfs.io/ipfs/bafkreiaxxxxxxxxxxxx".to_string()),
            fields: vec![
                models::SchemaField {
                    name: "name".to_string(),
                    field_type: "String".to_string(),
                    is_metadata_uri: false,
                    description: "Full legal or display name of the identity".to_string(),
                },
                models::SchemaField {
                    name: "age".to_string(),
                    field_type: "u32".to_string(),
                    is_metadata_uri: false,
                    description: "Age in completed years".to_string(),
                },
                models::SchemaField {
                    name: "verified".to_string(),
                    field_type: "bool".to_string(),
                    is_metadata_uri: false,
                    description: "Verification status flag".to_string(),
                },
                models::SchemaField {
                    name: "metadata_uri".to_string(),
                    field_type: "String".to_string(),
                    is_metadata_uri: true,
                    description: "Decentralized metadata pointer".to_string(),
                },
            ],
        },
        SchemaDocItem {
            uid: "8f12a9c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcde".to_string(),
            raw_schema: "credential_hash BytesN<32>, issuer Address, issue_date u64".to_string(),
            resolver: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".to_string(),
            revocable: false,
            deprecated: false,
            creator: Some("GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5".to_string()),
            metadata_uri: None,
            fields: vec![
                models::SchemaField {
                    name: "credential_hash".to_string(),
                    field_type: "BytesN<32>".to_string(),
                    is_metadata_uri: false,
                    description: "Cryptographic hash of the credential claim".to_string(),
                },
                models::SchemaField {
                    name: "issuer".to_string(),
                    field_type: "Address".to_string(),
                    is_metadata_uri: false,
                    description: "Issuing institution address".to_string(),
                },
                models::SchemaField {
                    name: "issue_date".to_string(),
                    field_type: "u64".to_string(),
                    is_metadata_uri: false,
                    description: "Issuance ledger timestamp".to_string(),
                },
            ],
        },
    ]
}

fn write_sample_config(path: &Path) -> Result<()> {
    let data = sample_fixture_data();
    let json_text = serde_json::to_string_pretty(&data)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, json_text)?;
    info!("Sample configuration written to {:?}", path);
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = Args::parse();

    // Check if user requested sample config generation
    if let Some(sample_path) = args.sample_config {
        return write_sample_config(&sample_path);
    }

    let network = NetworkConfig::for_network(&args.network, args.rpc_url.as_deref());
    info!(
        "Configured network: {} (RPC: {})",
        network.name, network.rpc_url
    );

    let schemas: Vec<SchemaDocItem> = if let Some(ref file_path) = args.from_file {
        fetcher::load_schemas_from_file(file_path)?
    } else if let Some(ref registry_id) = args.registry_contract_id {
        match fetcher::fetch_on_chain_schemas(&network, registry_id, args.start_index, args.limit) {
            Ok(items) => items,
            Err(e) => {
                error!("RPC failure while fetching on-chain schemas: {:#}", e);
                eprintln!("\nError fetching on-chain schemas: {:#}", e);
                eprintln!("Tip: You can use --from-file to generate documentation from an offline fixture,");
                eprintln!("     or check network connectivity and SCHEMA_REGISTRY_CONTRACT_ID.\n");
                return Err(e);
            }
        }
    } else {
        eprintln!("Error: Either --registry-contract-id (or SCHEMA_REGISTRY_CONTRACT_ID) or --from-file is required.");
        eprintln!("Run `sas-docgen --help` for usage information.");
        anyhow::bail!("Missing registry contract ID or input file");
    };

    let registry_display = args
        .registry_contract_id
        .as_deref()
        .unwrap_or("offline-fixture");

    info!(
        "Generating documentation site for {} schemas into {:?}",
        schemas.len(),
        args.output_dir
    );

    DocGenerator::generate_site(&schemas, &network, registry_display, &args.output_dir)
        .with_context(|| {
            format!(
                "Failed to generate documentation site in {:?}",
                args.output_dir
            )
        })?;

    info!(
        "Schema documentation generated successfully in {:?}",
        args.output_dir
    );
    println!("Documentation generation complete: {:?}", args.output_dir);
    Ok(())
}
