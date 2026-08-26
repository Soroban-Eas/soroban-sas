use clap::{Parser, Subcommand};

mod offchain;

#[derive(Parser)]
#[command(name = "soroban-sas")]
#[command(about = "CLI for Soroban Attestation Service")]
struct Cli {
    #[arg(long, global = true, help = "RPC Network to connect to")]
    network: Option<String>,

    #[arg(long, global = true, help = "Identity to use for signing")]
    identity: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Schema registry commands
    Schema {
        #[command(subcommand)]
        action: SchemaCommands,
    },
    /// Attestation lifecycle commands
    Attest {
        #[command(subcommand)]
        action: AttestCommands,
    },
    /// Indexer query commands
    Query {
        #[command(subcommand)]
        action: QueryCommands,
    },
    /// Sign delegated attestations/revocations off-chain, and submit
    /// already-signed ones on-chain via a relayer
    Delegate {
        #[command(subcommand)]
        action: DelegateCommands,
    },
    /// Off-chain attestation signing and verification
    Offchain {
        #[command(subcommand)]
        action: OffchainCommands,
    },
}

#[derive(Subcommand)]
enum OffchainCommands {
    /// Sign an attestation off-chain with an ed25519 key
    Sign {
        #[arg(long, help = "JSON file containing the attestation payload")]
        data_file: String,
        #[arg(
            long,
            help = "Signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: String,
        #[arg(long, help = "Replay-protection nonce bound into the signature")]
        nonce: u64,
        #[arg(long, help = "Network passphrase the signature is bound to")]
        network_passphrase: String,
        #[arg(long, help = "SAS contract address (C...) the signature is bound to")]
        contract_id: String,
        #[arg(
            long,
            help = "Write the signed attestation to this file instead of stdout"
        )]
        output: Option<String>,
    },
    /// Verify a signed off-chain attestation
    Verify {
        #[arg(long, help = "JSON file containing the signed attestation")]
        file: String,
    },
}

#[derive(Subcommand)]
enum SchemaCommands {
    /// Register a new schema. The registration is signed and submitted by
    /// --secret-key's account, which becomes the schema's owner.
    Register {
        #[arg(long, help = "Schema definition string")]
        schema: String,
        #[arg(
            long,
            help = "Resolver contract address (C...) invoked on attest/revoke"
        )]
        resolver: String,
        #[arg(long, help = "Whether attestations against this schema can be revoked")]
        revocable: bool,
        #[arg(
            long,
            help = "Owner's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: String,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: String,
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
    },
    /// Get an existing schema by UID
    Get {
        #[arg(long, help = "32-byte schema UID, hex encoded")]
        uid: String,
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
        #[arg(long, help = "Print raw JSON instead of a human-readable summary")]
        json: bool,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Subcommand)]
enum AttestCommands {
    /// Issue a new on-chain attestation directly from flags (no JSON data
    /// file required). Generates the UID and prints it on success.
    Attest {
        #[arg(long, help = "32-byte schema UID, hex encoded")]
        schema_uid: String,
        #[arg(long, help = "Recipient address (G... or C...)")]
        recipient: String,
        #[arg(
            long,
            help = "Attestation payload, hex or base64 encoded",
            default_value = ""
        )]
        data: String,
        #[arg(
            long,
            help = "Unix timestamp the attestation expires at (0 = no expiry)",
            default_value_t = 0
        )]
        expiration: u64,
        #[arg(long, help = "Whether this attestation can be revoked")]
        revocable: bool,
        #[arg(
            long,
            help = "Attester's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: String,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: String,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
        #[arg(long, help = "Output format: human or json", default_value = "human")]
        output: OutputFormat,
    },
    /// Create and submit a new on-chain attestation
    Create {
        #[arg(long, help = "JSON file containing attestation data")]
        data_file: String,
        #[arg(
            long,
            help = "Attester signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: String,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: String,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
    },
    /// Revoke an existing on-chain attestation
    Revoke {
        #[arg(long, help = "32-byte attestation UID, hex encoded")]
        uid: String,
        #[arg(
            long,
            help = "Attester signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: String,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: String,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
    },
    /// Verify an on-chain attestation's current validity
    Verify {
        #[arg(long, help = "32-byte attestation UID, hex encoded")]
        uid: String,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
        #[arg(long, help = "Print raw JSON instead of a human-readable result")]
        json: bool,
    },
    /// Atomically revoke an attestation and issue a replacement linked to
    /// it via ref_uid. The replacement's attester/recipient must match the
    /// original's.
    Replace {
        #[arg(
            long,
            help = "32-byte UID of the attestation being replaced, hex encoded"
        )]
        old_uid: String,
        #[arg(long, help = "JSON file containing the replacement attestation data")]
        data_file: String,
        #[arg(
            long,
            help = "Attester signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: String,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: String,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
    },
}

#[derive(Subcommand)]
enum QueryCommands {
    /// Query attestations by recipient address
    ByRecipient {
        #[arg(long, help = "Recipient account address (G...)")]
        address: String,
        #[arg(
            long,
            help = "Indexer contract address (C...)",
            env = "INDEXER_CONTRACT_ID"
        )]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
        #[arg(long, help = "Print raw JSON instead of one UID per line")]
        json: bool,
    },
    /// Query attestations by schema UID
    BySchema {
        #[arg(long, help = "32-byte schema UID, hex encoded")]
        uid: String,
        #[arg(
            long,
            help = "Indexer contract address (C...)",
            env = "INDEXER_CONTRACT_ID"
        )]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
        #[arg(long, help = "Print raw JSON instead of one UID per line")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum DelegateCommands {
    /// Sign a delegated revocation off-chain. (Attestation-issuance signing
    /// already exists via `offchain sign` — its output is what
    /// `submit-attest` expects.)
    SignRevoke {
        #[arg(long, help = "32-byte attestation UID to revoke, hex encoded")]
        uid: String,
        #[arg(
            long,
            help = "Attester account address (strkey G...); must match --secret-key"
        )]
        attester: String,
        #[arg(long, help = "Replay-protection nonce bound into the signature")]
        nonce: u64,
        #[arg(long, help = "Network passphrase the signature is bound to")]
        network_passphrase: String,
        #[arg(long, help = "SAS contract address (C...) the signature is bound to")]
        contract_id: String,
        #[arg(
            long,
            help = "Attester's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: String,
        #[arg(
            long,
            help = "Write the signed revocation to this file instead of stdout"
        )]
        output: Option<String>,
    },
    /// Submit an already-signed delegated attestation on-chain via
    /// `attest_by_delegation`, paid for by --secret-key's account (a
    /// relayer — it does not need to be the attester).
    SubmitAttest {
        #[arg(
            long,
            help = "JSON file containing a signed attestation (from `offchain sign`)"
        )]
        file: String,
        #[arg(
            long,
            help = "Relayer's signing key: S... strkey seed or 32-byte hex seed (pays for and submits the tx; need not be the attester)",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
    },
    /// Submit an already-signed delegated revocation on-chain via
    /// `revoke_by_delegation`, same relayer model as `submit-attest`.
    SubmitRevoke {
        #[arg(
            long,
            help = "JSON file containing a signed revocation (from `delegate sign-revoke`)"
        )]
        file: String,
        #[arg(
            long,
            help = "Relayer's signing key: S... strkey seed or 32-byte hex seed (pays for and submits the tx; need not be the attester)",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Commands::Offchain { action }) => run_offchain(action),
        Some(Commands::Schema { action }) => run_schema(action),
        Some(Commands::Attest { action }) => run_attest(action),
        Some(Commands::Query { action }) => run_query(action),
        Some(Commands::Delegate { action }) => run_delegate(action),
        _ => {
            println!("CLI initialized");
            Ok(())
        }
    };
    if let Err(err) = result {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run_attest(action: AttestCommands) -> Result<(), String> {
    let env = soroban_sdk::Env::default();
    match action {
        AttestCommands::Attest {
            schema_uid,
            recipient,
            data,
            expiration,
            revocable,
            secret_key,
            network_passphrase,
            contract_id,
            rpc_url,
            output,
        } => {
            let schema_uid_bytes = parse_uid(&schema_uid)?;
            let data_bytes = decode_hex_or_base64(&data)?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let attester = stellar_strkey::ed25519::PublicKey(
                soroban_sas_sdk::signature::derive_public_key(&seed),
            )
            .to_string();

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("system clock error: {e}"))?;
            let uid = offchain::generate_uid(
                &env,
                &schema_uid_bytes,
                &recipient,
                &attester,
                &data_bytes,
                now.as_nanos(),
            );

            let input = offchain::AttestationInput {
                uid: hex::encode(uid),
                schema_uid: schema_uid.clone(),
                time: now.as_secs(),
                expiration_time: expiration,
                ref_uid: hex::encode([0u8; 32]),
                recipient,
                attester,
                revocable,
                data: hex::encode(&data_bytes),
            };
            let attestation = offchain::parse_attestation(&env, &input)?;

            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let result = client
                .attest(&env, &rpc, &network_passphrase, &seed, attestation)
                .map_err(|e| format!("{e:?}"))?;

            if result.status != "SUCCESS" {
                return Err(format!("attest failed with status {}", result.status));
            }

            let uid_hex = hex::encode(uid);
            match output {
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "ok",
                        "uid": uid_hex,
                    }))
                    .map_err(|e| format!("serialization failed: {e}"))?
                ),
                OutputFormat::Human => println!("Attestation issued: {uid_hex}"),
            }
            Ok(())
        }
        AttestCommands::Create {
            data_file,
            secret_key,
            network_passphrase,
            contract_id,
            rpc_url,
        } => {
            let raw = std::fs::read_to_string(&data_file)
                .map_err(|e| format!("cannot read {data_file}: {e}"))?;
            let input: offchain::AttestationInput =
                serde_json::from_str(&raw).map_err(|e| format!("invalid attestation JSON: {e}"))?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let expected_attester = stellar_strkey::ed25519::PublicKey(
                soroban_sas_sdk::signature::derive_public_key(&seed),
            )
            .to_string();
            if input.attester != expected_attester {
                return Err(format!(
                    "attester {} does not match signing key account {expected_attester}",
                    input.attester
                ));
            }
            let attestation = offchain::parse_attestation(&env, &input)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let result = client
                .attest(&env, &rpc, &network_passphrase, &seed, attestation)
                .map_err(|e| format!("{e:?}"))?;
            print_transaction_result(result)
        }
        AttestCommands::Revoke {
            uid,
            secret_key,
            network_passphrase,
            contract_id,
            rpc_url,
        } => {
            let uid = parse_uid(&uid)?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let result = client
                .revoke(&env, &rpc, &network_passphrase, &seed, &uid)
                .map_err(|e| format!("{e:?}"))?;
            print_transaction_result(result)
        }
        AttestCommands::Verify {
            uid,
            contract_id,
            rpc_url,
            json,
        } => {
            let uid = parse_uid(&uid)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let valid = client
                .verify_attestation(&env, &rpc, &uid)
                .map_err(|e| format!("{e:?}"))?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "valid": valid }))
                        .map_err(|e| format!("serialization failed: {e}"))?
                );
            } else if valid {
                println!("Attestation is valid");
            } else {
                println!("Attestation is invalid or not found");
            }
            Ok(())
        }
        AttestCommands::Replace {
            old_uid,
            data_file,
            secret_key,
            network_passphrase,
            contract_id,
            rpc_url,
        } => {
            let old_uid = parse_uid(&old_uid)?;
            let raw = std::fs::read_to_string(&data_file)
                .map_err(|e| format!("cannot read {data_file}: {e}"))?;
            let input: offchain::AttestationInput =
                serde_json::from_str(&raw).map_err(|e| format!("invalid attestation JSON: {e}"))?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let expected_attester = stellar_strkey::ed25519::PublicKey(
                soroban_sas_sdk::signature::derive_public_key(&seed),
            )
            .to_string();
            if input.attester != expected_attester {
                return Err(format!(
                    "attester {} does not match signing key account {expected_attester}",
                    input.attester
                ));
            }
            let new_data = offchain::parse_attestation(&env, &input)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let result = client
                .replace_attestation(&env, &rpc, &network_passphrase, &seed, &old_uid, new_data)
                .map_err(|e| format!("{e:?}"))?;
            print_transaction_result(result)
        }
    }
}

fn parse_uid(value: &str) -> Result<[u8; 32], String> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|e| format!("invalid hex in uid: {e}"))?
        .try_into()
        .map_err(|_| "uid must be exactly 32 bytes".to_string())
}

/// Decodes an attestation `--data` value that may be either hex (optionally
/// `0x`-prefixed) or base64 encoded.
fn decode_hex_or_base64(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if let Some(hex_str) = trimmed.strip_prefix("0x") {
        return hex::decode(hex_str).map_err(|e| format!("invalid hex in data: {e}"));
    }
    let looks_like_hex = !trimmed.is_empty()
        && trimmed.len() & 1 == 0
        && trimmed.chars().all(|c| c.is_ascii_hexdigit());
    if looks_like_hex {
        return hex::decode(trimmed).map_err(|e| format!("invalid hex in data: {e}"));
    }
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| format!("data must be hex or base64 encoded: {e}"))
}

fn print_transaction_result(
    result: soroban_sas_sdk::rpc::GetTransactionResult,
) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "status": result.status,
            "envelopeXdr": result.envelope_xdr,
            "resultXdr": result.result_xdr,
        }))
        .map_err(|e| format!("serialization failed: {e}"))?
    );
    Ok(())
}

fn run_query(action: QueryCommands) -> Result<(), String> {
    let env = soroban_sdk::Env::default();
    match action {
        QueryCommands::ByRecipient {
            address,
            contract_id,
            rpc_url,
            json,
        } => {
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::IndexerClient::new(contract_id);
            let uids = client
                .get_attestations_by_recipient(&env, &rpc, &address)
                .map_err(|e| format!("{e:?}"))?;
            print_uids(&uids, json)
        }
        QueryCommands::BySchema {
            uid,
            contract_id,
            rpc_url,
            json,
        } => {
            let schema_uid = parse_uid(&uid)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::IndexerClient::new(contract_id);
            let uids = client
                .get_attestations_by_schema(&env, &rpc, &schema_uid)
                .map_err(|e| format!("{e:?}"))?;
            print_uids(&uids, json)
        }
    }
}

fn print_uids(uids: &soroban_sdk::Vec<soroban_sas_common::UID>, json: bool) -> Result<(), String> {
    let hex_uids: Vec<String> = uids
        .iter()
        .map(|uid| hex::encode(uid.0.to_array()))
        .collect();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&hex_uids)
                .map_err(|e| format!("serialization failed: {e}"))?
        );
    } else if hex_uids.is_empty() {
        println!("No attestations found");
    } else {
        for uid in hex_uids {
            println!("{uid}");
        }
    }
    Ok(())
}

fn decode_hex64(value: &str) -> Result<[u8; 64], String> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|e| format!("invalid hex: {e}"))?
        .try_into()
        .map_err(|_| "value must be exactly 64 bytes".to_string())
}

fn run_delegate(action: DelegateCommands) -> Result<(), String> {
    let env = soroban_sdk::Env::default();
    match action {
        DelegateCommands::SignRevoke {
            uid,
            attester,
            nonce,
            network_passphrase,
            contract_id,
            secret_key,
            output,
        } => {
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let signed = offchain::sign_delegated_revocation(
                &uid,
                &attester,
                nonce,
                &network_passphrase,
                &contract_id,
                &seed,
            )?;
            let json = serde_json::to_string_pretty(&signed)
                .map_err(|e| format!("serialization failed: {e}"))?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &json).map_err(|e| format!("cannot write {path}: {e}"))?
                }
                None => println!("{json}"),
            }
            Ok(())
        }
        DelegateCommands::SubmitAttest {
            file,
            secret_key,
            rpc_url,
        } => {
            let raw =
                std::fs::read_to_string(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
            let signed: offchain::SignedOffchainAttestation = serde_json::from_str(&raw)
                .map_err(|e| format!("invalid signed attestation JSON: {e}"))?;
            offchain::verify_offchain_attestation(&signed)?;

            let attestation = offchain::parse_attestation(&env, &signed.attestation)?;
            let public_key = parse_uid(&signed.public_key)?;
            let signature = decode_hex64(&signed.signature)?;
            let relayer_seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(signed.contract_id.clone());
            let result = client
                .attest_by_delegation(
                    &env,
                    &rpc,
                    &signed.network_passphrase,
                    &relayer_seed,
                    attestation,
                    signed.nonce,
                    &signature,
                    &public_key,
                )
                .map_err(|e| format!("{e:?}"))?;
            print_transaction_result(result)
        }
        DelegateCommands::SubmitRevoke {
            file,
            secret_key,
            rpc_url,
        } => {
            let raw =
                std::fs::read_to_string(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
            let signed: offchain::SignedDelegatedRevocation = serde_json::from_str(&raw)
                .map_err(|e| format!("invalid signed revocation JSON: {e}"))?;

            let uid = parse_uid(&signed.uid)?;
            let public_key = parse_uid(&signed.public_key)?;
            let signature = decode_hex64(&signed.signature)?;
            let relayer_seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(signed.contract_id.clone());
            let result = client
                .revoke_by_delegation(
                    &env,
                    &rpc,
                    &signed.network_passphrase,
                    &relayer_seed,
                    &uid,
                    signed.nonce,
                    &signature,
                    &public_key,
                )
                .map_err(|e| format!("{e:?}"))?;
            print_transaction_result(result)
        }
    }
}

fn run_schema(action: SchemaCommands) -> Result<(), String> {
    let env = soroban_sdk::Env::default();
    match action {
        SchemaCommands::Register {
            schema,
            resolver,
            revocable,
            secret_key,
            network_passphrase,
            registry_contract_id,
            rpc_url,
        } => {
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
            let result = client
                .register_schema(
                    &env,
                    &rpc,
                    &network_passphrase,
                    &seed,
                    &registry_contract_id,
                    &schema,
                    &resolver,
                    revocable,
                )
                .map_err(|e| format!("{e:?}"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": result.status,
                    "envelopeXdr": result.envelope_xdr,
                    "resultXdr": result.result_xdr,
                }))
                .map_err(|e| format!("serialization failed: {e}"))?
            );
            Ok(())
        }
        SchemaCommands::Get {
            uid,
            registry_contract_id,
            rpc_url,
            json,
        } => {
            let uid_bytes = parse_uid(&uid)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
            let schema = client
                .get_schema(&env, &rpc, &registry_contract_id, &uid_bytes)
                .map_err(|e| format!("{e:?}"))?;

            match schema {
                None => {
                    println!("Schema not found");
                }
                Some(record) => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "uid": hex::encode(record.uid.0.to_array()),
                                "resolver": soroban_string_to_std(&record.resolver.to_string()),
                                "revocable": record.revocable,
                                "schema": soroban_string_to_std(&record.schema),
                            }))
                            .map_err(|e| format!("serialization failed: {e}"))?
                        );
                    } else {
                        println!("uid:       {}", hex::encode(record.uid.0.to_array()));
                        println!(
                            "resolver:  {}",
                            soroban_string_to_std(&record.resolver.to_string())
                        );
                        println!("revocable: {}", record.revocable);
                        println!("schema:    {}", soroban_string_to_std(&record.schema));
                    }
                }
            }
            Ok(())
        }
    }
}

/// `soroban_sdk::String` (a host value) doesn't implement `Display` off-chain
/// — this copies it into a UTF-8 `std::String` for printing.
fn soroban_string_to_std(s: &soroban_sdk::String) -> String {
    let mut buf = vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

fn run_offchain(action: OffchainCommands) -> Result<(), String> {
    match action {
        OffchainCommands::Sign {
            data_file,
            secret_key,
            nonce,
            network_passphrase,
            contract_id,
            output,
        } => {
            let raw = std::fs::read_to_string(&data_file)
                .map_err(|e| format!("cannot read {data_file}: {e}"))?;
            let input: offchain::AttestationInput =
                serde_json::from_str(&raw).map_err(|e| format!("invalid attestation JSON: {e}"))?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let signed = offchain::sign_offchain_attestation(
                input,
                nonce,
                &network_passphrase,
                &contract_id,
                &seed,
            )?;
            let json = serde_json::to_string_pretty(&signed)
                .map_err(|e| format!("serialization failed: {e}"))?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &json).map_err(|e| format!("cannot write {path}: {e}"))?
                }
                None => println!("{json}"),
            }
            Ok(())
        }
        OffchainCommands::Verify { file } => {
            let raw =
                std::fs::read_to_string(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
            let signed: offchain::SignedOffchainAttestation = serde_json::from_str(&raw)
                .map_err(|e| format!("invalid signed attestation JSON: {e}"))?;
            offchain::verify_offchain_attestation(&signed)?;
            println!("Signature is valid");
            Ok(())
        }
    }
}

#[cfg(test)]
mod test;
