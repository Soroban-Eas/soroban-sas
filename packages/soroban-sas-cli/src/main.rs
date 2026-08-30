use clap::{Parser, Subcommand, ValueEnum};

mod offchain;

/// Output format shared by every subcommand (issue #27).
///
/// * `human` (default) prints a readable summary.
/// * `json` prints a single envelope: `{"status":"ok","data":{ … }}` on
///   success and `{"status":"error","message":"…"}` on failure. The error
///   envelope is emitted centrally by `main`, so *every* subcommand honours
///   `--output json` on the failure path and exits non-zero.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

/// Prints a success result in the requested format.
///
/// For `--output human` the `human` closure runs (free-form text). For
/// `--output json` a `{"status":"ok","data":<data>}` envelope is printed and
/// the closure is skipped.
fn emit_ok(
    output: OutputFormat,
    human: impl FnOnce(),
    data: serde_json::Value,
) -> Result<(), String> {
    match output {
        OutputFormat::Human => human(),
        OutputFormat::Json => {
            let envelope = serde_json::json!({ "status": "ok", "data": data });
            println!(
                "{}",
                serde_json::to_string_pretty(&envelope)
                    .map_err(|e| format!("serialization failed: {e}"))?
            );
        }
    }
    Ok(())
}

/// Prints a failure in the requested format: `error: <msg>` on stderr for
/// `--output human`, or a `{"status":"error","message":"<msg>"}` envelope on
/// stdout for `--output json`.
fn emit_error(output: OutputFormat, message: &str) {
    match output {
        OutputFormat::Human => eprintln!("error: {message}"),
        OutputFormat::Json => {
            let envelope = serde_json::json!({ "status": "error", "message": message });
            match serde_json::to_string_pretty(&envelope) {
                Ok(text) => println!("{text}"),
                Err(_) => println!(
                    "{{\"status\":\"error\",\"message\":\"{}\"}}",
                    message.replace('\\', "\\\\").replace('"', "\\\"")
                ),
            }
        }
    }
}

/// Client-side schema syntax check (issue #26), mirroring
/// `soroban_sas_common::validate_schema_syntax`: a schema must be a
/// comma-separated list of `name Type` pairs, be non-empty, and stay within
/// the 1024-byte cap. Runs before any transaction is built or simulated, so
/// an invalid schema fails fast with no RPC round-trip and no simulation fee.
const MAX_SCHEMA_LENGTH: usize = 1024;

fn is_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

fn trim_bounds(bytes: &[u8], mut start: usize, mut end: usize) -> Option<(usize, usize)> {
    while start < end {
        if !is_ascii_whitespace(bytes[start]) {
            break;
        }
        start += 1;
    }

    while end > start {
        if !is_ascii_whitespace(bytes[end - 1]) {
            break;
        }
        end -= 1;
    }

    if start >= end {
        None
    } else {
        Some((start, end))
    }
}

fn validate_schema_syntax(schema: &str) -> Result<(), String> {
    let schema = schema.as_bytes();
    if schema.is_empty() {
        return Err("schema is empty: pass a non-empty --schema definition string".to_string());
    }
    if schema.len() > MAX_SCHEMA_LENGTH {
        return Err(format!(
            "schema is {} bytes, which exceeds the {MAX_SCHEMA_LENGTH}-byte limit",
            schema.len()
        ));
    }

    let Some((mut start, end)) = trim_bounds(schema, 0, schema.len()) else {
        return Err("schema is empty: pass a non-empty --schema definition string".to_string());
    };

    let mut field_count = 0u32;
    while start < end {
        let mut field_end = start;
        while field_end < end && schema[field_end] != b',' {
            field_end += 1;
        }

        let Some((field_start, field_end)) = trim_bounds(schema, start, field_end) else {
            return Err(
                "schema must use comma-separated `name Type` field definitions".to_string(),
            );
        };

        let mut split_index = field_start;
        while split_index < field_end && !is_ascii_whitespace(schema[split_index]) {
            split_index += 1;
        }
        if split_index == field_start || split_index >= field_end {
            return Err(
                "schema must use comma-separated `name Type` field definitions".to_string(),
            );
        }

        let mut ty_start = split_index;
        while ty_start < field_end && is_ascii_whitespace(schema[ty_start]) {
            ty_start += 1;
        }
        if ty_start >= field_end {
            return Err(
                "schema must use comma-separated `name Type` field definitions".to_string(),
            );
        }

        let name = &schema[field_start..split_index];
        let ty = &schema[ty_start..field_end];
        let identifier_ok = !name.is_empty()
            && (name[0].is_ascii_alphabetic() || name[0] == b'_')
            && name[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
        let type_ok = !ty.is_empty()
            && ty.iter().any(|byte| byte.is_ascii_alphabetic())
            && ty.iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'_' | b'<' | b'>' | b'[' | b']' | b',' | b':' | b'(' | b')' | b' ' | b'?'
                    )
            });
        if !identifier_ok || !type_ok {
            return Err(
                "schema must use comma-separated `name Type` field definitions".to_string(),
            );
        }
        field_count += 1;

        if field_end >= end {
            break;
        }
        start = field_end + 1;
        while start < end && is_ascii_whitespace(schema[start]) {
            start += 1;
        }
        if start >= end {
            return Err("schema must use comma-separated `name Type` field definitions".to_string());
        }
    }

    if field_count == 0 {
        return Err("schema must define at least one field".to_string());
    }

    Ok(())
}

#[derive(Parser)]
#[command(name = "soroban-sas")]
#[command(about = "CLI for Soroban Attestation Service")]
struct Cli {
    #[arg(long, global = true, help = "RPC Network to connect to")]
    network: Option<String>,

    #[arg(long, global = true, help = "Identity to use for signing")]
    identity: Option<String>,

    #[arg(
        long,
        global = true,
        value_enum,
        default_value = "human",
        help = "Output format for all subcommands. `json` emits \
                {\"status\":\"ok\",\"data\":…} on success and \
                {\"status\":\"error\",\"message\":…} on failure."
    )]
    output: OutputFormat,

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
    },
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
    let output = cli.output;
    let result = match cli.command {
        Some(Commands::Offchain { action }) => run_offchain(action, output),
        Some(Commands::Schema { action }) => run_schema(action, output),
        Some(Commands::Attest { action }) => run_attest(action, output),
        Some(Commands::Query { action }) => run_query(action, output),
        Some(Commands::Delegate { action }) => run_delegate(action, output),
        _ => emit_ok(
            output,
            || println!("CLI initialized"),
            serde_json::json!({ "message": "CLI initialized" }),
        ),
    };
    if let Err(err) = result {
        emit_error(output, &err);
        std::process::exit(1);
    }
}

fn run_attest(action: AttestCommands, output: OutputFormat) -> Result<(), String> {
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
            print_transaction_result(result, output)
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
            print_transaction_result(result, output)
        }
        AttestCommands::Verify {
            uid,
            contract_id,
            rpc_url,
        } => {
            let uid = parse_uid(&uid)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let valid = client
                .verify_attestation(&env, &rpc, &uid)
                .map_err(|e| format!("{e:?}"))?;
            emit_ok(
                output,
                || {
                    if valid {
                        println!("Attestation is valid");
                    } else {
                        println!("Attestation is invalid or not found");
                    }
                },
                serde_json::json!({ "valid": valid }),
            )
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
            print_transaction_result(result, output)
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
    output: OutputFormat,
) -> Result<(), String> {
    // The pre-#27 CLI always printed this result as a pretty JSON object, so
    // the `human` rendering keeps that shape; `--output json` wraps it in the
    // standard `{status, data}` envelope.
    let data = serde_json::json!({
        "status": result.status,
        "envelopeXdr": result.envelope_xdr,
        "resultXdr": result.result_xdr,
    });
    let human_text = serde_json::to_string_pretty(&data)
        .map_err(|e| format!("serialization failed: {e}"))?;
    emit_ok(output, || println!("{human_text}"), data.clone())
}

fn run_query(action: QueryCommands, output: OutputFormat) -> Result<(), String> {
    let env = soroban_sdk::Env::default();
    match action {
        QueryCommands::ByRecipient {
            address,
            contract_id,
            rpc_url,
        } => {
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::IndexerClient::new(contract_id);
            let uids = client
                .get_attestations_by_recipient(&env, &rpc, &address)
                .map_err(|e| format!("{e:?}"))?;
            print_uids(&uids, output)
        }
        QueryCommands::BySchema {
            uid,
            contract_id,
            rpc_url,
        } => {
            let schema_uid = parse_uid(&uid)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::IndexerClient::new(contract_id);
            let uids = client
                .get_attestations_by_schema(&env, &rpc, &schema_uid)
                .map_err(|e| format!("{e:?}"))?;
            print_uids(&uids, output)
        }
    }
}

fn print_uids(
    uids: &soroban_sdk::Vec<soroban_sas_common::UID>,
    output: OutputFormat,
) -> Result<(), String> {
    let hex_uids: Vec<String> = uids
        .iter()
        .map(|uid| hex::encode(uid.0.to_array()))
        .collect();
    emit_ok(
        output,
        || {
            if hex_uids.is_empty() {
                println!("No attestations found");
            } else {
                for uid in &hex_uids {
                    println!("{uid}");
                }
            }
        },
        serde_json::json!({ "uids": hex_uids.clone() }),
    )
}

fn decode_hex64(value: &str) -> Result<[u8; 64], String> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|e| format!("invalid hex: {e}"))?
        .try_into()
        .map_err(|_| "value must be exactly 64 bytes".to_string())
}

fn run_delegate(action: DelegateCommands, output: OutputFormat) -> Result<(), String> {
    let env = soroban_sdk::Env::default();
    match action {
        DelegateCommands::SignRevoke {
            uid,
            attester,
            nonce,
            network_passphrase,
            contract_id,
            secret_key,
            output: output_file,
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
            let signed_json = serde_json::to_string_pretty(&signed)
                .map_err(|e| format!("serialization failed: {e}"))?;
            match output_file {
                Some(path) => {
                    std::fs::write(&path, &signed_json)
                        .map_err(|e| format!("cannot write {path}: {e}"))?;
                    emit_ok(
                        output,
                        || println!("wrote signed revocation to {path}"),
                        serde_json::json!({ "written_to": path.clone() }),
                    )
                }
                None => emit_ok(
                    output,
                    || println!("{signed_json}"),
                    serde_json::to_value(&signed)
                        .map_err(|e| format!("serialization failed: {e}"))?,
                ),
            }
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
            print_transaction_result(result, output)
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
            print_transaction_result(result, output)
        }
    }
}

fn run_schema(action: SchemaCommands, output: OutputFormat) -> Result<(), String> {
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
            // #26 — validate locally before touching the network, so an empty
            // or oversized schema exits 1 with a clear message and never pays
            // for a simulation.
            validate_schema_syntax(&schema)?;
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
            print_transaction_result(result, output)
        }
        SchemaCommands::Get {
            uid,
            registry_contract_id,
            rpc_url,
        } => {
            let uid_bytes = parse_uid(&uid)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
            let schema = client
                .get_schema(&env, &rpc, &registry_contract_id, &uid_bytes)
                .map_err(|e| format!("{e:?}"))?;

            match schema {
                None => emit_ok(
                    output,
                    || println!("Schema not found"),
                    serde_json::json!({ "found": false }),
                ),
                Some(record) => {
                    let uid_hex = hex::encode(record.uid.0.to_array());
                    let resolver = soroban_string_to_std(&record.resolver.to_string());
                    let schema_str = soroban_string_to_std(&record.schema);
                    let revocable = record.revocable;
                    emit_ok(
                        output,
                        || {
                            println!("uid:       {uid_hex}");
                            println!("resolver:  {resolver}");
                            println!("revocable: {revocable}");
                            println!("schema:    {schema_str}");
                        },
                        serde_json::json!({
                            "found": true,
                            "uid": uid_hex.clone(),
                            "resolver": resolver.clone(),
                            "revocable": revocable,
                            "schema": schema_str.clone(),
                        }),
                    )
                }
            }
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

fn run_offchain(action: OffchainCommands, output: OutputFormat) -> Result<(), String> {
    match action {
        OffchainCommands::Sign {
            data_file,
            secret_key,
            nonce,
            network_passphrase,
            contract_id,
            output: output_file,
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
            let signed_json = serde_json::to_string_pretty(&signed)
                .map_err(|e| format!("serialization failed: {e}"))?;
            match output_file {
                Some(path) => {
                    std::fs::write(&path, &signed_json)
                        .map_err(|e| format!("cannot write {path}: {e}"))?;
                    emit_ok(
                        output,
                        || println!("wrote signed attestation to {path}"),
                        serde_json::json!({ "written_to": path.clone() }),
                    )
                }
                None => emit_ok(
                    output,
                    || println!("{signed_json}"),
                    serde_json::to_value(&signed)
                        .map_err(|e| format!("serialization failed: {e}"))?,
                ),
            }
        }
        OffchainCommands::Verify { file } => {
            let raw =
                std::fs::read_to_string(&file).map_err(|e| format!("cannot read {file}: {e}"))?;
            let signed: offchain::SignedOffchainAttestation = serde_json::from_str(&raw)
                .map_err(|e| format!("invalid signed attestation JSON: {e}"))?;
            offchain::verify_offchain_attestation(&signed)?;
            emit_ok(
                output,
                || println!("Signature is valid"),
                serde_json::json!({ "valid": true }),
            )
        }
    }
}

#[cfg(test)]
mod test;
