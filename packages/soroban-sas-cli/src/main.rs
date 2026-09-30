use clap::{CommandFactory, Parser, Subcommand, ValueEnum};

mod bulk;
mod cache;
mod hardware;
mod identity;
mod io_safety;
mod manpage;
mod network;
mod offchain;

/// Resolves a subcommand's own flag against the global `--network` shorthand
/// (issue #174): an explicit flag (already merged with its environment
/// variable fallback by clap's `env = "..."`) always wins; `--network`
/// supplies the value only when the flag is entirely absent.
fn resolve_rpc_url(explicit: Option<String>, network: Option<&str>) -> Result<String, String> {
    if let Some(url) = explicit {
        return Ok(url);
    }
    match network {
        Some(name) => Ok(network::resolve_network(name)?.rpc_url),
        None => Err(
            "missing --rpc-url: pass it directly, set SOROBAN_RPC_URL, or pass --network"
                .to_string(),
        ),
    }
}

/// Same precedence as [`resolve_rpc_url`], for the network passphrase half
/// of a `--network` shorthand.
fn resolve_network_passphrase(
    explicit: Option<String>,
    network: Option<&str>,
) -> Result<String, String> {
    if let Some(passphrase) = explicit {
        return Ok(passphrase);
    }
    match network {
        Some(name) => Ok(network::resolve_network(name)?.network_passphrase),
        None => Err("missing --network-passphrase: pass it directly, set \
             SOROBAN_NETWORK_PASSPHRASE, or pass --network"
            .to_string()),
    }
}

/// Resolves a subcommand's own `--secret-key` (already merged with
/// `SAS_SECRET_KEY` by clap) against the global `--identity` shorthand
/// (issue #174): an explicit flag always wins; `--identity` looks the key up
/// from the local identity store only when the flag is entirely absent.
fn resolve_secret_key(
    explicit: Option<String>,
    identity: Option<&str>,
    hardware: Option<hardware::HardwareWallet>,
) -> Result<String, String> {
    if let Some(wallet) = hardware {
        return Err(wallet.signing_error());
    }
    if let Some(secret) = explicit {
        eprintln!(
            "warning: --secret-key / SAS_SECRET_KEY is deprecated and will be removed \
             in a future release. Use --identity <name> (a file in \
             ~/.soroban-sas/identities/) instead to keep secrets out of process \
             arguments and shell history."
        );
        return Ok(secret);
    }
    match identity {
        Some(name) => identity::resolve_identity_secret(name),
        None => Err(
            "missing --secret-key: pass it directly, set SAS_SECRET_KEY, pass --identity, \
             or pass --hardware-wallet"
                .to_string(),
        ),
    }
}

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

/// Rewrites raw RPC and transport failures into a short operator message
/// (issue #327). Messages that are not RPC failures are returned unchanged.
fn humanize_rpc_failure(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    let rpc_failure = lower.starts_with("rpc error:")
        || lower.starts_with("network error:")
        || lower.contains("jsonrpc")
        || lower.contains("too many requests")
        || lower.contains("connection refused")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("error sending request")
        || lower.contains("failed to lookup")
        || lower.contains("name or service not known")
        || lower.contains("rpc response");
    if !rpc_failure {
        return message.to_string();
    }
    if lower.contains("429") || lower.contains("too many requests") || lower.contains("rate limit")
    {
        return format!(
            "the Soroban RPC endpoint is rate-limiting requests. Wait and retry, or pass a \
             different --rpc-url. ({message})"
        );
    }
    if lower.contains("connection refused")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("error sending request")
        || lower.contains("failed to lookup")
        || lower.contains("name or service not known")
        || lower.starts_with("network error:")
    {
        return format!(
            "could not reach the Soroban RPC endpoint. Check --rpc-url or --network, and \
             confirm the node is online. ({message})"
        );
    }
    format!(
        "the Soroban RPC call failed. Confirm the endpoint, contract id, and network \
         passphrase, then retry. ({message})"
    )
}

/// Prints a failure in the requested format: `error: <msg>` on stderr for
/// `--output human`, or a `{"status":"error","message":"<msg>"}` envelope on
/// stdout for `--output json`. RPC failures are rewritten by
/// [`humanize_rpc_failure`] before they are printed.
fn emit_error(output: OutputFormat, message: &str) {
    let message = humanize_rpc_failure(message);
    match output {
        OutputFormat::Human => eprintln!("error: {message}"),
        OutputFormat::Json => {
            let envelope = serde_json::json!({ "status": "error", "message": message });
            match serde_json::to_string_pretty(&envelope) {
                Ok(text) => println!("{text}"),
                Err(_) => {
                    // Graceful fallback for malformed JSON: use manual escaping
                    // to ensure output is always valid JSON even with unusual characters
                    let escaped = message
                        .replace('\\', "\\\\")
                        .replace('"', "\\\"")
                        .replace('\n', "\\n")
                        .replace('\r', "\\r")
                        .replace('\t', "\\t");
                    println!("{{\"status\":\"error\",\"message\":\"{escaped}\"}}")
                }
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
            return Err(
                "schema must use comma-separated `name Type` field definitions".to_string(),
            );
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
    #[arg(
        long,
        global = true,
        help = "Named network (testnet, futurenet, mainnet/pubnet, local/standalone). \
                Supplies --rpc-url / --network-passphrase for any subcommand that \
                doesn't set them directly or via their SOROBAN_* env vars (issue #174)."
    )]
    network: Option<String>,

    #[arg(
        long,
        global = true,
        help = "Named identity to sign with, looked up from \
                ~/.soroban-sas/identities/<name> (or $SAS_IDENTITY_DIR/<name>). \
                Supplies --secret-key for any subcommand that doesn't set it directly \
                or via SAS_SECRET_KEY (issue #174)."
    )]
    identity: Option<String>,

    #[arg(
        long,
        global = true,
        value_enum,
        help = "Sign with a hardware wallet instead of --secret-key or --identity. \
                Requires the device path in SAS_LEDGER_DEVICE or SAS_TREZOR_DEVICE. \
                Signing commands fail closed and never fall back to a software key \
                (issue #328)."
    )]
    hardware_wallet: Option<hardware::HardwareWalletKind>,

    #[arg(
        long,
        global = true,
        default_value_t = 0,
        help = "BIP-44 account index used with --hardware-wallet (issue #328)."
    )]
    hd_account: u32,

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

    #[arg(
        long,
        global = true,
        help = "Bypass the on-disk read-only-query cache (issue #331) for this \
                invocation and always fetch fresh from RPC. The fresh result \
                still refreshes the cache for the next lookup. Cache TTL \
                defaults to 30s and is configurable via SAS_CACHE_TTL_SECS; \
                the cache directory defaults to ~/.soroban-sas/cache and is \
                configurable via SAS_CACHE_DIR."
    )]
    no_cache: bool,

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
    /// SAS contract commands
    Sas {
        #[command(subcommand)]
        action: SasCommands,
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
    /// Write a groff man page for soroban-sas (issue #330)
    Man {
        /// Write the page to this file instead of stdout
        #[arg(long, help = "Write the man page to this file instead of stdout")]
        path: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum SasCommands {
    /// Read the currently configured attestation fee, if any.
    #[command(name = "get-fee")]
    Get {
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
    },
    /// Admin: configure the token and amount charged for attestations.
    #[command(name = "set-fee")]
    Set {
        #[arg(long, help = "Fee asset: token contract address (C...)")]
        token: String,
        #[arg(long, help = "Fee amount, in the token's smallest unit (must be > 0)")]
        amount: i128,
        #[arg(
            long,
            help = "SAS admin's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Simulate the call and print its resource fee without signing or \
                    submitting a transaction. No state is changed and no fee is spent."
        )]
        dry_run: bool,
    },
    /// Admin: remove the attestation fee requirement.
    #[command(name = "clear-fee")]
    Clear {
        #[arg(
            long,
            help = "SAS admin's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Simulate the call and print its resource fee without signing or \
                    submitting a transaction. No state is changed and no fee is spent."
        )]
        dry_run: bool,
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
        secret_key: Option<String>,
        #[arg(long, help = "Replay-protection nonce bound into the signature")]
        nonce: u64,
        #[arg(long, help = "Network passphrase the signature is bound to")]
        network_passphrase: Option<String>,
        #[arg(long, help = "SAS contract address (C...) the signature is bound to")]
        contract_id: String,
        #[arg(
            long = "out-file",
            help = "Write the signed attestation to this file instead of stdout"
        )]
        out_file: Option<String>,
    },
    /// Verify a signed off-chain attestation.
    ///
    /// By default this performs *only* cryptographic checks (issue #175):
    /// the ed25519 signature, that its public key belongs to the declared
    /// attester, and that the payload hash matches the attestation
    /// contents. It does **not** confirm the attestation is still valid —
    /// pass `--online` to additionally check expiration, revocation, schema
    /// availability, and that the file's embedded network/contract match
    /// the network/contract you actually trust.
    Verify {
        #[arg(long, help = "JSON file containing the signed attestation")]
        file: String,
        #[arg(
            long,
            help = "Also check current on-chain status: expiration, revocation, schema \
                    availability, and that the embedded network/contract match the \
                    trusted target given via --contract-id/--network-passphrase (or \
                    --network). Without this flag only the cryptographic signature is \
                    checked."
        )]
        online: bool,
        #[arg(
            long,
            env = "SAS_CONTRACT_ID",
            help = "Trusted SAS contract address (C...) to verify against when --online \
                    is set. Required for --online: the contract_id embedded in the \
                    signed file is untrusted input and is only ever *compared* against \
                    this, never used to pick the verification target itself."
        )]
        contract_id: Option<String>,
        #[arg(
            long,
            env = "SOROBAN_NETWORK_PASSPHRASE",
            help = "Trusted network passphrase to verify against when --online is set \
                    (or supply --network). Same non-negotiable-trust-target rule as \
                    --contract-id."
        )]
        network_passphrase: Option<String>,
        #[arg(
            long,
            env = "SCHEMA_REGISTRY_CONTRACT_ID",
            help = "Schema Registry contract address (C...), to check schema \
                    availability when --online is set. Skipped (reported as \
                    \"not_checked\") if omitted."
        )]
        registry_contract_id: Option<String>,
        #[arg(
            long,
            env = "SOROBAN_RPC_URL",
            help = "Soroban RPC endpoint URL; required for --online (or supply --network)"
        )]
        rpc_url: Option<String>,
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
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Simulate the call and print its resource fee without signing or \
                    submitting a transaction. No state is changed and no fee is spent."
        )]
        dry_run: bool,
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
        rpc_url: Option<String>,
    },
    /// Look up an existing schema by its raw definition, without computing its
    /// UID off-chain. The registry derives the content-addressed UID with the
    /// same canonical rules `register` uses, so callers that cannot reproduce
    /// the host hashing rules can still check whether a definition is already
    /// registered. A malformed schema string is rejected.
    GetByContent {
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
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
    },
    /// Register a new schema, paying the configured registration fee.
    /// `token`/`value` must match what the registry admin configured via
    /// `set-fee`, or the call fails before anything is registered.
    RegisterWithValue {
        #[arg(long, help = "Schema definition string")]
        schema: String,
        #[arg(
            long,
            help = "Resolver contract address (C...) invoked on attest/revoke"
        )]
        resolver: String,
        #[arg(long, help = "Whether attestations against this schema can be revoked")]
        revocable: bool,
        #[arg(long, help = "Fee asset: token contract address (C...)")]
        token: String,
        #[arg(long, help = "Fee amount, in the token's smallest unit")]
        value: i128,
        #[arg(
            long,
            help = "Owner's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Simulate the call and print its resource fee without signing or \
                    submitting a transaction. No state is changed and no fee is spent."
        )]
        dry_run: bool,
    },
    /// Admin: pin the asset and exact amount `register-with-value` charges.
    SetFee {
        #[arg(long, help = "Fee asset: token contract address (C...)")]
        token: String,
        #[arg(long, help = "Fee amount, in the token's smallest unit")]
        amount: i128,
        #[arg(
            long,
            help = "Registry admin's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Simulate the call and print its resource fee without signing or \
                    submitting a transaction. No state is changed and no fee is spent."
        )]
        dry_run: bool,
    },
    /// Admin: remove the registration fee requirement.
    ClearFee {
        #[arg(
            long,
            help = "Registry admin's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Simulate the call and print its resource fee without signing or \
                    submitting a transaction. No state is changed and no fee is spent."
        )]
        dry_run: bool,
    },
    /// Admin: pin the address that receives registration fees.
    SetTreasury {
        #[arg(long, help = "Treasury address (G... account or C... contract)")]
        treasury: String,
        #[arg(
            long,
            help = "Registry admin's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Simulate the call and print its resource fee without signing or \
                    submitting a transaction. No state is changed and no fee is spent."
        )]
        dry_run: bool,
    },
    /// Admin: withdraw accumulated registration fees from the registry.
    WithdrawFees {
        #[arg(
            long,
            help = "Amount to withdraw, in the fee token's smallest unit (must be > 0)"
        )]
        amount: i128,
        #[arg(
            long,
            help = "Registry admin's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Simulate the call and print its resource fee without signing or \
                    submitting a transaction. No state is changed and no fee is spent."
        )]
        dry_run: bool,
    },
    /// Read the currently configured registration fee, if any.
    GetFee {
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
    },
    /// Read the currently configured treasury address, if any.
    GetTreasury {
        #[arg(
            long,
            help = "Schema Registry contract address (C...)",
            env = "SCHEMA_REGISTRY_CONTRACT_ID"
        )]
        registry_contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
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
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Use the local system clock if the network ledger time cannot be fetched or is out of range"
        )]
        allow_local_time: bool,
        #[arg(
            long,
            help = "Max seconds the network ledger time may disagree with the local clock before it is rejected",
            default_value_t = 300
        )]
        max_ledger_skew: u64,
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
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
    },
    /// Issue many on-chain attestations in one run, read from a CSV file
    ///
    /// The file needs a header row; `schema_uid` and `recipient` are
    /// required and `data`, `expiration`, and `revocable` are optional.
    /// Columns are matched by name, so their order is free. Every row is
    /// fully validated before the first transaction is submitted, so a
    /// typo in the last row cannot leave a half-issued batch behind. Use
    /// `--dry-run` to validate and print the plan without spending fees;
    /// it still needs a signing key, because each previewed UID is
    /// content-addressed to the attester.
    Bulk {
        #[arg(long, help = "CSV file with one attestation per row")]
        csv_file: String,
        #[arg(
            long,
            help = "Attester signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[arg(
            long,
            help = "Validate every row and print the plan without submitting any transaction"
        )]
        dry_run: bool,
        #[arg(
            long,
            help = "Keep submitting after a row fails, instead of stopping at the first failure"
        )]
        continue_on_error: bool,
        #[arg(
            long,
            help = "Use the local system clock if the network ledger time cannot be fetched or is out of range"
        )]
        allow_local_time: bool,
        #[arg(
            long,
            help = "Max seconds the network ledger time may disagree with the local clock before it is rejected",
            default_value_t = 300
        )]
        max_ledger_skew: u64,
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
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
    },
    /// Verify an on-chain attestation's current validity
    Verify {
        #[arg(long, help = "32-byte attestation UID, hex encoded")]
        uid: String,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
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
        secret_key: Option<String>,
        #[arg(
            long,
            help = "Network passphrase to sign against",
            env = "SOROBAN_NETWORK_PASSPHRASE"
        )]
        network_passphrase: Option<String>,
        #[arg(long, help = "SAS contract address (C...)", env = "SAS_CONTRACT_ID")]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
    },
}

/// Largest page `query by-* --limit` accepts. Each page is one
/// `simulateTransaction`, so keeping pages to one indexer chunk's worth of
/// UIDs keeps a single request comfortably inside the read budget (#306).
const MAX_QUERY_PAGE_SIZE: u32 = 100;

/// Pagination flags shared by the `query by-*` commands (#306). Without
/// either flag a query returns the complete history, exactly as before.
#[derive(clap::Args, Clone, Copy, Debug, Default, PartialEq, Eq)]
struct PageArgs {
    #[arg(
        long,
        help = "Zero-based position in the history (oldest first) to start the page at. \
                Enables pagination; resume with the `next_cursor` a page reports."
    )]
    cursor: Option<u32>,
    #[arg(
        long,
        help = "Maximum UIDs per page (1-100, default 100 when only --cursor is given). \
                Enables pagination; without --cursor/--limit the complete history is returned."
    )]
    limit: Option<u32>,
}

impl PageArgs {
    /// `None` for an unpaginated query, otherwise the validated
    /// `(cursor, limit)` window. Checked before any RPC call.
    fn resolve(self) -> Result<Option<(u32, u32)>, String> {
        if self.cursor.is_none() && self.limit.is_none() {
            return Ok(None);
        }
        let limit = self.limit.unwrap_or(MAX_QUERY_PAGE_SIZE);
        if limit == 0 || limit > MAX_QUERY_PAGE_SIZE {
            return Err(format!(
                "--limit must be between 1 and {MAX_QUERY_PAGE_SIZE}, got {limit}"
            ));
        }
        Ok(Some((self.cursor.unwrap_or(0), limit)))
    }
}

#[derive(Subcommand)]
#[allow(clippy::enum_variant_names)] // Mirrors the public `query by-*` command names.
enum QueryCommands {
    /// Query attestations by recipient address: the complete history, or
    /// one page of it with --cursor/--limit
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
        rpc_url: Option<String>,
        #[command(flatten)]
        page: PageArgs,
    },
    /// Query attestations by attester address: the complete history, or
    /// one page of it with --cursor/--limit
    ByAttester {
        #[arg(long, help = "Attester/issuer account address (G...)")]
        address: String,
        #[arg(
            long,
            help = "Indexer contract address (C...)",
            env = "INDEXER_CONTRACT_ID"
        )]
        contract_id: String,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
        #[command(flatten)]
        page: PageArgs,
    },
    /// Query attestations by schema UID: the complete history, or one page
    /// of it with --cursor/--limit
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
        rpc_url: Option<String>,
        #[command(flatten)]
        page: PageArgs,
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
        network_passphrase: Option<String>,
        #[arg(long, help = "SAS contract address (C...) the signature is bound to")]
        contract_id: String,
        #[arg(
            long,
            help = "Attester's signing key: S... strkey seed or 32-byte hex seed",
            env = "SAS_SECRET_KEY",
            hide_env_values = true
        )]
        secret_key: Option<String>,
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
        secret_key: Option<String>,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
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
        secret_key: Option<String>,
        #[arg(long, help = "Soroban RPC endpoint URL", env = "SOROBAN_RPC_URL")]
        rpc_url: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let output = cli.output;
    // Taken before matching on `cli.command`, which moves it.
    let network = cli.network;
    let identity = cli.identity;
    let no_cache = cli.no_cache;
    let hardware = cli.hardware_wallet.map(|kind| hardware::HardwareWallet {
        kind,
        account: cli.hd_account,
    });
    let result = match cli.command {
        Some(Commands::Offchain { action }) => {
            run_offchain(action, output, network, identity, hardware)
        }
        Some(Commands::Schema { action }) => {
            run_schema(action, output, network, identity, hardware, no_cache)
        }
        Some(Commands::Attest { action }) => {
            run_attest(action, output, network, identity, hardware)
        }
        Some(Commands::Sas { action }) => {
            run_sas(action, output, network, identity, hardware, no_cache)
        }
        Some(Commands::Query { action }) => run_query(action, output, network),
        Some(Commands::Delegate { action }) => {
            run_delegate(action, output, network, identity, hardware)
        }
        Some(Commands::Man { path }) => manpage::write_man_page(&Cli::command(), path.as_deref()),
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

pub(crate) fn fee_to_human(fee: &Option<(soroban_sdk::Address, i128)>) -> String {
    match fee {
        None => "Fee: free".to_string(),
        Some((token, amount)) => {
            let token_str = soroban_string_to_std(&token.to_string());
            format!("Fee: {amount} stroops of {token_str}")
        }
    }
}

pub(crate) fn fee_to_json(fee: &Option<(soroban_sdk::Address, i128)>) -> serde_json::Value {
    match fee {
        None => serde_json::Value::Null,
        Some((token, amount)) => {
            let token_str = soroban_string_to_std(&token.to_string());
            serde_json::json!({
                "token": token_str,
                "amount": amount,
            })
        }
    }
}

fn run_sas(
    action: SasCommands,
    output: OutputFormat,
    network: Option<String>,
    identity: Option<String>,
    hardware: Option<hardware::HardwareWallet>,
    no_cache: bool,
) -> Result<(), String> {
    let env = soroban_sdk::Env::default();
    match action {
        SasCommands::Get {
            contract_id,
            rpc_url,
        } => {
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let (human_msg, json_val) =
                cache::cached_or(&["sas-get-fee", &rpc_url, &contract_id], no_cache, || {
                    let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url.clone());
                    let client = soroban_sas_sdk::client::SASClient::new(contract_id.clone());
                    let fee = client.fetch_fee(&env, &rpc).map_err(|e| e.to_string())?;
                    Ok((fee_to_human(&fee), fee_to_json(&fee)))
                })?;
            emit_ok(output, || println!("{human_msg}"), json_val)
        }
        SasCommands::Set {
            token,
            amount,
            secret_key,
            network_passphrase,
            contract_id,
            rpc_url,
            dry_run,
        } => {
            validate_fee_amount(amount)?;
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            if dry_run {
                let result = client
                    .set_fee_dry_run(&env, &rpc, &seed, &token, amount)
                    .map_err(format_sas_admin_error)?;
                return print_dry_run_result(result, output);
            }
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let result = client
                .set_fee(&env, &rpc, &network_passphrase, &seed, &token, amount)
                .map_err(format_sas_admin_error)?;
            print_sas_fee_admin_result(result, output, Some((&token, amount)))
        }
        SasCommands::Clear {
            secret_key,
            network_passphrase,
            contract_id,
            rpc_url,
            dry_run,
        } => {
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            if dry_run {
                let result = client
                    .clear_fee_dry_run(&rpc, &seed)
                    .map_err(format_sas_admin_error)?;
                return print_dry_run_result(result, output);
            }
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let result = client
                .clear_fee(&env, &rpc, &network_passphrase, &seed)
                .map_err(format_sas_admin_error)?;
            print_sas_fee_admin_result(result, output, None)
        }
    }
}

fn validate_fee_amount(amount: i128) -> Result<(), String> {
    if amount <= 0 {
        Err("--amount must be greater than 0".to_string())
    } else {
        Ok(())
    }
}

fn format_sas_admin_error(error: soroban_sas_sdk::errors::SdkError) -> String {
    match error {
        soroban_sas_sdk::errors::SdkError::ContractError(301) => {
            "SASError::Unauthorized: caller is not the SAS admin".to_string()
        }
        other => other.to_string(),
    }
}

fn sas_fee_admin_output(
    result: &soroban_sas_sdk::rpc::GetTransactionResult,
    configured_fee: Option<(&str, i128)>,
) -> Result<(String, serde_json::Value), String> {
    if result.status != "SUCCESS" {
        return Err(format!(
            "SAS fee update failed with status {}",
            result.status
        ));
    }
    let hash = result
        .hash
        .as_deref()
        .ok_or_else(|| "successful SAS fee update returned no transaction hash".to_string())?;
    let human = match configured_fee {
        Some((token, amount)) => {
            format!("Fee set: {amount} of {token}\nTransaction hash: {hash}")
        }
        None => format!("Fee cleared — attestation is now fee-free\nTransaction hash: {hash}"),
    };
    Ok((human, serde_json::json!({ "tx_hash": hash })))
}

fn print_sas_fee_admin_result(
    result: soroban_sas_sdk::rpc::GetTransactionResult,
    output: OutputFormat,
    configured_fee: Option<(&str, i128)>,
) -> Result<(), String> {
    let (human, data) = sas_fee_admin_output(&result, configured_fee)?;
    emit_ok(output, || println!("{human}"), data)
}

/// Prints a [`soroban_sas_sdk::client::DryRunResult`] (issue #329's
/// `--dry-run`): no transaction was signed or submitted, so there is no
/// hash to report — only the simulated resource fee.
fn print_dry_run_result(
    result: soroban_sas_sdk::client::DryRunResult,
    output: OutputFormat,
) -> Result<(), String> {
    let human = format!(
        "Dry run: `{}` would succeed\nEstimated fee: {} stroops (simulated against ledger {})\nNo transaction was submitted.",
        result.function_name, result.total_fee, result.latest_ledger
    );
    let data = serde_json::json!({
        "dry_run": true,
        "function": result.function_name,
        "estimated_fee_stroops": result.total_fee,
        "min_resource_fee_stroops": result.min_resource_fee,
        "simulated_ledger": result.latest_ledger,
    });
    emit_ok(output, || println!("{human}"), data)
}

/// A CSV row that has passed every local check, ready to be submitted.
///
/// Holding the already-decoded UID and payload means the submission loop
/// never re-parses a row, and the pre-validation pass can prove the whole
/// file is issuable before the first transaction is built.
struct PreparedRow {
    line: usize,
    recipient: String,
    schema_uid: String,
    expiration: u64,
    revocable: bool,
    uid_hex: String,
    data_bytes: Vec<u8>,
}

/// Everything a single row submission needs that is fixed for the whole
/// batch, bundled so the per-row call site stays readable.
struct BulkContext<'a> {
    env: &'a soroban_sdk::Env,
    rpc: &'a soroban_sas_sdk::rpc::RpcClient,
    client: &'a soroban_sas_sdk::client::SASClient,
    network_passphrase: &'a str,
    seed: &'a [u8; 32],
    attester: &'a str,
    /// One ledger close time shared by every row in the run.
    issuance_time: u64,
}

/// Submits one already-validated row. Returns the attestation UID and the
/// transaction hash, or a human-readable reason it could not be issued.
fn submit_bulk_row(
    ctx: &BulkContext<'_>,
    row: &PreparedRow,
) -> Result<(String, Option<String>), String> {
    let input = offchain::AttestationInput {
        uid: row.uid_hex.clone(),
        schema_uid: row.schema_uid.clone(),
        time: ctx.issuance_time,
        expiration_time: row.expiration,
        ref_uid: hex::encode([0u8; 32]),
        recipient: row.recipient.clone(),
        attester: ctx.attester.to_string(),
        revocable: row.revocable,
        data: hex::encode(&row.data_bytes),
    };
    let attestation = offchain::parse_attestation(ctx.env, &input)?;

    let result = ctx
        .client
        .attest(
            ctx.env,
            ctx.rpc,
            ctx.network_passphrase,
            ctx.seed,
            attestation,
        )
        .map_err(|e| e.to_string())?;

    if result.status != "SUCCESS" {
        return Err(format!("attest failed with status {}", result.status));
    }

    Ok((row.uid_hex.clone(), result.hash))
}

fn run_attest(
    action: AttestCommands,
    output: OutputFormat,
    network: Option<String>,
    identity: Option<String>,
    hardware: Option<hardware::HardwareWallet>,
) -> Result<(), String> {
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
            allow_local_time,
            max_ledger_skew,
        } => {
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let schema_uid_bytes = parse_uid(&schema_uid)?;
            let data_bytes = decode_hex_or_base64(&data)?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let attester = stellar_strkey::ed25519::PublicKey(
                soroban_sas_sdk::signature::derive_public_key(&seed),
            )
            .to_string();
            // Before any RPC call (including the ledger-clock fetch below):
            // a missing/self recipient is a local input error (#304).
            offchain::validate_onchain_recipient(&env, &recipient, &attester)?;

            let local_now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("system clock error: {e}"))?;

            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);

            // Issuance time is the network ledger close time, not the local
            // clock (#172). The local clock is only a fallback the operator
            // must explicitly opt into with --allow-local-time.
            let issuance_time = resolve_cli_issuance_time(
                &rpc,
                local_now.as_secs(),
                max_ledger_skew,
                allow_local_time,
            )?;

            let uid = offchain::generate_uid(
                &env,
                &schema_uid_bytes,
                &recipient,
                &attester,
                &data_bytes,
            )?;

            let input = offchain::AttestationInput {
                uid: hex::encode(uid),
                schema_uid: schema_uid.clone(),
                time: issuance_time,
                expiration_time: expiration,
                ref_uid: hex::encode([0u8; 32]),
                recipient,
                attester,
                revocable,
                data: hex::encode(&data_bytes),
            };
            let attestation = offchain::parse_attestation(&env, &input)?;

            let result = client
                .attest(&env, &rpc, &network_passphrase, &seed, attestation)
                .map_err(|e| e.to_string())?;

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
                        "hash": result.hash,
                    }))
                    .map_err(|e| format!("serialization failed: {e}"))?
                ),
                OutputFormat::Human => {
                    println!("Attestation issued: {uid_hex}");
                    if let Some(hash) = &result.hash {
                        println!("Transaction hash:   {hash}");
                    }
                }
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
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let raw = io_safety::read_bounded(&data_file, io_safety::MAX_INPUT_FILE_BYTES)?;
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
            offchain::validate_onchain_parties(&env, &attestation)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            validate_expiration_before_submit(&rpc, &env, input.expiration_time)?;
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let result = client
                .attest(&env, &rpc, &network_passphrase, &seed, attestation)
                .map_err(|e| e.to_string())?;
            print_transaction_result(result, output)
        }
        AttestCommands::Bulk {
            csv_file,
            secret_key,
            network_passphrase,
            contract_id,
            rpc_url,
            dry_run,
            continue_on_error,
            allow_local_time,
            max_ledger_skew,
        } => {
            // Only the signing key is resolved up front: a dry run derives
            // UIDs locally, so it must work with no network configuration at
            // all. The RPC endpoint and network passphrase are resolved
            // after the dry-run exit below, since nothing is signed or sent
            // before then.
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;

            // Bounded read, same cap as every other file input (#176, #177).
            let raw = io_safety::read_bounded(&csv_file, io_safety::MAX_INPUT_FILE_BYTES)?;
            let rows = bulk::parse_bulk_csv(&raw)?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let attester = stellar_strkey::ed25519::PublicKey(
                soroban_sas_sdk::signature::derive_public_key(&seed),
            )
            .to_string();

            // Validate *every* row before submitting the first one. A typo in
            // the last line of a large file must not leave the operator with
            // a half-issued batch that they have to reconcile by hand.
            let mut prepared = Vec::with_capacity(rows.len());
            for row in &rows {
                let schema_uid_bytes = parse_uid(&row.schema_uid)
                    .map_err(|e| format!("line {}: schema_uid is invalid: {e}", row.line))?;
                let data_bytes = decode_hex_or_base64(&row.data)
                    .map_err(|e| format!("line {}: {e}", row.line))?;
                offchain::validate_onchain_recipient(&env, &row.recipient, &attester)
                    .map_err(|e| format!("line {}: {e}", row.line))?;
                let uid = offchain::generate_uid(
                    &env,
                    &schema_uid_bytes,
                    &row.recipient,
                    &attester,
                    &data_bytes,
                )
                .map_err(|e| format!("line {}: {e}", row.line))?;

                prepared.push(PreparedRow {
                    line: row.line,
                    recipient: row.recipient.clone(),
                    schema_uid: row.schema_uid.clone(),
                    expiration: row.expiration,
                    revocable: row.revocable,
                    uid_hex: hex::encode(uid),
                    data_bytes,
                });
            }

            // A dry run stops here: everything is validated and the plan is
            // known, but no transaction is built or submitted.
            if dry_run {
                let data = serde_json::json!({
                    "dry_run": true,
                    "total": prepared.len(),
                    "results": prepared
                        .iter()
                        .map(|p| serde_json::json!({
                            "line": p.line,
                            "recipient": p.recipient,
                            "schema_uid": p.schema_uid,
                            "uid": p.uid_hex,
                            "expiration": p.expiration,
                        }))
                        .collect::<Vec<_>>(),
                });
                return emit_ok(
                    output,
                    || {
                        println!(
                            "Dry run: {} row(s) validated, nothing submitted",
                            prepared.len()
                        );
                        for p in &prepared {
                            println!("  line {}: {} -> {}", p.line, p.recipient, p.uid_hex);
                        }
                    },
                    data,
                );
            }

            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;

            let local_now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("system clock error: {e}"))?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);

            // One issuance time for the whole batch: every row in a single
            // run is signed against the same ledger close, so a batch cannot
            // straddle a ledger boundary with mixed timestamps.
            let issuance_time = resolve_cli_issuance_time(
                &rpc,
                local_now.as_secs(),
                max_ledger_skew,
                allow_local_time,
            )?;

            let ctx = BulkContext {
                env: &env,
                rpc: &rpc,
                client: &client,
                network_passphrase: &network_passphrase,
                seed: &seed,
                attester: &attester,
                issuance_time,
            };

            let mut results: Vec<serde_json::Value> = Vec::with_capacity(prepared.len());
            let mut succeeded = 0usize;
            let mut failed = 0usize;
            let mut first_error: Option<String> = None;

            for p in &prepared {
                let outcome = submit_bulk_row(&ctx, p);

                match outcome {
                    Ok((uid_hex, hash)) => {
                        succeeded += 1;
                        results.push(serde_json::json!({
                            "line": p.line,
                            "status": "ok",
                            "recipient": p.recipient,
                            "uid": uid_hex,
                            "hash": hash,
                        }));
                    }
                    Err(message) => {
                        failed += 1;
                        // Rows are already fully validated, so a failure here
                        // is a chain-level rejection. Report the first one
                        // verbatim in the top-level message and the rest in
                        // the per-row results.
                        if first_error.is_none() {
                            first_error = Some(message.clone());
                        }
                        results.push(serde_json::json!({
                            "line": p.line,
                            "status": "error",
                            "recipient": p.recipient,
                            "uid": p.uid_hex,
                            "error": message,
                        }));
                        if !continue_on_error {
                            break;
                        }
                    }
                }
            }

            let data = serde_json::json!({
                "total": prepared.len(),
                "succeeded": succeeded,
                "failed": failed,
                "results": results,
            });

            if failed > 0 {
                let first = first_error.unwrap_or_default();
                emit_error(
                    output,
                    &format!(
                        "{failed} of {} attestation(s) failed; first error: {first}",
                        prepared.len()
                    ),
                );
                // Still print the per-row detail so the operator can see
                // which rows landed and which did not.
                if matches!(output, OutputFormat::Json) {
                    let envelope = serde_json::json!({
                        "status": "error",
                        "message": format!(
                            "{failed} of {} attestation(s) failed; first error: {first}",
                            prepared.len()
                        ),
                        "data": data,
                    });
                    if let Ok(text) = serde_json::to_string_pretty(&envelope) {
                        println!("{text}");
                    }
                }
                std::process::exit(1);
            }

            emit_ok(
                output,
                || {
                    println!("Issued {succeeded} attestation(s) from {}", csv_file);
                    for r in &results {
                        println!("  line {}: {} -> {}", r["line"], r["recipient"], r["uid"]);
                    }
                },
                data,
            )
        }
        AttestCommands::Revoke {
            uid,
            secret_key,
            network_passphrase,
            contract_id,
            rpc_url,
        } => {
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let uid = parse_uid(&uid)?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let result = client
                .revoke(&env, &rpc, &network_passphrase, &seed, &uid)
                .map_err(|e| e.to_string())?;
            print_transaction_result(result, output)
        }
        AttestCommands::Verify {
            uid,
            contract_id,
            rpc_url,
        } => {
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let uid = parse_uid(&uid)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let valid = client
                .verify_attestation(&env, &rpc, &uid)
                .map_err(|e| e.to_string())?;
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
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let old_uid = parse_uid(&old_uid)?;
            let raw = io_safety::read_bounded(&data_file, io_safety::MAX_INPUT_FILE_BYTES)?;
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
            offchain::validate_onchain_parties(&env, &new_data)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            validate_expiration_before_submit(&rpc, &env, input.expiration_time)?;
            let client = soroban_sas_sdk::client::SASClient::new(contract_id);
            let result = client
                .replace_attestation(&env, &rpc, &network_passphrase, &seed, &old_uid, new_data)
                .map_err(|e| e.to_string())?;
            print_transaction_result(result, output)
        }
    }
}

/// Rejects a JSON-supplied `expiration_time` that has already passed
/// against the network's ledger clock, before spending a submission
/// attempt (and fee) on a call the contract would reject as
/// `SASError::AlreadyExpired` anyway. `expiration_time == 0` (never
/// expires) always passes.
fn validate_expiration_before_submit(
    rpc: &soroban_sas_sdk::rpc::RpcClient,
    _env: &soroban_sdk::Env,
    expiration_time: u64,
) -> Result<(), String> {
    if expiration_time == 0 {
        return Ok(());
    }
    let ledger_time = rpc
        .fetch_current_ledger_time()
        .map_err(|e| format!("could not fetch network ledger time: {e:?}"))?;
    if expiration_time <= ledger_time {
        return Err(format!(
            "expiration_time {expiration_time} is already in the past (network ledger time {ledger_time})"
        ));
    }
    Ok(())
}

/// Resolves the timestamp a new attestation is issued with (#172).
///
/// Prefers the network ledger close time via [`RpcClient::get_latest_ledger_clock`],
/// validated against the local clock by
/// [`soroban_sas_sdk::rpc::resolve_issuance_time`]. Falls back to the local
/// clock only when `allow_local` is set; otherwise a fetch failure or an
/// out-of-range ledger time is a hard error telling the operator to retry or
/// pass `--allow-local-time`.
fn resolve_cli_issuance_time(
    rpc: &soroban_sas_sdk::rpc::RpcClient,
    local_now_secs: u64,
    max_skew_secs: u64,
    allow_local: bool,
) -> Result<u64, String> {
    match rpc.get_latest_ledger_clock() {
        Ok(clock) => {
            match soroban_sas_sdk::rpc::resolve_issuance_time(&clock, local_now_secs, max_skew_secs) {
                Ok(t) => Ok(t),
                Err(_) if allow_local => Ok(local_now_secs),
                Err(e) => Err(format!(
                    "network ledger time rejected ({e:?}); pass --allow-local-time to use the local clock"
                )),
            }
        }
        Err(_) if allow_local => Ok(local_now_secs),
        Err(e) => Err(format!(
            "could not fetch network ledger time ({e:?}); pass --allow-local-time to use the local clock"
        )),
    }
}

/// UID uniqueness entropy, deliberately independent of the semantic issuance
/// timestamp (#172). Mixes the local nanosecond reading with the process id
/// and a per-run counter, so two attestations issued in the same second — or
/// against a frozen clock — still get distinct UIDs.
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

/// Derives a schema's UID client-side, the same way the contract does,
/// so `register`/`register-with-value` can print it up front — before the
/// transaction even confirms — for use in a following `attest` call.
fn compute_schema_uid_hex(
    env: &soroban_sdk::Env,
    schema: &str,
    resolver: &str,
    revocable: bool,
) -> Result<String, String> {
    let resolver_addr = soroban_sas_sdk::strkey::parse_address(
        env,
        resolver,
        soroban_sas_sdk::strkey::AddressKind::Contract,
        "resolver",
    )
    .map_err(|e| e.to_string())?;
    let schema_val = soroban_sdk::String::from_str(env, schema);
    let uid = soroban_sas_common::schema_uid(env, &schema_val, &resolver_addr, revocable);
    Ok(hex::encode(uid.0.to_array()))
}

/// Like [`print_transaction_result`] but for a schema registration: prints
/// the schema's UID (computed locally, matching the contract) alongside
/// the transaction outcome, mirroring how `attest attest` surfaces its
/// generated attestation UID.
fn print_schema_registration_result(
    result: soroban_sas_sdk::rpc::GetTransactionResult,
    uid_hex: &str,
    output: OutputFormat,
) -> Result<(), String> {
    if result.status != "SUCCESS" {
        return Err(format!(
            "schema registration failed with status {}",
            result.status
        ));
    }
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "ok",
                "schema_uid": uid_hex,
                "hash": result.hash,
            }))
            .map_err(|e| format!("serialization failed: {e}"))?
        ),
        OutputFormat::Human => {
            println!("Schema registered: {uid_hex}");
            if let Some(hash) = &result.hash {
                println!("Transaction hash:  {hash}");
            }
        }
    }
    Ok(())
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
        "hash": result.hash,
        "envelopeXdr": result.envelope_xdr,
        "resultXdr": result.result_xdr,
    });
    let human_text =
        serde_json::to_string_pretty(&data).map_err(|e| format!("serialization failed: {e}"))?;
    emit_ok(output, || println!("{human_text}"), data.clone())
}

fn run_query(
    action: QueryCommands,
    output: OutputFormat,
    network: Option<String>,
) -> Result<(), String> {
    let env = soroban_sdk::Env::default();
    match action {
        QueryCommands::ByRecipient {
            address,
            contract_id,
            rpc_url,
            page,
        } => {
            let page = page.resolve()?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::IndexerClient::new(contract_id);
            let Some((cursor, limit)) = page else {
                let uids = client
                    .get_attestations_by_recipient(&env, &rpc, &address)
                    .map_err(|e| e.to_string())?;
                return print_uids(&uids, output);
            };
            let uids = client
                .get_attestations_by_recipient_paginated(&env, &rpc, &address, cursor, limit)
                .map_err(|e| e.to_string())?;
            let total = client
                .get_count_by_recipient(&env, &rpc, &address)
                .map_err(|e| e.to_string())?;
            print_page(None, &uids, cursor, limit, total, output)
        }
        QueryCommands::ByAttester {
            address,
            contract_id,
            rpc_url,
            page,
        } => {
            let page = page.resolve()?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::IndexerClient::new(contract_id);
            let Some((cursor, limit)) = page else {
                let uids = client
                    .get_attestations_by_attester(&env, &rpc, &address)
                    .map_err(|e| e.to_string())?;
                return print_attestations_by_attester(&address, &uids, output);
            };
            let uids = client
                .get_attestations_by_attester_paginated(&env, &rpc, &address, cursor, limit)
                .map_err(|e| e.to_string())?;
            let total = client
                .get_count_by_attester(&env, &rpc, &address)
                .map_err(|e| e.to_string())?;
            print_page(
                Some(("attester", &address)),
                &uids,
                cursor,
                limit,
                total,
                output,
            )
        }
        QueryCommands::BySchema {
            uid,
            contract_id,
            rpc_url,
            page,
        } => {
            let page = page.resolve()?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let schema_uid = parse_uid(&uid)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::IndexerClient::new(contract_id);
            let Some((cursor, limit)) = page else {
                let uids = client
                    .get_attestations_by_schema(&env, &rpc, &schema_uid)
                    .map_err(|e| e.to_string())?;
                return print_uids(&uids, output);
            };
            let uids = client
                .get_attestations_by_schema_paginated(&env, &rpc, &schema_uid, cursor, limit)
                .map_err(|e| e.to_string())?;
            let total = client
                .get_count_by_schema(&env, &rpc, &schema_uid)
                .map_err(|e| e.to_string())?;
            print_page(None, &uids, cursor, limit, total, output)
        }
    }
}

/// Renders one page of a `query by-* --cursor/--limit` result (#306).
///
/// `next_cursor` is `cursor + page.len()` while entries remain past this
/// page and `null` once the history is exhausted, so a caller loops until
/// it sees `null` and never skips or repeats a UID. `key` echoes the looked
/// up key where the unpaginated command already does (`by-attester`).
fn format_page(
    key: Option<(&str, &str)>,
    uids: &soroban_sdk::Vec<soroban_sas_common::UID>,
    cursor: u32,
    limit: u32,
    total: u32,
) -> (String, serde_json::Value) {
    let hex_uids: Vec<String> = uids
        .iter()
        .map(|uid| hex::encode(uid.0.to_array()))
        .collect();
    let end = cursor.saturating_add(uids.len());
    let next_cursor = (end < total).then_some(end);

    let mut human = if hex_uids.is_empty() {
        "No attestations found".to_string()
    } else {
        hex_uids.join("\n")
    };
    human.push('\n');
    if hex_uids.is_empty() {
        human.push_str(&format!(
            "Page: cursor {cursor} is past the end ({total} total)"
        ));
    } else {
        human.push_str(&format!("Page: {}-{end} of {total}", cursor + 1));
    }
    if let Some(next) = next_cursor {
        human.push_str(&format!(" (next: --cursor {next})"));
    }

    let mut data = serde_json::json!({
        "uids": hex_uids,
        "cursor": cursor,
        "limit": limit,
        "total": total,
        "next_cursor": next_cursor,
    });
    if let Some((name, value)) = key {
        data[name] = serde_json::Value::String(value.to_string());
    }
    (human, data)
}

fn print_page(
    key: Option<(&str, &str)>,
    uids: &soroban_sdk::Vec<soroban_sas_common::UID>,
    cursor: u32,
    limit: u32,
    total: u32,
    output: OutputFormat,
) -> Result<(), String> {
    let (human, data) = format_page(key, uids, cursor, limit, total);
    emit_ok(output, || println!("{human}"), data)
}

fn format_attestations_by_attester(
    attester: &str,
    uids: &soroban_sdk::Vec<soroban_sas_common::UID>,
) -> (String, serde_json::Value) {
    let hex_uids: Vec<String> = uids
        .iter()
        .map(|uid| hex::encode(uid.0.to_array()))
        .collect();
    let mut human = format!("Attestations found: {}", hex_uids.len());
    for uid in &hex_uids {
        human.push('\n');
        human.push_str(uid);
    }
    let data = serde_json::json!({
        "attester": attester,
        "uids": hex_uids,
    });
    (human, data)
}

fn print_attestations_by_attester(
    attester: &str,
    uids: &soroban_sdk::Vec<soroban_sas_common::UID>,
    output: OutputFormat,
) -> Result<(), String> {
    let (human, data) = format_attestations_by_attester(attester, uids);
    emit_ok(output, || println!("{human}"), data)
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

fn run_delegate(
    action: DelegateCommands,
    output: OutputFormat,
    network: Option<String>,
    identity: Option<String>,
    hardware: Option<hardware::HardwareWallet>,
) -> Result<(), String> {
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
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
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
                    io_safety::write_atomic_private(&path, &signed_json, false)?;
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
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let raw = io_safety::read_bounded(&file, io_safety::MAX_INPUT_FILE_BYTES)?;
            let signed: offchain::SignedOffchainAttestation = serde_json::from_str(&raw)
                .map_err(|e| format!("invalid signed attestation JSON: {e}"))?;
            offchain::verify_offchain_attestation(&signed)?;

            let attestation = offchain::parse_attestation(&env, &signed.attestation)?;
            offchain::validate_onchain_parties(&env, &attestation)?;
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
                .map_err(|e| e.to_string())?;
            print_transaction_result(result, output)
        }
        DelegateCommands::SubmitRevoke {
            file,
            secret_key,
            rpc_url,
        } => {
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let raw = io_safety::read_bounded(&file, io_safety::MAX_INPUT_FILE_BYTES)?;
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
                .map_err(|e| e.to_string())?;
            print_transaction_result(result, output)
        }
    }
}

fn run_schema(
    action: SchemaCommands,
    output: OutputFormat,
    network: Option<String>,
    identity: Option<String>,
    hardware: Option<hardware::HardwareWallet>,
    no_cache: bool,
) -> Result<(), String> {
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
            dry_run,
        } => {
            // #26 — validate locally before touching the network, so an empty
            // or oversized schema exits 1 with a clear message and never pays
            // for a simulation.
            validate_schema_syntax(&schema)?;
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
            if dry_run {
                let result = client
                    .register_schema_dry_run(
                        &env,
                        &rpc,
                        &seed,
                        &registry_contract_id,
                        &schema,
                        &resolver,
                        revocable,
                    )
                    .map_err(|e| e.to_string())?;
                return print_dry_run_result(result, output);
            }
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let uid_hex = compute_schema_uid_hex(&env, &schema, &resolver, revocable)?;
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
                .map_err(|e| e.to_string())?;
            print_schema_registration_result(result, &uid_hex, output)
        }
        SchemaCommands::Get {
            uid,
            registry_contract_id,
            rpc_url,
        } => {
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let uid_bytes = parse_uid(&uid)?;
            let (human, json_val) = cache::cached_or(
                &["schema-get", &rpc_url, &registry_contract_id, &uid],
                no_cache,
                || {
                    let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url.clone());
                    let client =
                        soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
                    let schema = client
                        .get_schema(&env, &rpc, &registry_contract_id, &uid_bytes)
                        .map_err(|e| e.to_string())?;
                    Ok(match schema {
                        None => (
                            "Schema not found".to_string(),
                            serde_json::json!({ "found": false }),
                        ),
                        Some(record) => {
                            let uid_hex = hex::encode(record.uid.0.to_array());
                            let resolver = soroban_string_to_std(&record.resolver.to_string());
                            let schema_str = soroban_string_to_std(&record.schema);
                            let revocable = record.revocable;
                            let human = format!(
                                "uid:       {uid_hex}\nresolver:  {resolver}\nrevocable: {revocable}\nschema:    {schema_str}"
                            );
                            let json_val = serde_json::json!({
                                "found": true,
                                "uid": uid_hex,
                                "resolver": resolver,
                                "revocable": revocable,
                                "schema": schema_str,
                            });
                            (human, json_val)
                        }
                    })
                },
            )?;
            emit_ok(output, || println!("{human}"), json_val)
        }
        SchemaCommands::GetByContent {
            schema,
            resolver,
            revocable,
            registry_contract_id,
            rpc_url,
        } => {
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let revocable_str = revocable.to_string();
            let (human, json_val) = cache::cached_or(
                &[
                    "schema-get-by-content",
                    &rpc_url,
                    &registry_contract_id,
                    &schema,
                    &resolver,
                    &revocable_str,
                ],
                no_cache,
                || {
                    let resolver_addr = soroban_sas_sdk::strkey::parse_address(
                        &env,
                        &resolver,
                        soroban_sas_sdk::strkey::AddressKind::Contract,
                        "resolver",
                    )
                    .map_err(|e| e.to_string())?;
                    let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url.clone());
                    let client =
                        soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
                    let schema_record = client
                        .get_schema_by_content(
                            &env,
                            &rpc,
                            &registry_contract_id,
                            &schema,
                            &resolver_addr,
                            revocable,
                        )
                        .map_err(|e| e.to_string())?;
                    Ok(match schema_record {
                        None => (
                            "Schema not found".to_string(),
                            serde_json::json!({ "found": false }),
                        ),
                        Some(record) => {
                            let uid_hex = hex::encode(record.uid.0.to_array());
                            let schema_str = soroban_string_to_std(&record.schema);
                            let revocable = record.revocable;
                            let human = format!(
                                "uid:       {uid_hex}\nrevocable: {revocable}\nschema:    {schema_str}"
                            );
                            let json_val = serde_json::json!({
                                "found": true,
                                "uid": uid_hex,
                                "revocable": revocable,
                                "schema": schema_str,
                            });
                            (human, json_val)
                        }
                    })
                },
            )?;
            emit_ok(output, || println!("{human}"), json_val)
        }
        SchemaCommands::RegisterWithValue {
            schema,
            resolver,
            revocable,
            token,
            value,
            secret_key,
            network_passphrase,
            registry_contract_id,
            rpc_url,
            dry_run,
        } => {
            validate_schema_syntax(&schema)?;
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
            if dry_run {
                let result = client
                    .register_schema_with_value_dry_run(
                        &env,
                        &rpc,
                        &seed,
                        &registry_contract_id,
                        &schema,
                        &resolver,
                        revocable,
                        &token,
                        value,
                    )
                    .map_err(|e| e.to_string())?;
                return print_dry_run_result(result, output);
            }
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let uid_hex = compute_schema_uid_hex(&env, &schema, &resolver, revocable)?;
            let result = client
                .register_schema_with_value(
                    &env,
                    &rpc,
                    &network_passphrase,
                    &seed,
                    &registry_contract_id,
                    &schema,
                    &resolver,
                    revocable,
                    &token,
                    value,
                )
                .map_err(|e| e.to_string())?;
            print_schema_registration_result(result, &uid_hex, output)
        }
        SchemaCommands::SetFee {
            token,
            amount,
            secret_key,
            network_passphrase,
            registry_contract_id,
            rpc_url,
            dry_run,
        } => {
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
            if dry_run {
                let result = client
                    .set_schema_fee_dry_run(
                        &env,
                        &rpc,
                        &seed,
                        &registry_contract_id,
                        &token,
                        amount,
                    )
                    .map_err(|e| e.to_string())?;
                return print_dry_run_result(result, output);
            }
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let result = client
                .set_schema_fee(
                    &env,
                    &rpc,
                    &network_passphrase,
                    &seed,
                    &registry_contract_id,
                    &token,
                    amount,
                )
                .map_err(|e| e.to_string())?;
            print_transaction_result(result, output)
        }
        SchemaCommands::ClearFee {
            secret_key,
            network_passphrase,
            registry_contract_id,
            rpc_url,
            dry_run,
        } => {
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
            if dry_run {
                let result = client
                    .clear_schema_fee_dry_run(&rpc, &seed, &registry_contract_id)
                    .map_err(|e| e.to_string())?;
                return print_dry_run_result(result, output);
            }
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let result = client
                .clear_schema_fee(
                    &env,
                    &rpc,
                    &network_passphrase,
                    &seed,
                    &registry_contract_id,
                )
                .map_err(|e| e.to_string())?;
            print_transaction_result(result, output)
        }
        SchemaCommands::SetTreasury {
            treasury,
            secret_key,
            network_passphrase,
            registry_contract_id,
            rpc_url,
            dry_run,
        } => {
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
            if dry_run {
                let result = client
                    .set_schema_treasury_dry_run(
                        &env,
                        &rpc,
                        &seed,
                        &registry_contract_id,
                        &treasury,
                    )
                    .map_err(|e| e.to_string())?;
                return print_dry_run_result(result, output);
            }
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let result = client
                .set_schema_treasury(
                    &env,
                    &rpc,
                    &network_passphrase,
                    &seed,
                    &registry_contract_id,
                    &treasury,
                )
                .map_err(|e| e.to_string())?;
            print_transaction_result(result, output)
        }
        SchemaCommands::WithdrawFees {
            amount,
            secret_key,
            network_passphrase,
            registry_contract_id,
            rpc_url,
            dry_run,
        } => {
            validate_fee_amount(amount)?;
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let seed = offchain::parse_secret_seed(&secret_key)?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url);
            let client = soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
            if dry_run {
                let result = client
                    .withdraw_schema_fees_dry_run(&env, &rpc, &seed, &registry_contract_id, amount)
                    .map_err(|e| e.to_string())?;
                return print_dry_run_result(result, output);
            }
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let result = client
                .withdraw_schema_fees(
                    &env,
                    &rpc,
                    &network_passphrase,
                    &seed,
                    &registry_contract_id,
                    amount,
                )
                .map_err(|e| e.to_string())?;
            print_transaction_result(result, output)
        }
        SchemaCommands::GetFee {
            registry_contract_id,
            rpc_url,
        } => {
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let (human, json_val) = cache::cached_or(
                &["schema-get-fee", &rpc_url, &registry_contract_id],
                no_cache,
                || {
                    let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url.clone());
                    let client =
                        soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
                    let fee = client
                        .get_schema_fee(&env, &rpc, &registry_contract_id)
                        .map_err(|e| e.to_string())?;
                    Ok(match fee {
                        None => (
                            "No fee configured — registration is free.".to_string(),
                            serde_json::json!({ "configured": false }),
                        ),
                        Some((token, amount)) => {
                            let token_str = soroban_string_to_std(&token.to_string());
                            let human = format!("token:  {token_str}\namount: {amount}");
                            let json_val = serde_json::json!({
                                "configured": true,
                                "token": token_str,
                                "amount": amount.to_string(),
                            });
                            (human, json_val)
                        }
                    })
                },
            )?;
            emit_ok(output, || println!("{human}"), json_val)
        }
        SchemaCommands::GetTreasury {
            registry_contract_id,
            rpc_url,
        } => {
            let rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let (human, json_val) = cache::cached_or(
                &["schema-get-treasury", &rpc_url, &registry_contract_id],
                no_cache,
                || {
                    let rpc = soroban_sas_sdk::rpc::RpcClient::new(rpc_url.clone());
                    let client =
                        soroban_sas_sdk::client::SASClient::new(registry_contract_id.clone());
                    let treasury = client
                        .get_schema_treasury(&env, &rpc, &registry_contract_id)
                        .map_err(|e| e.to_string())?;
                    Ok(match treasury {
                        None => (
                            "No treasury configured.".to_string(),
                            serde_json::json!({ "configured": false }),
                        ),
                        Some(addr) => {
                            let addr_str = soroban_string_to_std(&addr.to_string());
                            let human = format!("treasury: {addr_str}");
                            let json_val =
                                serde_json::json!({ "configured": true, "treasury": addr_str });
                            (human, json_val)
                        }
                    })
                },
            )?;
            emit_ok(output, || println!("{human}"), json_val)
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

fn run_offchain(
    action: OffchainCommands,
    output: OutputFormat,
    network: Option<String>,
    identity: Option<String>,
    hardware: Option<hardware::HardwareWallet>,
) -> Result<(), String> {
    match action {
        OffchainCommands::Sign {
            data_file,
            secret_key,
            nonce,
            network_passphrase,
            contract_id,
            out_file,
        } => {
            let secret_key = resolve_secret_key(secret_key, identity.as_deref(), hardware)?;
            let network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let raw = io_safety::read_bounded(&data_file, io_safety::MAX_INPUT_FILE_BYTES)?;
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
            match out_file {
                Some(path) => {
                    io_safety::write_atomic_private(&path, &signed_json, false)?;
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
        OffchainCommands::Verify {
            file,
            online,
            contract_id,
            network_passphrase,
            registry_contract_id,
            rpc_url,
        } => {
            let raw = io_safety::read_bounded(&file, io_safety::MAX_INPUT_FILE_BYTES)?;
            let signed: offchain::SignedOffchainAttestation = serde_json::from_str(&raw)
                .map_err(|e| format!("invalid signed attestation JSON: {e}"))?;
            // Cryptographic checks only: signature, attester binding, payload
            // hash. Runs regardless of `--online` — the online checks below
            // only ever add to this, never replace it.
            offchain::verify_offchain_attestation(&signed)?;

            if !online {
                return emit_ok(
                    output,
                    || {
                        println!("Cryptographic checks passed: signature, attester binding, and payload hash.");
                        println!(
                            "This does NOT confirm expiration, revocation, schema availability, \
                             or on-chain status — pass --online to check those."
                        );
                    },
                    serde_json::json!({
                        "signature_valid": true,
                        "online_checks_performed": false,
                    }),
                );
            }

            // Online mode: the trust target is *only* ever the network/rpc
            // this process was told to use (via these flags or --network) —
            // the file's embedded `network_passphrase`/`contract_id` are
            // untrusted input, compared against that target below, never
            // used to select it (issue #175's "embedded values cannot
            // silently choose the verifier's trust target").
            let trusted_network_passphrase =
                resolve_network_passphrase(network_passphrase, network.as_deref())?;
            let trusted_rpc_url = resolve_rpc_url(rpc_url, network.as_deref())?;
            let trusted_contract_id = contract_id.ok_or_else(|| {
                "--online requires --contract-id (or SAS_CONTRACT_ID) naming the trusted \
                 SAS contract to verify against"
                    .to_string()
            })?;
            let rpc = soroban_sas_sdk::rpc::RpcClient::new(trusted_rpc_url);

            let report = perform_online_verification(
                &signed,
                &trusted_network_passphrase,
                &trusted_contract_id,
                registry_contract_id.as_deref(),
                &rpc,
            )?;

            emit_ok(
                output,
                || {
                    println!(
                        "Cryptographic checks: signature, attester binding, payload hash — valid"
                    );
                    println!(
                        "Network matches trusted target: {} (trusted: {trusted_network_passphrase})",
                        report.network_matches_trusted
                    );
                    println!(
                        "Contract matches trusted target: {} (trusted: {trusted_contract_id})",
                        report.contract_matches_trusted
                    );
                    println!(
                        "On-chain: found={} expired={} revoked={}",
                        report.on_chain_found, report.expired, report.revoked
                    );
                    println!("Schema availability: {}", report.schema_status);
                    println!(
                        "Overall: {}",
                        if report.overall_valid {
                            "VALID"
                        } else {
                            "NOT VALID"
                        }
                    );
                },
                serde_json::json!({
                    "signature_valid": true,
                    "online_checks_performed": true,
                    "network_matches_trusted_target": report.network_matches_trusted,
                    "contract_matches_trusted_target": report.contract_matches_trusted,
                    "on_chain_found": report.on_chain_found,
                    "expired": report.expired,
                    "revoked": report.revoked,
                    "schema_status": report.schema_status,
                    "overall_valid": report.overall_valid,
                }),
            )
        }
    }
}

/// Result of `--online` protocol-status verification (issue #175). Every
/// guarantee is a separate field so callers (and `--output json`) can see
/// exactly what was and wasn't checked, rather than a single opaque bool.
struct OnlineVerificationReport {
    /// Whether the signed file's embedded `network_passphrase` matches the
    /// caller's trusted target — never the other way around.
    network_matches_trusted: bool,
    /// Whether the signed file's embedded `contract_id` matches the
    /// caller's trusted target — never the other way around.
    contract_matches_trusted: bool,
    /// Whether the attestation's UID is currently recorded on the trusted
    /// contract (as opposed to only ever having been signed off-chain).
    on_chain_found: bool,
    expired: bool,
    revoked: bool,
    /// `"available"`, `"not_found"`, or `"not_checked"` (no
    /// `--registry-contract-id` given).
    schema_status: &'static str,
    /// Conjunction of every check above — `false` if any one of them is.
    overall_valid: bool,
}

/// Performs every `--online` check against `trusted_contract_id` /
/// `trusted_network_passphrase` / `rpc` — values the caller supplied
/// directly, never read from `signed` itself. `signed`'s own
/// `network_passphrase` / `contract_id` are compared against that trusted
/// target, not used to pick it (issue #175).
fn perform_online_verification(
    signed: &offchain::SignedOffchainAttestation,
    trusted_network_passphrase: &str,
    trusted_contract_id: &str,
    registry_contract_id: Option<&str>,
    rpc: &soroban_sas_sdk::rpc::RpcClient,
) -> Result<OnlineVerificationReport, String> {
    let env = soroban_sdk::Env::default();
    let uid_bytes = parse_uid(&signed.attestation.uid)?;
    let client = soroban_sas_sdk::client::SASClient::new(trusted_contract_id.to_string());

    let network_matches_trusted = signed.network_passphrase == trusted_network_passphrase;
    let contract_matches_trusted = signed.contract_id == trusted_contract_id;

    let attestation = client.get_attestation(&env, rpc, &uid_bytes).map_err(|e| {
        format!("online verification failed while fetching the attestation from the trusted contract: {e}")
    })?;
    let (on_chain_found, expired, revoked) = match &attestation {
        Some(att) => {
            let ledger_time = rpc.fetch_current_ledger_time().map_err(|e| {
                format!("online verification failed while fetching ledger time: {e}")
            })?;
            let expired = att.expiration_time != 0 && ledger_time >= att.expiration_time;
            let revoked = att.revocation_time != 0;
            (true, expired, revoked)
        }
        None => (false, false, false),
    };

    let schema_status = match registry_contract_id {
        Some(registry_id) => {
            let schema_uid = parse_uid(&signed.attestation.schema_uid)?;
            match client.get_schema(&env, rpc, registry_id, &schema_uid) {
                Ok(Some(_)) => "available",
                Ok(None) => "not_found",
                Err(e) => {
                    return Err(format!(
                        "online verification failed while fetching the schema: {e}"
                    ))
                }
            }
        }
        None => "not_checked",
    };

    let overall_valid = network_matches_trusted
        && contract_matches_trusted
        && on_chain_found
        && !expired
        && !revoked
        && schema_status != "not_found";

    Ok(OnlineVerificationReport {
        network_matches_trusted,
        contract_matches_trusted,
        on_chain_found,
        expired,
        revoked,
        schema_status,
        overall_valid,
    })
}

#[cfg(test)]
mod test;
