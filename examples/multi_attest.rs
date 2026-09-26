// Batch attestation issuance via `SASClient::multi_attest`: builds a
// `Vec<Attestation>` and submits it as one call, which either commits every
// item or rolls the whole call back (see docs/events.md's `BatchAttested`).

use soroban_sas_sdk::attestation_builder::AttestationRequestBuilder;
use soroban_sas_sdk::client::SASClient;
use soroban_sas_sdk::rpc::RpcClient;
use soroban_sas_sdk::signature::derive_public_key;
use soroban_sdk::{Bytes, Env};

const HELP: &str = r#"multi_attest — batch-issues attestations in one SAS::multi_attest call.
USAGE: cargo run --example multi_attest -- [OPTIONS]
OPTIONS:
    --help                Show this help message
    --dry-run             Build the batch and print UIDs, no network call (default)
    --rpc-url <URL>       Soroban RPC endpoint (default: https://soroban-testnet.stellar.org)
    --secret-key <SEED>   ed25519 secret seed (strkey S...) paying for the batch
ENV (for a live submission): SAS_CONTRACT_ID, NETWORK_PASSPHRASE, SCHEMA_UID, RECIPIENT
"#;

/// How many attestations to pack into the demo batch.
const BATCH_SIZE: usize = 3;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return;
    }

    // No key means dry-run: never block on a live network or funded account.
    let dry_run = args.iter().any(|a| a == "--dry-run") || !args.iter().any(|a| a == "--secret-key");
    let rpc_url = flag_value(&args, "--rpc-url")
        .unwrap_or_else(|| "https://soroban-testnet.stellar.org".to_string());
    let secret_key = flag_value(&args, "--secret-key");

    let env = Env::default();

    // Step 1: a shared schema/recipient; each item differs only in `data`,
    // which feeds the content-addressed UID.
    let schema_uid = hex_decode_32(
        &env_or(
            "SCHEMA_UID",
            "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
        ),
        "SCHEMA_UID",
    );
    let recipient = env_or(
        "RECIPIENT",
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );

    // Step 2: derive the attester from the signing key, or a placeholder.
    let attester = match &secret_key {
        Some(seed_str) => {
            let seed = parse_secret_seed(seed_str);
            let public_key = derive_public_key(&seed);
            stellar_strkey::ed25519::PublicKey(public_key).to_string()
        }
        None => env_or(
            "ATTESTER",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        ),
    };

    // Step 3: build the batch; each `data` embeds its index for a distinct UID.
    let mut attestations = Vec::with_capacity(BATCH_SIZE);
    for i in 0..BATCH_SIZE {
        let mut data = [0u8; 32];
        data[31] = i as u8;
        let attestation = AttestationRequestBuilder::new()
            .with_schema_uid(schema_uid)
            .with_recipient(&recipient)
            .with_attester(&attester)
            .with_data(Bytes::from_array(&env, &data))
            .build(&env)
            .unwrap_or_else(|e| panic!("failed to build attestation #{i}: {e}"));
        attestations.push(attestation);
    }

    eprintln!("Built a batch of {} attestations:", attestations.len());
    for (i, a) in attestations.iter().enumerate() {
        eprintln!("  [{i}] UID: {}", hex::encode(a.uid.0.to_array()));
    }

    if dry_run {
        eprintln!("\nDry-run complete. Pass --secret-key S... to submit the batch.");
        return;
    }

    // Step 4: submit the whole batch as one `multi_attest` call (atomic).
    let contract_id = std::env::var("SAS_CONTRACT_ID")
        .expect("SAS_CONTRACT_ID is required to submit (or pass --dry-run)");
    let network_passphrase =
        env_or("NETWORK_PASSPHRASE", "Test SDF Network ; September 2015");
    let seed = parse_secret_seed(secret_key.as_deref().unwrap());

    let rpc = RpcClient::new(rpc_url);
    let client = SASClient::new(contract_id);

    eprintln!("Submitting batch via SAS::multi_attest...");
    match client.multi_attest(&env, &rpc, &network_passphrase, &seed, attestations) {
        Ok(result) => {
            eprintln!(
                "Success! Transaction hash: {}",
                result.hash.as_deref().unwrap_or("<unknown>")
            );
        }
        Err(e) => {
            // A batch either commits in full or not at all: a submission
            // failure here means none of the printed UIDs were issued.
            eprintln!("Batch submission failed, no attestations were issued: {e}");
            std::process::exit(1);
        }
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn hex_decode_32(hex_str: &str, field: &str) -> [u8; 32] {
    let cleaned = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(cleaned).unwrap_or_else(|e| panic!("invalid hex in {field}: {e}"));
    bytes
        .try_into()
        .unwrap_or_else(|_| panic!("{field} must be exactly 32 bytes"))
}

fn parse_secret_seed(value: &str) -> [u8; 32] {
    let trimmed = value.trim();
    if trimmed.starts_with('S') {
        stellar_strkey::ed25519::PrivateKey::from_string(trimmed)
            .expect("invalid secret seed strkey")
            .0
    } else {
        hex_decode_32(trimmed, "--secret-key")
    }
}
