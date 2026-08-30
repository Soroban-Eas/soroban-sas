use soroban_sas_common::Attestation;
use soroban_sas_sdk::attestation_builder::AttestationRequestBuilder;
use soroban_sas_sdk::client::{FeePolicy, SASClient};
use soroban_sas_sdk::rpc::RpcClient;
use soroban_sas_sdk::signature::derive_public_key;
use soroban_sas_sdk::simulate;
use soroban_sdk::{Address, Bytes, BytesN, Env, String as SorobanString};

const HELP: &str = r#"basic_attestation — demonstrates constructing and optionally submitting an attestation.

USAGE:
    cargo run --example basic_attestation [OPTIONS]

OPTIONS:
    --help                Show this help message
    --submit              Submit the attestation to Testnet (requires env vars below)

CONFIGURATION (required for --submit):
    SAS_CONTRACT_ID       Soroban contract ID (strkey C...)
    NETWORK_PASSPHRASE    Stellar network passphrase
    SECRET_SEED           ed25519 secret seed (strkey S...) or hex-encoded 32 bytes
    RPC_URL               Soroban RPC endpoint (default: https://soroban-testnet.stellar.org)
    RECIPIENT             Recipient address (strkey G... or C...)
    SCHEMA_UID            32-byte schema UID as hex
    ATTESTER              Attester address (strkey G...)

EXAMPLES:
    # Dry-run (no network, no credentials required):
    cargo run --example basic_attestation

    # Submit to Testnet:
    SAS_CONTRACT_ID=C... NETWORK_PASSPHRASE=... SECRET_SEED=S... \
    RECIPIENT=G... SCHEMA_UID=<hex> ATTESTER=G... \
    cargo run --example basic_attestation -- --submit
"#;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        print!("{HELP}");
        return;
    }

    let submit = args.contains(&"--submit".to_string());

    let env = Env::default();

    // --- Dry-run: build an attestation and hash it (no network needed) ---
    let schema_uid_hex = env_or("SCHEMA_UID", "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233");
    let schema_uid = hex_decode_32(&schema_uid_hex, "SCHEMA_UID");
    let recipient = env_or("RECIPIENT", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF");
    let attester = env_or("ATTESTER", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF");

    let attestation = AttestationRequestBuilder::new()
        .with_schema_uid(schema_uid)
        .with_recipient(&recipient)
        .with_attester(&attester)
        .with_data(Bytes::new(&env))
        .build(&env)
        .expect("failed to build attestation");

    eprintln!("Dry-run: built attestation");
    eprintln!("  UID:        {}", hex::encode(attestation.uid.0.to_array()));
    eprintln!("  Schema UID: {}", hex::encode(attestation.schema_uid.0.to_array()));
    eprintln!("  Attester:   {}", attester);
    eprintln!("  Recipient:  {}", recipient);

    // Demonstrate the typed-data hash path (same digest the contract verifies).
    let network_passphrase = env_or("NETWORK_PASSPHRASE", "Test SDF Network ; September 2015");
    let contract_id = env_or("SAS_CONTRACT_ID", "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4");
    let network_id = env
        .crypto()
        .sha256(&soroban_sdk::Bytes::from_slice(
            &env,
            network_passphrase.as_bytes(),
        ));
    let domain = soroban_sas_common::AttestationDomain {
        network_id,
        contract: Address::from_string(&SorobanString::from_str(&env, &contract_id)),
        nonce: 0,
    };
    let digest = soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain);
    eprintln!("  Payload hash: {}", hex::encode(digest.to_array()));

    if !submit {
        eprintln!("\nDry-run complete. Pass --submit to send to Testnet.");
        return;
    }

    // --- Live submission ---
    let rpc_url = env_or("RPC_URL", "https://soroban-testnet.stellar.org");
    let secret_seed_hex = std::env::var("SECRET_SEED").expect("SECRET_SEED is required for --submit");
    let secret_seed = parse_secret_seed(&secret_seed_hex);

    // Verify attester matches the signing key.
    let public_key = derive_public_key(&secret_seed);
    let expected_attester = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    if attester != expected_attester {
        eprintln!("Error: ATTESTER ({attester}) does not match SECRET_SEED account ({expected_attester})");
        std::process::exit(1);
    }

    let rpc = RpcClient::new(rpc_url);
    let client = SASClient::new(contract_id);

    eprintln!("Submitting attestation to Testnet...");
    match client.attest(&env, &rpc, &network_passphrase, &secret_seed, attestation) {
        Ok(result) => {
            eprintln!("Success! Transaction hash: {}", result.hash);
        }
        Err(e) => {
            eprintln!("Submission failed: {e}");
            std::process::exit(1);
        }
    }
}

fn hex_decode_32(hex_str: &str, field: &str) -> [u8; 32] {
    let cleaned = hex_str.trim_start_matches("0x");
    let bytes = hex::decode(cleaned).unwrap_or_else(|e| {
        panic!("invalid hex in {field}: {e}");
    });
    bytes.try_into().unwrap_or_else(|_| {
        panic!("{field} must be exactly 32 bytes");
    })
}

fn parse_secret_seed(value: &str) -> [u8; 32] {
    let trimmed = value.trim();
    if trimmed.starts_with('S') {
        let key = stellar_strkey::ed25519::PrivateKey::from_string(trimmed)
            .expect("invalid secret seed strkey");
        key.0
    } else {
        hex_decode_32(trimmed, "SECRET_SEED")
    }
}
