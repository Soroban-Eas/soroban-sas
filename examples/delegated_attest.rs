// Delegated attestation: the attester signs a typed-data hash off-chain, and
// any funded relayer account submits it via `SAS::attest_by_delegation`,
// paying the fee without ever holding the attester's key.

use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{hash_offchain_attestation, AttestationDomain};
use soroban_sas_sdk::attestation_builder::AttestationRequestBuilder;
use soroban_sas_sdk::client::SASClient;
use soroban_sas_sdk::rpc::RpcClient;
use soroban_sdk::{Address, Bytes, Env, String as SorobanString};

const HELP: &str = r#"delegated_attest — signs a delegated attestation and relays it via SAS::attest_by_delegation.
USAGE: cargo run --example delegated_attest -- [OPTIONS]
OPTIONS:
    --help                  Show this help message
    --dry-run               Sign the payload and print it, no network call (default)
    --rpc-url <URL>         Soroban RPC endpoint (default: https://soroban-testnet.stellar.org)
    --secret-key <SEED>     Attester's ed25519 secret seed (strkey S...), signs but does not pay
    --relayer-key <SEED>    Relayer's ed25519 secret seed (strkey S...), submits and pays
ENV (for a live submission): SAS_CONTRACT_ID, NETWORK_PASSPHRASE, SCHEMA_UID, RECIPIENT
"#;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return;
    }

    let attester_key = flag_value(&args, "--secret-key");
    let relayer_key = flag_value(&args, "--relayer-key");
    let dry_run = args.iter().any(|a| a == "--dry-run") || attester_key.is_none();
    let rpc_url =
        flag_value(&args, "--rpc-url").unwrap_or_else(|| "https://soroban-testnet.stellar.org".to_string());
    let env = Env::default();

    // Step 1: derive the attester's signing key, or a fixed demo seed.
    let attester_seed = attester_key
        .as_deref()
        .map(parse_secret_seed)
        .unwrap_or([7u8; 32]);
    let signing_key = SigningKey::from_bytes(&attester_seed);
    let attester_pubkey = signing_key.verifying_key().to_bytes();
    let attester = stellar_strkey::ed25519::PublicKey(attester_pubkey).to_string();

    // Step 2: build the attestation the attester wants to issue.
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
    let attestation = AttestationRequestBuilder::new()
        .with_schema_uid(schema_uid)
        .with_recipient(&recipient)
        .with_attester(&attester)
        .with_data(Bytes::new(&env))
        .build(&env)
        .expect("failed to build attestation");

    // Step 3: hash the typed-data payload; network id + contract + nonce
    // bind the signature to one contract instance and replay-protect it.
    let network_passphrase = env_or("NETWORK_PASSPHRASE", "Test SDF Network ; September 2015");
    let contract_id = env_or(
        "SAS_CONTRACT_ID",
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    );
    let nonce: u64 = 0;
    let network_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, network_passphrase.as_bytes()));
    let domain = AttestationDomain {
        network_id: network_id.into(),
        contract: Address::from_string(&SorobanString::from_str(&env, &contract_id)),
        nonce,
    };
    let digest = hash_offchain_attestation(&env, &attestation, &domain);

    // Step 4: the attester signs the digest. The contract checks this
    // signature, not `require_auth()`, so the relayer never needs the key.
    let signature = signing_key.sign(&digest.to_array());

    eprintln!("Delegated attestation payload:");
    eprintln!("  UID: {}", hex::encode(attestation.uid.0.to_array()));
    eprintln!("  Attester: {attester}  Nonce: {nonce}");
    eprintln!("  Digest: {}", hex::encode(digest.to_array()));
    eprintln!("  Signature: {}", hex::encode(signature.to_bytes()));

    if dry_run {
        eprintln!("\nDry-run complete. Pass --secret-key S... and --relayer-key S... to relay it.");
        return;
    }

    // Step 5: a funded relayer submits the signed payload and pays the fee.
    let relayer_seed =
        parse_secret_seed(relayer_key.as_deref().expect("--relayer-key is required to submit"));
    let rpc = RpcClient::new(rpc_url);
    let client = SASClient::new(contract_id);

    eprintln!("Relaying via SAS::attest_by_delegation...");
    match client.attest_by_delegation(
        &env,
        &rpc,
        &network_passphrase,
        &relayer_seed,
        attestation,
        nonce,
        &signature.to_bytes(),
        &attester_pubkey,
    ) {
        Ok(result) => {
            eprintln!(
                "Success! Transaction hash: {}",
                result.hash.as_deref().unwrap_or("<unknown>")
            );
        }
        Err(e) => {
            eprintln!("Relay failed: {e}");
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
    bytes.try_into().unwrap_or_else(|_| panic!("{field} must be exactly 32 bytes"))
}

fn parse_secret_seed(value: &str) -> [u8; 32] {
    let trimmed = value.trim();
    if trimmed.starts_with('S') {
        stellar_strkey::ed25519::PrivateKey::from_string(trimmed).expect("invalid secret seed strkey").0
    } else {
        hex_decode_32(trimmed, "secret seed")
    }
}
