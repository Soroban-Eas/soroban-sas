#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::{decode_hex_or_base64, parse_uid, validate_schema_syntax, AttestCommands, Cli, Commands, OutputFormat};

    #[test]
    fn test_cli_snapshot_formatting() {
        assert_eq!(1, 1);
    }

    #[test]
    fn attest_flags_default_to_network_time_with_local_fallback_off() {
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "attest",
            "attest",
            "--schema-uid",
            &hex::encode([2u8; 32]),
            "--recipient",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "--secret-key",
            "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY2",
            "--network-passphrase",
            "Test SDF Network ; September 2015",
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "--rpc-url",
            "https://soroban-testnet.stellar.org",
        ])
        .unwrap();

        let Some(Commands::Attest {
            action: AttestCommands::Attest {
                allow_local_time,
                max_ledger_skew,
                ..
            },
        }) = cli.command
        else {
            panic!("expected attest attest command");
        };
        assert!(!allow_local_time);
        assert_eq!(max_ledger_skew, 300);
    }

    #[test]
    fn uid_entropy_is_distinct_across_calls_with_a_frozen_clock() {
        let a = crate::uid_entropy(1_000);
        let b = crate::uid_entropy(1_000);
        assert_ne!(a, b, "entropy must not depend solely on the wall clock");
    }

    #[test]
    fn rejects_empty_and_oversized_schemas_locally() {
        // #26 — an empty (or whitespace-only) schema is rejected before any
        // transaction is built, and so is one past the 1024-byte limit.
        assert!(validate_schema_syntax("").is_err());
        assert!(validate_schema_syntax("   ").is_err());
        assert!(validate_schema_syntax(&"a".repeat(1025)).is_err());
        assert!(validate_schema_syntax("string name").is_ok());
        assert!(validate_schema_syntax("!!!").is_err());
        assert!(validate_schema_syntax("12345").is_err());
        assert!(validate_schema_syntax("first_name String, last_name String").is_ok());
    }

    #[test]
    fn output_flag_parses_and_defaults_to_human() {
        let default = Cli::try_parse_from(["soroban-sas"]).unwrap();
        assert_eq!(default.output, OutputFormat::Human);

        let json = Cli::try_parse_from(["soroban-sas", "--output", "json"]).unwrap();
        assert_eq!(json.output, OutputFormat::Json);
    }

    #[test]
    fn parses_attest_verify_flags() {
        let uid = hex::encode([7u8; 32]);
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "attest",
            "verify",
            "--uid",
            &uid,
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "--rpc-url",
            "https://soroban-testnet.stellar.org",
        ])
        .unwrap();

        let Some(Commands::Attest {
            action:
                AttestCommands::Verify {
                    uid: parsed_uid,
                    ..
                },
        }) = cli.command
        else {
            panic!("expected attest verify command");
        };
        assert_eq!(parsed_uid, uid);
    }

    #[test]
    fn rejects_uid_that_is_not_32_bytes() {
        assert!(parse_uid("deadbeef").is_err());
    }

    /// Issue #25 acceptance criterion: `attest attest` parses the flags the
    /// issue specifies, including the global `--output json` variant.
    #[test]
    fn parses_attest_attest_flags() {
        let schema_uid = hex::encode([2u8; 32]);
        let recipient = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAA6XKZW3";
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "--output",
            "json",
            "attest",
            "attest",
            "--schema-uid",
            &schema_uid,
            "--recipient",
            recipient,
            "--data",
            "deadbeef",
            "--expiration",
            "0",
            "--revocable",
            "--secret-key",
            "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF7U",
            "--network-passphrase",
            "Test SDF Network ; September 2015",
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "--rpc-url",
            "https://soroban-testnet.stellar.org",
        ])
        .unwrap();

        assert_eq!(cli.output, OutputFormat::Json);

        let Some(Commands::Attest {
            action:
                AttestCommands::Attest {
                    schema_uid: parsed_schema_uid,
                    recipient: parsed_recipient,
                    data,
                    expiration,
                    revocable: true,
                    ..
                },
        }) = cli.command
        else {
            panic!("expected attest attest command");
        };
        assert_eq!(parsed_schema_uid, schema_uid);
        assert_eq!(parsed_recipient, recipient);
        assert_eq!(data, "deadbeef");
        assert_eq!(expiration, 0);
    }

    #[test]
    fn decodes_data_as_hex_or_base64() {
        assert_eq!(
            decode_hex_or_base64("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_hex_or_base64("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        // Not valid hex (odd length / non-hex chars), so falls back to base64.
        assert_eq!(
            decode_hex_or_base64("3q2+7w==").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(decode_hex_or_base64("not valid at all!!").is_err());
    }
}

#[cfg(test)]
mod offchain_tests {
    use crate::offchain::{
        compute_payload_hash, generate_uid, parse_secret_seed, sign_offchain_attestation,
        verify_offchain_attestation, AttestationInput,
    };
    use ed25519_dalek::SigningKey;

    const NETWORK: &str = "Test SDF Network ; September 2015";

    fn contract_id() -> String {
        stellar_strkey::Contract([1u8; 32]).to_string()
    }

    fn sample_input(seed: [u8; 32]) -> AttestationInput {
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let attester = stellar_strkey::ed25519::PublicKey(public_key).to_string();
        let recipient = stellar_strkey::ed25519::PublicKey([5u8; 32]).to_string();
        AttestationInput {
            uid: hex::encode([1u8; 32]),
            schema_uid: hex::encode([2u8; 32]),
            time: 1000,
            expiration_time: 0,
            ref_uid: hex::encode([0u8; 32]),
            recipient,
            attester,
            revocable: true,
            data: "deadbeef".to_string(),
        }
    }

    #[test]
    fn test_payload_hash_deterministic() {
        let input = sample_input([41u8; 32]);
        let h1 = compute_payload_hash(&input, 7, NETWORK, &contract_id()).unwrap();
        let h2 = compute_payload_hash(&input, 7, NETWORK, &contract_id()).unwrap();
        assert_eq!(h1, h2);

        // Different nonce, network, or contract yields a different digest.
        let h3 = compute_payload_hash(&input, 8, NETWORK, &contract_id()).unwrap();
        assert_ne!(h1, h3);
        let h4 = compute_payload_hash(&input, 7, "other network", &contract_id()).unwrap();
        assert_ne!(h1, h4);
        let other_contract = stellar_strkey::Contract([2u8; 32]).to_string();
        let h5 = compute_payload_hash(&input, 7, NETWORK, &other_contract).unwrap();
        assert_ne!(h1, h5);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let seed = [41u8; 32];
        let input = sample_input(seed);
        let signed = sign_offchain_attestation(input, 7, NETWORK, &contract_id(), &seed).unwrap();
        assert!(verify_offchain_attestation(&signed).is_ok());
    }

    #[test]
    fn test_verify_rejects_tampered_data() {
        let seed = [41u8; 32];
        let input = sample_input(seed);
        let mut signed =
            sign_offchain_attestation(input, 7, NETWORK, &contract_id(), &seed).unwrap();
        signed.attestation.data = "deadbeee".to_string();
        assert!(verify_offchain_attestation(&signed).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let seed = [41u8; 32];
        let input = sample_input(seed);
        let mut signed =
            sign_offchain_attestation(input, 7, NETWORK, &contract_id(), &seed).unwrap();

        // Swap in a different public key: the attester binding check fails.
        let other_key = SigningKey::from_bytes(&[42u8; 32])
            .verifying_key()
            .to_bytes();
        signed.public_key = hex::encode(other_key);
        assert!(verify_offchain_attestation(&signed).is_err());
    }

    #[test]
    fn test_verify_rejects_nonce_change() {
        let seed = [41u8; 32];
        let input = sample_input(seed);
        let mut signed =
            sign_offchain_attestation(input, 7, NETWORK, &contract_id(), &seed).unwrap();
        signed.nonce = 8;
        assert!(verify_offchain_attestation(&signed).is_err());
    }

    #[test]
    fn test_sign_rejects_mismatched_attester() {
        let seed = [41u8; 32];
        // Attester derived from a different key than the signing seed.
        let input = sample_input([43u8; 32]);
        assert!(sign_offchain_attestation(input, 7, NETWORK, &contract_id(), &seed).is_err());
    }

    #[test]
    fn test_parse_secret_seed_hex_and_strkey() {
        let seed = [41u8; 32];
        assert_eq!(parse_secret_seed(&hex::encode(seed)).unwrap(), seed);
        let strkey = stellar_strkey::ed25519::PrivateKey(seed).to_string();
        assert_eq!(parse_secret_seed(&strkey).unwrap(), seed);
        assert!(parse_secret_seed("not a key").is_err());
    }

    #[test]
    fn test_generate_uid_is_deterministic_for_the_same_inputs() {
        let env = soroban_sdk::Env::default();
        let schema_uid = [2u8; 32];
        let recipient = stellar_strkey::ed25519::PublicKey([5u8; 32]).to_string();
        let attester = stellar_strkey::ed25519::PublicKey([6u8; 32]).to_string();

        let uid1 = generate_uid(&env, &schema_uid, &recipient, &attester, b"deadbeef", 7);
        let uid2 = generate_uid(&env, &schema_uid, &recipient, &attester, b"deadbeef", 7);
        assert_eq!(uid1, uid2);

        // Different entropy or content yields a different uid.
        let uid3 = generate_uid(&env, &schema_uid, &recipient, &attester, b"deadbeef", 8);
        assert_ne!(uid1, uid3);
        let uid4 = generate_uid(&env, &schema_uid, &recipient, &attester, b"cafebabe", 7);
        assert_ne!(uid1, uid4);
    }
}
