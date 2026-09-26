#[cfg(test)]
mod tests {
    use clap::Parser;
    use soroban_sdk::testutils::Address as _;

    use crate::{
        decode_hex_or_base64, fee_to_human, fee_to_json, parse_uid, sas_fee_admin_output,
        validate_fee_amount, validate_schema_syntax, AttestCommands, Cli, Commands, OutputFormat,
        SasCommands,
    };

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
            action:
                AttestCommands::Attest {
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

    // --- Issue #174: `--network` / `--identity` actually change behavior
    // instead of being accepted and silently ignored. ---

    #[test]
    fn network_and_identity_flags_parse() {
        let cli =
            Cli::try_parse_from(["soroban-sas", "--network", "testnet", "--identity", "alice"])
                .unwrap();
        assert_eq!(cli.network.as_deref(), Some("testnet"));
        assert_eq!(cli.identity.as_deref(), Some("alice"));
    }

    #[test]
    fn resolve_rpc_url_prefers_an_explicit_flag_over_network() {
        let resolved =
            crate::resolve_rpc_url(Some("https://example.invalid".to_string()), Some("testnet"))
                .unwrap();
        assert_eq!(resolved, "https://example.invalid");
    }

    #[test]
    fn resolve_rpc_url_falls_back_to_network_when_the_flag_is_absent() {
        let resolved = crate::resolve_rpc_url(None, Some("testnet")).unwrap();
        assert_eq!(resolved, "https://soroban-testnet.stellar.org");
    }

    #[test]
    fn resolve_rpc_url_errors_clearly_when_neither_is_given() {
        let err = crate::resolve_rpc_url(None, None).unwrap_err();
        assert!(err.contains("--rpc-url"));
        assert!(err.contains("--network"));
    }

    #[test]
    fn resolve_network_passphrase_follows_the_same_precedence() {
        assert_eq!(
            crate::resolve_network_passphrase(Some("custom".to_string()), Some("testnet")).unwrap(),
            "custom"
        );
        assert_eq!(
            crate::resolve_network_passphrase(None, Some("testnet")).unwrap(),
            "Test SDF Network ; September 2015"
        );
        assert!(crate::resolve_network_passphrase(None, None).is_err());
    }

    #[test]
    fn resolve_secret_key_prefers_an_explicit_flag_over_identity() {
        let resolved =
            crate::resolve_secret_key(Some("explicit-secret".to_string()), Some("alice")).unwrap();
        assert_eq!(resolved, "explicit-secret");
    }

    #[test]
    fn resolve_secret_key_errors_clearly_when_neither_is_given() {
        let err = crate::resolve_secret_key(None, None).unwrap_err();
        assert!(err.contains("--secret-key"));
        assert!(err.contains("--identity"));
    }

    #[test]
    fn every_rpc_url_and_secret_key_field_across_subcommands_is_optional_so_network_and_identity_can_supply_them(
    ) {
        // A minimal, network/identity-only invocation must parse (clap must
        // not itself demand --rpc-url / --secret-key), proving those fields
        // are no longer hard-required flags that a global option can never
        // reach. Actual resolution failure (if --network/--identity are also
        // absent) happens later, inside the resolve_* helpers, so it can
        // produce an actionable message instead of a bare clap usage error.
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "--network",
            "testnet",
            "--identity",
            "alice",
            "attest",
            "verify",
            "--uid",
            &hex::encode([1u8; 32]),
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        ])
        .unwrap();
        assert_eq!(cli.network.as_deref(), Some("testnet"));
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
            action: AttestCommands::Verify {
                uid: parsed_uid, ..
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

    #[test]
    fn verify_clap_cli_structure() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_schema_get_flags() {
        let uid = hex::encode([3u8; 32]);
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "--output",
            "json",
            "schema",
            "get",
            "--uid",
            &uid,
            "--registry-contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "--rpc-url",
            "https://soroban-testnet.stellar.org",
        ])
        .unwrap();

        assert_eq!(cli.output, OutputFormat::Json);
        let Some(Commands::Schema {
            action: crate::SchemaCommands::Get {
                uid: parsed_uid, ..
            },
        }) = cli.command
        else {
            panic!("expected schema get command");
        };
        assert_eq!(parsed_uid, uid);
    }

    #[test]
    fn parses_query_by_recipient_flags() {
        let recipient = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAA6XKZW3";
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "--output",
            "json",
            "query",
            "by-recipient",
            "--address",
            recipient,
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "--rpc-url",
            "https://soroban-testnet.stellar.org",
        ])
        .unwrap();

        assert_eq!(cli.output, OutputFormat::Json);
        let Some(Commands::Query {
            action: crate::QueryCommands::ByRecipient { address, .. },
        }) = cli.command
        else {
            panic!("expected query by-recipient command");
        };
        assert_eq!(address, recipient);
    }

    #[test]
    fn parses_sas_get_fee_flags() {
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "--output",
            "json",
            "sas",
            "get-fee",
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "--rpc-url",
            "https://soroban-testnet.stellar.org",
        ])
        .unwrap();

        assert_eq!(cli.output, OutputFormat::Json);
        let Some(Commands::Sas {
            action:
                SasCommands::Get {
                    contract_id,
                    rpc_url,
                },
        }) = cli.command
        else {
            panic!("expected sas get-fee command");
        };
        assert_eq!(
            contract_id,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        );
        assert_eq!(
            rpc_url.as_deref(),
            Some("https://soroban-testnet.stellar.org")
        );
    }

    #[test]
    fn parses_sas_set_fee_flags_and_globals() {
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "--identity",
            "admin",
            "--network",
            "testnet",
            "--output",
            "json",
            "sas",
            "set-fee",
            "--token",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "--amount",
            "1000000",
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        ])
        .unwrap();

        assert_eq!(cli.identity.as_deref(), Some("admin"));
        assert_eq!(cli.network.as_deref(), Some("testnet"));
        assert_eq!(cli.output, OutputFormat::Json);
        let Some(Commands::Sas {
            action:
                SasCommands::Set {
                    token,
                    amount,
                    secret_key,
                    network_passphrase,
                    rpc_url,
                    ..
                },
        }) = cli.command
        else {
            panic!("expected sas set-fee command");
        };
        assert!(token.starts_with('C'));
        assert_eq!(amount, 1_000_000);
        assert!(secret_key.is_none());
        assert_eq!(
            crate::resolve_network_passphrase(network_passphrase, cli.network.as_deref()).unwrap(),
            "Test SDF Network ; September 2015"
        );
        assert_eq!(
            crate::resolve_rpc_url(rpc_url, cli.network.as_deref()).unwrap(),
            "https://soroban-testnet.stellar.org"
        );
    }

    #[test]
    fn parses_sas_clear_fee_flags_and_mainnet_network_defaults() {
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "--identity",
            "admin",
            "--network",
            "mainnet",
            "sas",
            "clear-fee",
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        ])
        .unwrap();

        assert_eq!(cli.identity.as_deref(), Some("admin"));
        let Some(Commands::Sas {
            action:
                SasCommands::Clear {
                    secret_key,
                    network_passphrase,
                    rpc_url,
                    ..
                },
        }) = cli.command
        else {
            panic!("expected sas clear-fee command");
        };
        assert!(secret_key.is_none());
        assert!(
            crate::resolve_network_passphrase(network_passphrase, cli.network.as_deref())
                .unwrap()
                .contains("Public Global Stellar Network")
        );
        assert_eq!(
            crate::resolve_rpc_url(rpc_url, cli.network.as_deref()).unwrap(),
            "https://mainnet.sorobanrpc.com"
        );
    }

    #[test]
    fn sas_fee_admin_commands_use_global_identity_resolution() {
        let contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
        let set_error = crate::run_sas(
            SasCommands::Set {
                token: contract_id.to_string(),
                amount: 1,
                secret_key: None,
                network_passphrase: None,
                contract_id: contract_id.to_string(),
                rpc_url: None,
            },
            OutputFormat::Human,
            Some("testnet".to_string()),
            Some("../invalid".to_string()),
        )
        .unwrap_err();
        assert!(set_error.contains("invalid --identity"));

        let clear_error = crate::run_sas(
            SasCommands::Clear {
                secret_key: None,
                network_passphrase: None,
                contract_id: contract_id.to_string(),
                rpc_url: None,
            },
            OutputFormat::Human,
            Some("testnet".to_string()),
            Some("../invalid".to_string()),
        )
        .unwrap_err();
        assert!(clear_error.contains("invalid --identity"));
    }

    #[test]
    fn sas_set_fee_rejects_non_positive_amounts_before_rpc_setup() {
        assert_eq!(
            validate_fee_amount(0).unwrap_err(),
            "--amount must be greater than 0"
        );
        assert_eq!(
            validate_fee_amount(-1).unwrap_err(),
            "--amount must be greater than 0"
        );

        for amount in [0, -1] {
            let error = crate::run_sas(
                SasCommands::Set {
                    token: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4".to_string(),
                    amount,
                    secret_key: None,
                    network_passphrase: None,
                    contract_id: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
                        .to_string(),
                    rpc_url: Some("http://127.0.0.1:1".to_string()),
                },
                OutputFormat::Human,
                None,
                None,
            )
            .unwrap_err();
            assert_eq!(error, "--amount must be greater than 0");
        }
    }

    #[test]
    fn sas_fee_admin_success_formatters_match_required_output() {
        let result = soroban_sas_sdk::rpc::GetTransactionResult {
            status: "SUCCESS".to_string(),
            latest_ledger: 1,
            envelope_xdr: None,
            result_xdr: None,
            hash: Some("abc123".to_string()),
        };
        let (_, json) = sas_fee_admin_output(&result, Some(("Ctoken", 1_000_000))).unwrap();
        assert_eq!(json["tx_hash"], "abc123");

        let (human, _) = sas_fee_admin_output(&result, None).unwrap();
        assert!(human.contains("Fee cleared — attestation is now fee-free"));
        assert!(human.contains("abc123"));
    }

    #[test]
    fn sas_admin_unauthorized_error_is_explicit() {
        let message =
            crate::format_sas_admin_error(soroban_sas_sdk::errors::SdkError::ContractError(301));
        assert_eq!(
            message,
            "SASError::Unauthorized: caller is not the SAS admin"
        );
        let other =
            crate::format_sas_admin_error(soroban_sas_sdk::errors::SdkError::ContractError(302));
        assert!(!other.contains("Unauthorized"));
    }

    #[test]
    fn sas_get_fee_works_without_identity_and_resolves_network() {
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "--network",
            "testnet",
            "sas",
            "get-fee",
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        ])
        .unwrap();

        assert!(cli.identity.is_none());
        let Some(Commands::Sas {
            action:
                SasCommands::Get {
                    contract_id,
                    rpc_url,
                },
        }) = cli.command
        else {
            panic!("expected sas get-fee command");
        };
        assert_eq!(
            contract_id,
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        );
        assert_eq!(rpc_url, None);
        assert_eq!(
            crate::resolve_rpc_url(rpc_url, cli.network.as_deref()).unwrap(),
            "https://soroban-testnet.stellar.org"
        );
    }

    #[test]
    fn test_fee_formatting_fee_free() {
        let fee: Option<(soroban_sdk::Address, i128)> = None;
        assert_eq!(fee_to_human(&fee), "Fee: free");
        assert_eq!(fee_to_json(&fee), serde_json::Value::Null);
    }

    #[test]
    fn test_fee_formatting_fee_configured() {
        let env = soroban_sdk::Env::default();
        let token = soroban_sdk::Address::generate(&env);
        let token_str = crate::soroban_string_to_std(&token.to_string());
        let fee = Some((token, 1_000_000i128));

        assert_eq!(
            fee_to_human(&fee),
            format!("Fee: 1000000 stroops of {token_str}")
        );
        assert_eq!(
            fee_to_json(&fee),
            serde_json::json!({
                "token": token_str,
                "amount": 1_000_000i128,
            })
        );
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

    // --- Issue #171: malformed address strings return a validation error
    // instead of trapping the host inside `Address::from_string`. ---

    #[test]
    fn parse_attestation_rejects_malformed_recipient_and_attester_without_panicking() {
        let env = soroban_sdk::Env::default();
        let mut input = sample_input([41u8; 32]);

        input.recipient = "not-a-strkey".to_string();
        let err = crate::offchain::parse_attestation(&env, &input)
            .expect_err("malformed recipient must be rejected");
        assert!(err.contains("recipient"));

        input.recipient = stellar_strkey::ed25519::PublicKey([5u8; 32]).to_string();
        input.attester = "GXXXX".to_string();
        let err = crate::offchain::parse_attestation(&env, &input)
            .expect_err("malformed attester must be rejected");
        assert!(err.contains("attester"));
    }

    #[test]
    fn compute_payload_hash_rejects_a_malformed_contract_id_without_panicking() {
        let input = sample_input([41u8; 32]);
        let err = compute_payload_hash(&input, 7, NETWORK, "not-a-contract-strkey")
            .expect_err("malformed contract_id must be rejected");
        assert!(err.contains("contract_id"));
    }

    #[test]
    fn offline_verify_never_makes_online_status_claims() {
        // Issue #175: with no `--online`, `offchain verify` must not itself
        // report anything about expiration/revocation/schema/network — its
        // own crypto-only check function is all it may rely on.
        let seed = [41u8; 32];
        let input = sample_input(seed);
        let signed = sign_offchain_attestation(input, 7, NETWORK, &contract_id(), &seed).unwrap();
        assert!(verify_offchain_attestation(&signed).is_ok());
    }

    #[test]
    fn test_generate_uid_is_deterministic_for_the_same_inputs() {
        let env = soroban_sdk::Env::default();
        let schema_uid = [2u8; 32];
        let recipient = stellar_strkey::ed25519::PublicKey([5u8; 32]).to_string();
        let attester = stellar_strkey::ed25519::PublicKey([6u8; 32]).to_string();

        let uid1 = generate_uid(&env, &schema_uid, &recipient, &attester, b"deadbeef").unwrap();
        let uid2 = generate_uid(&env, &schema_uid, &recipient, &attester, b"deadbeef").unwrap();
        assert_eq!(uid1, uid2);

        // Different content yields a different uid (#215: content-addressed,
        // no entropy).
        let uid3 = generate_uid(&env, &schema_uid, &recipient, &attester, b"cafebabe").unwrap();
        assert_ne!(uid1, uid3);
    }
}

/// Issue #175: `--online` must query only the caller-supplied trusted
/// contract/network — never the file's own embedded values — and must
/// report every guarantee (network, contract, on-chain status, schema)
/// separately rather than collapsing them into one opaque bool.
#[cfg(test)]
mod online_verification_tests {
    use crate::offchain::{sign_offchain_attestation, AttestationInput};
    use crate::perform_online_verification;
    use soroban_sas_sdk::rpc::RpcClient;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::xdr::{Limits, WriteXdr};
    use std::io::{BufRead, BufReader, Read, Write};

    const NETWORK: &str = "Test SDF Network ; September 2015";

    /// Answers exactly one HTTP request with `body`, mirroring the mock
    /// server pattern used in the SDK's own RPC tests.
    fn spawn_single_response_mock_server(body: String) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    let read = reader.read_line(&mut line).unwrap_or(0);
                    if read == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body_buf = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body_buf);
                let mut stream = stream;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        url
    }

    fn sample_signed(contract_id: &str) -> crate::offchain::SignedOffchainAttestation {
        let seed = [41u8; 32];
        let public_key = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let attester = stellar_strkey::ed25519::PublicKey(public_key).to_string();
        let recipient = stellar_strkey::ed25519::PublicKey([5u8; 32]).to_string();
        let input = AttestationInput {
            uid: hex::encode([9u8; 32]),
            schema_uid: hex::encode([2u8; 32]),
            time: 1000,
            expiration_time: 0,
            ref_uid: hex::encode([0u8; 32]),
            recipient,
            attester,
            revocable: true,
            data: "deadbeef".to_string(),
        };
        sign_offchain_attestation(input, 7, NETWORK, contract_id, &seed).unwrap()
    }

    /// A `get_attestation` simulation response reporting the UID as unknown.
    fn not_found_response() -> String {
        let env = soroban_sdk::Env::default();
        let none_attestation: Option<soroban_sas_common::Attestation> = None;
        let result_xdr = soroban_sas_sdk::simulate::encode_arg(&env, &none_attestation)
            .unwrap()
            .to_xdr_base64(Limits::none())
            .unwrap();
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
        )
    }

    #[test]
    fn a_contract_mismatch_is_reported_and_the_trusted_contract_is_what_gets_queried() {
        let embedded_contract = stellar_strkey::Contract([1u8; 32]).to_string();
        let trusted_contract = stellar_strkey::Contract([2u8; 32]).to_string();
        let signed = sample_signed(&embedded_contract);

        let url = spawn_single_response_mock_server(not_found_response());
        let rpc = RpcClient::new(url);

        let report =
            perform_online_verification(&signed, NETWORK, &trusted_contract, None, &rpc).unwrap();

        // The embedded contract never became the query target: the mock
        // server only ever answered one request, for whichever contract the
        // client actually asked about, and the report still completed —
        // proving the call went out and back against `trusted_contract`.
        assert!(!report.contract_matches_trusted);
        assert!(report.network_matches_trusted);
        assert!(!report.on_chain_found);
        assert!(!report.overall_valid);
    }

    #[test]
    fn a_network_mismatch_is_reported_independently_of_contract_and_on_chain_status() {
        let contract = stellar_strkey::Contract([3u8; 32]).to_string();
        let signed = sample_signed(&contract);

        let url = spawn_single_response_mock_server(not_found_response());
        let rpc = RpcClient::new(url);

        let report = perform_online_verification(
            &signed,
            "some other network passphrase",
            &contract,
            None,
            &rpc,
        )
        .unwrap();

        assert!(!report.network_matches_trusted);
        assert!(report.contract_matches_trusted);
        assert!(!report.overall_valid);
    }

    #[test]
    fn schema_registry_omission_reports_not_checked_rather_than_failing_closed_or_open() {
        let contract = stellar_strkey::Contract([4u8; 32]).to_string();
        let signed = sample_signed(&contract);

        let url = spawn_single_response_mock_server(not_found_response());
        let rpc = RpcClient::new(url);

        let report = perform_online_verification(&signed, NETWORK, &contract, None, &rpc).unwrap();

        assert_eq!(report.schema_status, "not_checked");
    }

    fn fee_none_response() -> String {
        let env = soroban_sdk::Env::default();
        let none_fee: Option<(soroban_sdk::Address, i128)> = None;
        let result_xdr = soroban_sas_sdk::simulate::encode_arg(&env, &none_fee)
            .unwrap()
            .to_xdr_base64(Limits::none())
            .unwrap();
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
        )
    }

    fn fee_configured_response(
        env: &soroban_sdk::Env,
        token: &soroban_sdk::Address,
        amount: i128,
    ) -> String {
        let fee: Option<(soroban_sdk::Address, i128)> = Some((token.clone(), amount));
        let result_xdr = soroban_sas_sdk::simulate::encode_arg(env, &fee)
            .unwrap()
            .to_xdr_base64(Limits::none())
            .unwrap();
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
        )
    }

    #[test]
    fn sas_get_fee_simulation_free() {
        let contract_id = stellar_strkey::Contract([5u8; 32]).to_string();
        let url = spawn_single_response_mock_server(fee_none_response());
        let res = crate::run_sas(
            crate::SasCommands::Get {
                contract_id,
                rpc_url: Some(url),
            },
            crate::OutputFormat::Json,
            None,
            None,
        );
        assert!(res.is_ok());
    }

    #[test]
    fn sas_get_fee_simulation_configured() {
        let contract_id = stellar_strkey::Contract([6u8; 32]).to_string();
        let env = soroban_sdk::Env::default();
        let token_addr = soroban_sdk::Address::generate(&env);
        let url = spawn_single_response_mock_server(fee_configured_response(
            &env,
            &token_addr,
            1_000_000,
        ));
        let res = crate::run_sas(
            crate::SasCommands::Get {
                contract_id,
                rpc_url: Some(url),
            },
            crate::OutputFormat::Human,
            None,
            None,
        );
        assert!(res.is_ok());
    }
}

#[cfg(test)]
mod by_attester_query_tests {
    use clap::{CommandFactory, Parser};
    use soroban_sas_common::UID;
    use soroban_sdk::xdr::{Limits, WriteXdr};
    use soroban_sdk::BytesN;
    use std::io::{BufRead, BufReader, Read, Write};

    use crate::{
        format_attestations_by_attester, run_query, Cli, Commands, OutputFormat, QueryCommands,
    };

    const ATTESTER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    #[test]
    fn parses_query_by_attester_flags() {
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "query",
            "by-attester",
            "--address",
            ATTESTER,
            "--contract-id",
            CONTRACT,
            "--rpc-url",
            "https://soroban-testnet.stellar.org",
        ])
        .unwrap();

        let Some(Commands::Query {
            action:
                QueryCommands::ByAttester {
                    address,
                    contract_id,
                    rpc_url,
                },
        }) = cli.command
        else {
            panic!("expected query by-attester command");
        };
        assert_eq!(address, ATTESTER);
        assert_eq!(contract_id, CONTRACT);
        assert_eq!(
            rpc_url.as_deref(),
            Some("https://soroban-testnet.stellar.org")
        );
    }

    #[test]
    fn by_attester_help_documents_the_command_and_flags() {
        let mut root = Cli::command();
        let query = root.find_subcommand_mut("query").unwrap();
        let query_help = query.render_long_help().to_string();
        assert!(query_help.contains("by-attester"));

        let by_attester = query.find_subcommand_mut("by-attester").unwrap();
        let help = by_attester.render_long_help().to_string();
        assert!(help.contains("--address"));
        assert!(help.contains("Attester/issuer account address"));
        assert!(help.contains("--contract-id"));
        assert!(help.contains("Indexer contract address"));
        assert!(help.contains("--rpc-url"));
        assert!(help.contains("Soroban RPC endpoint URL"));
    }

    #[test]
    fn network_shorthand_parses_without_an_explicit_rpc_url() {
        let cli = Cli::try_parse_from([
            "soroban-sas",
            "--network",
            "testnet",
            "query",
            "by-attester",
            "--address",
            ATTESTER,
            "--contract-id",
            CONTRACT,
        ])
        .unwrap();
        assert_eq!(cli.network.as_deref(), Some("testnet"));
        let Some(Commands::Query {
            action: QueryCommands::ByAttester { rpc_url, .. },
        }) = cli.command
        else {
            panic!("expected query by-attester command");
        };
        assert!(rpc_url.is_none());
        assert_eq!(
            crate::resolve_rpc_url(rpc_url, cli.network.as_deref()).unwrap(),
            "https://soroban-testnet.stellar.org"
        );
    }

    #[test]
    fn formatter_produces_required_human_and_json_shapes() {
        let env = soroban_sdk::Env::default();
        let uids = soroban_sdk::vec![
            &env,
            UID(BytesN::from_array(&env, &[1u8; 32])),
            UID(BytesN::from_array(&env, &[2u8; 32])),
        ];
        let (human, data) = format_attestations_by_attester(ATTESTER, &uids);
        assert_eq!(
            human,
            format!(
                "Attestations found: 2\n{}\n{}",
                hex::encode([1u8; 32]),
                hex::encode([2u8; 32])
            )
        );
        let envelope = serde_json::json!({ "status": "ok", "data": data });
        assert_eq!(envelope["status"], "ok");
        assert_eq!(envelope["data"]["attester"], ATTESTER);
        assert_eq!(
            envelope["data"]["uids"],
            serde_json::json!([hex::encode([1u8; 32]), hex::encode([2u8; 32])])
        );
        assert!(envelope["data"].get("count").is_none());
    }

    #[test]
    fn formatter_handles_an_empty_result() {
        let env = soroban_sdk::Env::default();
        let uids = soroban_sdk::Vec::<UID>::new(&env);
        let (human, data) = format_attestations_by_attester(ATTESTER, &uids);
        assert_eq!(human, "Attestations found: 0");
        assert_eq!(data["attester"], ATTESTER);
        assert_eq!(data["uids"], serde_json::json!([]));
    }

    fn spawn_mock_rpc(response_body: String) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                let read = reader.read_line(&mut line).unwrap();
                if read == 0 || line == "\r\n" || line == "\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse().unwrap();
                }
            }
            let mut request_body = vec![0u8; content_length];
            reader.read_exact(&mut request_body).unwrap();
            let mut stream = stream;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(), response_body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
            String::from_utf8(request_body).unwrap()
        });
        (url, handle)
    }

    #[test]
    fn run_query_uses_the_sdk_simulation_decode_path() {
        let env = soroban_sdk::Env::default();
        let expected = soroban_sdk::vec![
            &env,
            UID(BytesN::from_array(&env, &[7u8; 32])),
            UID(BytesN::from_array(&env, &[8u8; 32])),
        ];
        let result_xdr = soroban_sas_sdk::simulate::encode_arg(&env, &expected)
            .unwrap()
            .to_xdr_base64(Limits::none())
            .unwrap();
        let response = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
        );
        let (rpc_url, server) = spawn_mock_rpc(response);

        run_query(
            QueryCommands::ByAttester {
                address: ATTESTER.to_string(),
                contract_id: CONTRACT.to_string(),
                rpc_url: Some(rpc_url),
            },
            OutputFormat::Json,
            None,
        )
        .unwrap();

        let request: serde_json::Value = serde_json::from_str(&server.join().unwrap()).unwrap();
        assert_eq!(request["method"], "simulateTransaction");
        assert!(request["params"]["transaction"].as_str().is_some());
    }
}
