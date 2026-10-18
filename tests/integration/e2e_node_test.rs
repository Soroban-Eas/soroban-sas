//! End-to-end integration tests against a real Soroban RPC node.
//!
//! Every other test in this workspace runs against `soroban_sdk::Env`'s
//! in-process mock host: it never serializes a transaction, never computes a
//! footprint, never pays a fee, and never crosses a real host/guest
//! boundary. These tests close that gap by deploying fresh instances of
//! `schema-registry`, `sas`, and `soroban-sas-indexer` to a live node and
//! driving them through `soroban-sas-sdk`'s `RpcClient`/`SASClient` exactly
//! as a real client would: build → simulate → sign → submit → poll.
//!
//! `#[ignore]`d by default so `cargo test` stays fast; run explicitly with:
//!
//! ```bash
//! cargo test --test integration -- --ignored
//! ```
//!
//! Configuration (see DEVELOPER_RUNBOOK.md for full setup):
//!   SOROBAN_RPC_URL     Soroban RPC endpoint (default: http://localhost:8000/soroban/rpc)
//!   STELLAR_SECRET_KEY  Funded ed25519 secret seed (S...) that deploys and pays for every call
//!   NETWORK_PASSPHRASE  Network passphrase (default: "Standalone Network ; February 2017",
//!                       matching docker-compose.yml's `stellar/quickstart:testing --standalone`)

use soroban_sas_sdk::attestation_builder::AttestationRequestBuilder;
use soroban_sas_sdk::client::{IndexerClient, SASClient};
use soroban_sas_sdk::rpc::RpcClient;
use soroban_sas_sdk::signature::derive_public_key;
use soroban_sas_sdk::transaction::SubmissionPolicy;
use soroban_sdk::{Bytes, Env};
use std::path::{Path, PathBuf};
use std::process::Command;

fn rpc_url() -> String {
    std::env::var("SOROBAN_RPC_URL")
        .unwrap_or_else(|_| "http://localhost:8000/soroban/rpc".to_string())
}

fn network_passphrase() -> String {
    std::env::var("NETWORK_PASSPHRASE")
        .unwrap_or_else(|_| "Standalone Network ; February 2017".to_string())
}

fn secret_key() -> String {
    std::env::var("STELLAR_SECRET_KEY").expect(
        "STELLAR_SECRET_KEY must be set to run integration tests (see DEVELOPER_RUNBOOK.md)",
    )
}

fn parse_secret_seed(value: &str) -> [u8; 32] {
    stellar_strkey::ed25519::PrivateKey::from_string(value.trim())
        .expect("STELLAR_SECRET_KEY must be a valid ed25519 secret seed (S...)")
        .0
}

fn admin_address(secret: &str) -> String {
    let seed = parse_secret_seed(secret);
    stellar_strkey::ed25519::PublicKey(derive_public_key(&seed)).to_string()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Friendbot-funds `address` against the local standalone network. Ignores
/// failure: an already-funded account (e.g. re-running against a node that
/// kept its volume) is not an error.
fn fund_account(address: &str) {
    let base = rpc_url().trim_end_matches("/soroban/rpc").to_string();
    let url = format!("{base}/friendbot?addr={address}");
    let _ = ureq::get(&url).call();
}

fn stellar_cli() -> &'static str {
    "stellar"
}

fn run(dir: &Path, program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn `{program} {}`: {e}", args.join(" ")));
    if !output.status.success() {
        panic!(
            "`{program} {}` failed:\nstdout: {}\nstderr: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Registers a throwaway CLI identity for `secret` and returns its name, so
/// every deploy/invoke call below can use `--source-account <name>` exactly
/// like scripts/deploy.sh does. The identity is left registered for the
/// duration of the test process (harmless in a disposable CI container).
fn register_identity(secret: &str) -> String {
    let name = format!("integration-test-{}", std::process::id());

    // In stellar-cli v22, `stellar keys add` requires a TTY and fails from stdin.
    // So we manually write the config TOML to bypass the bug.
    let config_dir = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").expect("HOME env var not set");
            std::path::PathBuf::from(home).join(".config")
        })
        .join("stellar")
        .join("identity");

    std::fs::create_dir_all(&config_dir).expect("failed to create stellar identity dir");

    let toml = format!("secret_key = \"{secret}\"\n");
    std::fs::write(config_dir.join(format!("{name}.toml")), toml)
        .expect("failed to write identity file");

    name
}

fn net_args<'a>(identity: &'a str, rpc: &'a str, passphrase: &'a str) -> Vec<&'a str> {
    vec![
        "--source-account",
        identity,
        "--rpc-url",
        rpc,
        "--network-passphrase",
        passphrase,
    ]
}

fn deploy_contract(dir: &Path, wasm: &Path, identity: &str, rpc: &str, passphrase: &str) -> String {
    let wasm_str = wasm.to_string_lossy().to_string();
    let mut args = vec!["contract", "deploy", "--wasm", wasm_str.as_str()];
    args.extend(net_args(identity, rpc, passphrase));
    let out = run(dir, stellar_cli(), &args);
    let id = out.lines().last().unwrap_or("").trim().to_string();
    assert!(
        id.starts_with('C'),
        "expected a contract id (C...) from `stellar contract deploy`, got: {out}"
    );
    id
}

fn invoke(
    dir: &Path,
    contract_id: &str,
    identity: &str,
    rpc: &str,
    passphrase: &str,
    call_args: &[&str],
) -> String {
    let mut args = vec!["contract", "invoke", "--id", contract_id];
    args.extend(net_args(identity, rpc, passphrase));
    args.push("--");
    args.extend_from_slice(call_args);
    run(dir, stellar_cli(), &args)
}

fn append_uleb128(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// A custom section changes the WASM hash without changing executable code.
/// Release verification can instead supply genuinely new binaries in
/// UPGRADE_CANDIDATE_DIR (schema_registry.wasm, sas.wasm, and
/// soroban_sas_indexer.wasm).
fn upgrade_candidate(name: &str, output_dir: &Path) -> PathBuf {
    let root = workspace_root();
    let original = root.join("target/wasm32v1-none/release").join(name);
    let original_bytes = std::fs::read(&original).expect("baseline WASM must be built first");
    assert!(original_bytes.starts_with(b"\0asm\x01\0\0\0"));

    let candidate_bytes = if let Some(dir) = std::env::var_os("UPGRADE_CANDIDATE_DIR") {
        std::fs::read(PathBuf::from(dir).join(name)).expect("candidate WASM must be readable")
    } else {
        let mut wasm = original_bytes.clone();
        let section_name = b"compatibility-test";
        let mut payload = Vec::new();
        append_uleb128(section_name.len(), &mut payload);
        payload.extend_from_slice(section_name);
        payload.extend_from_slice(name.as_bytes());
        wasm.push(0); // WASM custom-section id
        append_uleb128(payload.len(), &mut wasm);
        wasm.extend_from_slice(&payload);
        wasm
    };
    assert!(candidate_bytes.starts_with(b"\0asm\x01\0\0\0"));
    assert_ne!(
        candidate_bytes, original_bytes,
        "candidate must differ from baseline"
    );
    std::fs::create_dir_all(output_dir).expect("create upgrade candidate directory");
    let candidate = output_dir.join(name);
    std::fs::write(&candidate, candidate_bytes).expect("write upgrade candidate");
    candidate
}

fn upload_candidate(path: &Path, identity: &str, rpc: &str, passphrase: &str) -> String {
    let root = workspace_root();
    let path_str = path.to_string_lossy();
    let mut args = vec![
        "contract",
        "upload",
        "--wasm",
        path_str.as_ref(),
        "--optimize=false",
    ];
    args.extend(net_args(identity, rpc, passphrase));
    let output = run(&root, stellar_cli(), &args);
    let hash = output
        .split(|c: char| !c.is_ascii_hexdigit())
        .find(|part| part.len() == 64)
        .unwrap_or_else(|| panic!("upload did not return a 32-byte hash: {output}"));
    hash.to_string()
}

fn contract_version(id: &str, identity: &str, rpc: &str, passphrase: &str) -> u32 {
    invoke(
        &workspace_root(),
        id,
        identity,
        rpc,
        passphrase,
        &["get_version"],
    )
    .trim_matches('"')
    .parse()
    .expect("get_version must return a number")
}

/// Builds the three contracts' release WASM (skipped if already built),
/// deploys fresh instances, and wires them together exactly like
/// scripts/deploy.sh's own deploy/init sequence. Also deploys
/// `permissive-resolver` (contracts/permissive-resolver) — `SAS::attest`/
/// `revoke` always invoke the schema's resolver, so every schema this
/// harness registers needs one deployed, even though the test itself has no
/// interest in resolver-side enforcement. Returns
/// `(registry_id, sas_id, indexer_id, resolver_id)`.
fn deploy_stack(secret: &str) -> (String, String, String, String) {
    let root = workspace_root();
    let rpc = rpc_url();
    let passphrase = network_passphrase();
    let admin = admin_address(secret);

    fund_account(&admin);
    let identity = register_identity(secret);

    // Rust 1.82+ emits unsupported reference types for wasm32-unknown-unknown.
    // Stellar CLI selects wasm32v1-none and the Soroban-compatible build flags.
    for package in [
        "schema-registry",
        "sas",
        "soroban-sas-indexer",
        "permissive-resolver",
    ] {
        run(
            &root,
            stellar_cli(),
            &[
                "contract",
                "build",
                "--locked",
                "--package",
                package,
                "--optimize=false",
            ],
        );
    }

    let wasm_dir = root.join("target/wasm32v1-none/release");
    let registry_id = deploy_contract(
        &root,
        &wasm_dir.join("schema_registry.wasm"),
        &identity,
        &rpc,
        &passphrase,
    );
    let sas_id = deploy_contract(
        &root,
        &wasm_dir.join("sas.wasm"),
        &identity,
        &rpc,
        &passphrase,
    );
    let indexer_id = deploy_contract(
        &root,
        &wasm_dir.join("soroban_sas_indexer.wasm"),
        &identity,
        &rpc,
        &passphrase,
    );
    let resolver_id = deploy_contract(
        &root,
        &wasm_dir.join("permissive_resolver.wasm"),
        &identity,
        &rpc,
        &passphrase,
    );

    invoke(
        &root,
        &registry_id,
        &identity,
        &rpc,
        &passphrase,
        &["init", "--admin", &admin],
    );
    invoke(
        &root,
        &sas_id,
        &identity,
        &rpc,
        &passphrase,
        &["init", "--admin", &admin, "--registry", &registry_id],
    );
    invoke(
        &root,
        &indexer_id,
        &identity,
        &rpc,
        &passphrase,
        &["init", "--admin", &admin, "--sas", &sas_id],
    );
    invoke(
        &root,
        &sas_id,
        &identity,
        &rpc,
        &passphrase,
        &["set_indexer", "--indexer", &indexer_id],
    );

    (registry_id, sas_id, indexer_id, resolver_id)
}

/// Schema registration, attestation issuance, revocation, and indexer
/// reverse lookup, driven entirely through `soroban-sas-sdk` against the
/// live node deployed above.
#[tokio::test]
#[ignore]
async fn schema_registration_attest_revoke_and_indexer_lookup() {
    let secret_str = secret_key();
    let (registry_id, sas_id, indexer_id, resolver_id) =
        tokio::task::spawn_blocking(move || deploy_stack(&secret_str))
            .await
            .expect("deploy_stack panicked");

    let env = Env::default();
    let rpc = RpcClient::new(rpc_url());
    let passphrase = network_passphrase();
    let secret = parse_secret_seed(&secret_key());
    let admin = admin_address(&secret_key());
    let sas_client = SASClient::new(sas_id.clone())
        .with_submission_policy(SubmissionPolicy::default().with_max_polls(30));

    // 1. Schema registration.
    sas_client
        .register_schema(
            &rpc,
            &passphrase,
            &secret,
            &registry_id,
            "bool verified",
            &resolver_id,
            true,
        )
        .expect("register_schema failed");
    let resolver_address =
        soroban_sdk::Address::from_string(&soroban_sdk::String::from_str(&env, &resolver_id));
    let schema_uid = SASClient::compute_schema_uid("bool verified", &resolver_address, true);

    // Use a different recipient — the contract rejects self-attestation
    // (recipient == attester). Derive a second throwaway keypair from a
    // fixed, well-known seed that is always pre-funded by the CI bootstrap.
    let recipient_seed = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let recipient = admin_address(recipient_seed);
    fund_account(&recipient);

    // 2. Attestation issuance.
    let attestation = AttestationRequestBuilder::new()
        .with_schema_uid(schema_uid.0.to_array())
        .with_recipient(&recipient)
        .with_attester(&admin)
        .with_data(Bytes::from_slice(&env, b"integration test payload"))
        .build(&env)
        .expect("failed to build attestation");
    let uid = attestation.uid.0.to_array();

    sas_client
        .attest(&rpc, &passphrase, &secret, attestation)
        .expect("attest failed");

    let fetched = sas_client
        .get_attestation(&rpc, &uid)
        .expect("get_attestation failed")
        .expect("attestation was not found after a successful attest");
    assert_eq!(fetched.uid.0.to_array(), uid);
    assert_eq!(
        fetched.revocation_time, 0,
        "freshly issued attestation must not be revoked"
    );

    // 3. Indexer reverse lookup: the recipient's attestation must be
    // discoverable by recipient without knowing its UID in advance.
    let indexer_client = IndexerClient::new(indexer_id);
    let by_recipient = indexer_client
        .get_attestations_by_recipient(&rpc, &recipient)
        .expect("get_attestations_by_recipient failed");
    assert!(
        by_recipient.iter().any(|u| u.0.to_array() == uid),
        "indexer did not return the newly issued attestation for its recipient"
    );

    // 4. Revocation.
    sas_client
        .revoke(&rpc, &passphrase, &secret, &uid)
        .expect("revoke failed");
    let revoked = sas_client
        .get_attestation(&rpc, &uid)
        .expect("get_attestation after revoke failed")
        .expect("revoked attestation must still be readable");
    assert_ne!(
        revoked.revocation_time, 0,
        "revoke must set a nonzero revocation_time"
    );
}

/// Performs an actual uploaded-WASM swap on all three versioned contracts.
/// A changed hash alone is insufficient: old records and cross-contract
/// bindings must remain readable, and a new attestation must still index.
#[tokio::test]
#[ignore]
async fn wasm_upgrade_preserves_existing_data_and_new_writes() {
    let secret_string = secret_key();
    let (registry_id, sas_id, indexer_id, resolver_id) =
        tokio::task::spawn_blocking(move || deploy_stack(&secret_string))
            .await
            .expect("deploy_stack panicked");
    let root = workspace_root();
    let rpc_url = rpc_url();
    let passphrase = network_passphrase();
    let secret_string = secret_key();
    let secret = parse_secret_seed(&secret_string);
    let identity = register_identity(&secret_string);
    let admin = admin_address(&secret_string);
    let rpc = RpcClient::new(rpc_url.clone());
    let env = Env::default();
    let sas_client = SASClient::new(sas_id.clone())
        .with_submission_policy(SubmissionPolicy::default().with_max_polls(30));
    let indexer_client = IndexerClient::new(indexer_id.clone());

    sas_client
        .register_schema(
            &rpc,
            &passphrase,
            &secret,
            &registry_id,
            "bool upgrade_compatible",
            &resolver_id,
            true,
        )
        .expect("register baseline schema");
    let resolver =
        soroban_sdk::Address::from_string(&soroban_sdk::String::from_str(&env, &resolver_id));
    let schema_uid = SASClient::compute_schema_uid("bool upgrade_compatible", &resolver, true);
    let schema_before = sas_client
        .get_schema(&rpc, &registry_id, &schema_uid.0.to_array())
        .expect("read baseline schema")
        .expect("baseline schema missing");
    let recipient = stellar_strkey::ed25519::PublicKey(derive_public_key(&[1u8; 32])).to_string();
    fund_account(&recipient);
    let first = AttestationRequestBuilder::new()
        .with_schema_uid(schema_uid.0.to_array())
        .with_recipient(&recipient)
        .with_attester(&admin)
        .with_data(Bytes::from_slice(&env, b"before WASM upgrade"))
        .build(&env)
        .expect("build baseline attestation");
    let first_uid = first.uid.0.to_array();
    sas_client
        .attest(&rpc, &passphrase, &secret, first)
        .expect("issue baseline attestation");
    let attestation_before = sas_client
        .get_attestation(&rpc, &first_uid)
        .expect("read baseline attestation")
        .expect("baseline attestation missing");
    assert!(sas_client
        .verify_attestation(&rpc, &first_uid)
        .expect("verify baseline attestation"));
    assert!(indexer_client
        .get_attestations_by_recipient(&rpc, &recipient)
        .expect("baseline recipient index")
        .iter()
        .any(|uid| uid.0.to_array() == first_uid));
    assert!(indexer_client
        .get_attestations_by_schema(&rpc, &schema_uid.0.to_array())
        .expect("baseline schema index")
        .iter()
        .any(|uid| uid.0.to_array() == first_uid));

    let sas_binding_before = invoke(
        &root,
        &sas_id,
        &identity,
        &rpc_url,
        &passphrase,
        &["get_indexer"],
    );
    let indexer_binding_before = invoke(
        &root,
        &indexer_id,
        &identity,
        &rpc_url,
        &passphrase,
        &["get_sas"],
    );
    for contract in [&registry_id, &sas_id, &indexer_id] {
        assert_eq!(
            contract_version(contract, &identity, &rpc_url, &passphrase),
            1
        );
    }

    let candidate_dir = std::env::temp_dir().join(format!(
        "soroban-sas-upgrade-compatibility-{}",
        std::process::id()
    ));
    for (contract, artifact) in [
        (&registry_id, "schema_registry.wasm"),
        (&sas_id, "sas.wasm"),
        (&indexer_id, "soroban_sas_indexer.wasm"),
    ] {
        let candidate = upgrade_candidate(artifact, &candidate_dir);
        let hash = upload_candidate(&candidate, &identity, &rpc_url, &passphrase);
        invoke(
            &root,
            contract,
            &identity,
            &rpc_url,
            &passphrase,
            &["upgrade", "--new-wasm-hash", &hash, "--new-version", "2"],
        );
        assert_eq!(
            contract_version(contract, &identity, &rpc_url, &passphrase),
            2
        );
    }

    let schema_after = sas_client
        .get_schema(&rpc, &registry_id, &schema_uid.0.to_array())
        .expect("read schema after upgrade")
        .expect("schema lost after upgrade");
    assert_eq!(
        schema_after.uid.0.to_array(),
        schema_before.uid.0.to_array()
    );
    assert_eq!(
        schema_after.schema.to_string(),
        schema_before.schema.to_string()
    );
    assert_eq!(schema_after.revocable, schema_before.revocable);
    assert_eq!(schema_after.deprecated, schema_before.deprecated);

    let attestation_after = sas_client
        .get_attestation(&rpc, &first_uid)
        .expect("read attestation after upgrade")
        .expect("attestation lost after upgrade");
    assert_eq!(attestation_after.uid.0.to_array(), first_uid);
    assert_eq!(
        attestation_after.data.iter().collect::<Vec<_>>(),
        attestation_before.data.iter().collect::<Vec<_>>()
    );
    assert_eq!(attestation_after.revocation_time, 0);
    assert!(sas_client
        .verify_attestation(&rpc, &first_uid)
        .expect("verify attestation after upgrade"));
    assert!(indexer_client
        .get_attestations_by_recipient(&rpc, &recipient)
        .expect("recipient index after upgrade")
        .iter()
        .any(|uid| uid.0.to_array() == first_uid));
    assert!(indexer_client
        .get_attestations_by_schema(&rpc, &schema_uid.0.to_array())
        .expect("schema index after upgrade")
        .iter()
        .any(|uid| uid.0.to_array() == first_uid));
    assert_eq!(
        invoke(
            &root,
            &sas_id,
            &identity,
            &rpc_url,
            &passphrase,
            &["get_indexer"]
        ),
        sas_binding_before
    );
    assert_eq!(
        invoke(
            &root,
            &indexer_id,
            &identity,
            &rpc_url,
            &passphrase,
            &["get_sas"]
        ),
        indexer_binding_before
    );

    sas_client
        .register_schema(
            &rpc,
            &passphrase,
            &secret,
            &registry_id,
            "bool written_after_upgrade",
            &resolver_id,
            true,
        )
        .expect("register schema after upgrade");
    let new_schema_uid =
        SASClient::compute_schema_uid("bool written_after_upgrade", &resolver, true);
    assert!(sas_client
        .get_schema(&rpc, &registry_id, &new_schema_uid.0.to_array())
        .expect("read schema written after upgrade")
        .is_some());

    let second = AttestationRequestBuilder::new()
        .with_schema_uid(new_schema_uid.0.to_array())
        .with_recipient(&recipient)
        .with_attester(&admin)
        .with_data(Bytes::from_slice(&env, b"after WASM upgrade"))
        .build(&env)
        .expect("build post-upgrade attestation");
    let second_uid = second.uid.0.to_array();
    assert_ne!(second_uid, first_uid);
    sas_client
        .attest(&rpc, &passphrase, &secret, second)
        .expect("issue attestation after upgrade");
    assert!(indexer_client
        .get_attestations_by_recipient(&rpc, &recipient)
        .expect("post-upgrade recipient index")
        .iter()
        .any(|uid| uid.0.to_array() == second_uid));
    assert!(indexer_client
        .get_attestations_by_schema(&rpc, &new_schema_uid.0.to_array())
        .expect("post-upgrade schema index")
        .iter()
        .any(|uid| uid.0.to_array() == second_uid));
    std::fs::remove_dir_all(candidate_dir).expect("remove temporary upgrade artifacts");
}

/// SAC fee deduction: configures a fee in the native XLM SAC, attests with
/// `attest_with_value`, and asserts the contract's SAC balance increased by
/// exactly the configured amount.
#[tokio::test]
#[ignore]
async fn sac_fee_deduction_on_attest_with_value() {
    let secret_str = secret_key();
    let (registry_id, sas_id, _indexer_id, resolver_id) =
        tokio::task::spawn_blocking(move || deploy_stack(&secret_str))
            .await
            .expect("deploy_stack panicked");

    let root = workspace_root();
    let rpc_str = rpc_url();
    let passphrase = network_passphrase();
    let secret_string = secret_key();
    let identity = register_identity(&secret_string);

    // Deploy (or reuse) the native XLM Stellar Asset Contract wrapper.
    let token_id = run(
        &root,
        stellar_cli(),
        &[
            "contract",
            "asset",
            "deploy",
            "--asset",
            "native",
            "--source-account",
            &identity,
            "--rpc-url",
            &rpc_str,
            "--network-passphrase",
            &passphrase,
        ],
    )
    .lines()
    .last()
    .unwrap_or("")
    .trim()
    .to_string();
    assert!(
        token_id.starts_with('C'),
        "expected a SAC contract id, got: {token_id}"
    );

    const FEE_AMOUNT: i128 = 500;

    let env = Env::default();
    let rpc = RpcClient::new(rpc_str.clone());
    let secret = parse_secret_seed(&secret_string);
    let admin = admin_address(&secret_string);
    let sas_client = SASClient::new(sas_id.clone())
        .with_submission_policy(SubmissionPolicy::default().with_max_polls(30));

    sas_client
        .register_schema(
            &rpc,
            &passphrase,
            &secret,
            &registry_id,
            "bool paid",
            &resolver_id,
            true,
        )
        .expect("register_schema failed");
    let resolver_address =
        soroban_sdk::Address::from_string(&soroban_sdk::String::from_str(&env, &resolver_id));
    let schema_uid = SASClient::compute_schema_uid("bool paid", &resolver_address, true);

    sas_client
        .set_fee(&rpc, &passphrase, &secret, &token_id, FEE_AMOUNT)
        .expect("set_fee failed");

    let balance_before: i128 = invoke(
        &root,
        &token_id,
        &identity,
        &rpc_str,
        &passphrase,
        &["balance", "--id", &sas_id],
    )
    .trim()
    .trim_matches('"')
    .parse()
    .unwrap_or(0);

    // Use a different recipient — the contract rejects self-attestation.
    let recipient_seed = "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    let recipient = admin_address(recipient_seed);
    fund_account(&recipient);

    let attestation = AttestationRequestBuilder::new()
        .with_schema_uid(schema_uid.0.to_array())
        .with_recipient(&recipient)
        .with_attester(&admin)
        .with_data(Bytes::from_slice(&env, b"paid attestation"))
        .build(&env)
        .expect("failed to build attestation");

    sas_client
        .attest_with_value(
            &rpc,
            &passphrase,
            &secret,
            attestation,
            &token_id,
            FEE_AMOUNT,
        )
        .expect("attest_with_value failed");

    let balance_after: i128 = invoke(
        &root,
        &token_id,
        &identity,
        &rpc_str,
        &passphrase,
        &["balance", "--id", &sas_id],
    )
    .trim()
    .trim_matches('"')
    .parse()
    .unwrap_or(0);

    assert_eq!(
        balance_after - balance_before,
        FEE_AMOUNT,
        "SAS contract's SAC balance must increase by exactly the configured fee"
    );
}
