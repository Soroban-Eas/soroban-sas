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

use soroban_sas_sdk::client::{IndexerClient, SASClient};
use soroban_sas_sdk::rpc::RpcClient;
use soroban_sas_sdk::signature::derive_public_key;
use soroban_sas_sdk::attestation_builder::AttestationRequestBuilder;
use soroban_sdk::{Bytes, Env};
use std::path::{Path, PathBuf};
use std::process::Command;

fn rpc_url() -> String {
    std::env::var("SOROBAN_RPC_URL").unwrap_or_else(|_| "http://localhost:8000/soroban/rpc".to_string())
}

fn network_passphrase() -> String {
    std::env::var("NETWORK_PASSPHRASE")
        .unwrap_or_else(|_| "Standalone Network ; February 2017".to_string())
}

fn secret_key() -> String {
    std::env::var("STELLAR_SECRET_KEY")
        .expect("STELLAR_SECRET_KEY must be set to run integration tests (see DEVELOPER_RUNBOOK.md)")
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
    let base = rpc_url()
        .trim_end_matches("/soroban/rpc")
        .to_string();
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
    let output = Command::new(stellar_cli())
        .args(["keys", "add", &name, "--secret-key"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{secret}\n").as_bytes())?;
            child.wait_with_output()
        })
        .expect("failed to run `stellar keys add`");
    if !output.status.success() {
        // Identity may already exist from a prior run in the same container.
        eprintln!(
            "stellar keys add warning: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
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

fn invoke(dir: &Path, contract_id: &str, identity: &str, rpc: &str, passphrase: &str, call_args: &[&str]) -> String {
    let mut args = vec!["contract", "invoke", "--id", contract_id];
    args.extend(net_args(identity, rpc, passphrase));
    args.push("--");
    args.extend_from_slice(call_args);
    run(dir, stellar_cli(), &args)
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

    run(
        &root,
        "cargo",
        &[
            "build",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "-p",
            "schema-registry",
            "-p",
            "sas",
            "-p",
            "soroban-sas-indexer",
            "-p",
            "permissive-resolver",
        ],
    );

    let wasm_dir = root.join("target/wasm32-unknown-unknown/release");
    let registry_id = deploy_contract(
        &root,
        &wasm_dir.join("schema_registry.wasm"),
        &identity,
        &rpc,
        &passphrase,
    );
    let sas_id = deploy_contract(&root, &wasm_dir.join("sas.wasm"), &identity, &rpc, &passphrase);
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

    invoke(&root, &registry_id, &identity, &rpc, &passphrase, &["init", "--admin", &admin]);
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
    let sas_client = SASClient::new(sas_id.clone());

    // 1. Schema registration.
    sas_client
        .register_schema(&env, &rpc, &passphrase, &secret, &registry_id, "bool verified", &resolver_id, true)
        .expect("register_schema failed");
    let resolver_address =
        soroban_sdk::Address::from_string(&soroban_sdk::String::from_str(&env, &resolver_id));
    let schema_uid = SASClient::compute_schema_uid(
        &env,
        "bool verified",
        &resolver_address,
        true,
    );

    // 2. Attestation issuance: self-attest (admin is both attester and recipient).
    let attestation = AttestationRequestBuilder::new()
        .with_schema_uid(schema_uid.0.to_array())
        .with_recipient(&admin)
        .with_attester(&admin)
        .with_data(Bytes::from_slice(&env, b"integration test payload"))
        .build(&env)
        .expect("failed to build attestation");
    let uid = attestation.uid.0.to_array();

    sas_client
        .attest(&env, &rpc, &passphrase, &secret, attestation)
        .expect("attest failed");

    let fetched = sas_client
        .get_attestation(&env, &rpc, &uid)
        .expect("get_attestation failed")
        .expect("attestation was not found after a successful attest");
    assert_eq!(fetched.uid.0.to_array(), uid);
    assert_eq!(fetched.revocation_time, 0, "freshly issued attestation must not be revoked");

    // 3. Indexer reverse lookup: the admin's own attestation must be
    // discoverable by recipient without knowing its UID in advance.
    let indexer_client = IndexerClient::new(indexer_id);
    let by_recipient = indexer_client
        .get_attestations_by_recipient(&env, &rpc, &admin)
        .expect("get_attestations_by_recipient failed");
    assert!(
        by_recipient.iter().any(|u| u.0.to_array() == uid),
        "indexer did not return the newly issued attestation for its recipient"
    );

    // 4. Revocation.
    sas_client
        .revoke(&env, &rpc, &passphrase, &secret, &uid)
        .expect("revoke failed");
    let revoked = sas_client
        .get_attestation(&env, &rpc, &uid)
        .expect("get_attestation after revoke failed")
        .expect("revoked attestation must still be readable");
    assert_ne!(revoked.revocation_time, 0, "revoke must set a nonzero revocation_time");
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
    assert!(token_id.starts_with('C'), "expected a SAC contract id, got: {token_id}");

    const FEE_AMOUNT: i128 = 500;

    let env = Env::default();
    let rpc = RpcClient::new(rpc_str.clone());
    let secret = parse_secret_seed(&secret_string);
    let admin = admin_address(&secret_string);
    let sas_client = SASClient::new(sas_id.clone());

    sas_client
        .register_schema(&env, &rpc, &passphrase, &secret, &registry_id, "bool paid", &resolver_id, true)
        .expect("register_schema failed");
    let resolver_address =
        soroban_sdk::Address::from_string(&soroban_sdk::String::from_str(&env, &resolver_id));
    let schema_uid = SASClient::compute_schema_uid(&env, "bool paid", &resolver_address, true);

    sas_client
        .set_fee(&env, &rpc, &passphrase, &secret, &token_id, FEE_AMOUNT)
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

    let attestation = AttestationRequestBuilder::new()
        .with_schema_uid(schema_uid.0.to_array())
        .with_recipient(&admin)
        .with_attester(&admin)
        .with_data(Bytes::from_slice(&env, b"paid attestation"))
        .build(&env)
        .expect("failed to build attestation");

    sas_client
        .attest_with_value(&env, &rpc, &passphrase, &secret, attestation, &token_id, FEE_AMOUNT)
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
