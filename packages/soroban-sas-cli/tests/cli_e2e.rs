//! End-to-end tests for CLI workflows (#332).
//!
//! Every test runs the compiled `soroban-sas-cli` binary through its real
//! command-line interface and inspects only its exit code, stdout, and
//! stderr. Network reads go to [`RpcHost`], a local JSON-RPC endpoint that
//! answers `simulateTransaction` by decoding the CLI's transaction envelope
//! and invoking the *real* schema-registry, SAS, and Indexer contracts in an
//! in-process Soroban host. The indexed data the CLI reads is therefore
//! produced by the genuine SAS -> Indexer flow, and no external service or
//! funded account is needed: each test owns its own host and temp dir, so
//! runs are deterministic and isolated.
//!
//! Only read-only (simulated) calls are served. Write paths are exercised up
//! to the local validation that must reject bad input *before* any RPC call;
//! the host records every request so tests can prove none was made.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;

use base64::Engine as _;
use sha2::{Digest, Sha256};

use sas::{SASClient, SAS};
use schema_registry::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::{Attestation, UID};
use soroban_sas_indexer::{Indexer, IndexerClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::xdr::{
    AccountEntry, AccountEntryExt, AccountId, ExtensionPoint, HostFunction, LedgerEntryData,
    LedgerFootprint, Limits, OperationBody, PublicKey, ReadXdr, ScVal, SequenceNumber,
    SorobanResources, SorobanTransactionData, String32, Thresholds, TransactionEnvelope, Uint256,
    VecM, WriteXdr,
};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, BytesN, Env, String as SorobanString, Symbol,
    TryFromVal, Val,
};

const NETWORK: &str = "Standalone Network ; February 2017";
/// Attester seed; its account owns the fixture schema.
const ATTESTER_SEED: [u8; 32] = [41u8; 32];
const ZERO_ACCOUNT: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

mod accept_all_resolver {
    use super::*;

    #[contract]
    pub struct AcceptAllResolver;

    #[contractimpl]
    impl AcceptAllResolver {
        pub fn on_attest(_env: Env, _attestation: Attestation) {}
        pub fn on_revoke(_env: Env, _attestation: Attestation) {}
    }
}

// ---------------------------------------------------------------------------
// Fixture: real contracts populated through SAS
// ---------------------------------------------------------------------------

/// Everything a test needs to address the deployed contracts, as strings.
#[derive(Clone, Debug)]
struct Fixture {
    sas_id: String,
    indexer_id: String,
    /// Schema Registry the CLI registers/reads schemas against (#469).
    registry_id: String,
    /// The `AcceptAllResolver` contract the fixture schema uses — the
    /// wizard's resolver prompt needs a real `C...` address (#469).
    resolver_id: String,
    schema_uid: String,
    attester: String,
    recipient: String,
    other_recipient: String,
    /// `recipient`'s history, in issuance order (hex UIDs).
    recipient_uids: Vec<String>,
    /// The schema/attester history, in issuance order.
    schema_uids: Vec<String>,
    active_uid: String,
    revoked_uid: String,
}

fn account(seed: u8) -> String {
    stellar_strkey::ed25519::PublicKey([seed; 32]).to_string()
}

fn attester_account() -> String {
    let public_key = ed25519_dalek::SigningKey::from_bytes(&ATTESTER_SEED)
        .verifying_key()
        .to_bytes();
    stellar_strkey::ed25519::PublicKey(public_key).to_string()
}

fn strkey(address: &Address) -> String {
    let s = address.to_string();
    let mut buf = vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    String::from_utf8(buf).unwrap()
}

fn address(env: &Env, strkey: &str) -> Address {
    Address::from_string(&SorobanString::from_str(env, strkey))
}

fn uid_hex(uid: &UID) -> String {
    hex::encode(uid.0.to_array())
}

/// Deploys registry + SAS + Indexer, binds them as an operator would, and
/// issues attestations through SAS so the Indexer is populated by the real
/// SAS -> Indexer flow: 7 to `recipient` interleaved with 3 to
/// `other_recipient`, one of `recipient`'s later revoked.
fn populate(env: &Env) -> Fixture {
    env.mock_all_auths();
    env.budget().reset_unlimited();
    env.ledger().with_mut(|li| li.timestamp = 1_000);

    let admin = Address::generate(env);
    let registry_id = env.register_contract(None, SchemaRegistry);
    let registry = SchemaRegistryClient::new(env, &registry_id);
    registry.init(&admin);
    let sas_id = env.register_contract(None, SAS);
    let sas = SASClient::new(env, &sas_id);
    sas.init(&admin, &registry_id);
    let indexer_id = env.register_contract(None, Indexer);
    IndexerClient::new(env, &indexer_id).init(&admin, &sas_id);
    sas.set_indexer(&indexer_id);

    let resolver = env.register_contract(None, accept_all_resolver::AcceptAllResolver);
    let attester = address(env, &attester_account());
    let schema_uid = registry.register(
        &attester,
        &SorobanString::from_str(env, "bool verified"),
        &resolver,
        &true,
    );

    let recipient = address(env, &account(5));
    let other = address(env, &account(6));
    let mut recipient_uids = Vec::new();
    let mut schema_uids = Vec::new();
    for i in 0..10u32 {
        let to = if i % 3 == 2 { &other } else { &recipient };
        let data = Bytes::from_array(env, &i.to_be_bytes());
        let uid = sas.attest(&Attestation {
            uid: soroban_sas_common::attestation_uid(env, &schema_uid, to, &attester, &data),
            schema_uid: schema_uid.clone(),
            time: 0,
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
            recipient: to.clone(),
            attester: attester.clone(),
            revocable: true,
            data,
        });
        if to == &recipient {
            recipient_uids.push(uid_hex(&uid));
        }
        schema_uids.push(uid_hex(&uid));
    }
    assert_eq!(recipient_uids.len(), 7);

    env.ledger().with_mut(|li| li.timestamp = 2_000);
    let revoked = UID(BytesN::from_array(
        env,
        &hex::decode(&recipient_uids[1]).unwrap().try_into().unwrap(),
    ));
    sas.revoke(&revoked);

    Fixture {
        sas_id: strkey(&sas_id),
        indexer_id: strkey(&indexer_id),
        registry_id: strkey(&registry_id),
        resolver_id: strkey(&resolver),
        schema_uid: uid_hex(&schema_uid),
        attester: strkey(&attester),
        recipient: strkey(&recipient),
        other_recipient: strkey(&other),
        active_uid: recipient_uids[0].clone(),
        revoked_uid: recipient_uids[1].clone(),
        recipient_uids,
        schema_uids,
    }
}

// ---------------------------------------------------------------------------
// RpcHost: JSON-RPC over HTTP backed by an in-process Soroban host
// ---------------------------------------------------------------------------

/// Mutable host state shared between the listener thread and the test:
/// every JSON-RPC method received (for request-sequence assertions) and the
/// envelopes `sendTransaction` accepted, keyed by hash so `getTransaction`
/// can echo them back like real Soroban RPC does.
#[derive(Default)]
struct HostState {
    methods: Vec<String>,
    envelopes: HashMap<String, String>,
}

/// A local Soroban RPC stand-in. Owns the `Env` on its own thread (a host
/// is not `Send`) and serves one request per connection until dropped.
struct RpcHost {
    url: String,
    fixture: Fixture,
    state: Arc<Mutex<HostState>>,
    shutdown: Arc<AtomicBool>,
    port: u16,
    thread: Option<JoinHandle<()>>,
}

impl RpcHost {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(HostState::default()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel();

        let thread = {
            let state = state.clone();
            let shutdown = shutdown.clone();
            std::thread::spawn(move || {
                let env = Env::default();
                ready_tx.send(populate(&env)).unwrap();
                for stream in listener.incoming() {
                    if shutdown.load(Ordering::SeqCst) {
                        break;
                    }
                    if let Ok(stream) = stream {
                        serve(&env, stream, &state);
                    }
                }
            })
        };
        let fixture = ready_rx.recv().expect("fixture setup failed");
        RpcHost {
            url: format!("http://127.0.0.1:{port}/"),
            fixture,
            state,
            shutdown,
            port,
            thread: Some(thread),
        }
    }

    /// JSON-RPC methods received so far, in order.
    fn methods(&self) -> Vec<String> {
        self.state.lock().unwrap().methods.clone()
    }
}

impl Drop for RpcHost {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock `incoming()` so the thread observes the flag and exits.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(env: &Env, stream: TcpStream, state: &Mutex<HostState>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    if reader.read_exact(&mut body).is_err() || body.is_empty() {
        return;
    }
    let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let method = request["method"].as_str().unwrap_or_default().to_string();
    let mut state = state.lock().unwrap();
    state.methods.push(method.clone());

    let response = match method.as_str() {
        "simulateTransaction" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": simulate(env, request["params"]["transaction"].as_str().unwrap()),
        }),
        // The write pipeline (#469) first reads the source account's
        // sequence number; every requested key gets the canned account
        // entry, which is all `fetch_sequence_numbers` decodes.
        "getLedgerEntries" => {
            let entries: Vec<serde_json::Value> = request["params"]["keys"]
                .as_array()
                .map(|keys| {
                    keys.iter()
                        .map(|key| {
                            serde_json::json!({
                                "key": key.as_str().unwrap_or_default(),
                                "xdr": account_entry_xdr(),
                                "lastModifiedLedgerSeq": 1
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": { "entries": entries, "latestLedger": env.ledger().sequence() }
            })
        }
        // Executes the submitted invocation against the real contracts and
        // records the envelope under a deterministic hash, mirroring how a
        // validator would accept and store the transaction.
        "sendTransaction" => {
            let envelope_b64 = request["params"]["transaction"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let hash = tx_hash(&envelope_b64);
            let result = match invoke_envelope(env, &envelope_b64) {
                Ok(_) => {
                    state.envelopes.insert(hash.clone(), envelope_b64);
                    serde_json::json!({
                        "status": "SUCCESS",
                        "hash": hash,
                        "latestLedger": env.ledger().sequence()
                    })
                }
                Err(_) => serde_json::json!({
                    "status": "ERROR",
                    "hash": hash,
                    "latestLedger": env.ledger().sequence()
                }),
            };
            serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })
        }
        // Settles immediately with the stored envelope echoed back, so the
        // SDK's single poll sees `SUCCESS` without sleeping.
        "getTransaction" => {
            let hash = request["params"]["hash"].as_str().unwrap_or_default();
            let result = match state.envelopes.get(hash).cloned() {
                Some(envelope_xdr) => serde_json::json!({
                    "status": "SUCCESS",
                    "latestLedger": env.ledger().sequence(),
                    "envelopeXdr": envelope_xdr
                }),
                None => serde_json::json!({
                    "status": "NOT_FOUND",
                    "latestLedger": env.ledger().sequence()
                }),
            };
            serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })
        }
        other => serde_json::json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": { "code": -32601, "message": format!("method not served by test host: {other}") },
        }),
    };
    drop(state);
    let text = response.to_string();
    let mut stream = stream;
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        text.len(),
        text
    );
    let _ = stream.flush();
}

/// Deterministic stand-in for Stellar's transaction hash (the host only
/// needs a stable identifier to echo between `sendTransaction` and
/// `getTransaction`): SHA-256 over the envelope's raw bytes.
fn tx_hash(envelope_b64: &str) -> String {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(envelope_b64)
        .unwrap_or_default();
    hex::encode(Sha256::digest(bytes))
}

/// A minimal account ledger entry: `fetch_sequence_numbers` only decodes
/// the sequence number, so one canned entry answers every account lookup.
fn account_entry_xdr() -> String {
    LedgerEntryData::Account(AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7u8; 32]))),
        balance: 100_000_000,
        seq_num: SequenceNumber(7),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: Default::default(),
        ext: AccountEntryExt::V0,
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// The `transactionData` a write simulation must echo back so the SDK can
/// build the final signed transaction (`build_signed_write_at_sequence`).
fn transaction_data_xdr() -> String {
    SorobanTransactionData {
        ext: ExtensionPoint::V0,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: VecM::default(),
                read_write: VecM::default(),
            },
            instructions: 0,
            read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 0,
    }
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// Contract entrypoints that mutate storage. A real RPC node never applies
/// state changes during `simulateTransaction`, and the in-process host has
/// no transactional rollback, so [`simulate`] reports a canned success for
/// these instead of executing them — writes only ever happen when the CLI
/// actually submits via `sendTransaction` (#469). Read entrypoints are all
/// `get_*`/`has_*`-style and never match these prefixes.
fn mutates_storage(function_name: &str) -> bool {
    const WRITE_PREFIXES: [&str; 10] = [
        "register",
        "attest",
        "revoke",
        "set_",
        "add_",
        "remove_",
        "withdraw",
        "deprecate",
        "init",
        "reindex",
    ];
    WRITE_PREFIXES
        .iter()
        .any(|prefix| function_name.starts_with(prefix))
}

/// Decodes the envelope's single `InvokeContract` operation into the host
/// types the simulate/send paths share: the contract, the function symbol,
/// its name as a string (for [`mutates_storage`]), and the arguments.
fn decode_invocation(
    env: &Env,
    envelope_b64: &str,
) -> (Address, Symbol, String, soroban_sdk::Vec<Val>) {
    let envelope = TransactionEnvelope::from_xdr_base64(envelope_b64, Limits::none()).unwrap();
    let TransactionEnvelope::Tx(v1) = envelope else {
        panic!("CLI must send a V1 envelope");
    };
    let OperationBody::InvokeHostFunction(op) = &v1.tx.operations[0].body else {
        panic!("CLI must simulate an InvokeHostFunction operation");
    };
    let HostFunction::InvokeContract(call) = &op.host_function else {
        panic!("CLI must simulate an InvokeContract host function");
    };

    let contract = Address::try_from_val(env, &ScVal::Address(call.contract_address.clone()))
        .expect("contract address");
    let function = Symbol::try_from_val(env, &ScVal::Symbol(call.function_name.clone()))
        .expect("function name");
    let function_name = String::from_utf8_lossy(&call.function_name.0).into_owned();
    let mut args = soroban_sdk::Vec::<Val>::new(env);
    for arg in call.args.iter() {
        args.push_back(Val::try_from_val(env, arg).expect("argument"));
    }
    (contract, function, function_name, args)
}

/// Executes the envelope's single `InvokeContract` against the host,
/// returning the raw return value or the host's diagnostic (e.g.
/// `Error(Contract, #402)`). Used by the `sendTransaction` path (#469),
/// where a write must genuinely execute.
fn invoke_envelope(env: &Env, envelope_b64: &str) -> Result<Val, String> {
    let (contract, function, _function_name, args) = decode_invocation(env, envelope_b64);
    match env.try_invoke_contract::<Val, soroban_sdk::Error>(&contract, &function, args) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err("HostError: Error(Value, UnexpectedType)".to_string()),
        Err(Ok(error)) => Err(format!("HostError: {error:?}")),
        Err(Err(error)) => Err(format!("HostError: {error:?}")),
    }
}

/// Shapes an invocation's outcome like Soroban RPC's `simulateTransaction`:
/// `results[0].xdr` and a `transactionData` footprint on success (write
/// pipelines need the latter to build the signed transaction, #469), or an
/// `error` carrying the host's diagnostic. Read-only calls execute against
/// the real contracts; storage-mutating entrypoints are reported as a
/// canned success without executing (see [`mutates_storage`]).
fn simulate(env: &Env, envelope_b64: &str) -> serde_json::Value {
    let (contract, function, function_name, args) = decode_invocation(env, envelope_b64);
    let outcome = if mutates_storage(&function_name) {
        Ok(ScVal::Void.to_xdr_base64(Limits::none()).unwrap())
    } else {
        match env.try_invoke_contract::<Val, soroban_sdk::Error>(&contract, &function, args) {
            Ok(Ok(value)) => Ok(ScVal::try_from_val(env, &value)
                .unwrap()
                .to_xdr_base64(Limits::none())
                .unwrap()),
            Ok(Err(_)) => Err("HostError: Error(Value, UnexpectedType)".to_string()),
            Err(Ok(error)) => Err(format!("HostError: {error:?}")),
            Err(Err(error)) => Err(format!("HostError: {error:?}")),
        }
    };
    match outcome {
        Ok(xdr) => serde_json::json!({
            "latestLedger": env.ledger().sequence(),
            "results": [{ "xdr": xdr, "auth": [] }],
            "transactionData": transaction_data_xdr(),
            "minResourceFee": "0",
        }),
        Err(error) => serde_json::json!({
            "latestLedger": env.ledger().sequence(),
            "error": error,
        }),
    }
}

// ---------------------------------------------------------------------------
// Running the binary
// ---------------------------------------------------------------------------

/// A per-test scratch directory, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "soroban-sas-cli-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }

    fn write(&self, name: &str, contents: &str) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", self.stdout))
    }

    fn assert_ok(&self) -> &Self {
        assert_eq!(
            self.code,
            Some(0),
            "stdout: {}\nstderr: {}",
            self.stdout,
            self.stderr
        );
        self
    }

    fn assert_failed(&self) -> &Self {
        assert_eq!(
            self.code,
            Some(1),
            "stdout: {}\nstderr: {}",
            self.stdout,
            self.stderr
        );
        self
    }
}

/// Builds the CLI invocation with a scrubbed environment: none of the
/// `SOROBAN_*`/`SAS_*` fallbacks the developer's shell may define can leak
/// in, and identities resolve from `identity_dir` only.
fn command_for(identity_dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_soroban-sas-cli"));
    for var in [
        "SOROBAN_RPC_URL",
        "SOROBAN_NETWORK_PASSPHRASE",
        "SAS_SECRET_KEY",
        "SAS_CONTRACT_ID",
        "INDEXER_CONTRACT_ID",
        "SCHEMA_REGISTRY_CONTRACT_ID",
    ] {
        command.env_remove(var);
    }
    command.env("SAS_IDENTITY_DIR", identity_dir);
    command.args(args);
    command
}

/// Runs the CLI with `args` and its stdin closed (see [`command_for`]).
fn cli(identity_dir: &Path, args: &[&str]) -> Run {
    let Output {
        status,
        stdout,
        stderr,
    } = command_for(identity_dir, args)
        .output()
        .expect("spawn soroban-sas-cli");
    Run {
        code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

/// Like [`cli`], but pipes `stdin` into the child. The wizard's
/// non-interactive fallback (#469) reads its answers line by line from a
/// non-TTY stdin, which this drives exactly like a shell pipe would.
fn cli_with_stdin(identity_dir: &Path, args: &[&str], stdin: &str) -> Run {
    use std::process::Stdio;
    let mut child = command_for(identity_dir, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn soroban-sas-cli");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(stdin.as_bytes())
        .expect("write wizard answers");
    let Output {
        status,
        stdout,
        stderr,
    } = child.wait_with_output().expect("wait soroban-sas-cli");
    Run {
        code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    }
}

/// Test context: a live host plus a scratch dir holding an `attester`
/// identity for signing commands.
struct Ctx {
    host: RpcHost,
    dir: TempDir,
}

impl Ctx {
    fn new() -> Self {
        let dir = TempDir::new();
        dir.write("attester", &hex::encode(ATTESTER_SEED));
        Ctx {
            host: RpcHost::start(),
            dir,
        }
    }

    fn f(&self) -> &Fixture {
        &self.host.fixture
    }

    fn run(&self, args: &[&str]) -> Run {
        cli(self.dir.path(), args)
    }

    /// Runs the CLI with `stdin` piped in, driving line-based flows like the
    /// `schema wizard` (#469).
    fn run_stdin(&self, args: &[&str], stdin: &str) -> Run {
        cli_with_stdin(self.dir.path(), args, stdin)
    }

    /// `--output json query <by> <key-flag> <key> --contract-id <indexer>`
    /// against this host, plus `extra` flags.
    fn query(&self, by: &str, key_flag: &str, key: &str, extra: &[&str]) -> Run {
        let mut args = vec![
            "--output",
            "json",
            "query",
            by,
            key_flag,
            key,
            "--contract-id",
            &self.f().indexer_id,
            "--rpc-url",
            &self.host.url,
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }
}

fn uids_of(value: &serde_json::Value) -> Vec<String> {
    value["data"]["uids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// Follows `next_cursor` from 0 until `null`, returning every UID seen and
/// the size of each page.
fn walk(ctx: &Ctx, by: &str, key_flag: &str, key: &str, limit: &str) -> (Vec<String>, Vec<usize>) {
    let mut cursor = "0".to_string();
    let mut all = Vec::new();
    let mut sizes = Vec::new();
    loop {
        let run = ctx.query(
            by,
            key_flag,
            key,
            &["--cursor", cursor.as_str(), "--limit", limit],
        );
        let page = run.assert_ok().json();
        let uids = uids_of(&page);
        sizes.push(uids.len());
        all.extend(uids);
        match page["data"]["next_cursor"].as_u64() {
            Some(next) => cursor = next.to_string(),
            None => return (all, sizes),
        }
        assert!(sizes.len() < 100, "pagination did not terminate");
    }
}

// ---------------------------------------------------------------------------
// Indexed-data queries
// ---------------------------------------------------------------------------

#[test]
fn query_by_recipient_returns_the_sas_indexed_history_in_order() {
    let ctx = Ctx::new();
    let run = ctx.query("by-recipient", "--address", &ctx.f().recipient, &[]);
    let json = run.assert_ok().json();
    assert_eq!(json["status"], "ok");
    // Revoked attestations remain part of the auditable history.
    assert_eq!(uids_of(&json), ctx.f().recipient_uids);
    // The unpaginated shape is unchanged: no pagination fields.
    assert!(json["data"].get("next_cursor").is_none());
    assert_eq!(ctx.host.methods(), vec!["simulateTransaction"]);

    // Human output lists the same UIDs, one per line.
    let human = ctx.run(&[
        "query",
        "by-recipient",
        "--address",
        &ctx.f().recipient,
        "--contract-id",
        &ctx.f().indexer_id,
        "--rpc-url",
        &ctx.host.url,
    ]);
    let lines: Vec<String> = human
        .assert_ok()
        .stdout
        .lines()
        .map(str::to_string)
        .collect();
    assert_eq!(lines, ctx.f().recipient_uids);
}

#[test]
fn query_by_schema_and_attester_see_every_recipient() {
    let ctx = Ctx::new();
    let by_schema = ctx.query("by-schema", "--uid", &ctx.f().schema_uid, &[]);
    assert_eq!(uids_of(&by_schema.assert_ok().json()), ctx.f().schema_uids);

    // The other recipient's entries are exactly the schema history minus
    // the first recipient's, still in issuance order.
    let other = ctx.query("by-recipient", "--address", &ctx.f().other_recipient, &[]);
    let expected: Vec<String> = ctx
        .f()
        .schema_uids
        .iter()
        .filter(|uid| !ctx.f().recipient_uids.contains(uid))
        .cloned()
        .collect();
    assert_eq!(expected.len(), 3);
    assert_eq!(uids_of(&other.assert_ok().json()), expected);

    let by_attester = ctx.query("by-attester", "--address", &ctx.f().attester, &[]);
    let json = by_attester.assert_ok().json();
    assert_eq!(uids_of(&json), ctx.f().schema_uids);
    assert_eq!(json["data"]["attester"], ctx.f().attester.as_str());
}

#[test]
fn query_for_an_address_without_attestations_is_empty_not_an_error() {
    let ctx = Ctx::new();
    // Includes the zero-address "no recipient" sentinel: SAS never issues
    // to it, so nothing can be indexed under it (#304).
    for address in [account(77), ZERO_ACCOUNT.to_string()] {
        let json = ctx
            .query("by-recipient", "--address", &address, &[])
            .assert_ok()
            .json();
        assert_eq!(json["data"]["uids"], serde_json::json!([]));

        let human = ctx.run(&[
            "query",
            "by-recipient",
            "--address",
            &address,
            "--contract-id",
            &ctx.f().indexer_id,
            "--rpc-url",
            &ctx.host.url,
        ]);
        assert_eq!(human.assert_ok().stdout.trim(), "No attestations found");
    }
}

#[test]
fn query_rejects_malformed_keys_locally() {
    let ctx = Ctx::new();
    let run = ctx.query("by-recipient", "--address", "not-a-strkey", &[]);
    let json = run.assert_failed().json();
    assert_eq!(json["status"], "error");
    assert!(json["message"].as_str().unwrap().contains("recipient"));

    let run = ctx.query("by-schema", "--uid", "abcd", &[]);
    assert!(run.assert_failed().json()["message"]
        .as_str()
        .unwrap()
        .contains("32 bytes"));
    assert!(ctx.host.methods().is_empty(), "no RPC call for bad input");
}

#[test]
fn query_against_the_wrong_contract_reports_the_host_error() {
    let ctx = Ctx::new();
    // The SAS contract has no indexer lookups: the simulation fails and the
    // CLI must surface it as an error envelope, not crash or print `[]`.
    let run = ctx.run(&[
        "--output",
        "json",
        "query",
        "by-recipient",
        "--address",
        &ctx.f().recipient,
        "--contract-id",
        &ctx.f().sas_id,
        "--rpc-url",
        &ctx.host.url,
    ]);
    let json = run.assert_failed().json();
    assert_eq!(json["status"], "error");
    assert!(!json["message"].as_str().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Pagination (#306)
// ---------------------------------------------------------------------------

#[test]
fn paginated_walk_reassembles_the_history_without_gaps_or_repeats() {
    let ctx = Ctx::new();
    let (all, sizes) = walk(&ctx, "by-recipient", "--address", &ctx.f().recipient, "3");
    assert_eq!(all, ctx.f().recipient_uids);
    assert_eq!(sizes, vec![3, 3, 1]);

    let (all, sizes) = walk(&ctx, "by-schema", "--uid", &ctx.f().schema_uid, "4");
    assert_eq!(all, ctx.f().schema_uids);
    assert_eq!(sizes, vec![4, 4, 2]);

    let (all, _) = walk(&ctx, "by-attester", "--address", &ctx.f().attester, "100");
    assert_eq!(all, ctx.f().schema_uids);
}

#[test]
fn page_metadata_describes_first_middle_and_final_pages() {
    let ctx = Ctx::new();
    let f = ctx.f();

    let first = ctx.query("by-recipient", "--address", &f.recipient, &["--limit", "3"]);
    let first = first.assert_ok().json();
    assert_eq!(first["data"]["cursor"], 0);
    assert_eq!(first["data"]["limit"], 3);
    assert_eq!(first["data"]["total"], 7);
    assert_eq!(first["data"]["next_cursor"], 3);
    assert_eq!(uids_of(&first), f.recipient_uids[0..3]);

    let last = ctx.query(
        "by-recipient",
        "--address",
        &f.recipient,
        &["--cursor", "6", "--limit", "3"],
    );
    let last = last.assert_ok().json();
    assert_eq!(uids_of(&last), f.recipient_uids[6..]);
    assert_eq!(last["data"]["next_cursor"], serde_json::Value::Null);

    // Human rendering carries the same navigation hint.
    let human = ctx.run(&[
        "query",
        "by-recipient",
        "--address",
        &f.recipient,
        "--contract-id",
        &f.indexer_id,
        "--rpc-url",
        &ctx.host.url,
        "--cursor",
        "3",
        "--limit",
        "3",
    ]);
    let stdout = human.assert_ok().stdout.clone();
    assert!(stdout.contains(&f.recipient_uids[3]), "{stdout}");
    assert!(
        stdout.contains("Page: 4-6 of 7 (next: --cursor 6)"),
        "{stdout}"
    );

    // By-attester pages keep echoing the attester like the full query.
    let page = ctx.query("by-attester", "--address", &f.attester, &["--limit", "2"]);
    assert_eq!(
        page.assert_ok().json()["data"]["attester"],
        f.attester.as_str()
    );
}

#[test]
fn requests_beyond_the_end_return_an_empty_final_page() {
    let ctx = Ctx::new();
    for cursor in ["7", "50", "4294967295"] {
        let run = ctx.query(
            "by-recipient",
            "--address",
            &ctx.f().recipient,
            &["--cursor", cursor, "--limit", "3"],
        );
        let json = run.assert_ok().json();
        assert_eq!(
            json["data"]["uids"],
            serde_json::json!([]),
            "cursor {cursor}"
        );
        assert_eq!(json["data"]["total"], 7);
        assert_eq!(json["data"]["next_cursor"], serde_json::Value::Null);
    }

    // An empty history pages as a single empty, final page.
    let json = ctx
        .query("by-recipient", "--address", &account(77), &["--limit", "5"])
        .assert_ok()
        .json();
    assert_eq!(json["data"]["total"], 0);
    assert_eq!(json["data"]["next_cursor"], serde_json::Value::Null);
}

#[test]
fn invalid_page_arguments_fail_before_any_rpc_call() {
    let ctx = Ctx::new();
    for limit in ["0", "101"] {
        let run = ctx.query(
            "by-recipient",
            "--address",
            &ctx.f().recipient,
            &["--limit", limit],
        );
        let json = run.assert_failed().json();
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("--limit must be between 1 and 100"));
    }
    // Non-numeric values are clap usage errors (exit 2).
    let run = ctx.query(
        "by-recipient",
        "--address",
        &ctx.f().recipient,
        &["--cursor", "-1"],
    );
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    assert!(ctx.host.methods().is_empty());
}

#[test]
fn query_help_documents_pagination() {
    let run = cli(Path::new("."), &["query", "by-schema", "--help"]);
    let stdout = run.assert_ok().stdout.clone();
    assert!(stdout.contains("--cursor"), "{stdout}");
    assert!(stdout.contains("--limit"), "{stdout}");
    assert!(stdout.contains("complete history"), "{stdout}");
}

// ---------------------------------------------------------------------------
// On-chain verification of indexed attestations
// ---------------------------------------------------------------------------

#[test]
fn attest_verify_reflects_sas_state_for_indexed_uids() {
    let ctx = Ctx::new();
    let verify = |uid: &str| {
        ctx.run(&[
            "--output",
            "json",
            "attest",
            "verify",
            "--uid",
            uid,
            "--contract-id",
            &ctx.f().sas_id,
            "--rpc-url",
            &ctx.host.url,
        ])
        .assert_ok()
        .json()["data"]["valid"]
            .clone()
    };
    assert_eq!(verify(&ctx.f().active_uid), true);
    // Still listed by the indexer, but revoked in SAS: SAS is authoritative.
    assert!(ctx.f().recipient_uids.contains(&ctx.f().revoked_uid));
    assert_eq!(verify(&ctx.f().revoked_uid), false);
    assert_eq!(verify(&hex::encode([0xEEu8; 32])), false);
}

// ---------------------------------------------------------------------------
// Missing recipients on issuance paths (#304)
// ---------------------------------------------------------------------------

/// `attest attest` with `recipient`, signed by the fixture attester.
fn attest_to(ctx: &Ctx, recipient: &str) -> Run {
    ctx.run(&[
        "--output",
        "json",
        "--identity",
        "attester",
        "attest",
        "attest",
        "--schema-uid",
        &ctx.f().schema_uid,
        "--recipient",
        recipient,
        "--network-passphrase",
        NETWORK,
        "--contract-id",
        &ctx.f().sas_id,
        "--rpc-url",
        &ctx.host.url,
    ])
}

#[test]
fn attest_rejects_a_missing_recipient_before_any_rpc_call() {
    let ctx = Ctx::new();
    for sentinel in [
        ZERO_ACCOUNT.to_string(),
        stellar_strkey::Contract([0u8; 32]).to_string(),
    ] {
        let json = attest_to(&ctx, &sentinel).assert_failed().json();
        let message = json["message"].as_str().unwrap();
        assert!(message.contains("recipient is missing"), "{message}");
        assert!(message.contains("InvalidRecipient"), "{message}");
    }

    let json = attest_to(&ctx, &attester_account()).assert_failed().json();
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("must differ from the attester"));

    // Malformed input is a parse error, distinct from a missing recipient.
    let json = attest_to(&ctx, "").assert_failed().json();
    let message = json["message"].as_str().unwrap();
    assert!(message.contains("recipient"), "{message}");
    assert!(!message.contains("InvalidRecipient"), "{message}");

    // None of these reached the network (not even the ledger-clock read).
    assert!(ctx.host.methods().is_empty(), "{:?}", ctx.host.methods());
}

#[test]
fn attest_without_the_recipient_flag_is_a_usage_error() {
    let ctx = Ctx::new();
    let run = ctx.run(&[
        "--identity",
        "attester",
        "attest",
        "attest",
        "--schema-uid",
        &ctx.f().schema_uid,
        "--contract-id",
        &ctx.f().sas_id,
    ]);
    assert_eq!(run.code, Some(2), "{}", run.stderr);
    assert!(run.stderr.contains("--recipient"), "{}", run.stderr);
}

fn attestation_json(recipient: Option<&str>) -> String {
    let mut value = serde_json::json!({
        "uid": hex::encode([1u8; 32]),
        "schema_uid": hex::encode([2u8; 32]),
        "time": 1000,
        "expiration_time": 0,
        "ref_uid": hex::encode([0u8; 32]),
        "attester": attester_account(),
        "revocable": true,
        "data": "deadbeef",
    });
    if let Some(recipient) = recipient {
        value["recipient"] = serde_json::Value::String(recipient.to_string());
    }
    value.to_string()
}

#[test]
fn attest_create_handles_absent_and_sentinel_recipients_gracefully() {
    let ctx = Ctx::new();
    let create = |file: &str| {
        ctx.run(&[
            "--output",
            "json",
            "--identity",
            "attester",
            "attest",
            "create",
            "--data-file",
            file,
            "--network-passphrase",
            NETWORK,
            "--contract-id",
            &ctx.f().sas_id,
            "--rpc-url",
            &ctx.host.url,
        ])
    };

    let absent = ctx.dir.write("absent.json", &attestation_json(None));
    let json = create(&absent).assert_failed().json();
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("missing field `recipient`"));

    let sentinel = ctx
        .dir
        .write("sentinel.json", &attestation_json(Some(ZERO_ACCOUNT)));
    let json = create(&sentinel).assert_failed().json();
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("recipient is missing"));

    assert!(ctx.host.methods().is_empty());
}

#[test]
fn recipientless_offchain_attestation_signs_and_verifies_but_cannot_be_submitted() {
    let ctx = Ctx::new();
    let input = ctx
        .dir
        .write("public.json", &attestation_json(Some(ZERO_ACCOUNT)));

    // Off-chain, a recipient-less ("public") attestation is well-formed:
    // SAS places no recipient constraint on off-chain verification. In
    // human mode `offchain sign` prints the signed document to stdout.
    let run = ctx.run(&[
        "--identity",
        "attester",
        "offchain",
        "sign",
        "--data-file",
        &input,
        "--nonce",
        "1",
        "--network-passphrase",
        NETWORK,
        "--contract-id",
        &ctx.f().sas_id,
    ]);
    let signed_doc: serde_json::Value = serde_json::from_str(&run.assert_ok().stdout).unwrap();
    assert_eq!(signed_doc["attestation"]["recipient"], ZERO_ACCOUNT);
    let signed = ctx.dir.write("signed.json", &signed_doc.to_string());
    let verified = ctx
        .run(&["--output", "json", "offchain", "verify", "--file", &signed])
        .assert_ok()
        .json();
    assert_eq!(verified["data"]["signature_valid"], true);

    // Relaying it on-chain would be rejected by SAS, so the CLI refuses
    // locally with the same error instead of paying for a doomed submit.
    let json = ctx
        .run(&[
            "--output",
            "json",
            "--identity",
            "attester",
            "delegate",
            "submit-attest",
            "--file",
            &signed,
            "--rpc-url",
            &ctx.host.url,
        ])
        .assert_failed()
        .json();
    let message = json["message"].as_str().unwrap();
    assert!(message.contains("recipient is missing"), "{message}");
    assert!(message.contains("402"), "{message}");
    assert!(ctx.host.methods().is_empty());
}

#[test]
fn offchain_sign_reports_an_absent_recipient_field_without_panicking() {
    let ctx = Ctx::new();
    let input = ctx.dir.write("absent.json", &attestation_json(None));
    let run = ctx.run(&[
        "--identity",
        "attester",
        "offchain",
        "sign",
        "--data-file",
        &input,
        "--nonce",
        "1",
        "--network-passphrase",
        NETWORK,
        "--contract-id",
        &ctx.f().sas_id,
    ]);
    run.assert_failed();
    assert!(
        run.stderr
            .contains("error: invalid attestation JSON: missing field `recipient`"),
        "{}",
        run.stderr
    );
    assert!(!run.stderr.contains("panicked"), "{}", run.stderr);
}

// ---------------------------------------------------------------------------
// Bulk CSV issuance
// ---------------------------------------------------------------------------

/// A well-formed two-row CSV over the fixture's schema and recipients.
fn bulk_csv(ctx: &Ctx) -> String {
    format!(
        "schema_uid,recipient,data,revocable\n\
         {schema},{r1},0x01,true\n\
         {schema},{r2},0x02,false\n",
        schema = ctx.f().schema_uid,
        r1 = ctx.f().recipient,
        r2 = ctx.f().other_recipient,
    )
}

/// `--identity attester` is required even for a dry run: each UID is the
/// content-addressed UID *for this attester*, so the preview is only
/// meaningful with a key in hand.
fn bulk_args<'a>(ctx: &'a Ctx, csv: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "--output",
        "json",
        "--identity",
        "attester",
        "attest",
        "bulk",
        "--csv-file",
        csv,
        "--contract-id",
        &ctx.f().sas_id,
        "--rpc-url",
        &ctx.host.url,
    ];
    args.extend_from_slice(extra);
    args
}

#[test]
fn bulk_dry_run_reports_every_row_without_touching_the_network() {
    let ctx = Ctx::new();
    let csv = ctx.dir.write("bulk.csv", &bulk_csv(&ctx));

    let run = ctx.run(&bulk_args(&ctx, &csv, &["--dry-run"]));
    let json = run.assert_ok().json();

    assert_eq!(json["status"], "ok");
    assert_eq!(json["data"]["dry_run"], true);
    assert_eq!(json["data"]["total"], 2);

    let results = json["data"]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    // Line numbers point back into the operator's file, not at row indices.
    assert_eq!(results[0]["line"], 2);
    assert_eq!(results[1]["line"], 3);
    // Each UID is the content-addressed UID the single-row `attest attest`
    // command derives for the same inputs, so a dry run is a real preview.
    assert_eq!(results[0]["uid"].as_str().unwrap().len(), 64);
    assert_ne!(results[0]["uid"], results[1]["uid"]);

    // A dry run must not simulate, submit, or fetch the ledger clock.
    assert!(
        ctx.host.methods().is_empty(),
        "dry run made RPC calls: {:?}",
        ctx.host.methods()
    );
}

#[test]
fn bulk_rejects_a_malformed_file_before_any_rpc_call() {
    let ctx = Ctx::new();

    // Missing required column.
    let missing = ctx.dir.write("missing.csv", "schema_uid\nabcd\n");
    let json = ctx
        .run(&bulk_args(&ctx, &missing, &["--dry-run"]))
        .assert_failed()
        .json();
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("missing required column `recipient`"));

    // A typo in an *optional* column must be reported rather than silently
    // dropped, which would issue the attestation with a payload the operator
    // never intended. (A typo in a required column is caught by the
    // missing-column check first, which is the more useful message.)
    let unknown = ctx.dir.write(
        "unknown.csv",
        &format!(
            "schema_uid,recipient,recievable\n{},{},true\n",
            ctx.f().schema_uid,
            ctx.f().recipient
        ),
    );
    let json = ctx
        .run(&bulk_args(&ctx, &unknown, &["--dry-run"]))
        .assert_failed()
        .json();
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("unknown column `recievable`"));

    // A bad value in the *last* row still aborts the whole file, so a batch
    // is never half-issued.
    let bad_last = ctx.dir.write(
        "badlast.csv",
        &format!(
            "schema_uid,recipient\n{schema},{ok}\nnothex,{other}\n",
            schema = ctx.f().schema_uid,
            ok = ctx.f().recipient,
            other = ctx.f().other_recipient,
        ),
    );
    let json = ctx
        .run(&bulk_args(&ctx, &bad_last, &["--dry-run"]))
        .assert_failed()
        .json();
    assert_eq!(json["status"], "error");
    assert!(
        json["message"].as_str().unwrap().contains("line 3"),
        "{}",
        json["message"]
    );

    assert!(ctx.host.methods().is_empty(), "no RPC call for a bad CSV");
}

#[test]
fn bulk_rejects_a_recipient_the_contract_would_refuse() {
    let ctx = Ctx::new();
    // Attesting to yourself is rejected by SAS on-chain (#304); the CLI must
    // refuse it locally, before spending a fee.
    let csv = ctx.dir.write(
        "self.csv",
        &format!(
            "schema_uid,recipient\n{schema},{attester}\n",
            schema = ctx.f().schema_uid,
            attester = ctx.f().attester,
        ),
    );

    let json = ctx
        .run(&bulk_args(&ctx, &csv, &["--dry-run"]))
        .assert_failed()
        .json();
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("recipient must differ"),
        "{}",
        json["message"]
    );
    assert!(
        ctx.host.methods().is_empty(),
        "no RPC call for a bad recipient"
    );
}

#[test]
fn bulk_missing_file_is_reported_without_a_panic() {
    let ctx = Ctx::new();
    let missing = ctx
        .dir
        .path()
        .join("nope.csv")
        .to_string_lossy()
        .into_owned();

    let run = ctx.run(&bulk_args(&ctx, &missing, &["--dry-run"]));
    run.assert_failed();
    // In `--output json` the error envelope goes to stdout, not stderr.
    assert!(
        run.json()["message"]
            .as_str()
            .unwrap()
            .contains("cannot read"),
        "{}",
        run.stdout
    );
    assert!(!run.stderr.contains("panicked"), "{}", run.stderr);
}

// ---------------------------------------------------------------------------
// `schema wizard` (#469)
// ---------------------------------------------------------------------------

/// The content-addressed UID the registry derives for
/// `(schema, resolver, revocable)` — the same preimage the CLI computes
/// locally, so the wizard's printed UID can be cross-checked against it.
fn registered_uid(schema: &str, resolver: &str, revocable: bool) -> String {
    let env = Env::default();
    let resolver = Address::from_string(&SorobanString::from_str(&env, resolver));
    uid_hex(&soroban_sas_common::schema_uid(
        &env,
        &SorobanString::from_str(&env, schema),
        &resolver,
        revocable,
    ))
}

/// Drives the wizard end to end over piped (non-TTY) stdin: every answer is
/// read line by line, the fee is estimated by simulation *before* the
/// confirmation, and confirming submits a signed registration that the host
/// executes against the real schema-registry contract — a follow-up read
/// finds the schema on-chain.
#[test]
fn wizard_registers_a_schema_when_confirmed() {
    let ctx = Ctx::new();
    let schema = "bool verified, string full_name";
    // Answer order: name, fields (blank line finishes), revocable,
    // resolver, metadata URI, final confirmation.
    let stdin = format!(
        "KYC Proof v1\n\
         bool verified\n\
         string full_name\n\
         \n\
         y\n\
         {}\n\
         ipfs://bafy/meta.json\n\
         y\n",
        ctx.f().resolver_id
    );
    let run = ctx.run_stdin(
        &[
            "--output",
            "json",
            "schema",
            "wizard",
            "--identity",
            "attester",
            "--registry-contract-id",
            &ctx.f().registry_id,
            "--rpc-url",
            &ctx.host.url,
            "--network-passphrase",
            NETWORK,
        ],
        &stdin,
    );
    run.assert_ok();

    let data = &run.json()["data"];
    let expected_uid = registered_uid(schema, &ctx.f().resolver_id, true);
    assert_eq!(data["submitted"], true);
    // The UID the CLI computed off-chain matches the registry's own
    // content-addressed UID for (schema, resolver, revocable).
    assert_eq!(data["schema_uid"].as_str(), Some(expected_uid.as_str()));
    assert_eq!(data["name"].as_str(), Some("KYC Proof v1"));
    assert_eq!(data["metadata_uri"].as_str(), Some("ipfs://bafy/meta.json"));
    // A 64-hex-digit transaction hash the host derived from the submitted
    // envelope.
    let hash = data["hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "{hash}");

    // Prompts, the summary, and the fee estimate went to stderr…
    assert!(
        run.stderr.contains("stdin is not a terminal"),
        "{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("Registration summary")
            && run.stderr.contains("KYC Proof v1")
            && run.stderr.contains(schema),
        "{}",
        run.stderr
    );
    // …including the estimated network fee (BASE_FEE 100 + simulated 0),
    // and the summary precedes the confirmation prompt.
    let fee = run
        .stderr
        .find("Estimated network fee: 100 stroops")
        .unwrap();
    let confirm = run.stderr.find("Submit registration? [y/N]:").unwrap();
    assert!(fee < confirm, "{}", run.stderr);

    // The registration really executed on the network: a follow-up read
    // through the host's simulate path finds the schema on-chain…
    let found = ctx.run(&[
        "--output",
        "json",
        "schema",
        "get",
        "--uid",
        &expected_uid,
        "--registry-contract-id",
        &ctx.f().registry_id,
        "--rpc-url",
        &ctx.host.url,
    ]);
    found.assert_ok();
    assert_eq!(found.json()["data"]["found"], true);
    assert_eq!(found.json()["data"]["schema"], schema, "{}", found.stdout);

    // …and the host saw one complete write pipeline, with the fee-estimate
    // simulation happening before the submission.
    let methods = ctx.host.methods();
    let first_sim = methods
        .iter()
        .position(|m| m == "simulateTransaction")
        .expect("fee-estimate simulation");
    let send = methods
        .iter()
        .position(|m| m == "sendTransaction")
        .expect("registration submission");
    assert!(first_sim < send, "{methods:?}");
    assert_eq!(
        methods.iter().filter(|m| *m == "sendTransaction").count(),
        1
    );
    assert_eq!(methods.iter().filter(|m| *m == "getTransaction").count(), 1);
}
/// Declining the confirmation exits cleanly with `submitted: false` and
/// sends nothing: the only write-side call the host ever sees is the
/// fee-estimate simulation, and the schema never reaches the registry.
#[test]
fn wizard_aborts_without_submitting_when_declined() {
    let ctx = Ctx::new();
    let schema = "string full_name";
    let stdin = format!(
        "KYC\n\
         string full_name\n\
         \n\
         n\n\
         {}\n\
         \n\
         n\n",
        ctx.f().resolver_id
    );
    let run = ctx.run_stdin(
        &[
            "--output",
            "json",
            "schema",
            "wizard",
            "--identity",
            "attester",
            "--registry-contract-id",
            &ctx.f().registry_id,
            "--rpc-url",
            &ctx.host.url,
            "--network-passphrase",
            NETWORK,
        ],
        &stdin,
    );
    run.assert_ok();

    let data = &run.json()["data"];
    assert_eq!(data["submitted"], false);
    assert_eq!(
        data["schema_uid"].as_str(),
        Some(registered_uid(schema, &ctx.f().resolver_id, false).as_str())
    );
    // The decline is a clean success envelope, not an error.
    assert_eq!(run.json()["status"], "ok");

    // The estimate was simulated before the prompt…
    assert!(
        ctx.host
            .methods()
            .iter()
            .any(|m| m == "simulateTransaction"),
        "fee estimate should be simulated before the confirmation"
    );
    // …but nothing was submitted.
    assert!(
        !ctx.host.methods().iter().any(|m| m == "sendTransaction"),
        "declined wizard must not submit"
    );
    let missing_uid = registered_uid(schema, &ctx.f().resolver_id, false);
    let found = ctx.run(&[
        "--output",
        "json",
        "schema",
        "get",
        "--uid",
        &missing_uid,
        "--registry-contract-id",
        &ctx.f().registry_id,
        "--rpc-url",
        &ctx.host.url,
    ]);
    found.assert_ok();
    assert_eq!(found.json()["data"]["found"], false);
}

/// Every invalid answer triggers its inline validation error at the prompt
/// that asked for it — an empty name, a typeless field, a non-`y/n`
/// revocable answer, a non-contract resolver (twice: wrong kind, then
/// missing with no default), and a bad metadata scheme — and the wizard
/// still completes the registration once the retries are answered.
#[test]
fn wizard_reprompts_invalid_answers_before_submitting() {
    let ctx = Ctx::new();
    let stdin = format!(
        "\n\
         KYC Proof v1\n\
         verified\n\
         string full_name\n\
         \n\
         maybe\n\
         y\n\
         GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\n\
         \n\
         {}\n\
         ftp://example.com/schema.json\n\
         ipfs://bafy/meta.json\n\
         y\n",
        ctx.f().resolver_id
    );
    let run = ctx.run_stdin(
        &[
            "--output",
            "json",
            "schema",
            "wizard",
            "--identity",
            "attester",
            "--registry-contract-id",
            &ctx.f().registry_id,
            "--rpc-url",
            &ctx.host.url,
            "--network-passphrase",
            NETWORK,
        ],
        &stdin,
    );
    run.assert_ok();

    for expected in [
        "name must not be empty",
        "comma-separated `name Type` field definitions",
        "please answer y or n",
        "is not a valid Stellar strkey",
        "resolver is required",
        "metadata URI must start with",
    ] {
        assert!(
            run.stderr.contains(expected),
            "missing inline validation error {expected:?} in:\n{}",
            run.stderr
        );
    }

    let data = &run.json()["data"];
    assert_eq!(data["submitted"], true);
    assert_eq!(
        data["schema_uid"].as_str(),
        Some(registered_uid("string full_name", &ctx.f().resolver_id, true).as_str(),)
    );
    assert_eq!(data["metadata_uri"].as_str(), Some("ipfs://bafy/meta.json"));
}

/// `--resolver` prefills the resolver prompt: a blank answer (or a piped
/// EOF after it) uses the default instead of failing as "required".
#[test]
fn wizard_uses_the_prefilled_resolver_for_a_blank_answer() {
    let ctx = Ctx::new();
    let stdin = "KYC\nbool verified\n\nn\n\n\nn\n";
    let run = ctx.run_stdin(
        &[
            "--output",
            "json",
            "schema",
            "wizard",
            "--identity",
            "attester",
            "--registry-contract-id",
            &ctx.f().registry_id,
            "--resolver",
            &ctx.f().resolver_id,
            "--rpc-url",
            &ctx.host.url,
            "--network-passphrase",
            NETWORK,
        ],
        stdin,
    );
    run.assert_ok();

    let data = &run.json()["data"];
    assert_eq!(data["submitted"], false);
    // The blank resolver answer resolved to the `--resolver` default: the
    // UID preimage the wizard computed was built with it.
    assert_eq!(
        data["schema_uid"].as_str(),
        Some(registered_uid("bool verified", &ctx.f().resolver_id, false).as_str(),)
    );
    assert!(run.stderr.contains(&ctx.f().resolver_id), "{}", run.stderr);
    assert!(
        !run.stderr.contains("resolver is required"),
        "{}",
        run.stderr
    );
}
