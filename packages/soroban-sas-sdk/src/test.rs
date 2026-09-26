use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use soroban_sdk::xdr::{
    AccountEntry, AccountEntryExt, AccountId, ExtensionPoint, HostFunction, LedgerEntryData,
    LedgerFootprint, Limits, Memo, MuxedAccount, OperationBody, Preconditions, PublicKey, ReadXdr,
    SequenceNumber, SorobanResources, SorobanTransactionData, String32, Thresholds, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};
use soroban_sdk::{Bytes, Env};

/// Base64 XDR of a well-formed, empty V1 `TransactionEnvelope`, used by the
/// mock RPC's `getTransaction` reply so the SDK's envelope-variant check
/// (which rejects V0 / fee-bump envelopes) has something real to decode.
fn sample_v1_envelope_xdr() -> String {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .unwrap()
}

/// Strkey `G...` address of the account derived from `seed`.
fn strkey_account(seed: [u8; 32]) -> String {
    let public_key = crate::signature::derive_public_key(&seed);
    stellar_strkey::ed25519::PublicKey(public_key).to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_signature_generation() {
        let seed = [1u8; 32];
        let signature = crate::signature::generate_delegated_signature(&seed, b"message");
        assert_eq!(signature.len(), 64);
        assert_ne!(signature, [0u8; 64]);
    }
}

#[test]
fn test_rpc_mock_parsing() {}

#[test]
fn test_schema_builder_constructs_schema_record() {
    let env = soroban_sdk::Env::default();
    let resolver = stellar_strkey::Contract([7u8; 32]).to_string();

    let record = crate::SchemaBuilder::new()
        .with_schema("bool verified")
        .with_resolver(&resolver)
        .with_revocable(true)
        .build(&env)
        .unwrap();

    assert_eq!(
        record.schema,
        soroban_sdk::String::from_str(&env, "bool verified")
    );
    assert!(record.revocable);
}

#[test]
fn test_schema_builder_rejects_empty_schema() {
    let env = soroban_sdk::Env::default();
    let resolver = stellar_strkey::Contract([7u8; 32]).to_string();

    let result = crate::SchemaBuilder::new()
        .with_resolver(&resolver)
        .with_revocable(true)
        .build(&env);

    assert!(matches!(result, Err(crate::errors::SdkError::RpcError(_))));
}

// ---- AttestationRequestBuilder ----

#[test]
fn test_attestation_builder_constructs_attestation() {
    let env = Env::default();
    let recipient = strkey_account([3u8; 32]);
    let attester = strkey_account([4u8; 32]);
    let schema_uid = [2u8; 32];
    let data = Bytes::from_slice(&env, b"verified");

    let attestation = crate::attestation_builder::AttestationRequestBuilder::new()
        .with_recipient(&recipient)
        .with_attester(&attester)
        .with_schema_uid(schema_uid)
        .with_data(data.clone())
        .with_expiration(1234)
        .with_revocable(true)
        .build(&env)
        .unwrap();

    assert_eq!(
        attestation.recipient,
        soroban_sdk::Address::from_string(&soroban_sdk::String::from_str(&env, &recipient))
    );
    assert_eq!(
        attestation.attester,
        soroban_sdk::Address::from_string(&soroban_sdk::String::from_str(&env, &attester))
    );
    assert_eq!(attestation.schema_uid.0.to_array(), schema_uid);
    assert_eq!(attestation.data, data);
    assert_eq!(attestation.expiration_time, 1234);
    assert!(attestation.revocable);
    assert_eq!(attestation.revocation_time, 0);
    assert_eq!(attestation.ref_uid.0.to_array(), [0u8; 32]);
    assert_eq!(attestation.time, env.ledger().timestamp());
    assert_eq!(attestation.uid.0.to_array().len(), 32);
}

#[test]
fn test_attestation_builder_defaults_match_contract_semantics() {
    let env = Env::default();
    let recipient = strkey_account([3u8; 32]);
    let attester = strkey_account([4u8; 32]);

    let attestation = crate::attestation_builder::AttestationRequestBuilder::new()
        .with_recipient(&recipient)
        .with_attester(&attester)
        .with_schema_uid([2u8; 32])
        .with_data(Bytes::new(&env))
        .build(&env)
        .unwrap();

    // expiration_time 0 = never expires, ref_uid all-zero = no reference,
    // and a freshly built attestation is never pre-revoked.
    assert_eq!(attestation.expiration_time, 0);
    assert!(!attestation.revocable);
    assert_eq!(attestation.ref_uid.0.to_array(), [0u8; 32]);
    assert_eq!(attestation.revocation_time, 0);
}

#[test]
fn test_attestation_builder_uid_is_deterministic_and_content_addressed() {
    let env = Env::default();
    let recipient = strkey_account([3u8; 32]);
    let attester = strkey_account([4u8; 32]);

    let build_uid = |data: &[u8], ref_uid: [u8; 32]| {
        crate::attestation_builder::AttestationRequestBuilder::new()
            .with_recipient(&recipient)
            .with_attester(&attester)
            .with_schema_uid([2u8; 32])
            .with_data(Bytes::from_slice(&env, data))
            .with_ref_uid(ref_uid)
            .build(&env)
            .unwrap()
            .uid
    };

    let uid_a = build_uid(b"same data", [0u8; 32]);
    let uid_a_again = build_uid(b"same data", [0u8; 32]);
    assert_eq!(
        uid_a, uid_a_again,
        "identical inputs must produce the same UID"
    );

    let uid_b = build_uid(b"different data", [0u8; 32]);
    assert_ne!(uid_a, uid_b, "different data must produce a different UID");

    // `ref_uid` is deliberately not part of the content-addressing preimage
    // (`sha256(schema_uid || recipient || attester || data)`, #215), so it
    // must not affect the derived UID.
    let uid_c = build_uid(b"same data", [9u8; 32]);
    assert_eq!(uid_a, uid_c, "ref_uid must not affect the derived UID");
}

#[test]
fn test_attestation_builder_rejects_missing_required_fields() {
    let env = Env::default();
    let recipient = strkey_account([3u8; 32]);
    let attester = strkey_account([4u8; 32]);

    // Nothing set at all.
    assert!(matches!(
        crate::attestation_builder::AttestationRequestBuilder::new().build(&env),
        Err(crate::errors::SdkError::RpcError(_))
    ));

    // Any single required field on its own still leaves the builder
    // incomplete, so build() must keep returning an error.
    for partial in [
        crate::attestation_builder::AttestationRequestBuilder::new().with_recipient(&recipient),
        crate::attestation_builder::AttestationRequestBuilder::new().with_attester(&attester),
        crate::attestation_builder::AttestationRequestBuilder::new().with_schema_uid([2u8; 32]),
        crate::attestation_builder::AttestationRequestBuilder::new().with_data(Bytes::new(&env)),
    ] {
        assert!(
            matches!(
                partial.build(&env),
                Err(crate::errors::SdkError::RpcError(_))
            ),
            "expected an error for an incomplete builder"
        );
    }
}

/// Answers one JSON-RPC request on `stream` with a canned Soroban RPC
/// response. `account_entry_xdr` and `transaction_data_xdr` are the base64
/// XDR payloads the account-lookup and simulation steps need.
fn serve_rpc(stream: TcpStream, account_entry_xdr: &str, transaction_data_xdr: &str) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).unwrap_or(0);
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).unwrap();

    let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let method = request["method"].as_str().unwrap_or_default();
    let id = request["id"].clone();
    let response = match method {
        "getLedgerEntries" => serde_json::json!({
            "jsonrpc": "2.0", "id": id, "result": {
                "entries": [{
                    "key": "AAAAAA==",
                    "xdr": account_entry_xdr,
                    "lastModifiedLedgerSeq": 1
                }],
                "latestLedger": 1
            }
        }),
        "simulateTransaction" => serde_json::json!({
            "jsonrpc": "2.0", "id": id, "result": {
                "latestLedger": 1,
                "results": [{"xdr": "AAAAAA=="}],
                "transactionData": transaction_data_xdr,
                "minResourceFee": "0"
            }
        }),
        "sendTransaction" => serde_json::json!({
            "jsonrpc": "2.0", "id": id, "result": {
                "status": "PENDING",
                "hash": "abcd1234",
                "latestLedger": 1
            }
        }),
        "getTransaction" => serde_json::json!({
            "jsonrpc": "2.0", "id": id, "result": {
                "status": "SUCCESS",
                "latestLedger": 1,
                "envelopeXdr": sample_v1_envelope_xdr(),
                "resultXdr": "AAAAAQAAAAA="
            }
        }),
        other => panic!("unexpected RPC method: {other}"),
    }
    .to_string();

    let mut stream = stream;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.len(),
        response
    )
    .unwrap();
    stream.flush().unwrap();
}

/// Issue #18 acceptance criterion: an `Attestation` built through
/// `AttestationRequestBuilder` flows into `SASClient::attest` unchanged, and
/// the client accepts it — the whole build → encode → simulate → sign →
/// submit → poll pipeline succeeds against a mock Soroban RPC.
#[test]
fn test_attestation_builder_attestation_is_accepted_by_sas_client_attest() {
    let env = Env::default();

    // Canned XDR the mock RPC returns for the account and simulation steps.
    let secret_seed = [9u8; 32];
    let public_key = crate::signature::derive_public_key(&secret_seed);
    let account_entry = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key))),
        balance: 100_000_000,
        seq_num: SequenceNumber(7),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: Default::default(),
        ext: AccountEntryExt::V0,
    };
    let account_entry_xdr = LedgerEntryData::Account(account_entry)
        .to_xdr_base64(Limits::none())
        .unwrap();
    let transaction_data = SorobanTransactionData {
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
    };
    let transaction_data_xdr = transaction_data.to_xdr_base64(Limits::none()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        // getLedgerEntries, simulateTransaction, sendTransaction,
        // getTransaction — each request arrives on its own connection
        // because every response closes it. The loop runs until the test
        // process exits; nothing joins this thread.
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => serve_rpc(stream, &account_entry_xdr, &transaction_data_xdr),
                Err(_) => break,
            }
        }
    });

    let recipient = strkey_account([3u8; 32]);
    let attester = strkey_account([9u8; 32]);
    let contract_id = stellar_strkey::Contract([7u8; 32]).to_string();

    let attestation = crate::attestation_builder::AttestationRequestBuilder::new()
        .with_recipient(&recipient)
        .with_attester(&attester)
        .with_schema_uid([2u8; 32])
        .with_data(Bytes::from_slice(&env, b"built via the request builder"))
        .with_expiration(0)
        .with_revocable(true)
        .build(&env)
        .unwrap();

    let client = crate::client::SASClient::new(contract_id);
    let rpc = crate::rpc::RpcClient::new(url).with_timeout(Duration::from_secs(5));
    let result = client.attest(
        &env,
        &rpc,
        "Test SDF Network ; September 2015",
        &secret_seed,
        attestation,
    );

    // Detach the server thread; it exits when the test process ends.
    drop(server);
    assert!(
        result.is_ok(),
        "SASClient::attest rejected a builder-produced attestation: {result:?}"
    );
}

fn write_rpc_response(mut stream: TcpStream, response: &serde_json::Value) {
    let response = response.to_string();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.len(),
        response
    )
    .unwrap();
    stream.flush().unwrap();
}

fn read_rpc_request(stream: &TcpStream) -> serde_json::Value {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).unwrap_or(0);
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn write_pipeline_fixture(seed: [u8; 32]) -> (String, String) {
    let public_key = crate::signature::derive_public_key(&seed);
    let account_entry = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key))),
        balance: 100_000_000,
        seq_num: SequenceNumber(7),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: Default::default(),
        ext: AccountEntryExt::V0,
    };
    let account_xdr = LedgerEntryData::Account(account_entry)
        .to_xdr_base64(Limits::none())
        .unwrap();
    let transaction_data = SorobanTransactionData {
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
    .unwrap();
    (account_xdr, transaction_data)
}

/// Runs enough of a Soroban RPC to exercise two complete write pipelines and
/// returns every request to the test for invocation-XDR assertions.
fn spawn_fee_pipeline_server(
    seed: [u8; 32],
    request_tx: std::sync::mpsc::Sender<serde_json::Value>,
) -> (String, std::thread::JoinHandle<()>) {
    let (account_xdr, transaction_data) = write_pipeline_fixture(seed);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        for index in 0..8 {
            let (stream, _) = listener.accept().unwrap();
            let request = read_rpc_request(&stream);
            request_tx.send(request.clone()).unwrap();
            let id = request["id"].clone();
            let response = match request["method"].as_str().unwrap() {
                "getLedgerEntries" => serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "result": {
                        "entries": [{"key": "AAAAAA==", "xdr": account_xdr, "lastModifiedLedgerSeq": 1}],
                        "latestLedger": 1
                    }
                }),
                "simulateTransaction" => serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "result": {
                        "latestLedger": 1,
                        "results": [{"xdr": "AAAAAA=="}],
                        "transactionData": transaction_data,
                        "minResourceFee": "0"
                    }
                }),
                "sendTransaction" => serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "result": {
                        "status": "PENDING", "hash": format!("fee-hash-{index}"), "latestLedger": 1
                    }
                }),
                "getTransaction" => serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "result": {
                        "status": "SUCCESS", "latestLedger": 1,
                        "envelopeXdr": sample_v1_envelope_xdr(), "resultXdr": "AAAAAQAAAAA="
                    }
                }),
                method => panic!("unexpected RPC method: {method}"),
            };
            write_rpc_response(stream, &response);
        }
    });
    (url, handle)
}

#[test]
fn sas_fee_admin_writes_encode_and_settle_sequentially() {
    let env = Env::default();
    let seed = [21u8; 32];
    let contract_id = stellar_strkey::Contract([22u8; 32]).to_string();
    let token = stellar_strkey::Contract([23u8; 32]).to_string();
    let (request_tx, request_rx) = std::sync::mpsc::channel();
    let (url, server) = spawn_fee_pipeline_server(seed, request_tx);
    let rpc = crate::rpc::RpcClient::new(url).with_timeout(Duration::from_secs(5));
    let client = crate::client::SASClient::new(contract_id);

    let set_result = client
        .set_fee(
            &env,
            &rpc,
            "Test SDF Network ; September 2015",
            &seed,
            &token,
            1_000_000,
        )
        .unwrap();
    let clear_result = client
        .clear_fee(&env, &rpc, "Test SDF Network ; September 2015", &seed)
        .unwrap();
    assert_eq!(set_result.status, "SUCCESS");
    assert_eq!(clear_result.status, "SUCCESS");
    server.join().unwrap();

    let requests: Vec<_> = request_rx.try_iter().collect();
    let methods: Vec<_> = requests
        .iter()
        .map(|request| request["method"].as_str().unwrap())
        .collect();
    assert_eq!(
        methods,
        [
            "getLedgerEntries",
            "simulateTransaction",
            "sendTransaction",
            "getTransaction",
            "getLedgerEntries",
            "simulateTransaction",
            "sendTransaction",
            "getTransaction"
        ]
    );

    let invocations: Vec<_> = requests
        .iter()
        .filter(|request| request["method"] == "simulateTransaction")
        .map(|request| {
            let xdr = request["params"]["transaction"].as_str().unwrap();
            let TransactionEnvelope::Tx(envelope) =
                TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap()
            else {
                panic!("expected V1 transaction envelope");
            };
            let OperationBody::InvokeHostFunction(operation) = &envelope.tx.operations[0].body
            else {
                panic!("expected InvokeHostFunction operation");
            };
            let HostFunction::InvokeContract(invocation) = &operation.host_function else {
                panic!("expected InvokeContract host function");
            };
            invocation.clone()
        })
        .collect();
    assert_eq!(invocations[0].function_name.0.to_string(), "set_fee");
    assert_eq!(invocations[0].args.len(), 2);
    let token_address =
        crate::strkey::parse_address(&env, &token, crate::strkey::AddressKind::Contract, "token")
            .unwrap();
    assert_eq!(
        invocations[0].args[0],
        crate::simulate::encode_arg(&env, &token_address).unwrap()
    );
    assert_eq!(
        invocations[0].args[1],
        crate::simulate::encode_arg(&env, &1_000_000i128).unwrap()
    );
    assert_eq!(invocations[1].function_name.0.to_string(), "clear_fee");
    assert!(invocations[1].args.is_empty());
}

#[test]
fn sas_set_fee_rejects_invalid_amount_before_rpc() {
    let env = Env::default();
    let client = crate::client::SASClient::new(stellar_strkey::Contract([24u8; 32]).to_string());
    let rpc = crate::rpc::RpcClient::new("http://127.0.0.1:1".to_string());
    let token = stellar_strkey::Contract([25u8; 32]).to_string();
    for amount in [0, -1] {
        let error = client
            .set_fee(&env, &rpc, "network", &[26u8; 32], &token, amount)
            .unwrap_err();
        assert!(matches!(error, crate::errors::SdkError::InvalidInput(_)));
    }
}

#[test]
fn sas_set_fee_surfaces_unauthorized_simulation_as_contract_error_301() {
    let env = Env::default();
    let seed = [27u8; 32];
    let (account_xdr, _) = write_pipeline_fixture(seed);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for expected_method in ["getLedgerEntries", "simulateTransaction"] {
            let (stream, _) = listener.accept().unwrap();
            let request = read_rpc_request(&stream);
            assert_eq!(request["method"], expected_method);
            let id = request["id"].clone();
            let response = if expected_method == "getLedgerEntries" {
                serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "result": {
                        "entries": [{"key": "AAAAAA==", "xdr": account_xdr, "lastModifiedLedgerSeq": 1}],
                        "latestLedger": 1
                    }
                })
            } else {
                serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "result": {
                        "latestLedger": 1,
                        "error": "HostError: Error(301, Unauthorized)"
                    }
                })
            };
            write_rpc_response(stream, &response);
        }
    });

    let rpc = crate::rpc::RpcClient::new(url).with_timeout(Duration::from_secs(5));
    let client = crate::client::SASClient::new(stellar_strkey::Contract([28u8; 32]).to_string());
    let token = stellar_strkey::Contract([29u8; 32]).to_string();
    let error = client
        .set_fee(&env, &rpc, "network", &seed, &token, 1)
        .unwrap_err();
    server.join().unwrap();
    assert!(matches!(error, crate::errors::SdkError::ContractError(301)));
}

/// Issue #132 acceptance criterion: two writes for the same account, built
/// concurrently while sharing one [`SequenceManager`], are handed **distinct**
/// sequence numbers instead of both reading the same on-chain value and
/// racing. Exercises the real RPC sequence fetch under the manager's lock.
#[test]
fn concurrent_reservations_via_the_manager_get_distinct_sequences() {
    use crate::sequence::SequenceManager;
    use std::sync::{Arc, Barrier};

    let public_key = crate::signature::derive_public_key(&[5u8; 32]);
    let account_entry = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key))),
        balance: 100_000_000,
        seq_num: SequenceNumber(500),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: Default::default(),
        ext: AccountEntryExt::V0,
    };
    let account_entry_xdr = LedgerEntryData::Account(account_entry)
        .to_xdr_base64(Limits::none())
        .unwrap();

    // Mock RPC: every getLedgerEntries reports the same sequence, 500.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => serve_rpc(stream, &account_entry_xdr, ""),
                Err(_) => break,
            }
        }
    });

    let manager = Arc::new(SequenceManager::new());
    let threads = 8;
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let (manager, barrier, url) = (manager.clone(), barrier.clone(), url.clone());
            std::thread::spawn(move || {
                let rpc = crate::rpc::RpcClient::new(url).with_timeout(Duration::from_secs(5));
                barrier.wait();
                manager.reserve(&rpc, &public_key).unwrap().sequence()
            })
        })
        .collect();

    let mut got: Vec<i64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    drop(server);
    got.sort_unstable();
    assert_eq!(
        got,
        (501..501 + threads as i64).collect::<Vec<_>>(),
        "concurrent reservations collided or skipped a sequence number"
    );
}
