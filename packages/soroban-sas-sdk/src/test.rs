use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use soroban_sdk::xdr::{
    AccountEntry, AccountEntryExt, AccountId, ExtensionPoint, LedgerEntryData, LedgerFootprint,
    Limits, PublicKey, SequenceNumber, SorobanResources, SorobanTransactionData, String32,
    Thresholds, Uint256, VecM, WriteXdr,
};
use soroban_sdk::{Bytes, Env};

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

    let uid_c = build_uid(b"same data", [9u8; 32]);
    assert_ne!(
        uid_a, uid_c,
        "a different ref_uid must produce a different UID"
    );
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
    let response = match method {
        "getLedgerEntries" => serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "result": {
                "entries": [{
                    "key": "AAAAAA==",
                    "xdr": account_entry_xdr,
                    "lastModifiedLedgerSeq": 1
                }],
                "latestLedger": 1
            }
        }),
        "simulateTransaction" => serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "result": {
                "latestLedger": 1,
                "results": [{"xdr": "AAAAAA=="}],
                "transactionData": transaction_data_xdr,
                "minResourceFee": "0"
            }
        }),
        "sendTransaction" => serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "result": {
                "status": "PENDING",
                "hash": "abcd1234",
                "latestLedger": 1
            }
        }),
        "getTransaction" => serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "result": {
                "status": "SUCCESS",
                "latestLedger": 1,
                "envelopeXdr": "AAAAAgAAAAA=",
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
