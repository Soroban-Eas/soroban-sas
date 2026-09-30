//! Chaos engineering and fault injection for RPC network drops.
//!
//! Provides a configurable [`ChaosRpcServer`] capable of simulating various
//! transport-layer failures:
//! - Dropped connections before response (TCP reset / abrupt close)
//! - Truncated responses (premature EOF mid-stream)
//! - Artificial network delays exceeding timeouts
//! - Transient drops that recover after $N$ attempts
//! - HTTP 503 / 502 transient server errors

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Types of simulated network/transport faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaosFault {
    /// Closes the TCP connection immediately upon receiving the connection or request
    /// without sending any response bytes.
    DropConnection,
    /// Reads the request then terminates the connection without sending headers or body.
    DropBeforeResponse,
    /// Sends HTTP status headers and begins writing a payload, then abruptly severs the stream.
    TruncatedResponse,
    /// Injects an artificial delay, simulating packet loss or extreme network latency.
    Delay(Duration),
    /// Returns an HTTP error status code (e.g. 503 Service Unavailable, 502 Bad Gateway).
    HttpError(u16),
}

/// How frequently or under what conditions a fault is injected.
#[derive(Debug, Clone)]
pub enum ChaosSchedule {
    /// Always inject the fault for matching requests.
    Always(ChaosFault),
    /// Inject the fault for the first `fail_count` matching requests, then allow subsequent requests through.
    Transient {
        fail_count: usize,
        fault: ChaosFault,
    },
    /// Injects the fault every `cycle` requests (e.g., cycle = 2 fails every other request).
    Flapping { cycle: usize, fault: ChaosFault },
}

impl ChaosSchedule {
    fn should_inject(&self, attempt: usize) -> Option<ChaosFault> {
        match self {
            ChaosSchedule::Always(f) => Some(*f),
            ChaosSchedule::Transient { fail_count, fault } => {
                if attempt < *fail_count {
                    Some(*fault)
                } else {
                    None
                }
            }
            ChaosSchedule::Flapping { cycle, fault } => {
                if *cycle > 0 && attempt % *cycle == 0 {
                    Some(*fault)
                } else {
                    None
                }
            }
        }
    }
}

/// A configurable mock JSON-RPC server with fault injection capabilities.
pub struct ChaosRpcServer {
    url: String,
    shutdown: Arc<AtomicBool>,
    server_thread: Option<thread::JoinHandle<()>>,
    requests_received: Arc<AtomicUsize>,
    faults_injected: Arc<AtomicUsize>,
    requests_succeeded: Arc<AtomicUsize>,
    method_counters: Arc<Mutex<HashMap<String, usize>>>,
}

impl ChaosRpcServer {
    /// Starts a new `ChaosRpcServer` with a global fault schedule applied to all methods.
    pub fn new(schedule: ChaosSchedule) -> Self {
        Self::with_rules(vec![("*".to_string(), schedule)])
    }

    /// Starts a new `ChaosRpcServer` with specific per-method fault rules.
    ///
    /// `rules` is a list of `(method_name, ChaosSchedule)`. Use `"*"` as a fallback for any method.
    pub fn with_rules(rules: Vec<(String, ChaosSchedule)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind chaos server");
        let local_addr = listener.local_addr().expect("listener address");
        let url = format!("http://{local_addr}/");

        let shutdown = Arc::new(AtomicBool::new(false));
        let requests_received = Arc::new(AtomicUsize::new(0));
        let faults_injected = Arc::new(AtomicUsize::new(0));
        let requests_succeeded = Arc::new(AtomicUsize::new(0));
        let method_counters = Arc::new(Mutex::new(HashMap::new()));

        let shutdown_clone = shutdown.clone();
        let req_clone = requests_received.clone();
        let fault_clone = faults_injected.clone();
        let succ_clone = requests_succeeded.clone();
        let counters_clone = method_counters.clone();

        let rules = Arc::new(rules);

        let server_thread = thread::spawn(move || {
            // Set 500ms accept timeout so shutdown flag is checked regularly
            let _ = listener.set_nonblocking(false);

            for stream in listener.incoming() {
                if shutdown_clone.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(stream) = stream else {
                    continue;
                };

                let rules = rules.clone();
                let req_count = req_clone.clone();
                let fault_count = fault_clone.clone();
                let succ_count = succ_clone.clone();
                let counters = counters_clone.clone();

                thread::spawn(move || {
                    handle_connection(stream, &rules, req_count, fault_count, succ_count, counters);
                });
            }
        });

        Self {
            url,
            shutdown,
            server_thread: Some(server_thread),
            requests_received,
            faults_injected,
            requests_succeeded,
            method_counters,
        }
    }

    /// The base URL of the chaos server (e.g. `http://127.0.0.1:45678/`).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Number of requests received by the server.
    pub fn requests_received(&self) -> usize {
        self.requests_received.load(Ordering::SeqCst)
    }

    /// Number of simulated faults injected.
    pub fn faults_injected(&self) -> usize {
        self.faults_injected.load(Ordering::SeqCst)
    }

    /// Number of requests served successfully.
    pub fn requests_succeeded(&self) -> usize {
        self.requests_succeeded.load(Ordering::SeqCst)
    }

    /// Number of requests received for a specific JSON-RPC method.
    pub fn method_calls(&self, method: &str) -> usize {
        self.method_counters
            .lock()
            .unwrap()
            .get(method)
            .copied()
            .unwrap_or(0)
    }

    /// Stops the chaos RPC server.
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Poke the server to unblock accept
        let _ = ureq::get(&self.url)
            .timeout(Duration::from_millis(50))
            .call();
        if let Some(handle) = self.server_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for ChaosRpcServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = ureq::get(&self.url)
            .timeout(Duration::from_millis(50))
            .call();
        if let Some(handle) = self.server_thread.take() {
            let _ = handle.join();
        }
    }
}

fn sample_envelope_xdr() -> String {
    use soroban_sdk::xdr::{
        Limits, Memo, MuxedAccount, Preconditions, SequenceNumber, Transaction,
        TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
    };
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
    .unwrap_or_default()
}

fn handle_connection(
    mut stream: TcpStream,
    rules: &[(String, ChaosSchedule)],
    req_count: Arc<AtomicUsize>,
    fault_count: Arc<AtomicUsize>,
    succ_count: Arc<AtomicUsize>,
    method_counters: Arc<Mutex<HashMap<String, usize>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }

    req_count.fetch_add(1, Ordering::SeqCst);

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).unwrap_or(0);
        if read == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }

    let parsed_json: Result<serde_json::Value, _> = serde_json::from_slice(&body);
    let (method, id) = match &parsed_json {
        Ok(v) => (
            v["method"].as_str().unwrap_or("unknown").to_string(),
            v["id"].clone(),
        ),
        Err(_) => ("unknown".to_string(), serde_json::Value::Null),
    };

    let attempt = {
        let mut map = method_counters.lock().unwrap();
        let entry = map.entry(method.clone()).or_insert(0);
        let curr = *entry;
        *entry += 1;
        curr
    };

    // Find applicable fault schedule
    let mut fault_to_inject = None;
    for (rule_method, schedule) in rules {
        if rule_method == "*" || rule_method == &method {
            if let Some(fault) = schedule.should_inject(attempt) {
                fault_to_inject = Some(fault);
                break;
            }
        }
    }

    if let Some(fault) = fault_to_inject {
        fault_count.fetch_add(1, Ordering::SeqCst);
        match fault {
            ChaosFault::DropConnection => {
                let _ = stream.shutdown(Shutdown::Both);
                drop(stream);
                return;
            }
            ChaosFault::DropBeforeResponse => {
                let _ = stream.shutdown(Shutdown::Both);
                drop(stream);
                return;
            }
            ChaosFault::TruncatedResponse => {
                let partial = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"res";
                let _ = stream.write_all(partial.as_bytes());
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Both);
                drop(stream);
                return;
            }
            ChaosFault::Delay(dur) => {
                thread::sleep(dur);
                // After delay, drop the connection
                let _ = stream.shutdown(Shutdown::Both);
                drop(stream);
                return;
            }
            ChaosFault::HttpError(code) => {
                let resp = format!(
                    "HTTP/1.1 {code} Service Error\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n{{\"error\":\"service error\"}}"
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
                return;
            }
        }
    }

    succ_count.fetch_add(1, Ordering::SeqCst);

    let default_response = match method.as_str() {
        "sendTransaction" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "status": "PENDING",
                "hash": "deadbeef1234567890abcdef",
                "latestLedger": 100
            }
        }),
        "getTransaction" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "status": "SUCCESS",
                "latestLedger": 102,
                "envelopeXdr": sample_envelope_xdr(),
                "resultXdr": "AAAAAA=="
            }
        }),
        "getLatestLedger" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "id": "abc",
                "sequence": 100,
                "protocolVersion": 20,
                "closeTime": 1700000000
            }
        }),
        "simulateTransaction" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "latestLedger": 100,
                "results": [{"xdr": "AAAAAA=="}],
                "transactionData": "AAAAAA==",
                "minResourceFee": "100"
            }
        }),
        "getLedgerEntries" => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "entries": [],
                "latestLedger": 100
            }
        }),
        _ => serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {}
        }),
    };

    let resp_bytes = serde_json::to_vec(&default_response).unwrap_or_default();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_bytes.len()
    );

    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&resp_bytes);
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::SdkError;
    use crate::rpc::RpcClient;
    use crate::transaction::{SubmissionPolicy, TransactionSubmitter};

    #[test]
    fn test_chaos_drop_connection_immediately() {
        let server = ChaosRpcServer::new(ChaosSchedule::Always(ChaosFault::DropConnection));
        let client = RpcClient::new(server.url().to_string()).with_timeout(Duration::from_secs(1));

        let res = client.get_latest_ledger();
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), SdkError::TransportError(_)));
        assert_eq!(server.faults_injected(), 1);
        server.shutdown();
    }

    #[test]
    fn test_chaos_truncated_response_mid_stream() {
        let server = ChaosRpcServer::new(ChaosSchedule::Always(ChaosFault::TruncatedResponse));
        let client = RpcClient::new(server.url().to_string()).with_timeout(Duration::from_secs(1));

        let res = client.get_latest_ledger();
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), SdkError::TransportError(_)));
        assert_eq!(server.faults_injected(), 1);
        server.shutdown();
    }

    #[test]
    fn test_chaos_http_503_error() {
        let server = ChaosRpcServer::new(ChaosSchedule::Always(ChaosFault::HttpError(503)));
        let client = RpcClient::new(server.url().to_string()).with_timeout(Duration::from_secs(1));

        let res = client.get_latest_ledger();
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), SdkError::TransportError(_)));
        assert_eq!(server.faults_injected(), 1);
        server.shutdown();
    }

    #[test]
    fn test_chaos_transient_drops_then_recovery() {
        // Drop first 2 requests, succeed on 3rd
        let server = ChaosRpcServer::new(ChaosSchedule::Transient {
            fail_count: 2,
            fault: ChaosFault::DropBeforeResponse,
        });
        let client = RpcClient::new(server.url().to_string()).with_timeout(Duration::from_secs(1));

        // First attempt: dropped
        let res1 = client.get_latest_ledger();
        assert!(matches!(res1.unwrap_err(), SdkError::TransportError(_)));

        // Second attempt: dropped
        let res2 = client.get_latest_ledger();
        assert!(matches!(res2.unwrap_err(), SdkError::TransportError(_)));

        // Third attempt: recovered!
        let res3 = client.get_latest_ledger();
        assert!(res3.is_ok(), "Expected recovery after transient drops");

        assert_eq!(server.faults_injected(), 2);
        assert_eq!(server.requests_succeeded(), 1);
        server.shutdown();
    }

    #[test]
    fn test_chaos_resilient_polling_with_network_drops() {
        // Drop getTransaction on first 2 calls, then succeed on 3rd call
        let server = ChaosRpcServer::with_rules(vec![
            (
                "getTransaction".to_string(),
                ChaosSchedule::Transient {
                    fail_count: 2,
                    fault: ChaosFault::DropConnection,
                },
            ),
            (
                "sendTransaction".to_string(),
                ChaosSchedule::Transient {
                    fail_count: 0,
                    fault: ChaosFault::DropConnection,
                },
            ),
        ]);

        let client = RpcClient::new(server.url().to_string()).with_timeout(Duration::from_secs(1));

        // Policy with retry_transport_errors: true
        let policy = SubmissionPolicy::default()
            .with_poll_interval(Duration::from_millis(50))
            .with_max_polls(5)
            .with_retry_transport_errors(true);

        let outcome = TransactionSubmitter::submit_with_policy(&client, "AAAAAA==", &policy);
        assert!(
            outcome.is_ok(),
            "Expected submit_with_policy to survive transient network drops: {outcome:?}"
        );
        let result = outcome.unwrap();
        assert_eq!(result.status, "SUCCESS");
        assert_eq!(server.faults_injected(), 2);
        server.shutdown();
    }

    #[test]
    fn test_chaos_persistent_drops_exceed_max_polls() {
        let server = ChaosRpcServer::with_rules(vec![(
            "getTransaction".to_string(),
            ChaosSchedule::Always(ChaosFault::DropConnection),
        )]);

        let client = RpcClient::new(server.url().to_string()).with_timeout(Duration::from_secs(1));

        let policy = SubmissionPolicy::default()
            .with_poll_interval(Duration::from_millis(10))
            .with_max_polls(3)
            .with_retry_transport_errors(true);

        let outcome = TransactionSubmitter::submit_with_policy(&client, "AAAAAA==", &policy);
        assert!(
            outcome.is_err(),
            "Expected failure after all retries exhausted by chaos drops"
        );
        assert!(matches!(outcome.unwrap_err(), SdkError::TransportError(_)));
        server.shutdown();
    }
}
