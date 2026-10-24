//! Compares cached schema lookups against uncached RPC lookups under contention.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use soroban_sas_common::SchemaRecord;
use soroban_sas_sdk::client::SASClient;
use soroban_sas_sdk::rpc::RpcClient;
use soroban_sas_sdk::{encode_arg, SchemaCache};
use soroban_sdk::xdr::{Limits, WriteXdr};
use soroban_sdk::Env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

const LOOKUPS_PER_THREAD: usize = 16;

struct MockRpcServer {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    requests: Arc<AtomicU64>,
    worker: Option<JoinHandle<()>>,
}

impl MockRpcServer {
    fn new(result_xdr: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock RPC listener");
        listener
            .set_nonblocking(true)
            .expect("configure mock RPC listener");
        let address = listener.local_addr().expect("read mock RPC address");
        let stopped = Arc::new(AtomicBool::new(false));
        let worker_stopped = Arc::clone(&stopped);
        let requests = Arc::new(AtomicU64::new(0));
        let worker_requests = Arc::clone(&requests);
        let worker = thread::spawn(move || {
            while !worker_stopped.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        worker_requests.fetch_add(1, Ordering::Relaxed);
                        respond(stream, &result_xdr);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            address,
            stopped,
            requests,
            worker: Some(worker),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for MockRpcServer {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn respond(mut stream: TcpStream, result_xdr: &str) {
    let mut request = Vec::new();
    let mut buffer = [0u8; 2048];
    let (header_end, content_length) = loop {
        let read = match stream.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        request.extend_from_slice(&buffer[..read]);

        let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        else {
            continue;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        });
        let Some(content_length) = content_length else {
            return;
        };
        if request.len() >= header_end + content_length {
            break (header_end, content_length);
        }
    };

    let request_body =
        String::from_utf8_lossy(&request[header_end..header_end + content_length]);
    let Some(id) = request_id(&request_body) else {
        return;
    };
    let response = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
    );
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.len(),
        response
    );
}

fn request_id(request: &str) -> Option<&str> {
    let value = request.split_once("\"id\":")?.1.trim_start();
    let digits = value
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .count();
    (digits > 0).then_some(&value[..digits])
}

fn benchmark_schema_lookups(c: &mut Criterion) {
    let env = Env::default();
    let missing: Option<SchemaRecord> = None;
    let result_xdr = encode_arg(&env, &missing)
        .expect("encode empty schema response")
        .to_xdr_base64(Limits::none())
        .expect("serialize empty schema response");
    let server = MockRpcServer::new(result_xdr);
    let rpc = RpcClient::new(server.url());
    let registry_id = stellar_strkey::Contract([1u8; 32]).to_string();
    let client_id = stellar_strkey::Contract([2u8; 32]).to_string();
    let uid = [3u8; 32];
    let uncached = SASClient::new(client_id.clone())
        .with_rpc(rpc.clone())
        .with_registry(registry_id.clone());
    let cache = SchemaCache::new(1, Duration::from_secs(60 * 60 * 24 * 365));
    cache.insert(uid, None).expect("prime schema cache");
    let cached = SASClient::new(client_id)
        .with_rpc(rpc)
        .with_registry(registry_id)
        .with_schema_cache(cache);

    let requests_before_uncached = server.request_count();
    uncached
        .fetch_schema(&uid)
        .expect("verify uncached RPC lookup");
    assert_eq!(server.request_count(), requests_before_uncached + 1);

    let requests_before_cached = server.request_count();
    cached
        .fetch_schema(&uid)
        .expect("verify cached lookup");
    assert_eq!(server.request_count(), requests_before_cached);

    let mut group = c.benchmark_group("schema_lookup_high_contention");
    for thread_count in [1usize, 4, 16] {
        let lookup_count = (LOOKUPS_PER_THREAD * thread_count) as u64;
        group.throughput(criterion::Throughput::Elements(lookup_count));
        for (name, client) in [
            ("uncached_rpc", uncached.clone()),
            ("cached_lru", cached.clone()),
        ] {
            group.bench_with_input(
                BenchmarkId::new(name, thread_count),
                &thread_count,
                |bench, &threads| {
                    bench.iter(|| {
                        thread::scope(|scope| {
                            for _ in 0..threads {
                                let client = client.clone();
                                scope.spawn(move || {
                                    for _ in 0..LOOKUPS_PER_THREAD {
                                        black_box(
                                            client
                                                .fetch_schema(black_box(&uid))
                                                .expect("fetch schema"),
                                        );
                                    }
                                });
                            }
                        });
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, benchmark_schema_lookups);
criterion_main!(benches);
