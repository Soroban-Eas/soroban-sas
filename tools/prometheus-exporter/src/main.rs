//! SAS Prometheus metrics exporter
//!
//! Exposes a `/metrics` endpoint in standard Prometheus text exposition format.
//! Tracks attestation throughput, batch sizes, transaction latency, CPU instruction
//! consumption, revocations, and re-index failures — all required for production
//! SAS indexer and relayer observability.
//!
//! # Environment variables
//! | Variable                      | Default          | Description                        |
//! |-------------------------------|------------------|------------------------------------|
//! | `SAS_CONTRACT_ID`             | *(required)*     | Soroban contract address to track  |
//! | `SCHEMA_REGISTRY_CONTRACT_ID` | *(optional)*     | Schema registry contract address   |
//! | `INDEXER_CONTRACT_ID`         | *(optional)*     | Indexer contract address           |
//! | `METRICS_ADDR`                | `0.0.0.0:9090`   | TCP address for `/metrics` server  |
//!
//! # Memory budget
//! Each `Histogram` with N buckets allocates ~(N+2)*8 bytes of counter state.
//! With three histograms (11 buckets each) + six counters + two gauges the
//! static metric footprint is well under 1 KB.  Under a 10 000 event/s stream
//! the exporter stays comfortably inside the 64 MB budget because it holds no
//! per-event state — every incoming event is aggregated into the metrics in O(1)
//! and the raw event is dropped.

#![allow(dead_code)]
#![allow(clippy::new_without_default)]

use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use prometheus::{Counter, Encoder, Gauge, Histogram, HistogramOpts, Registry, TextEncoder};
use soroban_sas_sdk::events::SasEvent;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

// ── Configuration ─────────────────────────────────────────────────────────────

struct Config {
    sas_contract_id: String,
    schema_registry_contract_id: Option<String>,
    indexer_contract_id: Option<String>,
    metrics_addr: SocketAddr,
}

impl Config {
    fn from_env() -> Result<Self> {
        let sas_contract_id = env::var("SAS_CONTRACT_ID")
            .map_err(|_| anyhow::anyhow!("SAS_CONTRACT_ID environment variable is required"))?;
        let schema_registry_contract_id = env::var("SCHEMA_REGISTRY_CONTRACT_ID").ok();
        let indexer_contract_id = env::var("INDEXER_CONTRACT_ID").ok();
        let metrics_addr: SocketAddr = env::var("METRICS_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:9090".to_string())
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid METRICS_ADDR: {}", e))?;
        Ok(Self {
            sas_contract_id,
            schema_registry_contract_id,
            indexer_contract_id,
            metrics_addr,
        })
    }
}

// ── Metric buckets ────────────────────────────────────────────────────────────

/// Latency buckets (seconds): 1 ms … 10 s, tuned for Soroban transaction
/// confirmation times on Stellar Testnet / Mainnet.
const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Batch-size buckets: 1 attestation (single) through 512 (large batch).
const BATCH_SIZE_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0, 512.0];

/// CPU instruction buckets (millions): 0 … 100 M instructions.
/// Soroban's compute limit is 100 M instructions per transaction.
const CPU_INSTRUCTION_BUCKETS: &[f64] = &[
    100_000.0,
    500_000.0,
    1_000_000.0,
    5_000_000.0,
    10_000_000.0,
    25_000_000.0,
    50_000_000.0,
    100_000_000.0,
];

// ── Metrics registry ──────────────────────────────────────────────────────────

/// All SAS Prometheus metrics in a single struct.
///
/// Cloning is cheap — every field is a `prometheus` handle which is internally
/// reference-counted.
#[derive(Clone)]
pub struct SasMetrics {
    pub registry: Registry,

    // ── Issue #569: required histograms ───────────────────────────────────────
    /// Distribution of batch sizes (attestations per batch operation).
    ///
    /// Use this to understand whether clients are using batching efficiently.
    /// A p99 below 5 with a high `sas_attestations_total` rate indicates
    /// clients are not batching and each attestation is a separate transaction.
    pub sas_attestation_batch_size: Histogram,

    /// End-to-end transaction latency from submission to ledger confirmation.
    ///
    /// Histogram buckets cover 1 ms–10 s. The p99 drives the SLA alert:
    /// `histogram_quantile(0.99, rate(sas_transaction_latency_seconds_bucket[5m]))`
    pub sas_transaction_latency_seconds: Histogram,

    /// CPU instructions consumed per transaction as reported by Soroban.
    ///
    /// Soroban's hard limit is 100 M instructions; approaching that limit
    /// means the transaction is near the compute ceiling.
    pub sas_cpu_instructions_consumed: Histogram,

    // ── Issue #569: required counters ─────────────────────────────────────────
    /// Monotonic count of all attestations written to the ledger (singles + batches).
    pub sas_attestations_total: Counter,

    /// Monotonic count of all revocations written to the ledger (singles + batches).
    pub sas_revocations_total: Counter,

    /// Total re-index failures.  Alert when this is non-zero.
    pub sas_reindex_failures_total: Counter,

    // ── Existing metrics retained for backward compatibility ──────────────────
    pub attestation_issued_total: Counter,
    pub attestation_revoked_total: Counter,
    pub batch_attested_total: Counter,
    pub batch_revoked_total: Counter,
    pub schema_registered_total: Counter,
    pub fee_config_updated_total: Counter,
    pub indexer_strict_updated_total: Counter,
    pub active_attestations: Gauge,
    pub active_schemas: Gauge,
    pub event_processing_duration: Histogram,
}

impl SasMetrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        // ── Issue #569 histograms ─────────────────────────────────────────────

        let sas_attestation_batch_size = Histogram::with_opts(
            HistogramOpts::new(
                "sas_attestation_batch_size",
                "Number of attestations per batch operation",
            )
            .buckets(BATCH_SIZE_BUCKETS.to_vec()),
        )?;
        registry.register(Box::new(sas_attestation_batch_size.clone()))?;

        let sas_transaction_latency_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "sas_transaction_latency_seconds",
                "End-to-end transaction latency from submission to ledger confirmation",
            )
            .buckets(LATENCY_BUCKETS.to_vec()),
        )?;
        registry.register(Box::new(sas_transaction_latency_seconds.clone()))?;

        let sas_cpu_instructions_consumed = Histogram::with_opts(
            HistogramOpts::new(
                "sas_cpu_instructions_consumed",
                "CPU instructions consumed per Soroban transaction (Soroban limit: 100 M)",
            )
            .buckets(CPU_INSTRUCTION_BUCKETS.to_vec()),
        )?;
        registry.register(Box::new(sas_cpu_instructions_consumed.clone()))?;

        // ── Issue #569 counters ───────────────────────────────────────────────

        let sas_attestations_total = Counter::new(
            "sas_attestations_total",
            "Total attestations written to the ledger (single + batch)",
        )?;
        registry.register(Box::new(sas_attestations_total.clone()))?;

        let sas_revocations_total = Counter::new(
            "sas_revocations_total",
            "Total revocations written to the ledger (single + batch)",
        )?;
        registry.register(Box::new(sas_revocations_total.clone()))?;

        let sas_reindex_failures_total = Counter::new(
            "sas_reindex_failures_total",
            "Total re-index failures; non-zero value requires investigation",
        )?;
        registry.register(Box::new(sas_reindex_failures_total.clone()))?;

        // ── Existing metrics ──────────────────────────────────────────────────

        let attestation_issued_total = Counter::new(
            "sas_attestation_issued_total",
            "Total number of attestations issued",
        )?;
        registry.register(Box::new(attestation_issued_total.clone()))?;

        let attestation_revoked_total = Counter::new(
            "sas_attestation_revoked_total",
            "Total number of attestations revoked",
        )?;
        registry.register(Box::new(attestation_revoked_total.clone()))?;

        let batch_attested_total = Counter::new(
            "sas_batch_attested_total",
            "Total number of batch attestations completed",
        )?;
        registry.register(Box::new(batch_attested_total.clone()))?;

        let batch_revoked_total = Counter::new(
            "sas_batch_revoked_total",
            "Total number of batch revocations completed",
        )?;
        registry.register(Box::new(batch_revoked_total.clone()))?;

        let schema_registered_total = Counter::new(
            "sas_schema_registered_total",
            "Total number of schemas registered",
        )?;
        registry.register(Box::new(schema_registered_total.clone()))?;

        let fee_config_updated_total = Counter::new(
            "sas_fee_config_updated_total",
            "Total number of fee configuration updates",
        )?;
        registry.register(Box::new(fee_config_updated_total.clone()))?;

        let indexer_strict_updated_total = Counter::new(
            "sas_indexer_strict_updated_total",
            "Total number of indexer strict policy updates",
        )?;
        registry.register(Box::new(indexer_strict_updated_total.clone()))?;

        let active_attestations = Gauge::new(
            "sas_active_attestations",
            "Current number of active attestations",
        )?;
        registry.register(Box::new(active_attestations.clone()))?;

        let active_schemas = Gauge::new("sas_active_schemas", "Current number of active schemas")?;
        registry.register(Box::new(active_schemas.clone()))?;

        let event_processing_duration = Histogram::with_opts(
            HistogramOpts::new(
                "sas_event_processing_duration_seconds",
                "Duration of event processing in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
        )?;
        registry.register(Box::new(event_processing_duration.clone()))?;

        Ok(Self {
            registry,
            sas_attestation_batch_size,
            sas_transaction_latency_seconds,
            sas_cpu_instructions_consumed,
            sas_attestations_total,
            sas_revocations_total,
            sas_reindex_failures_total,
            attestation_issued_total,
            attestation_revoked_total,
            batch_attested_total,
            batch_revoked_total,
            schema_registered_total,
            fee_config_updated_total,
            indexer_strict_updated_total,
            active_attestations,
            active_schemas,
            event_processing_duration,
        })
    }

    /// Record a SAS contract event, updating all relevant counters and histograms.
    ///
    /// This is the single call-site for event → metric translation.  It must be
    /// called exactly once per processed event; calling it multiple times for the
    /// same event will double-count.
    pub fn record_event(&self, event: &SasEvent, _contract_id: &str) {
        let timer = self.event_processing_duration.start_timer();
        match event {
            SasEvent::AttestationIssued(_) => {
                self.attestation_issued_total.inc();
                self.sas_attestations_total.inc();
                self.active_attestations.inc();
                // Single-attestation transaction: batch size = 1
                self.sas_attestation_batch_size.observe(1.0);
            }
            SasEvent::AttestationRevoked(_) => {
                self.attestation_revoked_total.inc();
                self.sas_revocations_total.inc();
                self.active_attestations.dec();
            }
            SasEvent::BatchAttested(batch) => {
                self.batch_attested_total.inc();
                let count = batch.count as f64;
                self.sas_attestations_total.inc_by(count);
                self.active_attestations.add(count);
                self.sas_attestation_batch_size.observe(count);
            }
            SasEvent::BatchRevoked(batch) => {
                self.batch_revoked_total.inc();
                let count = batch.count as f64;
                self.sas_revocations_total.inc_by(count);
                self.active_attestations.sub(count);
            }
            SasEvent::SchemaRegistered(_) => {
                self.schema_registered_total.inc();
                self.active_schemas.inc();
            }
            SasEvent::FeeConfigUpdated(_) => {
                self.fee_config_updated_total.inc();
            }
            SasEvent::IndexerStrictUpdated(_) => {
                self.indexer_strict_updated_total.inc();
            }
        }
        timer.observe_duration();
    }

    /// Record the end-to-end latency for a single transaction (seconds).
    ///
    /// Call this after the transaction is confirmed on-ledger using the delta
    /// between your submission timestamp and the ledger close time.
    ///
    /// ```rust,ignore
    /// let start = std::time::Instant::now();
    /// submit_transaction(&tx).await?;
    /// metrics.record_transaction_latency(start.elapsed().as_secs_f64());
    /// ```
    pub fn record_transaction_latency(&self, latency_seconds: f64) {
        self.sas_transaction_latency_seconds
            .observe(latency_seconds);
    }

    /// Record the CPU instruction count for a Soroban transaction.
    ///
    /// The `instructions` value comes from the `TransactionMeta::V3` field
    /// `soroban_meta.resources.instructions` in the ledger close metadata.
    pub fn record_cpu_instructions(&self, instructions: u64) {
        self.sas_cpu_instructions_consumed
            .observe(instructions as f64);
    }

    /// Increment the re-index failure counter.
    ///
    /// Call this when the indexer fails to process a ledger range and must
    /// skip or defer it.  Any non-zero value in production should trigger an
    /// alert.
    pub fn record_reindex_failure(&self) {
        self.sas_reindex_failures_total.inc();
    }
}

// ── HTTP handler ──────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ExporterState {
    metrics: Arc<SasMetrics>,
}

async fn metrics_handler(
    state: ExporterState,
    req: Request<Body>,
) -> hyper::Result<Response<Body>> {
    match req.uri().path() {
        "/metrics" => {
            let encoder = TextEncoder::new();
            let metric_families = state.metrics.registry.gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", encoder.format_type())
                .body(Body::from(buffer))
                .unwrap())
        }
        "/health" => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain")
            .body(Body::from("ok"))
            .unwrap()),
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not Found"))
            .unwrap()),
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let config = Config::from_env()?;

    info!("Starting SAS Prometheus metrics exporter");
    info!("SAS Contract ID: {}", config.sas_contract_id);
    info!("Metrics address: {}", config.metrics_addr);
    if let Some(ref sr) = config.schema_registry_contract_id {
        info!("Schema Registry Contract ID: {}", sr);
    }
    if let Some(ref idx) = config.indexer_contract_id {
        info!("Indexer Contract ID: {}", idx);
    }

    let metrics = Arc::new(SasMetrics::new()?);
    let state = ExporterState { metrics };

    let state_clone = state.clone();
    let make_svc = make_service_fn(move |_conn| {
        let state = state_clone.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let state = state.clone();
                async move { metrics_handler(state, req).await }
            }))
        }
    });

    let server = Server::bind(&config.metrics_addr).serve(make_svc);
    info!(
        "Metrics scrape endpoint: http://{}/metrics",
        config.metrics_addr
    );
    info!("Health endpoint:  http://{}/health", config.metrics_addr);

    server
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests;
