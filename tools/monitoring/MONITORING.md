# SAS Monitoring Setup

Complete Docker Compose setup for running the SAS Prometheus metrics exporter
alongside Prometheus and Grafana.

## Prerequisites

- Docker ≥ 24 and Docker Compose plugin (`docker compose`)
- A running Soroban network (Testnet or Futurenet) and a deployed SAS contract

## Quick start

```bash
cd tools/monitoring
cp .env.example .env
# Edit .env and set SAS_CONTRACT_ID at minimum
docker compose up -d
```

The stack starts three containers:

| Container             | Port  | Purpose                                      |
|-----------------------|-------|----------------------------------------------|
| `sas-exporter`        | 9090  | Prometheus metrics scrape endpoint `/metrics` |
| `prometheus`          | 9091  | Prometheus TSDB + query engine               |
| `grafana`             | 3000  | Grafana dashboards (admin / admin by default) |

## Environment variables

Copy `.env.example` to `.env` and fill in at minimum `SAS_CONTRACT_ID`.

| Variable                      | Default          | Required | Description                                   |
|-------------------------------|------------------|----------|-----------------------------------------------|
| `SAS_CONTRACT_ID`             | —                | **Yes**  | Soroban SAS contract address to watch         |
| `SCHEMA_REGISTRY_CONTRACT_ID` | —                | No       | Schema registry contract (enables extra stats)|
| `INDEXER_CONTRACT_ID`         | —                | No       | Indexer contract address                      |
| `METRICS_ADDR`                | `0.0.0.0:9090`   | No       | TCP address for the `/metrics` endpoint       |
| `RUST_LOG`                    | `info`           | No       | Tracing filter (`debug`, `info`, `warn`, …)   |

## Accessing the services

### Prometheus

Open <http://localhost:9091> and try these example queries:

```promql
# Attestation throughput (attestations per second)
rate(sas_attestations_total[5m])

# p99 transaction latency
histogram_quantile(0.99, rate(sas_transaction_latency_seconds_bucket[5m]))

# p95 batch size
histogram_quantile(0.95, rate(sas_attestation_batch_size_bucket[5m]))

# CPU instruction usage vs 100M Soroban limit
histogram_quantile(0.99, rate(sas_cpu_instructions_consumed_bucket[5m]))

# Re-index failures (alert condition: > 0)
sas_reindex_failures_total
```

### Grafana

1. Open <http://localhost:3000> and log in as **admin / admin**.
2. The **SAS — Soroban Attestation Service** dashboard is provisioned
   automatically and appears under *Dashboards → SAS*.
3. The Prometheus datasource is also pre-configured — no manual setup needed.

## Dashboard panels

The pre-built dashboard (`tools/grafana/sas-dashboard.json`) includes:

| Section                   | Panels                                                                 |
|---------------------------|------------------------------------------------------------------------|
| Attestation Throughput    | Attestation & revocation rate, totals, active count, re-index failures |
| Batch Sizes               | p50/p95/p99 batch size percentiles, average batch size                 |
| Transaction Latency       | p50/p95/p99 latency, p99 stat, average latency                         |
| CPU Cost (Instructions)   | p50/p95/p99 CPU instructions, p99 gauge vs 100 M Soroban limit         |

## Alerting

Add these recording rules and alerts to your Prometheus configuration:

```yaml
# prometheus/alerts.yml
groups:
  - name: sas
    interval: 30s
    rules:
      # Re-index failures — fire immediately on any failure
      - alert: SasReindexFailure
        expr: increase(sas_reindex_failures_total[5m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "SAS re-index failure detected"
          description: "{{ $value }} re-index failure(s) in the last 5 minutes"

      # High transaction latency
      - alert: SasHighTransactionLatency
        expr: >
          histogram_quantile(0.99,
            rate(sas_transaction_latency_seconds_bucket[5m])
          ) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "SAS p99 transaction latency above 5 s"
          description: "p99 latency is {{ $value | humanizeDuration }}"

      # CPU instructions approaching Soroban limit
      - alert: SasCpuInstructionsNearLimit
        expr: >
          histogram_quantile(0.99,
            rate(sas_cpu_instructions_consumed_bucket[5m])
          ) > 80000000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "SAS transactions consuming >80% of Soroban CPU limit"
          description: "p99 is {{ $value | humanize }} instructions (limit: 100M)"
```

## Memory footprint

The exporter holds no per-event state. Every event is processed in O(1) and
immediately aggregated into counters/histograms before the event data is
dropped. Static metric state (3 histograms × 12 buckets + 6 counters + 2
gauges) is under 1 KB. Under a sustained 10 000 event/s stream the process
stays well inside the 64 MB budget specified in issue #569.

## File layout

```
tools/
├── prometheus-exporter/
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs          # Metrics registry + /metrics HTTP server
│       └── tests.rs         # Unit tests for all 6 required metrics
├── grafana/
│   └── sas-dashboard.json   # Importable Grafana dashboard model
└── monitoring/
    ├── docker-compose.yml   # Prometheus + Grafana + exporter stack
    ├── .env.example         # Required environment variables
    ├── prometheus/
    │   └── prometheus.yml   # Scrape config pointing at sas-exporter:9090
    └── grafana/
        └── provisioning/
            ├── datasources/
            │   └── prometheus.yml
            └── dashboards/
                ├── dashboards.yml
                └── sas-dashboard.json  # symlink → ../../sas-dashboard.json
```
