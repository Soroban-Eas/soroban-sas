# SAS Prometheus Metrics Exporter

A Prometheus metrics exporter and monitoring toolkit for Soroban SAS (Stellar Attestation Service) contracts and protocol activity.

## Overview

This tool exposes Prometheus metrics over HTTP for monitoring SAS protocol activity, resource usage, contract health, and error states. It supports monitoring event streams, tracking active attestations and schemas, measuring CPU instruction consumption, monitoring batch sizes, and detecting contract reverts and circuit breaker activations.

## Metrics Catalog

### Counters

- `sas_attestation_issued_total` — Total number of attestations issued.
- `sas_attestation_revoked_total` — Total number of attestations revoked.
- `sas_batch_attested_total` — Total number of batch attestations completed.
- `sas_batch_revoked_total` — Total number of batch revocations completed.
- `sas_schema_registered_total` — Total number of schemas registered.
- `sas_fee_config_updated_total` — Total number of fee configuration updates.
- `sas_indexer_strict_updated_total` — Total number of indexer strict policy updates.
- `sas_contract_reverts_total{error_code="..."}` — Total number of contract reverts grouped by error code (e.g. `501` for `ContractPaused`, `502` for `Reentrancy`, `405` for `BatchTooLarge`).

### Gauges

- `sas_active_attestations` — Current number of active attestations on-chain.
- `sas_active_schemas` — Current number of active schemas registered.
- `sas_total_active_schemas` — Total count of active schemas registered on-chain.
- `sas_registered_attesters` — Total number of currently registered attester keyholders.
- `sas_total_registered_attesters` — Total count of registered attester keyholders.
- `sas_contract_paused` — Circuit breaker pause status (`1.0` if paused, `0.0` if operational).

### Histograms

- `sas_event_processing_duration_seconds` — Duration of event processing and dispatch in seconds.
- `sas_batch_size_distribution` — Distribution of transaction batch sizes for `multi_attest` and `multi_revoke` operations (buckets: 1, 2, 5, 10, 25, 50, 100, 250, 500).
- `sas_transaction_cpu_instructions` — Soroban contract execution CPU instructions consumed per transaction (buckets: 50k, 100k, 250k, 500k, 1M, 2.5M, 5M, 10M, 25M, 50M).

## Prometheus Alerting Rules

Pre-configured Prometheus alert rules are located in [`alerts.yml`](./alerts.yml). These rules define:
- `ContractPausedAlert` (`critical`): Triggered when contract pause state or error code `501` reverts are detected.
- `ReentrancySpikeAlert` (`critical`): Triggered on contract reverts with error code `502` (reentrancy violation).
- `HighRevocationRateAlert` (`warning`): Triggered when revocation rates spike abnormally relative to issuance.

See the [Operations and Alerts Runbook](../../docs/OPERATIONS_AND_ALERTS_RUNBOOK.md) for triage and remediation procedures.

## Grafana Dashboard

A sample Grafana dashboard configuration is provided in [`grafana-dashboard.json`](./grafana-dashboard.json). It visualizes:
- Circuit breaker pause status and health indicators
- Active schemas, active attestations, and registered attester counts
- Transaction batch size distributions and average batch sizes
- CPU instructions consumption percentiles (p50, p90, p99)
- Revert rates grouped by contract error code
- Attestation issuance vs. revocation throughput

To import:
1. Open Grafana UI -> **Dashboards** -> **New** -> **Import**.
2. Upload `grafana-dashboard.json` or paste the JSON content.
3. Select your Prometheus datasource and click **Import**.

## Integration Boundaries & Protocol Data Sources

1. **Batch Size Distribution**: Derived from `BatchAttested` and `BatchRevoked` events emitted by `multi_attest` and `multi_revoke` contracts calls, recording exact item counts per batch.
2. **CPU Instructions**: Collected from Soroban RPC transaction simulation results (`SorobanResources.instructions`) and ledger transaction metadata. When running in event-only mode without full RPC simulation hooks, the exporter accepts CPU instruction observations through `record_cpu_instructions`.
3. **Reverts Grouped by Error Code**: Extracted from failed simulation responses (`SdkError::ContractError(code)`) and failed on-chain transaction result XDRs.
4. **Active Schemas and Attesters**: Sourced on startup by querying `SchemaRegistry::get_schemas` and attester key counts from contract storage, and incremented/decremented continuously as lifecycle events are ingested.

## Usage

### Build

```bash
cargo build -p soroban-sas-prometheus-exporter
```

### Run

```bash
# Set required environment variables
export SAS_CONTRACT_ID="C..."
export SCHEMA_REGISTRY_CONTRACT_ID="C..." # optional
export INDEXER_CONTRACT_ID="C..."         # optional

# Run the exporter
./target/debug/soroban-sas-prometheus-exporter
```

### Environment Variables

- `SAS_CONTRACT_ID` — SAS contract ID to monitor (required)
- `SCHEMA_REGISTRY_CONTRACT_ID` — Schema Registry contract ID to monitor (optional)
- `INDEXER_CONTRACT_ID` — Indexer contract ID to monitor (optional)
- `METRICS_ADDR` — Prometheus metrics server address (default: `0.0.0.0:9090`)

### Accessing Metrics

Metrics are available at `http://localhost:9090/metrics`:

```bash
curl http://localhost:9090/metrics
```

## Example PromQL Queries

### Average Batch Size over 5 minutes
```promql
rate(sas_batch_size_distribution_sum[5m]) / rate(sas_batch_size_distribution_count[5m])
```

### 99th Percentile CPU Instructions
```promql
histogram_quantile(0.99, sum(rate(sas_transaction_cpu_instructions_bucket[5m])) by (le))
```

### Reverts by Error Code Rate
```promql
sum by (error_code) (rate(sas_contract_reverts_total[5m]))
```

### Revocation to Issuance Ratio
```promql
rate(sas_attestation_revoked_total[5m]) / (rate(sas_attestation_issued_total[5m]) + 1e-6)
```

## License

Same as the parent soroban-sas project.
