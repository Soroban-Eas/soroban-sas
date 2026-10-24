//! Unit tests for the SAS Prometheus metrics exporter.
//!
//! Covers:
//!  - All 6 metrics required by issue #569
//!  - Existing backward-compatible metrics
//!  - Batch size histogram observations
//!  - Transaction latency and CPU instruction recording helpers
//!  - Re-index failure counter
//!  - Registry completeness (all metric names present in gathered output)
//!  - Prometheus text format emission

use super::*;
use soroban_sas_sdk::events::{
    AttestationIssued, AttestationRevoked, BatchAttested, BatchRevoked, SasEvent, SchemaRegistered,
};
use soroban_sdk::xdr::{Hash, ScAddress};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_metrics() -> SasMetrics {
    SasMetrics::new().expect("SasMetrics::new must succeed")
}

fn issued_event() -> SasEvent {
    SasEvent::AttestationIssued(AttestationIssued {
        uid: [0u8; 32],
        schema_uid: [1u8; 32],
        attester: ScAddress::Contract(Hash([2u8; 32])),
        recipient: ScAddress::Contract(Hash([3u8; 32])),
    })
}

fn revoked_event() -> SasEvent {
    SasEvent::AttestationRevoked(AttestationRevoked {
        uid: [0u8; 32],
        timestamp: 12345,
    })
}

fn batch_attested_event(count: u32) -> SasEvent {
    SasEvent::BatchAttested(BatchAttested {
        count,
        attester_count: 1,
    })
}

fn batch_revoked_event(count: u32) -> SasEvent {
    SasEvent::BatchRevoked(BatchRevoked {
        count,
        attester_count: 1,
    })
}

// ── Construction ──────────────────────────────────────────────────────────────

#[test]
fn test_metrics_creation() {
    assert!(SasMetrics::new().is_ok());
}

// ── Issue #569: sas_attestations_total counter ───────────────────────────────

#[test]
fn test_sas_attestations_total_single_issue() {
    let m = make_metrics();
    m.record_event(&issued_event(), "c1");
    assert_eq!(m.sas_attestations_total.get(), 1.0);
}

#[test]
fn test_sas_attestations_total_batch() {
    let m = make_metrics();
    m.record_event(&batch_attested_event(7), "c1");
    assert_eq!(m.sas_attestations_total.get(), 7.0);
}

#[test]
fn test_sas_attestations_total_accumulates_across_events() {
    let m = make_metrics();
    m.record_event(&issued_event(), "c1"); // +1
    m.record_event(&batch_attested_event(4), "c1"); // +4
    m.record_event(&issued_event(), "c1"); // +1
    assert_eq!(m.sas_attestations_total.get(), 6.0);
}

#[test]
fn test_sas_attestations_total_not_incremented_by_revocation() {
    let m = make_metrics();
    m.record_event(&issued_event(), "c1");
    m.record_event(&revoked_event(), "c1");
    // Revocations increment sas_revocations_total, not sas_attestations_total
    assert_eq!(m.sas_attestations_total.get(), 1.0);
}

// ── Issue #569: sas_revocations_total counter ────────────────────────────────

#[test]
fn test_sas_revocations_total_single_revoke() {
    let m = make_metrics();
    m.record_event(&revoked_event(), "c1");
    assert_eq!(m.sas_revocations_total.get(), 1.0);
}

#[test]
fn test_sas_revocations_total_batch() {
    let m = make_metrics();
    m.record_event(&batch_revoked_event(3), "c1");
    assert_eq!(m.sas_revocations_total.get(), 3.0);
}

#[test]
fn test_sas_revocations_total_accumulates() {
    let m = make_metrics();
    m.record_event(&revoked_event(), "c1"); // +1
    m.record_event(&batch_revoked_event(9), "c1"); // +9
    assert_eq!(m.sas_revocations_total.get(), 10.0);
}

// ── Issue #569: sas_reindex_failures_total counter ───────────────────────────

#[test]
fn test_sas_reindex_failures_initial_zero() {
    let m = make_metrics();
    assert_eq!(m.sas_reindex_failures_total.get(), 0.0);
}

#[test]
fn test_sas_reindex_failures_increments() {
    let m = make_metrics();
    m.record_reindex_failure();
    assert_eq!(m.sas_reindex_failures_total.get(), 1.0);
}

#[test]
fn test_sas_reindex_failures_accumulates() {
    let m = make_metrics();
    for _ in 0..5 {
        m.record_reindex_failure();
    }
    assert_eq!(m.sas_reindex_failures_total.get(), 5.0);
}

#[test]
fn test_sas_reindex_failures_not_affected_by_events() {
    let m = make_metrics();
    m.record_event(&issued_event(), "c1");
    m.record_event(&revoked_event(), "c1");
    assert_eq!(m.sas_reindex_failures_total.get(), 0.0);
}

// ── Issue #569: sas_attestation_batch_size histogram ─────────────────────────

#[test]
fn test_sas_attestation_batch_size_single_issue_records_one() {
    let m = make_metrics();
    m.record_event(&issued_event(), "c1");
    // Single attestation should observe batch_size = 1
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_attestation_batch_size")
        .expect("sas_attestation_batch_size must be registered");
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 1);
    assert_eq!(metric.get_histogram().get_sample_sum(), 1.0);
}

#[test]
fn test_sas_attestation_batch_size_batch_event() {
    let m = make_metrics();
    m.record_event(&batch_attested_event(25), "c1");
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_attestation_batch_size")
        .unwrap();
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 1);
    assert_eq!(metric.get_histogram().get_sample_sum(), 25.0);
}

#[test]
fn test_sas_attestation_batch_size_multiple_observations() {
    let m = make_metrics();
    m.record_event(&issued_event(), "c1"); // obs 1.0
    m.record_event(&batch_attested_event(10), "c1"); // obs 10.0
    m.record_event(&batch_attested_event(5), "c1"); // obs 5.0
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_attestation_batch_size")
        .unwrap();
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 3);
    assert_eq!(metric.get_histogram().get_sample_sum(), 16.0);
}

// ── Issue #569: sas_transaction_latency_seconds histogram ────────────────────

#[test]
fn test_sas_transaction_latency_initial_empty() {
    let m = make_metrics();
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_transaction_latency_seconds")
        .expect("sas_transaction_latency_seconds must be registered");
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 0);
}

#[test]
fn test_sas_transaction_latency_records_observation() {
    let m = make_metrics();
    m.record_transaction_latency(0.123);
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_transaction_latency_seconds")
        .unwrap();
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 1);
    let sum = metric.get_histogram().get_sample_sum();
    // Float comparison with tolerance
    assert!((sum - 0.123).abs() < 1e-9, "sum={sum}");
}

#[test]
fn test_sas_transaction_latency_multiple_observations() {
    let m = make_metrics();
    m.record_transaction_latency(0.05);
    m.record_transaction_latency(0.25);
    m.record_transaction_latency(1.0);
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_transaction_latency_seconds")
        .unwrap();
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 3);
    let sum = metric.get_histogram().get_sample_sum();
    assert!((sum - 1.3).abs() < 1e-9, "sum={sum}");
}

#[test]
fn test_sas_transaction_latency_buckets_are_correct() {
    // Verify that LATENCY_BUCKETS are surfaced in the exposition output
    let m = make_metrics();
    let encoder = prometheus::TextEncoder::new();
    let families = m.registry.gather();
    let mut buf = Vec::new();
    encoder.encode(&families, &mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    // The 0.001 bucket should appear in the output
    assert!(
        text.contains("sas_transaction_latency_seconds_bucket{le=\"0.001\"}"),
        "0.001 s bucket missing from exposition output"
    );
    // The 10 s bucket should also appear
    assert!(
        text.contains("sas_transaction_latency_seconds_bucket{le=\"10\"}"),
        "10 s bucket missing from exposition output"
    );
}

// ── Issue #569: sas_cpu_instructions_consumed histogram ──────────────────────

#[test]
fn test_sas_cpu_instructions_initial_empty() {
    let m = make_metrics();
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_cpu_instructions_consumed")
        .expect("sas_cpu_instructions_consumed must be registered");
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 0);
}

#[test]
fn test_sas_cpu_instructions_records_observation() {
    let m = make_metrics();
    m.record_cpu_instructions(5_000_000);
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_cpu_instructions_consumed")
        .unwrap();
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 1);
    assert_eq!(metric.get_histogram().get_sample_sum(), 5_000_000.0);
}

#[test]
fn test_sas_cpu_instructions_near_soroban_limit() {
    let m = make_metrics();
    // 100 M instructions is Soroban's hard compute limit
    m.record_cpu_instructions(100_000_000);
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_cpu_instructions_consumed")
        .unwrap();
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 1);
    assert_eq!(metric.get_histogram().get_sample_sum(), 100_000_000.0);
}

#[test]
fn test_sas_cpu_instructions_zero_is_valid() {
    let m = make_metrics();
    m.record_cpu_instructions(0);
    let families = m.registry.gather();
    let hist = families
        .iter()
        .find(|f| f.get_name() == "sas_cpu_instructions_consumed")
        .unwrap();
    let metric = &hist.get_metric()[0];
    assert_eq!(metric.get_histogram().get_sample_count(), 1);
}

// ── Existing backward-compatible metrics ─────────────────────────────────────

#[test]
fn test_record_attestation_issued() {
    let m = make_metrics();
    m.record_event(&issued_event(), "test_contract");
    assert_eq!(m.attestation_issued_total.get(), 1.0);
    assert_eq!(m.active_attestations.get(), 1.0);
}

#[test]
fn test_record_attestation_revoked() {
    let m = make_metrics();
    m.record_event(&revoked_event(), "test_contract");
    assert_eq!(m.attestation_revoked_total.get(), 1.0);
    assert_eq!(m.active_attestations.get(), -1.0);
}

#[test]
fn test_record_batch_attested() {
    let m = make_metrics();
    m.record_event(&batch_attested_event(5), "test_contract");
    assert_eq!(m.batch_attested_total.get(), 1.0);
    assert_eq!(m.active_attestations.get(), 5.0);
}

#[test]
fn test_record_batch_revoked() {
    let m = make_metrics();
    m.record_event(&batch_revoked_event(3), "test_contract");
    assert_eq!(m.batch_revoked_total.get(), 1.0);
    assert_eq!(m.active_attestations.get(), -3.0);
}

#[test]
fn test_record_schema_registered() {
    let m = make_metrics();
    let event = SasEvent::SchemaRegistered(SchemaRegistered {
        schema_uid: [0u8; 32],
        owner: ScAddress::Contract(Hash([1u8; 32])),
    });
    m.record_event(&event, "test_contract");
    assert_eq!(m.schema_registered_total.get(), 1.0);
    assert_eq!(m.active_schemas.get(), 1.0);
    assert_eq!(m.total_active_schemas.get(), 1.0);
}

#[test]
fn test_record_batch_metrics() {
    let metrics = SasMetrics::new().unwrap();

    let event = SasEvent::BatchAttested(BatchAttested {
        count: 25,
        attester_count: 8,
    });
    metrics.record_event(&event, "test_contract");

    assert_eq!(metrics.registered_attesters.get(), 8.0);
    assert_eq!(metrics.total_registered_attesters.get(), 8.0);
    assert_eq!(metrics.batch_size_distribution.get_sample_count(), 1);
    assert_eq!(metrics.batch_size_distribution.get_sample_sum(), 25.0);

    metrics.record_batch_size(15);
    assert_eq!(metrics.batch_size_distribution.get_sample_count(), 2);
    assert_eq!(metrics.batch_size_distribution.get_sample_sum(), 40.0);
}

#[test]
fn test_record_cpu_instructions() {
    let metrics = SasMetrics::new().unwrap();
    metrics.record_cpu_instructions(1_500_000);
    metrics.record_cpu_instructions(2_500_000);

    assert_eq!(metrics.transaction_cpu_instructions.get_sample_count(), 2);
    assert_eq!(
        metrics.transaction_cpu_instructions.get_sample_sum(),
        4_000_000.0
    );
}

#[test]
fn test_contract_reverts_and_pause() {
    let metrics = SasMetrics::new().unwrap();

    // Reentrancy error (502)
    metrics.record_contract_revert(502);
    // Contract paused error (501)
    metrics.record_contract_revert(501);

    assert_eq!(
        metrics
            .contract_reverts_total
            .with_label_values(&["502"])
            .get(),
        1.0
    );
    assert_eq!(
        metrics
            .contract_reverts_total
            .with_label_values(&["501"])
            .get(),
        1.0
    );
    // Error 501 sets paused gauge to 1.0
    assert_eq!(metrics.contract_paused.get(), 1.0);

    metrics.set_contract_paused(false);
    assert_eq!(metrics.contract_paused.get(), 0.0);
}

#[test]
fn test_attester_and_schema_gauges() {
    let metrics = SasMetrics::new().unwrap();

    metrics.set_active_schemas(42.0);
    assert_eq!(metrics.active_schemas.get(), 42.0);
    assert_eq!(metrics.total_active_schemas.get(), 42.0);

    metrics.set_registered_attesters(10.0);
    assert_eq!(metrics.registered_attesters.get(), 10.0);
    assert_eq!(metrics.total_registered_attesters.get(), 10.0);

    metrics.record_attester_registered();
    assert_eq!(metrics.registered_attesters.get(), 11.0);

    metrics.record_attester_revoked();
    assert_eq!(metrics.registered_attesters.get(), 10.0);
}

#[test]
fn test_registry_contains_all_required_issue_569_metrics() {
    let m = make_metrics();
    let metric_families = m.registry.gather();
    let names: Vec<&str> = metric_families.iter().map(|f| f.get_name()).collect();

    // Issue #569 histograms
    assert!(
        names.contains(&"sas_attestation_batch_size"),
        "missing sas_attestation_batch_size"
    );
    assert!(
        names.contains(&"sas_transaction_latency_seconds"),
        "missing sas_transaction_latency_seconds"
    );
    assert!(
        names.contains(&"sas_cpu_instructions_consumed"),
        "missing sas_cpu_instructions_consumed"
    );

    // Issue #569 counters
    assert!(
        names.contains(&"sas_attestations_total"),
        "missing sas_attestations_total"
    );
    assert!(
        names.contains(&"sas_revocations_total"),
        "missing sas_revocations_total"
    );
    assert!(
        names.contains(&"sas_reindex_failures_total"),
        "missing sas_reindex_failures_total"
    );
}

#[test]
fn test_registry_contains_all_existing_metrics() {
    let m = make_metrics();
    m.record_contract_revert(500);
    let metric_families = m.registry.gather();
    let names: Vec<&str> = metric_families.iter().map(|f| f.get_name()).collect();

    assert!(names.contains(&"sas_attestation_issued_total"));
    assert!(names.contains(&"sas_attestation_revoked_total"));
    assert!(names.contains(&"sas_batch_attested_total"));
    assert!(names.contains(&"sas_batch_revoked_total"));
    assert!(names.contains(&"sas_schema_registered_total"));
    assert!(names.contains(&"sas_fee_config_updated_total"));
    assert!(names.contains(&"sas_indexer_strict_updated_total"));
    assert!(names.contains(&"sas_active_attestations"));
    assert!(names.contains(&"sas_active_schemas"));
    assert!(names.contains(&"sas_total_active_schemas"));
    assert!(names.contains(&"sas_registered_attesters"));
    assert!(names.contains(&"sas_total_registered_attesters"));
    assert!(names.contains(&"sas_contract_paused"));
    assert!(names.contains(&"sas_event_processing_duration_seconds"));
    assert!(names.contains(&"sas_batch_size_distribution"));
    assert!(names.contains(&"sas_transaction_cpu_instructions"));
    assert!(names.contains(&"sas_contract_reverts_total"));
}

// ── Prometheus text exposition format ─────────────────────────────────────────

#[test]
fn test_metrics_endpoint_produces_valid_prometheus_text() {
    let m = make_metrics();
    // Record some data so the output is non-trivial
    m.record_event(&issued_event(), "c1");
    m.record_transaction_latency(0.05);
    m.record_cpu_instructions(1_000_000);
    m.record_reindex_failure();

    let encoder = prometheus::TextEncoder::new();
    let families = m.registry.gather();
    let mut buf = Vec::new();
    encoder.encode(&families, &mut buf).unwrap();

    let text = String::from_utf8(buf).unwrap();

    // Must contain HELP lines
    assert!(text.contains("# HELP sas_attestations_total"));
    assert!(text.contains("# HELP sas_revocations_total"));
    assert!(text.contains("# HELP sas_reindex_failures_total"));
    assert!(text.contains("# HELP sas_attestation_batch_size"));
    assert!(text.contains("# HELP sas_transaction_latency_seconds"));
    assert!(text.contains("# HELP sas_cpu_instructions_consumed"));

    // Must contain TYPE declarations
    assert!(text.contains("# TYPE sas_attestations_total counter"));
    assert!(text.contains("# TYPE sas_attestation_batch_size histogram"));
    assert!(text.contains("# TYPE sas_transaction_latency_seconds histogram"));
    assert!(text.contains("# TYPE sas_cpu_instructions_consumed histogram"));

    // Counters must have actual values
    assert!(text.contains("sas_attestations_total 1"));
    assert!(text.contains("sas_reindex_failures_total 1"));
}

#[test]
fn test_metrics_content_type_is_text_plain() {
    // TextEncoder::format_type() must return the standard Prometheus content type
    let encoder = prometheus::TextEncoder::new();
    assert!(
        encoder.format_type().starts_with("text/plain"),
        "format_type must start with text/plain, got: {}",
        encoder.format_type()
    );
}
