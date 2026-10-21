use super::*;
use soroban_sas_sdk::events::{
    AttestationIssued, AttestationRevoked, BatchAttested, BatchRevoked, SasEvent, SchemaRegistered,
};
use soroban_sdk::xdr::{Hash, ScAddress};

#[test]
fn test_metrics_creation() {
    let metrics = SasMetrics::new();
    assert!(metrics.is_ok());
}

#[test]
fn test_record_attestation_issued() {
    let metrics = SasMetrics::new().unwrap();

    let event = SasEvent::AttestationIssued(AttestationIssued {
        uid: [0u8; 32],
        schema_uid: [1u8; 32],
        attester: ScAddress::Contract(Hash([2u8; 32])),
        recipient: ScAddress::Contract(Hash([3u8; 32])),
    });

    metrics.record_event(&event, "test_contract");

    assert_eq!(metrics.attestation_issued_total.get(), 1.0);
    assert_eq!(metrics.active_attestations.get(), 1.0);
}

#[test]
fn test_record_attestation_revoked() {
    let metrics = SasMetrics::new().unwrap();

    let event = SasEvent::AttestationRevoked(AttestationRevoked {
        uid: [0u8; 32],
        timestamp: 12345,
    });

    metrics.record_event(&event, "test_contract");

    assert_eq!(metrics.attestation_revoked_total.get(), 1.0);
    assert_eq!(metrics.active_attestations.get(), -1.0);
}

#[test]
fn test_record_batch_attested() {
    let metrics = SasMetrics::new().unwrap();

    let event = SasEvent::BatchAttested(BatchAttested {
        count: 5,
        attester_count: 2,
    });

    metrics.record_event(&event, "test_contract");

    assert_eq!(metrics.batch_attested_total.get(), 1.0);
    assert_eq!(metrics.active_attestations.get(), 5.0);
}

#[test]
fn test_record_batch_revoked() {
    let metrics = SasMetrics::new().unwrap();

    let event = SasEvent::BatchRevoked(BatchRevoked {
        count: 3,
        attester_count: 1,
    });

    metrics.record_event(&event, "test_contract");

    assert_eq!(metrics.batch_revoked_total.get(), 1.0);
    assert_eq!(metrics.active_attestations.get(), -3.0);
}

#[test]
fn test_record_schema_registered() {
    let metrics = SasMetrics::new().unwrap();

    let event = SasEvent::SchemaRegistered(SchemaRegistered {
        schema_uid: [0u8; 32],
        owner: ScAddress::Contract(Hash([1u8; 32])),
    });

    metrics.record_event(&event, "test_contract");

    assert_eq!(metrics.schema_registered_total.get(), 1.0);
    assert_eq!(metrics.active_schemas.get(), 1.0);
    assert_eq!(metrics.total_active_schemas.get(), 1.0);
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
fn test_registry_completeness() {
    let metrics = SasMetrics::new().unwrap();
    let metric_families = metrics.registry.gather();

    let metric_names: Vec<&str> = metric_families.iter().map(|m| m.get_name()).collect();

    assert!(metric_names.contains(&"sas_attestation_issued_total"));
    assert!(metric_names.contains(&"sas_attestation_revoked_total"));
    assert!(metric_names.contains(&"sas_batch_attested_total"));
    assert!(metric_names.contains(&"sas_batch_revoked_total"));
    assert!(metric_names.contains(&"sas_schema_registered_total"));
    assert!(metric_names.contains(&"sas_fee_config_updated_total"));
    assert!(metric_names.contains(&"sas_indexer_strict_updated_total"));
    assert!(metric_names.contains(&"sas_active_attestations"));
    assert!(metric_names.contains(&"sas_active_schemas"));
    assert!(metric_names.contains(&"sas_total_active_schemas"));
    assert!(metric_names.contains(&"sas_registered_attesters"));
    assert!(metric_names.contains(&"sas_total_registered_attesters"));
    assert!(metric_names.contains(&"sas_contract_paused"));
    assert!(metric_names.contains(&"sas_event_processing_duration_seconds"));
    assert!(metric_names.contains(&"sas_batch_size_distribution"));
    assert!(metric_names.contains(&"sas_transaction_cpu_instructions"));
    assert!(metric_names.contains(&"sas_contract_reverts_total"));
}
