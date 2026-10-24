use super::*;
use crate::models::{NetworkConfig, SchemaDocItem};
use crate::parser::{is_uri_field, parse_schema_fields};
use std::fs;

#[test]
fn test_parse_schema_fields_multiple() {
    let schema = "first_name String, age u32, is_active bool, ipfs_hash String";
    let fields = parse_schema_fields(schema);

    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0].name, "first_name");
    assert_eq!(fields[0].field_type, "String");
    assert!(!fields[0].is_metadata_uri);

    assert_eq!(fields[1].name, "age");
    assert_eq!(fields[1].field_type, "u32");

    assert_eq!(fields[2].name, "is_active");
    assert_eq!(fields[2].field_type, "bool");

    assert_eq!(fields[3].name, "ipfs_hash");
    assert_eq!(fields[3].field_type, "String");
    assert!(fields[3].is_metadata_uri);
}

#[test]
fn test_parse_schema_fields_empty() {
    let fields = parse_schema_fields("");
    assert!(fields.is_empty());

    let fields_whitespace = parse_schema_fields("   ");
    assert!(fields_whitespace.is_empty());
}

#[test]
fn test_uri_detection() {
    assert!(is_uri_field("metadata_uri", "String"));
    assert!(is_uri_field("ipfs_cid", "String"));
    assert!(is_uri_field("doc_url", "String"));
    assert!(is_uri_field("schema_ref", "URI"));
    assert!(!is_uri_field("first_name", "String"));
    assert!(!is_uri_field("balance", "i128"));
}

#[test]
fn test_markdown_site_generation() {
    let out_path = std::env::temp_dir().join("sas_docgen_test_out");
    let _ = fs::remove_dir_all(&out_path);

    let network = NetworkConfig::for_network("testnet", None);
    let schemas = sample_fixture_data();

    DocGenerator::generate_site(&schemas, &network, "TEST_REGISTRY_ID", &out_path).unwrap();

    // Verify files created
    assert!(out_path.join("index.md").exists());
    assert!(out_path.join("SUMMARY.md").exists());

    for s in &schemas {
        let file_path = out_path.join(format!("{}.md", s.uid));
        assert!(file_path.exists());

        let content = fs::read_to_string(file_path).unwrap();
        // Check frontmatter
        assert!(content.contains(&format!("title: \"Schema: {}\"", s.uid)));
        assert!(content.contains(&format!("id: \"{}\"", s.uid)));
        // Check field table
        assert!(content.contains("Field Specifications"));
        assert!(content.contains(&s.fields[0].name));
        // Check integration examples
        assert!(content.contains("Rust (`soroban-sas-sdk`)"));
        assert!(content.contains("TypeScript (`@soroban-eas/sas-sdk`)"));
        assert!(content.contains("cURL (Soroban RPC)"));
    }

    let _ = fs::remove_dir_all(&out_path);
}

#[test]
fn test_fixture_serialization_roundtrip() {
    let original = sample_fixture_data();
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: Vec<SchemaDocItem> = serde_json::from_str(&serialized).unwrap();

    assert_eq!(original.len(), deserialized.len());
    assert_eq!(original[0].uid, deserialized[0].uid);
    assert_eq!(original[0].fields.len(), deserialized[0].fields.len());
}
