use crate::examples::IntegrationExamples;
use crate::models::{NetworkConfig, SchemaDocItem};
use std::fs;
use std::path::Path;

/// Markdown documentation site generator compatible with VitePress, Docusaurus, and mdBook.
pub struct DocGenerator;

impl DocGenerator {
    /// Generates the complete documentation bundle into `output_dir`.
    pub fn generate_site(
        schemas: &[SchemaDocItem],
        network: &NetworkConfig,
        registry_contract_id: &str,
        output_dir: &Path,
    ) -> anyhow::Result<()> {
        fs::create_dir_all(output_dir)?;

        // 1. Generate index.md (overview catalog)
        let index_content = Self::generate_index_markdown(schemas, network, registry_contract_id);
        fs::write(output_dir.join("index.md"), index_content)?;

        // 2. Generate individual schema markdown files
        for schema in schemas {
            let filename = format!("{}.md", schema.uid);
            let schema_content =
                Self::generate_schema_markdown(schema, network, registry_contract_id);
            fs::write(output_dir.join(filename), schema_content)?;
        }

        // 3. Generate SUMMARY.md for mdBook compatibility
        let summary_content = Self::generate_summary_markdown(schemas);
        fs::write(output_dir.join("SUMMARY.md"), summary_content)?;

        Ok(())
    }

    /// Generates markdown documentation for a single schema item.
    pub fn generate_schema_markdown(
        schema: &SchemaDocItem,
        network: &NetworkConfig,
        registry_contract_id: &str,
    ) -> String {
        let uid_short = if schema.uid.len() > 16 {
            format!("{}...", &schema.uid[..16])
        } else {
            schema.uid.clone()
        };

        let rust_code = IntegrationExamples::rust_example(schema, network);
        let ts_code = IntegrationExamples::typescript_example(schema, network);
        let curl_code = IntegrationExamples::curl_example(schema, network);

        let creator_display = schema
            .creator
            .as_deref()
            .unwrap_or("`Not specified / On-chain record`");

        let metadata_display = schema
            .metadata_uri
            .as_deref()
            .unwrap_or("None declared in schema definition");

        let status_badge = if schema.deprecated {
            "🔴 **DEPRECATED**"
        } else {
            "🟢 **ACTIVE**"
        };

        let revocable_badge = if schema.revocable {
            "✅ Revocable"
        } else {
            "🔒 Immutable (Non-revocable)"
        };

        // Build fields table
        let mut field_table = String::new();
        field_table.push_str("| Field Name | Type | Metadata / Role | Description |\n");
        field_table.push_str("|------------|------|-----------------|-------------|\n");

        if schema.fields.is_empty() {
            field_table.push_str(
                "| *(none)* | *(empty schema)* | — | Schema contains no field declarations |\n",
            );
        } else {
            for field in &schema.fields {
                let role = if field.is_metadata_uri {
                    "**Metadata URI**"
                } else {
                    "Data"
                };
                field_table.push_str(&format!(
                    "| `{}` | `{}` | {} | {} |\n",
                    field.name, field.field_type, role, field.description
                ));
            }
        }

        format!(
            r#"---
title: "Schema: {uid}"
id: "{uid}"
description: "Documentation, fields specification, and integration examples for schema {uid}"
sidebar_label: "{uid_short}"
---

# Schema Specification: `{uid_short}`

{status_badge} &nbsp; {revocable_badge}

## Overview

| Attribute | Value |
|-----------|-------|
| **Schema UID** | `{uid}` |
| **Status** | {status_badge} |
| **Revocability** | {revocable_badge} |
| **Resolver Contract** | `{resolver}` |
| **Creator Address** | {creator_display} |
| **Metadata Reference** | {metadata_display} |
| **Registry Contract** | `{registry_contract}` |
| **Target Network** | `{network_name}` |

---

## Schema Definition

Raw canonical definition registered on-chain:

```text
{raw_schema}
```

---

## Field Specifications

{field_table}

---

## Integration Examples

### Rust (`soroban-sas-sdk`)

```rust
{rust_code}
```

### TypeScript (`@soroban-eas/sas-sdk`)

```typescript
{ts_code}
```

### cURL (Soroban RPC)

```bash
{curl_code}
```

---

*Generated automatically by `sas-docgen` from Soroban on-chain schema registry.*
"#,
            uid = schema.uid,
            uid_short = uid_short,
            status_badge = status_badge,
            revocable_badge = revocable_badge,
            resolver = schema.resolver,
            creator_display = creator_display,
            metadata_display = metadata_display,
            registry_contract = registry_contract_id,
            network_name = network.name,
            raw_schema = schema.raw_schema,
            field_table = field_table,
            rust_code = rust_code,
            ts_code = ts_code,
            curl_code = curl_code,
        )
    }

    /// Generates the catalog `index.md` listing all registered schemas.
    pub fn generate_index_markdown(
        schemas: &[SchemaDocItem],
        network: &NetworkConfig,
        registry_contract_id: &str,
    ) -> String {
        let mut table = String::new();
        table.push_str("| Schema UID | Definition | Revocable | Status | Documentation |\n");
        table.push_str("|------------|------------|-----------|--------|---------------|\n");

        if schemas.is_empty() {
            table.push_str("| *(none)* | *(no schemas found)* | — | — | — |\n");
        } else {
            for schema in schemas {
                let uid_short = if schema.uid.len() > 16 {
                    format!("{}...", &schema.uid[..16])
                } else {
                    schema.uid.clone()
                };
                let status = if schema.deprecated {
                    "Deprecated"
                } else {
                    "Active"
                };
                let revocable = if schema.revocable { "Yes" } else { "No" };
                let raw_truncated = if schema.raw_schema.len() > 30 {
                    format!("{}...", &schema.raw_schema[..30])
                } else {
                    schema.raw_schema.clone()
                };

                table.push_str(&format!(
                    "| [`{}`](./{}.md) | `{}` | {} | {} | [View Docs](./{}.md) |\n",
                    uid_short, schema.uid, raw_truncated, revocable, status, schema.uid
                ));
            }
        }

        format!(
            r#"---
title: "Registered Schemas Catalog"
id: "schemas-index"
description: "Authoritative list of on-chain schemas registered in the Soroban SAS Schema Registry"
sidebar_label: "Overview"
---

# Registered Schemas Catalog

Authoritative documentation for all schemas registered on the Soroban SAS Schema Registry.

- **Network**: `{network_name}`
- **RPC URL**: `{rpc_url}`
- **Schema Registry Contract**: `{registry_id}`
- **Total Registered Schemas**: {count}

---

## Schema List

{table}

---

*Generated automatically by `sas-docgen`.*
"#,
            network_name = network.name,
            rpc_url = network.rpc_url,
            registry_id = registry_contract_id,
            count = schemas.len(),
            table = table
        )
    }

    /// Generates `SUMMARY.md` for mdBook compatibility.
    pub fn generate_summary_markdown(schemas: &[SchemaDocItem]) -> String {
        let mut summary =
            String::from("# Summary\n\n[Overview](index.md)\n\n## Registered Schemas\n\n");
        for schema in schemas {
            let uid_short = if schema.uid.len() > 16 {
                format!("{}...", &schema.uid[..16])
            } else {
                schema.uid.clone()
            };
            summary.push_str(&format!("- [{}]({}.md)\n", uid_short, schema.uid));
        }
        summary
    }
}
