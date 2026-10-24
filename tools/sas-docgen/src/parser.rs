use crate::models::{SchemaDocItem, SchemaField};

/// Parses a schema definition string into structured [`SchemaField`] entries.
///
/// Format: comma-separated pairs of `<identifier> <type>`.
/// Example: `"name String, age u32, metadata_uri String, verified bool"`
pub fn parse_schema_fields(schema: &str) -> Vec<SchemaField> {
    let mut fields = Vec::new();
    let trimmed = schema.trim();
    if trimmed.is_empty() {
        return fields;
    }

    for item in trimmed.split(',') {
        let entry = item.trim();
        if entry.is_empty() {
            continue;
        }

        // Split by whitespace: <identifier> <type>
        let parts: Vec<&str> = entry.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let name = parts[0].to_string();
        let field_type = if parts.len() > 1 {
            parts[1..].join(" ")
        } else {
            "Bytes".to_string()
        };

        let is_metadata_uri = is_uri_field(&name, &field_type);
        let description = generate_field_description(&name, &field_type);

        fields.push(SchemaField {
            name,
            field_type,
            is_metadata_uri,
            description,
        });
    }

    fields
}

/// Determines if a field name or type represents a metadata URI or pointer.
pub fn is_uri_field(name: &str, field_type: &str) -> bool {
    let lower_name = name.to_lowercase();
    let lower_type = field_type.to_lowercase();

    lower_name.contains("uri")
        || lower_name.contains("url")
        || lower_name.contains("ipfs")
        || lower_name.contains("cid")
        || lower_name.contains("metadata")
        || lower_type.contains("uri")
        || lower_type.contains("url")
}

/// Generates a human-friendly description for standard Soroban/SAS field types.
fn generate_field_description(name: &str, field_type: &str) -> String {
    let lower_name = name.to_lowercase();
    let lower_type = field_type.to_lowercase();

    if is_uri_field(name, field_type) {
        return "Pointer or URI to off-chain metadata (IPFS, HTTPS, Arweave, or decentralized storage)".to_string();
    }

    if lower_name.contains("time") || lower_name.contains("date") || lower_name.contains("expir") {
        return "Unix timestamp in seconds".to_string();
    }

    if lower_name.contains("addr")
        || lower_name.contains("recipient")
        || lower_name.contains("owner")
    {
        return "Stellar/Soroban account or contract address".to_string();
    }

    match lower_type.as_str() {
        "string" => format!("UTF-8 text value for `{}`", name),
        "bytes" | "bytesn<32>" => {
            format!("Raw binary payload or 32-byte identifier for `{}`", name)
        }
        "address" => format!("Soroban Address (account or contract) for `{}`", name),
        "u32" | "u64" => format!("Unsigned integer value representing `{}`", name),
        "i32" | "i64" | "i128" => format!("Signed integer or balance amount for `{}`", name),
        "bool" => format!("Boolean flag indicating `{}`", name),
        _ => format!("Field `{}` typed as `{}`", name, field_type),
    }
}

/// Builds a complete [`SchemaDocItem`] from raw on-chain data.
pub fn build_schema_doc_item(
    uid_hex: &str,
    raw_schema: &str,
    resolver: &str,
    revocable: bool,
    deprecated: bool,
    creator: Option<String>,
) -> SchemaDocItem {
    let fields = parse_schema_fields(raw_schema);

    // Detect if any field provides a default or primary metadata URI
    let metadata_uri = fields
        .iter()
        .find(|f| f.is_metadata_uri)
        .map(|f| format!("Documented via field `{}`", f.name));

    SchemaDocItem {
        uid: uid_hex.to_string(),
        raw_schema: raw_schema.to_string(),
        resolver: resolver.to_string(),
        revocable,
        deprecated,
        creator,
        metadata_uri,
        fields,
    }
}
