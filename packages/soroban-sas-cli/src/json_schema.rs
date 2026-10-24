//! Off-chain JSON Schema Draft-7 export for SAS schema definitions (#537).
//!
//! SAS primitives map to Draft-7 as follows:
//! - `bool` -> `boolean`
//! - `string` -> `string`
//! - `uint256` -> `string` with pattern `^[0-9]+$` (Draft-7 numbers are not 256-bit)
//! - `bytes32` -> `string` with pattern `^0x[0-9a-fA-F]{64}$`
//!
//! Every field is required. `x-sas-type` keeps the original scalar so a
//! round trip restores the SAS definition.

use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaField {
    pub name: String,
    pub sas_type: String,
}

pub struct LintResult {
    pub document: Value,
    pub warnings: Vec<String>,
}

pub fn lint_schema(schema: &str) -> Result<LintResult, String> {
    let fields = parse_fields(schema)?;
    let mut warnings = Vec::new();
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &fields {
        let mapped = map_primitive(&field.sas_type);
        if let Some(warning) = mapped.warning {
            warnings.push(format!("field `{}`: {warning}", field.name));
        }
        let mut spec = Map::new();
        spec.insert(
            "type".to_string(),
            Value::String(mapped.json_type.to_string()),
        );
        spec.insert(
            "x-sas-type".to_string(),
            Value::String(field.sas_type.clone()),
        );
        if let Some(pattern) = mapped.pattern {
            spec.insert("pattern".to_string(), Value::String(pattern.to_string()));
        }
        properties.insert(field.name.clone(), Value::Object(spec));
        required.push(Value::String(field.name.clone()));
    }
    let document = serde_json::json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
    });
    Ok(LintResult { document, warnings })
}

/// Export then read the document back. Field names, required order, and
/// scalar types are taken from `required` and `x-sas-type`.
pub fn round_trip_schema(schema: &str) -> Result<String, String> {
    let linted = lint_schema(schema)?;
    let fields = fields_from_document(&linted.document)?;
    Ok(render_schema(&fields))
}

pub fn fields_from_document(document: &Value) -> Result<Vec<SchemaField>, String> {
    let required = document
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| "JSON Schema is missing required".to_string())?;
    let properties = document
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| "JSON Schema is missing properties".to_string())?;
    let mut fields = Vec::new();
    for entry in required {
        let name = entry
            .as_str()
            .ok_or_else(|| "required entry is not a string".to_string())?
            .to_string();
        let spec = properties
            .get(&name)
            .ok_or_else(|| format!("missing property `{name}`"))?;
        let sas_type = spec
            .get("x-sas-type")
            .and_then(Value::as_str)
            .unwrap_or("string")
            .to_string();
        fields.push(SchemaField { name, sas_type });
    }
    Ok(fields)
}

struct MappedType {
    json_type: &'static str,
    pattern: Option<&'static str>,
    warning: Option<String>,
}

fn map_primitive(sas_type: &str) -> MappedType {
    match sas_type.to_ascii_lowercase().as_str() {
        "bool" | "boolean" => MappedType {
            json_type: "boolean",
            pattern: None,
            warning: None,
        },
        "string" | "str" => MappedType {
            json_type: "string",
            pattern: None,
            warning: None,
        },
        "uint256" | "u256" => MappedType {
            json_type: "string",
            pattern: Some("^[0-9]+$"),
            warning: None,
        },
        "bytes32" | "b32" => MappedType {
            json_type: "string",
            pattern: Some("^0x[0-9a-fA-F]{64}$"),
            warning: None,
        },
        _ => {
            let warning = if sas_type
                .bytes()
                .any(|byte| matches!(byte, b'<' | b'[' | b'?' | b'>'))
            {
                format!(
                    "incompatible syntax `{sas_type}` is not a JSON Schema Draft-7 SAS primitive; exported as string"
                )
            } else {
                format!(
                    "unknown SAS type `{sas_type}` is not a Draft-7 primitive (bool, uint256, bytes32, string); exported as string"
                )
            };
            MappedType {
                json_type: "string",
                pattern: None,
                warning: Some(warning),
            }
        }
    }
}

fn render_schema(fields: &[SchemaField]) -> String {
    fields
        .iter()
        .map(|field| format!("{} {}", field.name, field.sas_type))
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_fields(schema: &str) -> Result<Vec<SchemaField>, String> {
    let trimmed = schema.trim();
    if trimmed.is_empty() {
        return Err("schema is empty".to_string());
    }
    if trimmed.starts_with(',') || trimmed.ends_with(',') {
        return Err("schema has an empty field".to_string());
    }
    let mut fields = Vec::new();
    let mut seen = Vec::new();
    for raw in trimmed.split(',') {
        let field = raw.trim();
        if field.is_empty() {
            return Err("schema has an empty field".to_string());
        }
        let mut parts = field.split(' ');
        let name = parts.next().unwrap_or("").trim();
        let sas_type = parts.next().unwrap_or("").trim();
        if name.is_empty() || sas_type.is_empty() || parts.next().is_some() {
            return Err(format!(
                "schema field `{field}` must be `name type` with one space"
            ));
        }
        if !is_identifier(name) {
            return Err(format!("schema field name `{name}` is not an identifier"));
        }
        let key = name.to_ascii_lowercase();
        if seen.iter().any(|existing: &String| existing == &key) {
            return Err(format!(
                "schema field `{name}` collides with an earlier field and would break serialization"
            ));
        }
        seen.push(key);
        fields.push(SchemaField {
            name: name.to_string(),
            sas_type: sas_type.to_string(),
        });
    }
    Ok(fields)
}

fn is_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
