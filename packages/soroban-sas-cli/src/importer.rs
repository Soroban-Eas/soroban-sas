//! Fault-tolerant CSV and JSON Lines input for `attest import`.
//! Each parsed row carries its original source line, including failures.

use crate::bulk::{parse_bulk_csv, split_records, BulkRow, MAX_BULK_ROWS};
use serde::Deserialize;

#[derive(Debug)]
pub struct ImportRecord {
    pub line: usize,
    pub row: Result<BulkRow, String>,
}

#[derive(Deserialize)]
struct JsonRow {
    #[serde(default)]
    schema_uid: String,
    #[serde(default)]
    recipient: String,
    #[serde(default)]
    data: String,
    #[serde(default, alias = "expiration_time")]
    expiration: u64,
    #[serde(default)]
    revocable: bool,
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('\n') || value.contains('\r') || value.contains('"') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// CSV row errors do not discard other rows, and JSON-L parsing failures
/// remain visible with their source-line context.
pub fn parse_import(content: &str, extension: &str) -> Result<Vec<ImportRecord>, String> {
    let mut rows = Vec::new();
    match extension.to_ascii_lowercase().as_str() {
        "csv" => {
            let records = split_records(content)?;
            let mut records = records
                .into_iter()
                .filter(|(_, cols)| !cols.iter().all(|x| x.trim().is_empty()));
            let Some((_, header)) = records.next() else {
                return Err("CSV file is empty; expected a header".into());
            };
            let header = header
                .iter()
                .map(|field| csv_field(field))
                .collect::<Vec<_>>()
                .join(",");
            for (line, fields) in records {
                if rows.len() >= MAX_BULK_ROWS {
                    return Err(format!("import may contain at most {MAX_BULK_ROWS} rows"));
                }
                let body = fields
                    .iter()
                    .map(|field| csv_field(field))
                    .collect::<Vec<_>>()
                    .join(",");
                let reconstructed = format!("{header}\n{body}\n");
                let row = parse_bulk_csv(&reconstructed)
                    .and_then(|mut items| {
                        let mut item = items.pop().ok_or("missing CSV row")?;
                        item.line = line;
                        Ok(item)
                    })
                    .map_err(|err| format!("line {line}: {err}"));
                rows.push(ImportRecord { line, row });
            }
        }
        "jsonl" | "ndjson" => {
            for (i, source) in content.lines().enumerate() {
                if source.trim().is_empty() {
                    continue;
                }
                if rows.len() >= MAX_BULK_ROWS {
                    return Err(format!("import may contain at most {MAX_BULK_ROWS} rows"));
                }
                let line = i + 1;
                let row = serde_json::from_str::<JsonRow>(source)
                    .map_err(|err| format!("line {line}: invalid JSON-L: {err}"))
                    .and_then(|item| {
                        if item.schema_uid.trim().is_empty() || item.recipient.trim().is_empty() {
                            return Err(format!(
                                "line {line}: schema_uid and recipient are required"
                            ));
                        }
                        Ok(BulkRow {
                            line,
                            schema_uid: item.schema_uid,
                            recipient: item.recipient,
                            data: item.data,
                            expiration: item.expiration,
                            revocable: item.revocable,
                        })
                    });
                rows.push(ImportRecord { line, row });
            }
        }
        _ => return Err("expected a .csv, .jsonl, or .ndjson file".to_string()),
    }
    if rows.is_empty() {
        return Err("import file has no data rows".into());
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_invalid_csv_rows_without_dropping_valid_rows() {
        let records = parse_import(
            "schema_uid,recipient,expiration\naa,GONE,0\nbb,GTWO,invalid\ncc,GTHREE,0\n",
            "csv",
        )
        .unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].line, 2);
        assert_eq!(records[2].line, 4);
        assert!(records[0].row.is_ok());
        assert!(records[1].row.is_err());
        assert!(records[2].row.is_ok());
    }

    #[test]
    fn jsonl_handles_errors_and_fields() {
        let records = parse_import(
            "{\"schema_uid\":\"a\",\"recipient\":\"GA\",\"revocable\":true}\nnot-json\n{\"schema_uid\":\"b\",\"recipient\":\"GB\"}\n",
            "jsonl",
        ).unwrap();
        assert_eq!(records.len(), 3);
        assert!(records[0].row.as_ref().unwrap().revocable);
        assert!(records[1].row.is_err());
        assert_eq!(records[2].row.as_ref().unwrap().recipient, "GB");
    }

    #[test]
    fn accepts_one_thousand_plus_records() {
        let data = format!("schema_uid,recipient\n{}", "aa,GABC\n".repeat(1001));
        assert_eq!(parse_import(&data, "csv").unwrap().len(), 1001);
    }
}
