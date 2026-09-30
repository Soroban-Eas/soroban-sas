//! CSV parsing for the `attest bulk` subcommand (issue #335).
//!
//! Deliberately dependency-free: the format is a plain RFC 4180 subset
//! (comma-separated, optional double-quoted fields, `""` escapes a quote
//! inside a quoted field, `\n` or `\r\n` record separators) and a full
//! CSV crate would be a new dependency for a few dozen lines of
//! straight-line parsing. Keeping it in-tree also keeps every error
//! message anchored to a **1-based source line**, which is what an
//! operator needs when one row out of thousands is wrong.
//!
//! Parsing is separated from validation on purpose. [`parse_bulk_csv`]
//! only turns text into typed rows; address, hex, and duplicate checks
//! live in the caller so that a malformed file is rejected before any
//! on-chain transaction is submitted.

/// Largest number of data rows `attest bulk` will accept in one file.
///
/// Every row is one on-chain transaction, so an unbounded file would let
/// a mistyped or hostile path turn a single command into an unbounded
/// sequence of fee-spending writes. Callers pair this with
/// [`io_safety::read_bounded`](crate::io_safety) for the byte-level cap.
pub const MAX_BULK_ROWS: usize = 5_000;

/// Columns that must be present in the header row.
const REQUIRED_COLUMNS: [&str; 2] = ["schema_uid", "recipient"];

/// Columns accepted but optional; a missing one takes its default.
const OPTIONAL_COLUMNS: [(&str, &str); 3] = [
    ("data", "empty payload"),
    ("expiration", "0 (no expiry)"),
    ("revocable", "false"),
];

/// One parsed CSV data row, before address/hex validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkRow {
    /// 1-based line in the source file this row was read from, used in
    /// every error message so an operator can find the offending row.
    pub line: usize,
    /// 32-byte schema UID, hex encoded.
    pub schema_uid: String,
    /// Recipient address (`G...` or `C...`).
    pub recipient: String,
    /// Attestation payload, hex or base64 encoded; may be empty.
    pub data: String,
    /// Unix timestamp the attestation expires at (`0` = no expiry).
    pub expiration: u64,
    /// Whether the issued attestation can be revoked.
    pub revocable: bool,
}

/// Splits CSV text into records of raw fields, keeping the 1-based source
/// line each record started on.
///
/// Implements the RFC 4180 subset documented at the module level:
/// comma separators, double-quoted fields (with `""` as an escaped quote),
/// and both `\n` and `\r\n` record separators. A quoted field may legally
/// span lines. A lone `\r` outside quotes is treated as literal data, so a
/// file written with old-Mac line endings is reported as one long record
/// rather than silently accepted.
fn split_records(input: &str) -> Result<Vec<(usize, Vec<String>)>, String> {
    let mut records: Vec<(usize, Vec<String>)> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut line: usize = 1;
    let mut record_line: usize = 1;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' => {
                    // `""` inside a quoted field is one literal quote;
                    // otherwise the quote closes the field.
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                    }
                }
                '\n' => {
                    line += 1;
                    field.push(c);
                }
                other => field.push(other),
            }
            continue;
        }

        match c {
            '"' => {
                if !field.is_empty() {
                    return Err(format!(
                        "line {record_line}: unexpected `\"` in the middle of an unquoted field; \
                         quote the whole field and double any quote inside it"
                    ));
                }
                in_quotes = true;
            }
            ',' => record.push(std::mem::take(&mut field)),
            '\r' => {
                // Swallow the LF of a CRLF pair; a bare CR ends the record
                // too, so a file saved with CR-only endings still parses.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                record.push(std::mem::take(&mut field));
                records.push((record_line, std::mem::take(&mut record)));
                line += 1;
                record_line = line;
            }
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push((record_line, std::mem::take(&mut record)));
                line += 1;
                record_line = line;
            }
            other => field.push(other),
        }
    }

    if in_quotes {
        return Err(format!(
            "line {record_line}: unterminated quoted field; a quoted value must be closed with `\"`"
        ));
    }

    // A trailing separator or newline leaves a final field/record pending.
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push((record_line, record));
    }

    Ok(records)
}

/// Parses a `attest bulk` CSV document into validated-typed rows.
///
/// The header row selects columns by name, so column order is free and a
/// typo'd column is reported instead of being silently ignored. Only the
/// header row is required; blank lines anywhere are skipped.
pub fn parse_bulk_csv(input: &str) -> Result<Vec<BulkRow>, String> {
    let mut records = split_records(input)?
        .into_iter()
        .filter(|(_, fields)| !fields.iter().all(|f| f.trim().is_empty()))
        .peekable();

    let Some((header_line, header)) = records.next() else {
        return Err("CSV file is empty; expected a header row".to_string());
    };

    let header: Vec<String> = header
        .into_iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();

    let index_of = |name: &str| header.iter().position(|h| h == name);

    for required in REQUIRED_COLUMNS {
        if index_of(required).is_none() {
            return Err(format!(
                "line {header_line}: missing required column `{required}`; \
                 the header must contain {}",
                REQUIRED_COLUMNS.join(" and ")
            ));
        }
    }

    // A misspelled column is far more likely than a deliberately
    // unrecognised one, and silently dropping it would issue an
    // attestation with a payload the operator never intended.
    for name in &header {
        let known = REQUIRED_COLUMNS.contains(&name.as_str())
            || OPTIONAL_COLUMNS.iter().any(|(c, _)| c == name);
        if !known {
            return Err(format!(
                "line {header_line}: unknown column `{name}`; \
                 expected one of {}",
                supported_columns().join(", ")
            ));
        }
    }

    let i_schema = index_of("schema_uid").expect("checked above");
    let i_recipient = index_of("recipient").expect("checked above");
    let i_data = index_of("data");
    let i_expiration = index_of("expiration");
    let i_revocable = index_of("revocable");

    let mut rows = Vec::new();

    for (line, fields) in records {
        // A trailing empty field from a line-final comma is not a column.
        let width = header.len();
        let mut fields = fields;
        if fields.len() > width && fields[width..].iter().all(|f| f.trim().is_empty()) {
            fields.truncate(width);
        }

        if fields.len() != width {
            return Err(format!(
                "line {line}: expected {width} field{} to match the header, found {}",
                if width == 1 { "" } else { "s" },
                fields.len()
            ));
        }

        if rows.len() == MAX_BULK_ROWS {
            return Err(format!(
                "too many rows: this command accepts at most {MAX_BULK_ROWS} attestations per file"
            ));
        }

        let schema_uid = fields[i_schema].trim().to_string();
        if schema_uid.is_empty() {
            return Err(format!("line {line}: `schema_uid` must not be empty"));
        }

        let recipient = fields[i_recipient].trim().to_string();
        if recipient.is_empty() {
            return Err(format!("line {line}: `recipient` must not be empty"));
        }

        let data = i_data
            .map(|i| fields[i].trim().to_string())
            .unwrap_or_default();

        let expiration = match i_expiration.map(|i| fields[i].trim()) {
            None | Some("") => 0,
            Some(raw) => raw.parse::<u64>().map_err(|_| {
                format!(
                    "line {line}: `expiration` must be a whole number of seconds, found `{raw}`"
                )
            })?,
        };

        let revocable = match i_revocable.map(|i| fields[i].trim()) {
            None | Some("") => false,
            Some(raw) => parse_bool(raw).ok_or_else(|| {
                format!("line {line}: `revocable` must be true or false, found `{raw}`")
            })?,
        };

        rows.push(BulkRow {
            line,
            schema_uid,
            recipient,
            data,
            expiration,
            revocable,
        });
    }

    if rows.is_empty() {
        return Err("CSV file has a header row but no attestation rows".to_string());
    }

    Ok(rows)
}

/// The column names a header may contain, for error messages.
fn supported_columns() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = REQUIRED_COLUMNS.to_vec();
    names.extend(OPTIONAL_COLUMNS.iter().map(|(c, _)| *c));
    names
}

/// Accepts the spellings an operator is likely to type in a spreadsheet.
fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" => Some(true),
        "false" | "f" | "no" | "n" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_file() {
        let rows = parse_bulk_csv(
            "schema_uid,recipient\n\
             aabb,GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF\n",
        )
        .unwrap();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].schema_uid, "aabb");
        assert_eq!(
            rows[0].recipient,
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        );
        assert_eq!(rows[0].data, "");
        assert_eq!(rows[0].expiration, 0);
        assert!(!rows[0].revocable);
    }

    #[test]
    fn honours_column_order_and_optional_defaults() {
        let rows = parse_bulk_csv(
            "recipient,revocable,schema_uid,expiration,data\n\
             GCRR,true,bbcc,1700000000,0xdeadbeef\n",
        )
        .unwrap();

        assert_eq!(rows[0].recipient, "GCRR");
        assert_eq!(rows[0].schema_uid, "bbcc");
        assert_eq!(rows[0].data, "0xdeadbeef");
        assert_eq!(rows[0].expiration, 1_700_000_000);
        assert!(rows[0].revocable);
    }

    #[test]
    fn column_names_are_case_insensitive_and_trimmed() {
        let rows = parse_bulk_csv(" Schema_UID , Recipient \nccdd , GCRR \n").unwrap();
        assert_eq!(rows[0].schema_uid, "ccdd");
        assert_eq!(rows[0].recipient, "GCRR");
    }

    #[test]
    fn parses_quoted_fields_containing_commas_and_newlines() {
        let rows = parse_bulk_csv(
            "schema_uid,recipient,data\n\
             \"aa,bb\",\"GCRR\",\"line1\nline2\"\n",
        )
        .unwrap();

        assert_eq!(rows[0].schema_uid, "aa,bb");
        assert_eq!(rows[0].data, "line1\nline2");
    }

    #[test]
    fn unescapes_doubled_quotes_inside_a_quoted_field() {
        let rows =
            parse_bulk_csv("schema_uid,recipient,data\ncc,\"GCRR\",\"say \"\"hi\"\"\"\n").unwrap();
        assert_eq!(rows[0].data, "say \"hi\"");
    }

    #[test]
    fn handles_both_line_ending_styles() {
        let crlf = parse_bulk_csv("schema_uid,recipient\r\naa,GCRR\r\nbb,GXYZ\r\n").unwrap();
        let lf = parse_bulk_csv("schema_uid,recipient\naa,GCRR\nbb,GXYZ\n").unwrap();
        assert_eq!(crlf, lf);
        assert_eq!(crlf.len(), 2);
    }

    #[test]
    fn tolerates_a_missing_trailing_newline() {
        let rows = parse_bulk_csv("schema_uid,recipient\naa,GCRR").unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn skips_blank_lines() {
        let rows =
            parse_bulk_csv("schema_uid,recipient\n\n aa , GCRR \n\n\n bb , GXYZ \n\n").unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn reports_the_source_line_of_each_row() {
        let rows = parse_bulk_csv(
            "schema_uid,recipient\n\
             \n\
             aa,GCRR\n\
             bb,GXYZ\n",
        )
        .unwrap();
        assert_eq!(rows[0].line, 3);
        assert_eq!(rows[1].line, 4);
    }

    #[test]
    fn rejects_a_missing_required_column() {
        let err = parse_bulk_csv("schema_uid\nabcd\n").unwrap_err();
        assert!(err.contains("missing required column `recipient`"), "{err}");
    }

    #[test]
    fn rejects_an_unknown_column() {
        let err = parse_bulk_csv("schema_uid,recipient,reciepient\nabcd,GCRR,GCRR\n").unwrap_err();
        assert!(err.contains("unknown column `reciepient`"), "{err}");
    }

    #[test]
    fn rejects_a_row_whose_field_count_disagrees_with_the_header() {
        let err = parse_bulk_csv("schema_uid,recipient\naa\n").unwrap_err();
        assert!(err.contains("expected 2 fields"), "{err}");
        assert!(err.contains("line 2"), "{err}");
    }

    #[test]
    fn rejects_an_unterminated_quote() {
        let err = parse_bulk_csv("schema_uid,recipient\n\"aa,GCRR\n").unwrap_err();
        assert!(err.contains("unterminated quoted field"), "{err}");
    }

    #[test]
    fn rejects_a_quote_inside_an_unquoted_field() {
        let err = parse_bulk_csv("schema_uid,recipient\nab\"cd,GCRR\n").unwrap_err();
        assert!(err.contains("unexpected `\"`"), "{err}");
    }

    #[test]
    fn rejects_a_non_numeric_expiration() {
        let err = parse_bulk_csv("schema_uid,recipient,expiration\naa,GCRR,soon\n").unwrap_err();
        assert!(err.contains("`expiration` must be a whole number"), "{err}");
    }

    #[test]
    fn rejects_a_non_boolean_revocable() {
        let err = parse_bulk_csv("schema_uid,recipient,revocable\naa,GCRR,maybe\n").unwrap_err();
        assert!(err.contains("`revocable` must be true or false"), "{err}");
    }

    #[test]
    fn rejects_empty_required_cells() {
        let err = parse_bulk_csv("schema_uid,recipient\n,GCRR\n").unwrap_err();
        assert!(err.contains("`schema_uid` must not be empty"), "{err}");

        let err = parse_bulk_csv("schema_uid,recipient\naa,\n").unwrap_err();
        assert!(err.contains("`recipient` must not be empty"), "{err}");
    }

    #[test]
    fn rejects_a_header_only_file() {
        let err = parse_bulk_csv("schema_uid,recipient\n").unwrap_err();
        assert!(err.contains("no attestation rows"), "{err}");
    }

    #[test]
    fn rejects_an_empty_file() {
        let err = parse_bulk_csv("").unwrap_err();
        assert!(err.contains("CSV file is empty"), "{err}");
    }

    #[test]
    fn rejects_more_rows_than_the_cap() {
        let mut csv = String::from("schema_uid,recipient\n");
        for _ in 0..=MAX_BULK_ROWS {
            csv.push_str("aa,GCRR\n");
        }
        let err = parse_bulk_csv(&csv).unwrap_err();
        assert!(err.contains("too many rows"), "{err}");
    }

    #[test]
    fn accepts_a_file_exactly_at_the_cap() {
        let mut csv = String::from("schema_uid,recipient\n");
        for _ in 0..MAX_BULK_ROWS {
            csv.push_str("aa,GCRR\n");
        }
        assert_eq!(parse_bulk_csv(&csv).unwrap().len(), MAX_BULK_ROWS);
    }

    #[test]
    fn parses_common_boolean_spellings() {
        let rows = parse_bulk_csv(
            "schema_uid,recipient,revocable\n\
             a,GCRR,yes\n\
             b,GCRR,1\n\
             c,GCRR,False\n\
             d,GCRR,no\n",
        )
        .unwrap();

        assert_eq!(
            rows.iter().map(|r| r.revocable).collect::<Vec<_>>(),
            vec![true, true, false, false]
        );
    }
}
