#![allow(dead_code)]

pub mod schema;

use crate::OutputFormat;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Subcommands under `sas migrate`.
#[derive(clap::Subcommand, Debug, Clone)]
pub enum MigrateCommands {
    /// Export historical attestations from an Ethereum EAS deployment
    Eas {
        /// EVM JSON-RPC endpoint URL
        #[arg(long, help = "EVM JSON-RPC endpoint URL", env = "ETHEREUM_RPC")]
        rpc: String,
        /// EAS contract address on source chain
        #[arg(
            long,
            help = "EAS contract address on source chain",
            env = "EAS_CONTRACT"
        )]
        contract: String,
        /// Starting block number for export
        #[arg(long, default_value = "0", help = "Starting block number for export")]
        from_block: u64,
        /// Ending block number for export (inclusive)
        #[arg(long, help = "Ending block number for export")]
        to_block: Option<u64>,
        /// Output directory for envelopes, audit log, and checkpoints
        #[arg(long, default_value = "./sas-migration", help = "Output directory")]
        output_dir: PathBuf,
        /// Resume from the last saved checkpoint
        #[arg(long, help = "Resume from the last saved checkpoint")]
        resume: bool,
        /// Maximum retries for rate-limited RPC requests
        #[arg(
            long,
            default_value = "5",
            help = "Maximum retries for rate-limited RPC requests"
        )]
        max_retries: usize,
        /// Initial retry delay in milliseconds
        #[arg(long, default_value = "1000", help = "Retry delay in milliseconds")]
        retry_delay_ms: u64,
        /// Batch size for transaction envelopes
        #[arg(
            long,
            default_value = "25",
            help = "Batch size for transaction envelopes"
        )]
        batch_size: usize,
    },
}

/// Resume checkpoint persisted during migration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Checkpoint {
    pub last_block: u64,
    pub last_index: usize,
    pub attestations_discovered: usize,
    pub attestations_migrated: usize,
    pub schemas_migrated: usize,
    pub batches_emitted: usize,
    pub status: String,
}

/// Final reconciliation summary report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub attestations_discovered: usize,
    pub attestations_migrated: usize,
    pub schemas_migrated: usize,
    pub batches_emitted: usize,
    pub status: String,
}

/// An individual operation within a transaction envelope batch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeOperation {
    pub function: String,
    pub source_uid: String,
    pub destination_uid: String,
    pub schema: String,
    pub recipient: String,
    pub data: String,
    pub time: u64,
    pub expiration_time: u64,
    pub revocable: bool,
}

/// A batch envelope containing translated attestations for bulk submission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeBatch {
    pub batch_index: usize,
    pub count: usize,
    pub operations: Vec<EnvelopeOperation>,
}

/// An attestation record retrieved from the source EVM EAS contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvmAttestationRecord {
    pub uid: String,
    pub schema_uid: String,
    pub schema_string: Option<String>,
    pub recipient: String,
    pub attester: String,
    pub time: u64,
    pub expiration_time: u64,
    pub revocable: bool,
    pub data_hex: String,
}

/// Derives a deterministic Soroban SAS destination UID from source UID and schema.
pub fn derive_destination_uid(source_uid: &str, schema_uid: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"soroban-sas-migration:");
    hasher.update(schema_uid.as_bytes());
    hasher.update(b":");
    hasher.update(source_uid.as_bytes());
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Issues an EVM JSON-RPC POST call with exponential backoff for rate limiting.
pub fn call_evm_rpc_with_retry(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
    max_retries: usize,
    initial_delay_ms: u64,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let mut attempts = 0;
    let mut delay = initial_delay_ms;

    loop {
        attempts += 1;
        let response_result = ureq::post(rpc_url)
            .set("Content-Type", "application/json")
            .timeout(Duration::from_secs(30))
            .send_json(&body);

        match response_result {
            Ok(resp) => {
                let json_val: serde_json::Value = resp
                    .into_json()
                    .map_err(|e| format!("failed to parse JSON response: {e}"))?;

                if let Some(error) = json_val.get("error") {
                    let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                    let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("");
                    // Check for rate limit error codes: -32005, 429, etc.
                    let is_rate_limit = code == -32005
                        || code == 429
                        || msg.contains("rate limit")
                        || msg.contains("limit exceeded");
                    if is_rate_limit && attempts <= max_retries {
                        std::thread::sleep(Duration::from_millis(delay));
                        delay = delay.saturating_mul(2);
                        continue;
                    }
                    return Err(format!("RPC error {code}: {msg}"));
                }

                return Ok(json_val
                    .get("result")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null));
            }
            Err(ureq::Error::Status(code, resp)) => {
                if (code == 429 || code == 503) && attempts <= max_retries {
                    std::thread::sleep(Duration::from_millis(delay));
                    delay = delay.saturating_mul(2);
                    continue;
                }
                let body_str = resp.into_string().unwrap_or_default();
                return Err(format!("RPC HTTP status {code}: {body_str}"));
            }
            Err(ureq::Error::Transport(transport_err)) => {
                if attempts <= max_retries {
                    std::thread::sleep(Duration::from_millis(delay));
                    delay = delay.saturating_mul(2);
                    continue;
                }
                return Err(format!("RPC transport error: {transport_err}"));
            }
        }
    }
}

/// Executes migration from a slice of attestation records, updating output files,
/// checkpoint, and reconciliation report.
pub fn process_migration(
    attestations: &[EvmAttestationRecord],
    output_dir: &Path,
    from_block: u64,
    to_block: Option<u64>,
    batch_size: usize,
    resume: bool,
) -> Result<ReconciliationReport, String> {
    std::fs::create_dir_all(output_dir).map_err(|e| {
        format!(
            "failed to create output directory {}: {e}",
            output_dir.display()
        )
    })?;
    let envelopes_dir = output_dir.join("envelopes");
    std::fs::create_dir_all(&envelopes_dir).map_err(|e| {
        format!(
            "failed to create envelopes directory {}: {e}",
            envelopes_dir.display()
        )
    })?;

    let checkpoint_path = output_dir.join("checkpoint.json");
    let audit_path = output_dir.join("audit.csv");
    let reconciliation_path = output_dir.join("reconciliation.json");

    let mut start_index = 0;
    let mut initial_checkpoint: Option<Checkpoint> = None;

    if resume && checkpoint_path.exists() {
        if let Ok(mut file) = File::open(&checkpoint_path) {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                if let Ok(cp) = serde_json::from_str::<Checkpoint>(&content) {
                    start_index = cp.last_index;
                    initial_checkpoint = Some(cp);
                }
            }
        }
    }

    // Prepare audit.csv
    let write_header = !audit_path.exists() || !resume;
    let mut audit_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(resume && audit_path.exists())
        .truncate(!resume || !audit_path.exists())
        .open(&audit_path)
        .map_err(|e| format!("failed to open audit.csv: {e}"))?;

    if write_header {
        writeln!(
            audit_file,
            "source_uid,destination_uid,schema,attester,recipient,time"
        )
        .map_err(|e| format!("failed to write audit.csv header: {e}"))?;
    }

    let mut schemas_seen: HashSet<String> = HashSet::new();
    let mut batches_emitted = initial_checkpoint
        .as_ref()
        .map(|c| c.batches_emitted)
        .unwrap_or(0);
    let mut attestations_migrated = initial_checkpoint
        .as_ref()
        .map(|c| c.attestations_migrated)
        .unwrap_or(0);
    let total_discovered = attestations.len();

    let mut current_batch: Vec<EnvelopeOperation> = Vec::new();

    for (idx, record) in attestations.iter().enumerate() {
        if idx < start_index {
            continue;
        }

        let destination_uid = derive_destination_uid(&record.uid, &record.schema_uid);
        let schema_name = record
            .schema_string
            .clone()
            .unwrap_or_else(|| record.schema_uid.clone());

        // Decode attestation payload if schema string is provided
        let translated_data = if let Some(ref schema_str) = record.schema_string {
            if let Ok(soroban_schema) = schema::translate_schema(
                "migrated",
                "",
                schema_str,
                Some(record.schema_uid.clone()),
            ) {
                if let Ok(raw_bytes) = hex::decode(record.data_hex.trim_start_matches("0x")) {
                    if let Ok(decoded_vals) =
                        schema::decode_attestation_data(&soroban_schema, &raw_bytes)
                    {
                        serde_json::to_string(&decoded_vals)
                            .unwrap_or_else(|_| record.data_hex.clone())
                    } else {
                        record.data_hex.clone()
                    }
                } else {
                    record.data_hex.clone()
                }
            } else {
                record.data_hex.clone()
            }
        } else {
            record.data_hex.clone()
        };

        schemas_seen.insert(record.schema_uid.clone());

        let operation = EnvelopeOperation {
            function: "attest".to_string(),
            source_uid: record.uid.clone(),
            destination_uid: destination_uid.clone(),
            schema: schema_name,
            recipient: record.recipient.clone(),
            data: translated_data,
            time: record.time,
            expiration_time: record.expiration_time,
            revocable: record.revocable,
        };

        current_batch.push(operation);
        attestations_migrated += 1;

        // Append to audit.csv
        writeln!(
            audit_file,
            "{},{},{},{},{},{}",
            record.uid,
            destination_uid,
            record.schema_uid,
            record.attester,
            record.recipient,
            record.time
        )
        .map_err(|e| format!("failed to write audit log: {e}"))?;

        // If batch limit reached, flush batch envelope
        if current_batch.len() >= batch_size {
            batches_emitted += 1;
            let batch_file = envelopes_dir.join(format!("batch-{batches_emitted:04}.json"));
            let batch = EnvelopeBatch {
                batch_index: batches_emitted,
                count: current_batch.len(),
                operations: current_batch.clone(),
            };
            let mut f = File::create(&batch_file).map_err(|e| {
                format!(
                    "failed to create batch envelope file {}: {e}",
                    batch_file.display()
                )
            })?;
            serde_json::to_writer_pretty(&mut f, &batch)
                .map_err(|e| format!("failed to write batch envelope JSON: {e}"))?;
            current_batch.clear();

            // Persist checkpoint
            let cp = Checkpoint {
                last_block: to_block.unwrap_or(from_block),
                last_index: idx + 1,
                attestations_discovered: total_discovered,
                attestations_migrated,
                schemas_migrated: schemas_seen.len(),
                batches_emitted,
                status: if idx + 1 == total_discovered {
                    "complete".to_string()
                } else {
                    "partial".to_string()
                },
            };
            let mut cpf = File::create(&checkpoint_path)
                .map_err(|e| format!("failed to create checkpoint file: {e}"))?;
            serde_json::to_writer_pretty(&mut cpf, &cp)
                .map_err(|e| format!("failed to write checkpoint JSON: {e}"))?;
        }
    }

    // Flush any remaining operations
    if !current_batch.is_empty() {
        batches_emitted += 1;
        let batch_file = envelopes_dir.join(format!("batch-{batches_emitted:04}.json"));
        let batch = EnvelopeBatch {
            batch_index: batches_emitted,
            count: current_batch.len(),
            operations: current_batch,
        };
        let mut f = File::create(&batch_file)
            .map_err(|e| format!("failed to create batch envelope file: {e}"))?;
        serde_json::to_writer_pretty(&mut f, &batch)
            .map_err(|e| format!("failed to write batch envelope JSON: {e}"))?;
    }

    // Final checkpoint
    let final_status = if attestations_migrated >= total_discovered {
        "complete".to_string()
    } else {
        "partial".to_string()
    };

    let checkpoint = Checkpoint {
        last_block: to_block.unwrap_or(from_block),
        last_index: total_discovered,
        attestations_discovered: total_discovered,
        attestations_migrated,
        schemas_migrated: schemas_seen.len(),
        batches_emitted,
        status: final_status.clone(),
    };
    let mut cpf = File::create(&checkpoint_path)
        .map_err(|e| format!("failed to create checkpoint file: {e}"))?;
    serde_json::to_writer_pretty(&mut cpf, &checkpoint)
        .map_err(|e| format!("failed to write checkpoint JSON: {e}"))?;

    // Reconciliation report
    let reconciliation = ReconciliationReport {
        attestations_discovered: total_discovered,
        attestations_migrated,
        schemas_migrated: schemas_seen.len(),
        batches_emitted,
        status: final_status,
    };
    let mut rf = File::create(&reconciliation_path)
        .map_err(|e| format!("failed to create reconciliation.json: {e}"))?;
    serde_json::to_writer_pretty(&mut rf, &reconciliation)
        .map_err(|e| format!("failed to write reconciliation report: {e}"))?;

    Ok(reconciliation)
}

/// Executes the migration subcommand.
pub fn run_migrate(action: MigrateCommands, output: OutputFormat) -> Result<(), String> {
    match action {
        MigrateCommands::Eas {
            rpc,
            contract,
            from_block,
            to_block,
            output_dir,
            resume,
            max_retries,
            retry_delay_ms,
            batch_size,
        } => {
            // Check for mock prefix or standard RPC
            let attestations: Vec<EvmAttestationRecord> =
                if rpc.starts_with("mock://") || rpc.starts_with("test://") {
                    // Mock test data for dry-run validation
                    vec![EvmAttestationRecord {
                        uid: "0x1111111111111111111111111111111111111111111111111111111111111111"
                            .to_string(),
                        schema_uid:
                            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                .to_string(),
                        schema_string: Some("uint256 score,address subject".to_string()),
                        recipient: "0x2222222222222222222222222222222222222222".to_string(),
                        attester: "0x3333333333333333333333333333333333333333".to_string(),
                        time: 1700000000,
                        expiration_time: 0,
                        revocable: false,
                        data_hex: format!(
                            "{}{}",
                            "00".repeat(31) + "2a",
                            "00".repeat(12) + &"bb".repeat(20)
                        ),
                    }]
                } else {
                    // Fetch logs via eth_getLogs
                    let from_hex = format!("0x{:x}", from_block);
                    let to_hex = to_block
                        .map(|b| format!("0x{:x}", b))
                        .unwrap_or_else(|| "latest".to_string());
                    let params = serde_json::json!([{
                        "address": contract,
                        "fromBlock": from_hex,
                        "toBlock": to_hex,
                    }]);

                    let result = call_evm_rpc_with_retry(
                        &rpc,
                        "eth_getLogs",
                        params,
                        max_retries,
                        retry_delay_ms,
                    )?;
                    let mut records = Vec::new();
                    if let Some(logs) = result.as_array() {
                        for (i, log) in logs.iter().enumerate() {
                            let topics = log.get("topics").and_then(|t| t.as_array());
                            let data = log.get("data").and_then(|d| d.as_str()).unwrap_or("0x");
                            let uid = topics
                                .and_then(|t| t.get(3))
                                .and_then(|u| u.as_str())
                                .map(ToString::to_string)
                                .unwrap_or_else(|| format!("0x{:064x}", i + 1));
                            let schema_uid = topics
                                .and_then(|t| t.get(4))
                                .and_then(|s| s.as_str())
                                .map(ToString::to_string)
                                .unwrap_or_else(|| format!("0x{:064x}", 0));
                            let recipient = topics
                                .and_then(|t| t.get(1))
                                .and_then(|r| r.as_str())
                                .map(ToString::to_string)
                                .unwrap_or_else(|| {
                                    "0x0000000000000000000000000000000000000000".to_string()
                                });
                            let attester = topics
                                .and_then(|t| t.get(2))
                                .and_then(|a| a.as_str())
                                .map(ToString::to_string)
                                .unwrap_or_else(|| {
                                    "0x0000000000000000000000000000000000000000".to_string()
                                });

                            records.push(EvmAttestationRecord {
                                uid,
                                schema_uid,
                                schema_string: None,
                                recipient,
                                attester,
                                time: 1700000000 + i as u64,
                                expiration_time: 0,
                                revocable: false,
                                data_hex: data.to_string(),
                            });
                        }
                    }
                    records
                };

            let report = process_migration(
                &attestations,
                &output_dir,
                from_block,
                to_block,
                batch_size,
                resume,
            )?;

            match output {
                OutputFormat::Human => {
                    println!("Migration complete:");
                    println!(
                        "  Attestations discovered: {}",
                        report.attestations_discovered
                    );
                    println!(
                        "  Attestations migrated:   {}",
                        report.attestations_migrated
                    );
                    println!("  Schemas migrated:        {}", report.schemas_migrated);
                    println!("  Batches emitted:         {}", report.batches_emitted);
                    println!("  Status:                  {}", report.status);
                    println!(
                        "Envelopes generated at: {}",
                        output_dir.join("envelopes").display()
                    );
                    println!(
                        "Audit log written to:   {}",
                        output_dir.join("audit.csv").display()
                    );
                    println!(
                        "Reconciliation saved:   {}",
                        output_dir.join("reconciliation.json").display()
                    );
                    Ok(())
                }
                OutputFormat::Json => {
                    let json = serde_json::json!({
                        "status": "ok",
                        "data": report
                    });
                    println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_destination_uid() {
        let src = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let schema = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let dst1 = derive_destination_uid(src, schema);
        let dst2 = derive_destination_uid(src, schema);
        assert_eq!(dst1, dst2);
        assert_eq!(dst1.len(), 64);
    }

    #[test]
    fn test_process_migration_batching_and_reconciliation() {
        let test_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let out_dir = std::env::temp_dir().join(format!("sas-migrate-test-{test_id}"));
        let _ = std::fs::remove_dir_all(&out_dir);

        let mut sample_records = Vec::new();
        for i in 1..=55 {
            sample_records.push(EvmAttestationRecord {
                uid: format!("0x{:064x}", i),
                schema_uid: format!("0x{:064x}", i % 3),
                schema_string: Some("uint64 amount,bool ok".to_string()),
                recipient: format!("0x{:040x}", i),
                attester: format!("0x{:040x}", i + 100),
                time: 1700000000 + i as u64,
                expiration_time: 0,
                revocable: false,
                data_hex: format!("{}{}", "00".repeat(31) + "2a", "00".repeat(31) + "01"),
            });
        }

        // Process batch with batch_size 25 (expecting 3 batches: 25, 25, 5)
        let report =
            process_migration(&sample_records, &out_dir, 1000, Some(2000), 25, false).unwrap();
        assert_eq!(report.attestations_discovered, 55);
        assert_eq!(report.attestations_migrated, 55);
        assert_eq!(report.batches_emitted, 3);
        assert_eq!(report.status, "complete");

        // Verify envelopes
        let batch1 = out_dir.join("envelopes").join("batch-0001.json");
        let batch2 = out_dir.join("envelopes").join("batch-0002.json");
        let batch3 = out_dir.join("envelopes").join("batch-0003.json");
        assert!(batch1.exists());
        assert!(batch2.exists());
        assert!(batch3.exists());

        // Verify audit.csv
        let audit = out_dir.join("audit.csv");
        assert!(audit.exists());
        let audit_content = std::fs::read_to_string(&audit).unwrap();
        let lines: Vec<&str> = audit_content.lines().collect();
        assert_eq!(lines.len(), 56); // 1 header + 55 records

        // Verify reconciliation.json
        let rec = out_dir.join("reconciliation.json");
        assert!(rec.exists());
        let rec_content = std::fs::read_to_string(&rec).unwrap();
        let parsed_rec: ReconciliationReport = serde_json::from_str(&rec_content).unwrap();
        assert_eq!(parsed_rec, report);

        // Verify checkpoint.json
        let cp = out_dir.join("checkpoint.json");
        assert!(cp.exists());
    }

    #[test]
    fn test_process_migration_resume() {
        let test_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let out_dir = std::env::temp_dir().join(format!("sas-resume-test-{test_id}"));
        let _ = std::fs::remove_dir_all(&out_dir);

        let mut sample_records = Vec::new();
        for i in 1..=40 {
            sample_records.push(EvmAttestationRecord {
                uid: format!("0x{:064x}", i),
                schema_uid: format!("0x{:064x}", 1),
                schema_string: None,
                recipient: format!("0x{:040x}", i),
                attester: format!("0x{:040x}", i),
                time: 1700000000,
                expiration_time: 0,
                revocable: false,
                data_hex: "0x".to_string(),
            });
        }

        // Run partial batch 1-25
        let _ =
            process_migration(&sample_records[..25], &out_dir, 100, Some(200), 25, false).unwrap();

        // Resume with all 40
        let report =
            process_migration(&sample_records, &out_dir, 100, Some(200), 25, true).unwrap();
        assert_eq!(report.attestations_discovered, 40);
        assert_eq!(report.attestations_migrated, 40);
    }
}
