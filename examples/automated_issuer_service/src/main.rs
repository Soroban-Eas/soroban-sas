//! Multi-channel Soroban automated attestation issuer (#497).
//!
//! Each funded channel is an *independent authorized attester*. This
//! deliberately avoids the single-issuer delegated nonce high-water mark,
//! which cannot safely be advanced in parallel out of order.
//! Contract signing, sequence reservation and settlement use soroban-sas-sdk.
use soroban_sas_sdk::{
    account, attestation_builder::AttestationRequestBuilder, client::SASClient, limits,
    rpc::RpcClient, sequence::SequenceManager, signature,
};
use soroban_sdk::{
    xdr::{LedgerEntryData, ReadXdr},
    Bytes, Env,
};
use std::{
    collections::HashSet,
    env,
    sync::Arc,
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunMode {
    Single,
    Channels,
    Compare,
}

#[derive(Clone)]
struct Config {
    rpc_url: String,
    passphrase: String,
    contract_id: String,
    schema_uid: [u8; 32],
    recipient: String,
    jobs: usize,
    min_balance: i64,
    mode: RunMode,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let contract_id = required("SAS_CONTRACT_ID")?;
        let recipient = required("RECIPIENT")?;
        let passphrase = required("NETWORK_PASSPHRASE")?;
        let schema_uid = decode32(&required("SCHEMA_UID")?, "SCHEMA_UID")?;
        let jobs = env::var("JOBS")
            .unwrap_or_else(|_| "24".into())
            .parse::<usize>()
            .map_err(|_| "JOBS must be an integer".to_string())?;
        if jobs == 0 || jobs > 10_000 {
            return Err("JOBS must be between 1 and 10000".into());
        }
        let min_balance = env::var("MIN_CHANNEL_BALANCE_STROOPS")
            .unwrap_or_else(|_| "1000000".into())
            .parse::<i64>()
            .map_err(|_| "MIN_CHANNEL_BALANCE_STROOPS must be an integer".to_string())?;
        if min_balance < 0 {
            return Err("Minimum balance cannot be negative".into());
        }
        let mode = match env::var("MODE")
            .unwrap_or_else(|_| "compare".into())
            .as_str()
        {
            "single" => RunMode::Single,
            "channels" => RunMode::Channels,
            "compare" => RunMode::Compare,
            _ => return Err("MODE must be single, channels or compare".into()),
        };
        stellar_strkey::Contract::from_string(&contract_id)
            .map_err(|_| "SAS_CONTRACT_ID must be a valid C... strkey".to_string())?;
        let valid_recipient = stellar_strkey::ed25519::PublicKey::from_string(&recipient).is_ok()
            || stellar_strkey::Contract::from_string(&recipient).is_ok();
        if !valid_recipient {
            return Err("RECIPIENT must be a valid G... or C... strkey".into());
        }
        Ok(Self {
            rpc_url: env::var("RPC_URL")
                .unwrap_or_else(|_| "http://localhost:8000/soroban/rpc".into()),
            passphrase,
            contract_id,
            schema_uid,
            recipient,
            jobs,
            min_balance,
            mode,
        })
    }
}

fn required(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("Missing required variable: {name}"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(value)
}

fn decode32(hex_string: &str, label: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(hex_string.trim_start_matches("0x"))
        .map_err(|_| format!("{label} must be 32 hex-encoded bytes"))?;
    raw.try_into()
        .map_err(|_| format!("{label} must be exactly 32 bytes"))
}

#[derive(Clone)]
struct Channel {
    secret: [u8; 32],
    public: [u8; 32],
    address: String,
}

struct ChannelPool {
    channels: Vec<Channel>,
    sequences: Arc<SequenceManager>,
}

impl ChannelPool {
    fn from_env() -> Result<Self, String> {
        let value = required("CHANNEL_SEEDS_HEX")?;
        let mut channels = Vec::new();
        let mut seen = HashSet::new();
        for (index, item) in value.split(',').enumerate() {
            let secret = decode32(item.trim(), &format!("CHANNEL_SEEDS_HEX[{index}]"))?;
            let public = signature::derive_public_key(&secret);
            if !seen.insert(public) {
                return Err(
                    "A channel key was listed twice; each channel must have its own sequence"
                        .into(),
                );
            }
            channels.push(Channel {
                secret,
                public,
                address: stellar_strkey::ed25519::PublicKey(public).to_string(),
            });
        }
        if channels.is_empty() {
            return Err("Provide at least one funded channel seed".into());
        }
        Ok(Self {
            channels,
            sequences: SequenceManager::shared(),
        })
    }

    fn preflight(&mut self, rpc: &RpcClient, min_balance: i64) -> Result<(), String> {
        for channel in &mut self.channels {
            // An account with no ledger entry is not a funded channel.
            let seq = account::fetch_sequence_number(rpc, &channel.public)
                .map_err(|e| format!("{}: sequence lookup failed: {e}", channel.address))?;
            let balance = account_balance(rpc, &channel.address)?;
            if balance < min_balance {
                return Err(format!(
                    "{} has {} stroops (minimum required {}), fund it first",
                    channel.address, balance, min_balance
                ));
            }
            println!(
                "channel={} seq={} balance_stroops={}",
                channel.address, seq, balance
            );
        }
        Ok(())
    }
}

/// Reads the actual classic account ledger balance, not a simulated estimate.
fn account_balance(rpc: &RpcClient, address: &str) -> Result<i64, String> {
    let key = account::account_ledger_key_base64(address).map_err(|e| e.to_string())?;
    let response = rpc
        .get_ledger_entries(vec![key])
        .map_err(|e| format!("balance RPC failed: {e}"))?;
    let entry = response
        .entries
        .first()
        .ok_or("funded account ledger entry missing")?;
    let decoded =
        LedgerEntryData::from_xdr_base64(&entry.xdr, limits::default_rpc_response_limits())
            .map_err(|e| format!("invalid account ledger XDR: {e:?}"))?;
    match decoded {
        LedgerEntryData::Account(a) => Ok(a.balance),
        _ => Err("expected a Stellar classic account ledger entry".into()),
    }
}

/// No two workers ever submit from the same channel simultaneously.
/// Each channel gets its own ordered queue and independent source sequence.
fn work_partition(jobs: usize, channels: usize) -> Vec<Vec<usize>> {
    let mut partitions = vec![Vec::new(); channels];
    for job in 0..jobs {
        partitions[job % channels].push(job);
    }
    partitions
}

#[derive(Default)]
struct WorkerResult {
    successes: usize,
    failures: usize,
    errors: Vec<String>,
}

struct Metrics {
    mode: &'static str,
    successes: usize,
    failures: usize,
    seconds: f64,
}

impl Metrics {
    fn tps(&self) -> f64 {
        self.successes as f64 / self.seconds.max(0.000_001)
    }
    fn print(&self) {
        println!(
            "METRIC mode={} succeeded={} failed={} elapsed_seconds={:.3} throughput_tps={:.3}",
            self.mode,
            self.successes,
            self.failures,
            self.seconds,
            self.tps()
        );
    }
}

fn run_phase(
    config: Arc<Config>,
    channels: &[Channel],
    sequence: Arc<SequenceManager>,
    phase: &'static str,
    run_id: u128,
) -> Metrics {
    let partitions = work_partition(config.jobs, channels.len());
    let started = Instant::now();
    let mut handles = Vec::new();
    for (channel, tasks) in channels.iter().cloned().zip(partitions.into_iter()) {
        let config = Arc::clone(&config);
        let sequence = Arc::clone(&sequence);
        handles.push(thread::spawn(move || -> WorkerResult {
            let env = Env::default();
            let client = SASClient::new(config.contract_id.clone()).with_sequence_manager(sequence);
            let rpc = RpcClient::new(config.rpc_url.clone());
            let mut result = WorkerResult::default();
            for job in tasks {
                // Even in sequential-vs-parallel compare mode no two jobs can
                // share a content-addressed UID, preventing duplicate writes.
                let payload = format!("sas-channel-issuer:{run_id}:{phase}:{job}");
                let attestation = AttestationRequestBuilder::new()
                    .with_schema_uid(config.schema_uid)
                    .with_attester(&channel.address)
                    .with_recipient(&config.recipient)
                    .with_data(Bytes::from_slice(&env, payload.as_bytes()))
                    .with_revocable(true)
                    .build(&env);
                let attestation = match attestation {
                    Ok(a) => a,
                    Err(e) => {
                        result.failures += 1;
                        result.errors.push(format!("job={job} build failed: {e}"));
                        continue;
                    }
                };
                let uid = hex::encode(attestation.uid.0.to_array());
                match client.attest(&rpc, &config.passphrase, &channel.secret, attestation) {
                    Ok(tx) if tx.status == "SUCCESS" => {
                        result.successes += 1;
                        println!(
                            "submitted mode={phase} channel={} job={job} uid={uid} tx={}",
                            channel.address,
                            tx.hash.as_deref().unwrap_or("<unknown>")
                        );
                    }
                    Ok(tx) => {
                        // A PENDING result must never be counted as successful.
                        result.failures += 1;
                        result.errors.push(format!(
                            "job={job} uid={uid} status={} tx={:?}; reconcile before retrying",
                            tx.status, tx.hash,
                        ));
                    }
                    Err(e) => {
                        // The SDK's SequenceManager resyncs/retries bad-sequence
                        // submissions. A timeout may already be included; we do
                        // not blindly resend a potentially settled attestation.
                        result.failures += 1;
                        result.errors.push(format!(
                            "job={job} uid={uid} channel={} error={e}; check chain before retry",
                            channel.address,
                        ));
                    }
                }
            }
            result
        }));
    }
    let mut success = 0;
    let mut failed = 0;
    for h in handles {
        match h.join() {
            Ok(worker) => {
                success += worker.successes;
                failed += worker.failures;
                for error in worker.errors {
                    eprintln!("ERROR {error}");
                }
            }
            Err(_) => {
                failed += 1;
                eprintln!("ERROR channel worker panicked");
            }
        }
    }
    Metrics {
        mode: phase,
        successes: success,
        failures: failed,
        seconds: started.elapsed().as_secs_f64(),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("issuer: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Arc::new(Config::from_env()?);
    let mut pool = ChannelPool::from_env()?;
    let rpc = RpcClient::new(config.rpc_url.clone());
    pool.preflight(&rpc, config.min_balance)?;
    if config.mode != RunMode::Single && pool.channels.len() < 2 {
        return Err(
            "For channels/compare mode provide at least two distinct funded accounts".into(),
        );
    }
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system clock invalid: {e}"))?
        .as_nanos();
    match config.mode {
        RunMode::Single => {
            let m = run_phase(
                config.clone(),
                &pool.channels[..1],
                pool.sequences.clone(),
                "single",
                run_id,
            );
            m.print();
            if m.failures > 0 {
                return Err("one or more submissions failed".into());
            }
        }
        RunMode::Channels => {
            let m = run_phase(
                config.clone(),
                &pool.channels,
                pool.sequences.clone(),
                "channels",
                run_id,
            );
            m.print();
            if m.failures > 0 {
                return Err("one or more submissions failed".into());
            }
        }
        RunMode::Compare => {
            let single = run_phase(
                config.clone(),
                &pool.channels[..1],
                pool.sequences.clone(),
                "single",
                run_id,
            );
            single.print();
            let concurrent = run_phase(
                config.clone(),
                &pool.channels,
                pool.sequences.clone(),
                "channels",
                run_id,
            );
            concurrent.print();
            if single.successes > 0 {
                println!(
                    "METRIC relative_throughput={:.3}x",
                    concurrent.tps() / single.tps()
                );
            }
            if single.failures + concurrent.failures > 0 {
                return Err(
                    "not all submissions succeeded; do not claim throughput for failed workloads"
                        .into(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partitions_are_exhaustive_without_duplicate_jobs() {
        let p = work_partition(103, 7);
        let mut seen = HashSet::new();
        for q in p {
            for job in q {
                assert!(seen.insert(job));
            }
        }
        assert_eq!(seen.len(), 103);
    }
    #[test]
    fn rejects_bad_secret_lengths() {
        assert!(decode32("aa", "TEST").is_err());
        assert_eq!(decode32(&"00".repeat(32), "TEST").unwrap(), [0u8; 32]);
    }
    #[test]
    fn throughput_is_successful_transactions_not_attempts() {
        let m = Metrics {
            mode: "test",
            successes: 8,
            failures: 2,
            seconds: 2.0,
        };
        assert_eq!(m.tps(), 4.0);
    }
}
