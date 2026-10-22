//! Submits a transaction and, unless the caller opts out, polls until it
//! settles.
//!
//! [`SubmissionPolicy`] makes the wait tunable (issue #133): poll interval,
//! optional wall-clock deadline, a hard cap on polls, fixed or exponential
//! backoff, and a `mode` that either blocks until settlement or returns the
//! hash immediately for the caller to poll on its own schedule. The three
//! ways a blocking submission can end are distinct:
//!
//! * terminal ledger status (`SUCCESS`) — `Ok(result)` with
//!   `result.status` naming it and `result.hash` populated;
//! * terminal failure status (`FAILED`) — `Err` with structured diagnostic
//!   data containing the result XDR and ledger context;
//! * the deadline / poll cap elapsed while still `PENDING`/`NOT_FOUND` —
//!   `Err(SdkError::SettlementTimeout { .. })`;
//! * an RPC call failed — `Err` with that call's own `SdkError`.

use crate::errors::SdkError;
use crate::rpc::{GetTransactionResult, RpcClient};
use serde::{Deserialize, Serialize};
use soroban_sdk::xdr::{
    LedgerFootprint, LedgerKey, Limits, ReadXdr, SorobanTransactionData, TransactionEnvelope,
    TransactionExt, WriteXdr,
};
use std::time::{Duration, Instant};

/// Configuration for padding footprints during auto-tuning.
/// Allows adding extra read-only and read-write keys for high-concurrency environments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FootprintPadding {
    pub additional_read_only: Vec<LedgerKey>,
    pub additional_read_write: Vec<LedgerKey>,
}

/// Options to customize automatic footprint tuning.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FootprintAutoTuneOptions {
    /// Manually override the entire ledger footprint instead of using simulation.
    pub footprint_override: Option<LedgerFootprint>,
    /// Pad the simulated footprint with additional keys.
    pub padding: Option<FootprintPadding>,
    /// Fee policy for calculating the resource fee.
    pub fee_policy: Option<crate::client::FeePolicy>,
}

const SETTLING_STATUSES: [&str; 2] = ["NOT_FOUND", "PENDING"];

/// Default poll cadence and cap, preserved from before the policy existed.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
pub const DEFAULT_MAX_POLLS: u32 = 10;

/// Whether a submission blocks until the transaction settles or returns as
/// soon as the network has accepted it for inclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionMode {
    /// Poll `getTransaction` until settlement, timeout, or RPC failure.
    #[default]
    Blocking,
    /// Return right after `sendTransaction`; `result.hash` carries the hash
    /// and `result.status` is the `sendTransaction` status (`PENDING`).
    Async,
}

/// How the delay between polls evolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backoff {
    /// Every wait is `poll_interval`.
    Fixed,
    /// Wait `poll_interval * factor^n`, capped at `max_interval`.
    Exponential { factor: u32, max_interval: Duration },
}

/// Tunables for how [`TransactionSubmitter`] waits for settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SubmissionPolicy {
    /// Delay before the first re-poll (and every poll under [`Backoff::Fixed`]).
    pub poll_interval: Duration,
    /// Hard cap on the number of `getTransaction` polls.
    pub max_polls: u32,
    /// Optional wall-clock ceiling measured from just after `sendTransaction`.
    /// Whichever of this and `max_polls` trips first ends the wait.
    pub deadline: Option<Duration>,
    /// Backoff schedule for the inter-poll delay.
    pub backoff: Backoff,
    /// Blocking vs. asynchronous submission.
    pub mode: SubmissionMode,
    /// Whether transient network/transport errors during polling should be retried
    /// until `max_polls` or `deadline` expires.
    #[serde(default)]
    pub retry_transport_errors: bool,
}

impl Default for SubmissionPolicy {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            max_polls: DEFAULT_MAX_POLLS,
            deadline: None,
            backoff: Backoff::Fixed,
            mode: SubmissionMode::Blocking,
            retry_transport_errors: false,
        }
    }
}

impl SubmissionPolicy {
    /// The historical behaviour: 10 polls, 2s apart, no deadline, blocking.
    pub fn blocking_default() -> Self {
        Self::default()
    }

    /// Return the hash immediately without polling.
    pub fn asynchronous() -> Self {
        Self {
            mode: SubmissionMode::Async,
            ..Self::default()
        }
    }

    /// Builder-style setter for the poll interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Builder-style setter for the poll cap.
    pub fn with_max_polls(mut self, max_polls: u32) -> Self {
        self.max_polls = max_polls;
        self
    }

    /// Builder-style setter for the wall-clock deadline.
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Builder-style setter for the backoff schedule.
    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// Builder-style setter for retrying on transient transport errors.
    pub fn with_retry_transport_errors(mut self, retry: bool) -> Self {
        self.retry_transport_errors = retry;
        self
    }

    fn delay_for(&self, poll_index: u32) -> Duration {
        match self.backoff {
            Backoff::Fixed => self.poll_interval,
            Backoff::Exponential {
                factor,
                max_interval,
            } => {
                let mut d = self.poll_interval;
                for _ in 0..poll_index {
                    d = d.saturating_mul(factor.max(1));
                    if d >= max_interval {
                        return max_interval;
                    }
                }
                d.min(max_interval)
            }
        }
    }
}

/// Injectable clock so settlement tests can drive time and sleeps
/// deterministically instead of really blocking a thread.
pub trait Clock {
    fn now(&self) -> Instant;
    fn sleep(&self, dur: Duration);
}

/// The real clock: `Instant::now` and `std::thread::sleep`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, dur: Duration) {
        std::thread::sleep(dur);
    }
}

pub struct TransactionSubmitter;

impl TransactionSubmitter {
    /// Back-compat entry point: send, then poll `max_attempts` times
    /// `poll_interval` apart with fixed backoff and no deadline.
    pub fn submit_with_retries(
        client: &RpcClient,
        tx_envelope_xdr: &str,
        max_attempts: u32,
        poll_interval: Duration,
    ) -> Result<GetTransactionResult, SdkError> {
        Self::submit_with_policy(
            client,
            tx_envelope_xdr,
            &SubmissionPolicy {
                poll_interval,
                max_polls: max_attempts,
                ..SubmissionPolicy::default()
            },
        )
    }

    /// Sends `tx_envelope_xdr` and then behaves per `policy`.
    pub fn submit_with_policy(
        client: &RpcClient,
        tx_envelope_xdr: &str,
        policy: &SubmissionPolicy,
    ) -> Result<GetTransactionResult, SdkError> {
        Self::submit_with_policy_using(client, tx_envelope_xdr, policy, &SystemClock)
    }

    /// As [`submit_with_policy`](Self::submit_with_policy) but with an
    /// explicit [`Clock`], so tests can simulate time and ledger progression.
    pub fn submit_with_policy_using(
        client: &RpcClient,
        tx_envelope_xdr: &str,
        policy: &SubmissionPolicy,
        clock: &dyn Clock,
    ) -> Result<GetTransactionResult, SdkError> {
        let sent = client.send_transaction(tx_envelope_xdr)?;

        if sent.status.eq_ignore_ascii_case("ERROR") {
            return Err(SdkError::SubmissionRejected {
                status: sent.status,
                error_result_xdr: sent.error_result_xdr,
            });
        }

        if sent.status.eq_ignore_ascii_case("FAILED") {
            return Err(SdkError::TransactionFailed {
                result_xdr: sent.error_result_xdr.unwrap_or_default(),
                last_ledger: sent.latest_ledger,
            });
        }

        if policy.mode == SubmissionMode::Async {
            return Ok(GetTransactionResult {
                status: sent.status,
                latest_ledger: sent.latest_ledger,
                envelope_xdr: None,
                result_xdr: None,
                hash: Some(sent.hash),
            });
        }

        let hash = sent.hash;
        let started = clock.now();
        Self::poll_until_settled(policy, clock, started, &hash, || {
            client.get_transaction(&hash)
        })
    }

    /// Automatically tunes the storage footprint and resource parameters of a transaction
    /// envelope using Soroban RPC simulation.
    ///
    /// Takes a transaction envelope XDR string, simulates it against `rpc`, parses the simulated
    /// `SorobanTransactionData`, applies any manual footprint overrides or padding, checks against
    /// impending network limits (>80% of block limit), attaches the tuned footprint to the transaction
    /// envelope, updates the transaction fee, and re-encodes the envelope into base64 XDR.
    ///
    /// Returns the tuned envelope XDR and the parsed `SorobanTransactionData`.
    pub fn auto_tune_footprint(
        rpc: &RpcClient,
        tx_envelope_xdr: &str,
        options: Option<FootprintAutoTuneOptions>,
    ) -> Result<(String, SorobanTransactionData), SdkError> {
        let sim = rpc.simulate_transaction(tx_envelope_xdr)?;
        if let Some(error) = sim.error {
            if let Some(code) = crate::errors::extract_contract_error_code(&error) {
                return Err(SdkError::ContractError(code));
            }
            return Err(SdkError::SimulationError(error));
        }

        if let Some(preamble) = sim.restore_preamble {
            return Err(SdkError::RestorationRequired {
                message: "archived footprint entry requires restoreFootprint".to_string(),
                min_resource_fee: Some(preamble.min_resource_fee),
                transaction_data: Some(preamble.transaction_data),
            });
        }

        let transaction_data_b64 = sim.transaction_data.ok_or_else(|| {
            SdkError::RpcError("simulation succeeded but returned no transactionData".to_string())
        })?;

        let mut soroban_data = SorobanTransactionData::from_xdr_base64(
            transaction_data_b64,
            crate::limits::default_rpc_response_limits(),
        )
        .map_err(|e| SdkError::DecodingError(format!("failed to decode transactionData: {e:?}")))?;

        let options = options.unwrap_or_default();

        // 1. Apply footprint override if requested
        if let Some(custom_footprint) = options.footprint_override {
            soroban_data.resources.footprint = custom_footprint;
        }

        // 2. Apply footprint padding if requested
        if let Some(padding) = options.padding {
            let mut ro: Vec<LedgerKey> = soroban_data.resources.footprint.read_only.to_vec();
            for key in padding.additional_read_only {
                if !ro.contains(&key) {
                    ro.push(key);
                }
            }
            let mut rw: Vec<LedgerKey> = soroban_data.resources.footprint.read_write.to_vec();
            for key in padding.additional_read_write {
                if !rw.contains(&key) {
                    rw.push(key);
                }
            }
            soroban_data.resources.footprint.read_only = ro.try_into().map_err(|e| {
                SdkError::ValidationError(format!("too many read_only footprint entries: {e:?}"))
            })?;
            soroban_data.resources.footprint.read_write = rw.try_into().map_err(|e| {
                SdkError::ValidationError(format!("too many read_write footprint entries: {e:?}"))
            })?;
        }

        // 3. Check for impending storage and resource limits (>80% threshold)
        let ro_count = soroban_data.resources.footprint.read_only.len() as u32;
        let rw_count = soroban_data.resources.footprint.read_write.len() as u32;
        let total_keys = ro_count + rw_count;

        if total_keys > 32 {
            eprintln!(
                "warning: impending storage footprint limit: total keys {} approaches limit 40 (>80%)",
                total_keys
            );
        }
        if rw_count > 20 {
            eprintln!(
                "warning: impending storage footprint limit: read-write keys {} approaches limit 25 (>80%)",
                rw_count
            );
        }
        if soroban_data.resources.read_bytes > 160_000 {
            eprintln!(
                "warning: impending read bytes limit: {} approaches limit 200,000 (>80%)",
                soroban_data.resources.read_bytes
            );
        }
        if soroban_data.resources.write_bytes > 104_000 {
            eprintln!(
                "warning: impending write bytes limit: {} approaches limit 130,000 (>80%)",
                soroban_data.resources.write_bytes
            );
        }
        if soroban_data.resources.instructions > 80_000_000 {
            eprintln!(
                "warning: impending CPU instructions limit: {} approaches limit 100,000,000 (>80%)",
                soroban_data.resources.instructions
            );
        }

        // 4. Decode the transaction envelope, attach the footprint and resource data, and update fee
        let mut envelope = TransactionEnvelope::from_xdr_base64(
            tx_envelope_xdr,
            crate::limits::default_rpc_response_limits(),
        )
        .map_err(|e| {
            SdkError::DecodingError(format!("failed to decode transaction envelope: {e:?}"))
        })?;

        let min_resource_fee: i64 = sim
            .min_resource_fee
            .as_deref()
            .unwrap_or("0")
            .parse()
            .map_err(|e| SdkError::RpcError(format!("invalid minResourceFee: {e:?}")))?;

        match &mut envelope {
            TransactionEnvelope::Tx(v1) => {
                let base_fee = v1.tx.fee;
                let policy = options
                    .fee_policy
                    .as_ref()
                    .unwrap_or(&crate::client::FeePolicy::Default);
                let computed_fee =
                    crate::client::apply_fee_policy(base_fee, min_resource_fee, policy)?;
                v1.tx.fee = computed_fee;
                v1.tx.ext = TransactionExt::V1(soroban_data.clone());
            }
            TransactionEnvelope::TxV0(_) => {
                return Err(SdkError::ValidationError(
                    "cannot attach Soroban resources to legacy TxV0 envelope".to_string(),
                ));
            }
            TransactionEnvelope::TxFeeBump(_) => {}
        }

        let tuned_envelope_xdr = envelope.to_xdr_base64(Limits::none()).map_err(|e| {
            SdkError::DecodingError(format!("failed to encode tuned transaction: {e:?}"))
        })?;

        Ok((tuned_envelope_xdr, soroban_data))
    }

    /// Polls `fetch` until the transaction leaves `NOT_FOUND`/`PENDING`
    /// (returned as `Ok`), the policy's poll cap or deadline is reached
    /// (`Err(SdkError::SettlementTimeout)`), or `fetch` itself errors
    /// (that `Err` is propagated unchanged). If the transaction settles
    /// with a `FAILED` status, returns `Err(SdkError::TransactionFailed)`
    /// containing the result XDR and ledger context.
    fn poll_until_settled<F>(
        policy: &SubmissionPolicy,
        clock: &dyn Clock,
        started: Instant,
        hash: &str,
        mut fetch: F,
    ) -> Result<GetTransactionResult, SdkError>
    where
        F: FnMut() -> Result<GetTransactionResult, SdkError>,
    {
        let mut last_status = String::from("NOT_FOUND");
        let mut last_transport_err = None;
        for poll in 0..policy.max_polls {
            let mut result = match fetch() {
                Ok(r) => {
                    last_transport_err = None;
                    r
                }
                Err(SdkError::TransportError(err)) if policy.retry_transport_errors => {
                    last_transport_err = Some(err);
                    if poll + 1 >= policy.max_polls {
                        break;
                    }
                    if let Some(deadline) = policy.deadline {
                        let elapsed = clock.now().duration_since(started);
                        if elapsed >= deadline {
                            break;
                        }
                        let wait = policy.delay_for(poll).min(deadline - elapsed);
                        clock.sleep(wait);
                    } else {
                        clock.sleep(policy.delay_for(poll));
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            last_status.clone_from(&result.status);
            if result.status.eq_ignore_ascii_case("FAILED") {
                return Err(SdkError::TransactionFailed {
                    result_xdr: result.result_xdr.unwrap_or_default(),
                    last_ledger: result.latest_ledger,
                });
            }
            if !SETTLING_STATUSES.contains(&result.status.as_str()) {
                result.hash = Some(hash.to_string());
                return Ok(result);
            }
            if poll + 1 >= policy.max_polls {
                break;
            }
            if let Some(deadline) = policy.deadline {
                let elapsed = clock.now().duration_since(started);
                if elapsed >= deadline {
                    break;
                }
                let wait = policy.delay_for(poll).min(deadline - elapsed);
                clock.sleep(wait);
            } else {
                clock.sleep(policy.delay_for(poll));
            }
        }
        if let Some(err) = last_transport_err {
            return Err(SdkError::TransportError(err));
        }
        Err(SdkError::SettlementTimeout {
            hash: hash.to_string(),
            last_status,
            polls: policy.max_polls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn result(status: &str) -> GetTransactionResult {
        GetTransactionResult {
            status: status.to_string(),
            latest_ledger: 1,
            envelope_xdr: None,
            result_xdr: None,
            hash: None,
        }
    }

    /// Test clock: `now` advances only when `sleep` is called, and every
    /// sleep is recorded so tests can assert the backoff schedule.
    struct FakeClock {
        start: Instant,
        elapsed: RefCell<Duration>,
        sleeps: RefCell<Vec<Duration>>,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                start: Instant::now(),
                elapsed: RefCell::new(Duration::ZERO),
                sleeps: RefCell::new(Vec::new()),
            }
        }
        fn sleeps(&self) -> Vec<Duration> {
            self.sleeps.borrow().clone()
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Instant {
            self.start + *self.elapsed.borrow()
        }
        fn sleep(&self, dur: Duration) {
            *self.elapsed.borrow_mut() += dur;
            self.sleeps.borrow_mut().push(dur);
        }
    }

    fn poll<F: FnMut() -> Result<GetTransactionResult, SdkError>>(
        policy: &SubmissionPolicy,
        clock: &dyn Clock,
        fetch: F,
    ) -> Result<GetTransactionResult, SdkError> {
        TransactionSubmitter::poll_until_settled(policy, clock, clock.now(), "abc123", fetch)
    }

    #[test]
    fn returns_immediately_once_settled_and_fills_in_the_hash() {
        let clock = FakeClock::new();
        let mut calls = 0;
        let outcome = poll(&SubmissionPolicy::default(), &clock, || {
            calls += 1;
            Ok(result("SUCCESS"))
        })
        .unwrap();

        assert_eq!(calls, 1);
        assert_eq!(outcome.status, "SUCCESS");
        assert_eq!(outcome.hash.as_deref(), Some("abc123"));
        assert!(clock.sleeps().is_empty());
    }

    #[test]
    fn keeps_polling_while_pending() {
        let clock = FakeClock::new();
        let mut calls = 0;
        let outcome = poll(&SubmissionPolicy::default(), &clock, || {
            calls += 1;
            Ok(if calls < 3 {
                result("PENDING")
            } else {
                result("SUCCESS")
            })
        })
        .unwrap();

        assert_eq!(calls, 3);
        assert_eq!(outcome.status, "SUCCESS");
        assert_eq!(
            clock.sleeps(),
            vec![DEFAULT_POLL_INTERVAL, DEFAULT_POLL_INTERVAL]
        );
    }

    #[test]
    fn timeout_is_distinct_from_rpc_and_terminal_failure() {
        let clock = FakeClock::new();
        let policy = SubmissionPolicy::default().with_max_polls(3);
        let err = poll(&policy, &clock, || Ok(result("NOT_FOUND"))).unwrap_err();
        match err {
            SdkError::SettlementTimeout {
                hash,
                last_status,
                polls,
            } => {
                assert_eq!(hash, "abc123");
                assert_eq!(last_status, "NOT_FOUND");
                assert_eq!(polls, 3);
            }
            other => panic!("expected SettlementTimeout, got {other:?}"),
        }

        // A settled FAILED status is a hard error, not an Ok result the
        // caller has to remember to inspect.
        let terminal_err = poll(&policy, &FakeClock::new(), || Ok(result("FAILED"))).unwrap_err();
        assert!(matches!(terminal_err, SdkError::TransactionFailed { .. }));

        // An RPC failure propagates as its own error kind.
        let rpc_err = poll(&policy, &FakeClock::new(), || {
            Err(SdkError::RpcError("boom".into()))
        })
        .unwrap_err();
        assert!(matches!(rpc_err, SdkError::RpcError(_)));
    }

    #[test]
    fn deadline_ends_the_wait_before_the_poll_cap() {
        let clock = FakeClock::new();
        let policy = SubmissionPolicy::default()
            .with_max_polls(100)
            .with_poll_interval(Duration::from_secs(2))
            .with_deadline(Duration::from_secs(5));

        let err = poll(&policy, &clock, || Ok(result("PENDING"))).unwrap_err();
        assert!(matches!(err, SdkError::SettlementTimeout { .. }));
        // 2s + 2s + 1s (clamped to the deadline) — never overshoots.
        let total: Duration = clock.sleeps().iter().sum();
        assert!(
            total <= Duration::from_secs(5),
            "slept {total:?}, past the deadline"
        );
    }

    #[test]
    fn exponential_backoff_grows_then_caps() {
        let clock = FakeClock::new();
        let policy = SubmissionPolicy::default()
            .with_max_polls(6)
            .with_poll_interval(Duration::from_millis(100))
            .with_backoff(Backoff::Exponential {
                factor: 2,
                max_interval: Duration::from_millis(500),
            });
        let _ = poll(&policy, &clock, || Ok(result("PENDING")));
        assert_eq!(
            clock.sleeps(),
            vec![
                Duration::from_millis(100),
                Duration::from_millis(200),
                Duration::from_millis(400),
                Duration::from_millis(500),
                Duration::from_millis(500),
            ]
        );
    }

    #[test]
    fn propagates_rpc_errors_immediately() {
        let clock = FakeClock::new();
        let mut calls = 0;
        let outcome = poll(&SubmissionPolicy::default(), &clock, || {
            calls += 1;
            Err(SdkError::RpcError("boom".to_string()))
        });

        assert_eq!(calls, 1);
        assert!(matches!(outcome, Err(SdkError::RpcError(_))));
    }

    use soroban_sdk::xdr::{
        AccountId, ExtensionPoint, LedgerKeyAccount, Memo, MuxedAccount, Preconditions, PublicKey,
        SequenceNumber, SorobanResources, Transaction, TransactionV1Envelope, Uint256, VecM,
    };
    use std::io::{BufRead, BufReader, Read, Write};

    fn sample_envelope_xdr() -> String {
        TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: Transaction {
                source_account: MuxedAccount::Ed25519(Uint256([1u8; 32])),
                fee: 100,
                seq_num: SequenceNumber(1),
                cond: Preconditions::None,
                memo: Memo::None,
                operations: VecM::default(),
                ext: TransactionExt::V0,
            },
            signatures: VecM::default(),
        })
        .to_xdr_base64(Limits::none())
        .unwrap()
    }

    fn sample_account_key(id: u8) -> LedgerKey {
        LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([id; 32]))),
        })
    }

    fn spawn_mock_rpc(response_body: String) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut content_length = 0usize;
                let mut line = String::new();
                while let Ok(n) = reader.read_line(&mut line) {
                    if n == 0 || line == "\r\n" {
                        break;
                    }
                    if line.to_lowercase().starts_with("content-length:") {
                        if let Some(val) = line.split(':').nth(1) {
                            content_length = val.trim().parse().unwrap_or(0);
                        }
                    }
                    line.clear();
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let mut writer = stream;
                let _ = writer.write_all(response.as_bytes());
            }
        });
        url
    }

    #[test]
    fn auto_tune_footprint_attaches_simulated_resources_and_footprint() {
        let key1 = sample_account_key(1);
        let key2 = sample_account_key(2);
        let tx_data = SorobanTransactionData {
            ext: ExtensionPoint::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![key1.clone()].try_into().unwrap(),
                    read_write: vec![key2.clone()].try_into().unwrap(),
                },
                instructions: 1_500_000,
                read_bytes: 5_000,
                write_bytes: 2_000,
            },
            resource_fee: 1_200,
        };
        let tx_data_b64 = tx_data.to_xdr_base64(Limits::none()).unwrap();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": 1234,
                "transactionData": tx_data_b64,
                "minResourceFee": "1200",
                "results": []
            }
        })
        .to_string();

        let url = spawn_mock_rpc(response);
        let rpc = RpcClient::new(url);
        let draft_xdr = sample_envelope_xdr();

        let (tuned_xdr, data) =
            TransactionSubmitter::auto_tune_footprint(&rpc, &draft_xdr, None).unwrap();
        assert_eq!(data.resources.instructions, 1_500_000);
        assert_eq!(data.resources.footprint.read_only.len(), 1);
        assert_eq!(data.resources.footprint.read_write.len(), 1);

        let env = TransactionEnvelope::from_xdr_base64(&tuned_xdr, Limits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = env else {
            panic!("expected V1 transaction envelope");
        };
        assert_eq!(v1.tx.fee, 1300); // 100 base + 1200 resource fee
        match v1.tx.ext {
            TransactionExt::V1(ext) => {
                assert_eq!(ext.resources.instructions, 1_500_000);
                assert_eq!(ext.resources.footprint.read_only.first().unwrap(), &key1);
                assert_eq!(ext.resources.footprint.read_write.first().unwrap(), &key2);
            }
            _ => panic!("expected TransactionExt::V1"),
        }
    }

    #[test]
    fn auto_tune_footprint_applies_padding_and_override() {
        let key1 = sample_account_key(1);
        let key2 = sample_account_key(2);
        let pad_ro = sample_account_key(3);
        let pad_rw = sample_account_key(4);

        let tx_data = SorobanTransactionData {
            ext: ExtensionPoint::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: vec![key1].try_into().unwrap(),
                    read_write: vec![key2].try_into().unwrap(),
                },
                instructions: 1_000_000,
                read_bytes: 4_000,
                write_bytes: 1_500,
            },
            resource_fee: 500,
        };
        let tx_data_b64 = tx_data.to_xdr_base64(Limits::none()).unwrap();

        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": 1234,
                "transactionData": tx_data_b64,
                "minResourceFee": "500",
                "results": []
            }
        })
        .to_string();

        let url = spawn_mock_rpc(response);
        let rpc = RpcClient::new(url);
        let draft_xdr = sample_envelope_xdr();

        let options = FootprintAutoTuneOptions {
            footprint_override: None,
            padding: Some(FootprintPadding {
                additional_read_only: vec![pad_ro.clone()],
                additional_read_write: vec![pad_rw.clone()],
            }),
            fee_policy: None,
        };

        let (_tuned_xdr, data) =
            TransactionSubmitter::auto_tune_footprint(&rpc, &draft_xdr, Some(options)).unwrap();
        assert_eq!(data.resources.footprint.read_only.len(), 2);
        assert_eq!(data.resources.footprint.read_write.len(), 2);
        assert!(data.resources.footprint.read_only.contains(&pad_ro));
        assert!(data.resources.footprint.read_write.contains(&pad_rw));
    }

    #[test]
    fn auto_tune_footprint_surfaces_contract_error() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": 1234,
                "error": "HostError: Error(301, Unauthorized)"
            }
        })
        .to_string();

        let url = spawn_mock_rpc(response);
        let rpc = RpcClient::new(url);
        let draft_xdr = sample_envelope_xdr();

        let err = TransactionSubmitter::auto_tune_footprint(&rpc, &draft_xdr, None).unwrap_err();
        match err {
            SdkError::ContractError(code) => assert_eq!(code, 301),
            other => panic!("expected ContractError(301), got {other:?}"),
        }
    }

    #[test]
    fn auto_tune_footprint_surfaces_restoration_required() {
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "latestLedger": 1234,
                "restorePreamble": {
                    "transactionData": "AAAA",
                    "minResourceFee": "7500"
                }
            }
        })
        .to_string();

        let url = spawn_mock_rpc(response);
        let rpc = RpcClient::new(url);
        let draft_xdr = sample_envelope_xdr();

        let err = TransactionSubmitter::auto_tune_footprint(&rpc, &draft_xdr, None).unwrap_err();
        match err {
            SdkError::RestorationRequired {
                min_resource_fee, ..
            } => assert_eq!(min_resource_fee.as_deref(), Some("7500")),
            other => panic!("expected RestorationRequired, got {other:?}"),
        }
    }
}
