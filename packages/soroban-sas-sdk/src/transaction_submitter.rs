#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors returned by the transaction submitter.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum SubmitError {
    #[error("transaction build error: {0}")]
    Build(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("RPC error (status {status}): {message}")]
    Rpc { status: u16, message: String },
    #[error("transaction failed: {0}")]
    TxFailed(String),
    #[error("fee cap exceeded: required {required} strops, cap {cap} strops")]
    FeeCapExceeded { required: i64, cap: i64 },
    #[error("max fee-bump attempts exhausted after {attempts} attempts")]
    MaxAttemptsExhausted { attempts: u32 },
    #[error("sequence number conflict for account {account}: expected {expected}, got {actual}")]
    SequenceConflict {
        account: String,
        expected: i64,
        actual: i64,
    },
    #[error("timed out waiting for confirmation after {ledgers} ledgers")]
    ConfirmationTimeout { ledgers: u32 },
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

/// RPC transport abstraction so the submitter can be tested and used with any node.
pub trait RpcClient: Send + Sync {
    fn submit_transaction(
        &self,
        envelope_xdr: &str,
    ) -> impl std::future::Future<Output = Result<SubmitResponse, SubmitError>> + Send;

    fn get_transaction_status(
        &self,
        hash: hex::Hash,
    ) -> impl std::future::Future<Output = Result<TransactionStatus, SubmitError>> + Send;

    fn get_latest_ledger(
        &self,
    ) -> impl std::future::Future<Output = Result<u32, SubmitError>> + Send;

    fn get_account_sequence(
        &self,
        account: &str,
    ) -> impl std::future::Future<Output = Result<i64, SubmitError>> + Send;
}

/// Result of a submit call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitResponse {
    /// Transaction was accepted into the mempool.
    Pending { hash: hex::Hash },
    /// Transaction was included in a ledger.
    Confirmed { hash: hex::Hash, ledger: u32 },
    /// Transaction was rejected with a result code.
    Rejected { code: String, message: String },
}

/// Status of a previously submitted transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Confirmed { ledger: u32 },
    NotFound,
    Failed { code: String },
}

/// Strategy for fee bumping a stuck transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeeBumpStrategy {
    /// Number of ledgers a transaction may remain pending before a fee bump.
    pub pending_ledger_threshold: u32,
    /// Multiplier applied to the previous fee each bump round.
    pub fee_bump_multiplier: f64,
    /// Absolute ceiling for the fee of any single envelope (strops).
    pub max_fee_strops: i64,
    /// Maximum number of fee bumps before giving up.
    pub max_attempts: u32,
    /// Base fee for the initial submission (strops).
    pub base_fee_strops: i64,
}

impl Default for FeeBumpStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl FeeBumpStrategy {
    pub fn new() -> Self {
        Self {
            pending_ledger_threshold: 5,
            fee_bump_multiplier: 2.0,
            max_fee_strops: 10_000_000,
            max_attempts: 5,
            base_fee_strops: 1000,
        }
    }

    pub fn validate(&self) -> Result<(), SubmitError> {
        if self.pending_ledger_threshold == 0 {
            return Err(SubmitError::InvalidConfig(
                "pending_ledger_threshold must be > 0".to_string(),
            ));
        }
        if self.fee_bump_multiplier <= 1.0 {
            return Err(SubmitError::InvalidConfig(
                "fee_bump_multiplier must be > 1.0".to_string(),
            ));
        }
        if self.max_fee_strops <= 0 {
            return Err(SubmitError::InvalidConfig(
                "max_fee_strops must be > 0".to_string(),
            ));
        }
        if self.max_attempts == 0 {
            return Err(SubmitError::InvalidConfig(
                "max_attempts must be > 0".to_string(),
            ));
        }
        if self.base_fee_strops <= 0 {
            return Err(SubmitError::InvalidConfig(
                "base_fee_strops must be > 0".to_string(),
            ));
        }
        Ok(())
    }

    /// Compute the fee for the next bump round, honoring the cap.
    pub fn next_fee(&self, current_fee: i64) -> Result<i64, SubmitError> {
        let multiplied = (current_fee as f64 * self.fee_bump_multiplier).ceil() as i64;
        let next = multiplied.max(current_fee + 1);
        if next > self.max_fee_strops {
            return Err(SubmitError::FeeCapExceeded {
                required: next,
                cap: self.max_fee_strops,
            });
        }
        Ok(next)
    }
}

/// Exponential backoff policy for RPC rate-limiting and timeouts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
    pub jitter_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryPolicy {
    pub fn new() -> Self {
        Self {
            max_retries: 5,
            base_delay_ms: 100,
            max_delay_ms: 10_000,
            backoff_multiplier: 2.0,
            jitter_ms: 50,
        }
    }

    /// Delay before the given retry attempt (0-based).
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let exponent = attempt.min(31);
        let factor = self.backoff_multiplier.powi(exponent as i32);
        let raw = (self.base_delay_ms as f64 * factor).min(self.max_delay_ms as f64);
        let jitter = if self.jitter_ms == 0 {
            0
        } else {
            (attempt as u64).wrapping_mul(2654435761) % self.jitter_ms
        };
        Duration::from_millis(raw as u64 + jitter)
    }

    /// Return true if the given RPC status is retryable.
    pub fn is_retryable_status(status: u16) -> bool {
        matches!(status, 429 | 504 | 503 | 502)
    }
}

/// A signed fee bump envelope produced by the submitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeBumpTransactionEnvelope {
    pub inner_tx_hash: hex::Hash,
    pub fee_strops: i64,
    pub fee_source: String,
    pub sequence_number: i64,
    pub envelope_xdr: String,
    pub envelope_hash: hex::Hash,
}

/// Signer abstraction for fee-bump envelopes.
pub trait FeeBumpSigner: Send + Sync {
    fn sign_fee_bump(
        &self,
        inner_tx_hash: &hex::Hash,
        fee_source: &str,
        fee_strops: i64,
        sequence_number: i64,
    ) -> Result<FeeBumpTransactionEnvelope, SubmitError>;
}

/// Tracks the lifecycle of a single submitted transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransaction {
    pub original_hash: hex::Hash,
    pub current_hash: hex::Hash,
    pub current_fee_strops: i64,
    pub submitted_at_ledger: u32,
    pub attempts: u32,
    pub sequence_number: i64,
    pub fee_source: String,
}

/// Submits transactions and automatically fee-bumps stuck ones.
pub struct TransactionSubmitter<C>
where
    C: RpcClient,
{
    client: Arc<C>,
    strategy: FeeBumpStrategy,
    retry_policy: RetryPolicy,
    signer: Arc<dyn FeeBumpSigner>,
    pending: HashMap<hex::Hash, PendingTransaction>,
}

impl<C> TransactionSubmitter<C>
where
    C: RpcClient + 'static,
{
    pub fn new(
        client: Arc<C>,
        strategy: FeeBumpStrategy,
        retry_policy: RetryPolicy,
        signer: Arc<dyn FeeBumpSigner>,
    ) -> Result<Self, SubmitError> {
        strategy.validate()?;
        Ok(Self {
            client,
            strategy,
            retry_policy,
            signer,
            pending: HashMap::new(),
        })
    }

    /// Submit an initial transaction envelope and track it for future fee bumps.
    pub async fn submit(
        &mut self,
        envelope_xdr: &str,
        fee_source: &str,
        sequence_number: i64,
        fee_strops: i64,
    ) -> Result<hex::Hash, SubmitError> {
        if fee_strops > self.strategy.max_fee_strops {
            return Err(SubmitError::FeeCapExceeded {
                required: fee_strops,
                cap: self.strategy.max_fee_strops,
            });
        }

        // Honor account sequence rules before submission.
        let on_chain_seq = self.client.get_account_sequence(fee_source).await?;
        if sequence_number != on_chain_seq + 1 {
            return Err(SubmitError::SequenceConflict {
                account: fee_source.to_string(),
                expected: on_chain_seq + 1,
                actual: sequence_number,
            });
        }

        let ledger = self.client.get_latest_ledger().await?;
        let resp = self.submit_with_retry(envelope_xdr, fee_strops).await?;
        match resp {
            SubmitResponse::Pending { hash } => {
                self.pending.insert(
                    hash,
                    PendingTransaction {
                        original_hash: hash,
                        current_hash: hash,
                        current_fee_strops: fee_strops,
                        submitted_at_ledger: ledger,
                        attempts: 0,
                        sequence_number,
                        fee_source: fee_source.to_string(),
                    },
                );
                Ok(hash)
            }
            SubmitResponse::Confirmed { hash, ledger: _ } => Ok(hash),
            SubmitResponse::Rejected { code, message } => {
                Err(SubmitError::TxFailed(format!("{}: {}", code, message)))
            }
        }
    }

    /// Check all pending transactions and fee-bump those that have been stuck for
    /// too many ledgers. Returns the list of new envelope hashes produced.
    pub async fn check_and_bump(&mut self) -> Result<Vec<hex::Hash>, SubmitError> {
        let latest = self.client.get_latest_ledger().await?;
        let mutations: Vec<hex::Hash> = self.pending.keys().copied().collect();
        let mut bumped = Vec::new();

        for hash in mutations {
            let status = self.client.get_transaction_status(hash).await?;
            match status {
                TransactionStatus::Confirmed { .. } | TransactionStatus::Failed { .. } => {
                    self.pending.remove(&hash);
                }
                TransactionStatus::NotFound | TransactionStatus::Pending => {
                    if let Some(new_hash) = self.maybe_bump(&hash, latest).await? {
                        bumped.push(new_hash);
                    }
                }
            }
        }

        Ok(bumped)
    }

    async fn maybe_bump(
        &mut self,
        hash: &hex::Hash,
        latest_ledger: u32,
    ) -> Result<Option<hex::Hash>, SubmitError> {
        let pending = match self.pending.get(hash) {
            Some(p) => p.clone(),
            None => return Ok(None),
        };

        let ledgers_pending = latest_ledger.saturating_sub(pending.submitted_at_ledger);
        if ledgers_pending < self.strategy.pending_ledger_threshold {
            return Ok(None);
        }

        if pending.attempts >= self.strategy.max_attempts {
            return Err(SubmitError::MaxAttemptsExhausted {
                attempts: pending.attempts,
            });
        }

        // Honor account sequence rules: the fee bump must not consume a new sequence
        // number on the fee source account beyond what is already pending.
        let on_chain_seq = self
            .client
            .get_account_sequence(&pending.fee_source)
            .await?;
        if pending.sequence_number != on_chain_seq + 1 {
            return Err(SubmitError::SequenceConflict {
                account: pending.fee_source.clone(),
                expected: on_chain_seq + 1,
                actual: pending.sequence_number,
            });
        }

        let next_fee = self.strategy.next_fee(pending.current_fee_strops)?;
        let envelope = self.signer.sign_fee_bump(
            &pending.current_hash,
            &pending.fee_source,
            next_fee,
            pending.sequence_number,
        )?;

        let resp = self
            .submit_with_retry(&envelope.envelope_xdr, next_fee)
            .await?;
        match resp {
            SubmitResponse::Pending { hash: new_hash } => {
                if let Some(p) = self.pending.get_mut(hash) {
                    p.current_hash = new_hash;
                    p.current_fee_strops = next_fee;
                    p.submitted_at_ledger = latest_ledger;
                    p.attempts += 1;
                }
                Ok(Some(new_hash))
            }
            SubmitResponse::Confirmed {
                hash: new_hash,
                ledger: _,
            } => {
                self.pending.remove(hash);
                Ok(Some(new_hash))
            }
            SubmitResponse::Rejected { code, message } => {
                Err(SubmitError::TxFailed(format!("{}: {}", code, message)))
            }
        }
    }

    async fn submit_with_retry(
        &self,
        envelope_xdr: &str,
        _fee_strops: i64,
    ) -> Result<SubmitResponse, SubmitError> {
        let mut attempt = 0u32;
        loop {
            match self.client.submit_transaction(envelope_xdr).await {
                Ok(resp) => return Ok(resp),
                Err(SubmitError::Rpc { status, .. })
                    if RetryPolicy::is_retryable_status(status)
                        && attempt < self.retry_policy.max_retries =>
                {
                    let delay = self.retry_policy.delay_for(attempt);
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                Err(SubmitError::Rpc { status, message }) => {
                    return Err(SubmitError::Rpc { status, message });
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Number of transactions currently being tracked.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Return the tracked state for a transaction hash, if present.
    pub fn pending(&self, hash: &hex::Hash) -> Option<&PendingTransaction> {
        self.pending.get(hash)
    }
}

pub mod hex {
    use serde::{Deserialize, Serialize};
    use std::fmt;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Hash([u8; 32]);

    impl Hash {
        pub fn from_bytes(bytes: [u8; 32]) -> Self {
            Hash(bytes)
        }

        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.0
        }
    }

    impl fmt::Display for Hash {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for b in self.0.iter() {
                write!(f, "{:02X}", b)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockClient {
        latest_ledger: Mutex<u32>,
        sequence: Mutex<i64>,
        statuses: Mutex<HashMap<hex::Hash, TransactionStatus>>,
        submit_results: Mutex<Vec<Result<SubmitResponse, SubmitError>>>,
        submit_calls: Mutex<u32>,
    }

    impl MockClient {
        fn new() -> Self {
            Self {
                latest_ledger: Mutex::new(100),
                sequence: Mutex::new(42),
                statuses: Mutex::new(HashMap::new()),
                submit_results: Mutex::new(Vec::new()),
                submit_calls: Mutex::new(0),
            }
        }

        fn push_submit(&self, res: Result<SubmitResponse, SubmitError>) {
            self.submit_results.lock().unwrap().push(res);
        }

        fn set_status(&self, hash: hex::Hash, status: TransactionStatus) {
            self.statuses.lock().unwrap().insert(hash, status);
        }

        fn set_latest_ledger(&self, ledger: u32) {
            *self.latest_ledger.lock().unwrap() = ledger;
        }
    }

    impl RpcClient for MockClient {
        async fn submit_transaction(
            &self,
            _envelope_xdr: &str,
        ) -> Result<SubmitResponse, SubmitError> {
            *self.submit_calls.lock().unwrap() += 1;
            let mut results = self.submit_results.lock().unwrap();
            if results.is_empty() {
                return Ok(SubmitResponse::Pending {
                    hash: hex::Hash::from_bytes([1; 32]),
                });
            }
            results.remove(0)
        }

        async fn get_transaction_status(
            &self,
            hash: hex::Hash,
        ) -> Result<TransactionStatus, SubmitError> {
            Ok(self
                .statuses
                .lock()
                .unwrap()
                .get(&hash)
                .cloned()
                .unwrap_or(TransactionStatus::Pending))
        }

        async fn get_latest_ledger(&self) -> Result<u32, SubmitError> {
            Ok(*self.latest_ledger.lock().unwrap())
        }

        async fn get_account_sequence(&self, _account: &str) -> Result<i64, SubmitError> {
            Ok(*self.sequence.lock().unwrap())
        }
    }

    struct MockSigner {
        next_hash: Mutex<u32>,
        fees: Mutex<Vec<i64>>,
    }

    impl MockSigner {
        fn new() -> Self {
            Self {
                next_hash: Mutex::new(2),
                fees: Mutex::new(Vec::new()),
            }
        }
    }

    impl FeeBumpSigner for MockSigner {
        fn sign_fee_bump(
            &self,
            inner_tx_hash: &hex::Hash,
            fee_source: &str,
            fee_strops: i64,
            sequence_number: i64,
        ) -> Result<FeeBumpTransactionEnvelope, SubmitError> {
            let mut n = self.next_hash.lock().unwrap();
            let bytes = [*n as u8; 32];
            *n += 1;
            self.fees.lock().unwrap().push(fee_strops);
            let hash = hex::Hash::from_bytes(bytes);
            Ok(FeeBumpTransactionEnvelope {
                inner_tx_hash: *inner_tx_hash,
                fee_strops,
                fee_source: fee_source.to_string(),
                sequence_number,
                envelope_xdr: format!("fee-bump-envelope-{}", hash),
                envelope_hash: hash,
            })
        }
    }

    fn build_submitter(
        client: Arc<MockClient>,
        signer: Arc<MockSigner>,
        strategy: FeeBumpStrategy,
    ) -> TransactionSubmitter<MockClient> {
        TransactionSubmitter::new(client, strategy, RetryPolicy::new(), signer).unwrap()
    }

    #[tokio::test]
    async fn submit_tracks_pending_transaction() {
        let client = Arc::new(MockClient::new());
        client.push_submit(Ok(SubmitResponse::Pending {
            hash: hex::Hash::from_bytes([1; 32]),
        }));
        let signer = Arc::new(MockSigner::new());
        let mut submitter = build_submitter(client.clone(), signer, FeeBumpStrategy::new());
        let hash = submitter.submit("envelope", "G", 43, 1000).await.unwrap();
        assert_eq!(hash, hex::Hash::from_bytes([1; 32]));
        assert_eq!(submitter.pending_count(), 1);
    }

    #[tokio::test]
    async fn stuck_transaction_gets_fee_bumped() {
        let client = Arc::new(MockClient::new());
        client.push_submit(Ok(SubmitResponse::Pending {
            hash: hex::Hash::from_bytes([1; 32]),
        }));
        client.push_submit(Ok(SubmitResponse::Pending {
            hash: hex::Hash::from_bytes([2; 32]),
        }));
        client.set_status(hex::Hash::from_bytes([1; 32]), TransactionStatus::Pending);
        let signer = Arc::new(MockSigner::new());
        let mut submitter = build_submitter(client.clone(), signer.clone(), FeeBumpStrategy::new());
        submitter.submit("envelope", "G", 43, 1000).await.unwrap();

        // Not yet stuck (102 - 100 = 2 < 5).
        client.set_latest_ledger(102);
        let bumped = submitter.check_and_bump().await.unwrap();
        assert!(bumped.is_empty());

        // Now stuck (105 - 100 = 5 >= 5).
        client.set_latest_ledger(105);
        let bumped = submitter.check_and_bump().await.unwrap();
        assert_eq!(bumped.len(), 1);
        assert_eq!(bumped[0], hex::Hash::from_bytes([2; 32]));
        let fees = signer.fees.lock().unwrap().clone();
        assert_eq!(fees, vec![2000]);
        let p = submitter.pending(&hex::Hash::from_bytes([1; 32])).unwrap();
        assert_eq!(p.attempts, 1);
        assert_eq!(p.current_fee_strops, 2000);
    }

    #[tokio::test]
    async fn fee_bump_respects_max_cap() {
        let client = Arc::new(MockClient::new());
        client.push_submit(Ok(SubmitResponse::Pending {
            hash: hex::Hash::from_bytes([1; 32]),
        }));
        client.set_status(hex::Hash::from_bytes([1; 32]), TransactionStatus::Pending);
        let signer = Arc::new(MockSigner::new());
        let mut strategy = FeeBumpStrategy::new();
        strategy.max_fee_strops = 1500;
        let mut submitter = build_submitter(client.clone(), signer, strategy);
        submitter.submit("envelope", "G", 43, 1000).await.unwrap();
        client.set_latest_ledger(105);
        let err = submitter.check_and_bump().await.unwrap_err();
        assert!(matches!(err, SubmitError::FeeCapExceeded { .. }));
    }

    #[tokio::test]
    async fn retries_on_429_and_succeeds() {
        let client = Arc::new(MockClient::new());
        client.push_submit(Err(SubmitError::Rpc {
            status: 429,
            message: "too many requests".to_string(),
        }));
        client.push_submit(Ok(SubmitResponse::Pending {
            hash: hex::Hash::from_bytes([1; 32]),
        }));
        let signer = Arc::new(MockSigner::new());
        let mut submitter = build_submitter(client.clone(), signer, FeeBumpStrategy::new());
        let hash = submitter.submit("envelope", "G", 43, 1000).await.unwrap();
        assert_eq!(hash, hex::Hash::from_bytes([1; 32]));
        assert_eq!(*client.submit_calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn retries_on_504_and_exhausts() {
        let client = Arc::new(MockClient::new());
        for _ in 0..6 {
            client.push_submit(Err(SubmitError::Rpc {
                status: 504,
                message: "gateway timeout".to_string(),
            }));
        }
        let signer = Arc::new(MockSigner::new());
        let mut submitter = build_submitter(client.clone(), signer, FeeBumpStrategy::new());
        let err = submitter
            .submit("envelope", "G", 43, 1000)
            .await
            .unwrap_err();
        assert!(matches!(err, SubmitError::Rpc { status: 504, .. }));
        assert_eq!(*client.submit_calls.lock().unwrap(), 6);
    }

    #[test]
    fn exponential_backoff_increases_and_caps() {
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay_ms: 100,
            max_delay_ms: 1000,
            backoff_multiplier: 2.0,
            jitter_ms: 0,
        };
        assert_eq!(policy.delay_for(0), Duration::from_millis(100));
        assert_eq!(policy.delay_for(1), Duration::from_millis(200));
        assert_eq!(policy.delay_for(2), Duration::from_millis(400));
        assert_eq!(policy.delay_for(10), Duration::from_millis(1000));
    }
}
