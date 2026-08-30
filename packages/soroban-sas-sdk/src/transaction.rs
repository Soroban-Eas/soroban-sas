//! Submits a transaction and, unless the caller opts out, polls until it
//! settles.
//!
//! [`SubmissionPolicy`] makes the wait tunable (issue #133): poll interval,
//! optional wall-clock deadline, a hard cap on polls, fixed or exponential
//! backoff, and a `mode` that either blocks until settlement or returns the
//! hash immediately for the caller to poll on its own schedule. The three
//! ways a blocking submission can end are distinct:
//!
//! * terminal ledger status (`SUCCESS`, `FAILED`, …) — `Ok(result)` with
//!   `result.status` naming it and `result.hash` populated;
//! * the deadline / poll cap elapsed while still `PENDING`/`NOT_FOUND` —
//!   `Err(SdkError::SettlementTimeout { .. })`;
//! * an RPC call failed — `Err` with that call's own `SdkError`.

use crate::errors::SdkError;
use crate::rpc::{GetTransactionResult, RpcClient};
use std::time::{Duration, Instant};

const SETTLING_STATUSES: [&str; 2] = ["NOT_FOUND", "PENDING"];

/// Default poll cadence and cap, preserved from before the policy existed.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
pub const DEFAULT_MAX_POLLS: u32 = 10;

/// Whether a submission blocks until the transaction settles or returns as
/// soon as the network has accepted it for inclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubmissionMode {
    /// Poll `getTransaction` until settlement, timeout, or RPC failure.
    #[default]
    Blocking,
    /// Return right after `sendTransaction`; `result.hash` carries the hash
    /// and `result.status` is the `sendTransaction` status (`PENDING`).
    Async,
}

/// How the delay between polls evolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backoff {
    /// Every wait is `poll_interval`.
    Fixed,
    /// Wait `poll_interval * factor^n`, capped at `max_interval`.
    Exponential { factor: u32, max_interval: Duration },
}

/// Tunables for how [`TransactionSubmitter`] waits for settlement.
#[derive(Debug, Clone, Copy)]
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
}

impl Default for SubmissionPolicy {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            max_polls: DEFAULT_MAX_POLLS,
            deadline: None,
            backoff: Backoff::Fixed,
            mode: SubmissionMode::Blocking,
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

    /// Polls `fetch` until the transaction leaves `NOT_FOUND`/`PENDING`
    /// (returned as `Ok`), the policy's poll cap or deadline is reached
    /// (`Err(SdkError::SettlementTimeout)`), or `fetch` itself errors
    /// (that `Err` is propagated unchanged).
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
        for poll in 0..policy.max_polls {
            let mut result = fetch()?;
            last_status.clone_from(&result.status);
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

        // Terminal failure is an Ok result the caller inspects, not an Err.
        let terminal = poll(&policy, &FakeClock::new(), || Ok(result("FAILED"))).unwrap();
        assert_eq!(terminal.status, "FAILED");

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
}
