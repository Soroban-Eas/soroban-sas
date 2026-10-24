#![allow(dead_code)]

use serde_json::Value;
use std::time::Duration;

/// Error classification for RPC failures that determine whether a retry is worthwhile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcErrorKind {
    /// HTTP 429 - the node is rate-limiting us.
    RateLimited,
    /// HTTP 504 - the node is temporarily unavailable.
    GatewayTimeout,
    /// Network transport failure (connection reset, DNS, etc.).
    Transport,
    /// Any other error; not retried.
    Other,
}

impl RpcErrorKind {
    /// Maps an HTTP status code to a retry classification.
    pub fn from_status(status: u16) -> Self {
        match status {
            429 => RpcErrorKind::RateLimited,
            504 => RpcErrorKind::GatewayTimeout,
            _ => RpcErrorKind::Other,
        }
    }

    /// Returns true if this error should be retried with backoff.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            RpcErrorKind::RateLimited | RpcErrorKind::GatewayTimeout | RpcErrorKind::Transport
        )
    }
}

/// Exponential backoff policy for RPC retries.
///
/// Delays grow as `base_delay * multiplier^attempt`, capped at `max_delay`.
/// A small amount of deterministic jitter is added to avoid thundering herds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExponentialBackoff {
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: u32,
    pub max_attempts: u32,
    pub jitter_millis: u64,
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(30),
            multiplier: 2,
            max_attempts: 6,
            jitter_millis: 50,
        }
    }
}

impl ExponentialBackoff {
    /// Computes the delay before the given attempt (0-indexed).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let exponent = attempt.min(32);
        let factor = self.multiplier.saturating_pow(exponent) as u64;
        let raw_millis = self.base_delay.as_millis().saturating_mul(factor as u128);
        let jitter = if self.jitter_millis == 0 {
            0
        } else {
            (attempt as u64) % self.jitter_millis
        };
        let millis = raw_millis.saturating_add(jitter as u128);
        let bounded_millis = millis.min(self.max_delay.as_millis()) as u64;
        Duration::from_millis(bounded_millis)
    }

    /// Returns true if another attempt is allowed after `attempt` failures.
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }
}

/// Retry policy that combines error classification with exponential backoff.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RetryPolicy {
    pub backoff: ExponentialBackoff,
}

impl RetryPolicy {
    /// Decides whether to retry given the attempt index and the error kind.
    pub fn should_retry(&self, attempt: u32, kind: RpcErrorKind) -> bool {
        kind.is_retryable() && self.backoff.should_retry(attempt)
    }

    /// Returns the delay to wait before the next attempt.
    pub fn delay_for(&self, attempt: u32) -> Duration {
        self.backoff.delay_for_attempt(attempt)
    }

    /// Executes an async operation with exponential backoff on retryable failures.
    pub async fn execute_async<T, F, Fut>(&self, mut attempt_fn: F) -> Result<T, RpcErrorKind>
    where
        F: FnMut(u32) -> Fut,
        Fut: std::future::Future<Output = Result<T, RpcErrorKind>>,
    {
        let mut attempt: u32 = 0;
        loop {
            match attempt_fn(attempt).await {
                Ok(value) => return Ok(value),
                Err(kind) => {
                    if !self.should_retry(attempt, kind.clone()) {
                        return Err(kind);
                    }
                    tokio::time::sleep(self.delay_for(attempt)).await;
                    attempt += 1;
                }
            }
        }
    }
}

/// Extracts an RPC status code from a JSON-RPC error payload, if present.
pub fn classify_rpc_payload(payload: &Value) -> RpcErrorKind {
    if let Some(code) = payload
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64)
    {
        match code {
            -32033 => RpcErrorKind::RateLimited,
            -32000 => RpcErrorKind::GatewayTimeout,
            _ => RpcErrorKind::Other,
        }
    } else {
        RpcErrorKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[derive(Debug)]
    struct FakeRng {
        seed: u64,
    }

    impl FakeRng {
        fn new(seed: u64) -> Self {
            Self { seed }
        }

        fn next(&mut self) -> u64 {
            self.seed = self.seed.wrapping_mul(6364132237202944751).wrapping_add(1);
            self.seed
        }
    }

    #[test]
    fn rate_limited_and_timeout_are_retryable() {
        assert!(RpcErrorKind::from_status(429).is_retryable());
        assert!(RpcErrorKind::from_status(504).is_retryable());
        assert!(!RpcErrorKind::from_status(400).is_retryable());
    }

    #[test]
    fn backoff_grows_exponentially_and_caps_at_max() {
        let policy = ExponentialBackoff {
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
            multiplier: 2,
            max_attempts: 10,
            jitter_millis: 0,
        };
        assert_eq!(policy.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(policy.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(policy.delay_for_attempt(2), Duration::from_millis(400));
        // Capped at max_delay.
        assert_eq!(policy.delay_for_attempt(5), Duration::from_millis(500));
    }

    #[test]
    fn backoff_stops_after_max_attempts() {
        let policy = ExponentialBackoff {
            max_attempts: 3,
            ..ExponentialBackoff::default()
        };
        assert!(policy.should_retry(0));
        assert!(policy.should_retry(2));
        assert!(!policy.should_retry(3));
    }

    #[test]
    fn jitter_is_deterministic_and_bounded() {
        let policy = ExponentialBackoff {
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_secs(1),
            multiplier: 2,
            max_attempts: 10,
            jitter_millis: 7,
        };
        for attempt in 0..10 {
            let delay = policy.delay_for_attempt(attempt);
            assert!(delay <= policy.max_delay);
            assert_eq!(delay, policy.delay_for_attempt(attempt));
        }
    }

    #[test]
    fn retry_policy_respects_error_kind() {
        let policy = RetryPolicy::default();
        assert!(policy.should_retry(0, RpcErrorKind::RateLimited));
        assert!(policy.should_retry(0, RpcErrorKind::GatewayTimeout));
        assert!(!policy.should_retry(0, RpcErrorKind::Other));
    }

    #[test]
    fn classify_rpc_payload_maps_codes() {
        let rate_limited =
            serde_json::json!({ "error": { "code": -32033, "message": "rate limit" } });
        assert_eq!(
            classify_rpc_payload(&rate_limited),
            RpcErrorKind::RateLimited
        );
        let timeout = serde_json::json!({ "error": { "code": -32000, "message": "timeout" } });
        assert_eq!(classify_rpc_payload(&timeout), RpcErrorKind::GatewayTimeout);
        let other = serde_json::json!({ "error": { "code": -32602, "message": "bad request" } });
        assert_eq!(classify_rpc_payload(&other), RpcErrorKind::Other);
    }

    #[tokio::test]
    async fn execute_async_retries_until_success() {
        let policy = RetryPolicy {
            backoff: ExponentialBackoff {
                base_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(4),
                multiplier: 2,
                max_attempts: 5,
                jitter_millis: 0,
            },
        };
        let mut rng = FakeRng::new(42);
        let result = policy
            .execute_async(|attempt| {
                let fail = rng.next() % 3 != 0;
                async move {
                    if fail {
                        Err(RpcErrorKind::RateLimited)
                    } else {
                        Ok(attempt)
                    }
                }
            })
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn execute_async_stops_on_non_retryable() {
        let policy = RetryPolicy::default();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let result: Result<(), RpcErrorKind> = policy
            .execute_async(|_attempt| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { Err(RpcErrorKind::Other) }
            })
            .await;
        assert_eq!(result, Err(RpcErrorKind::Other));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
