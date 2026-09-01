//! Concurrency-safe account sequence numbers for SDK writes (issue #132).
//!
//! Every submittable transaction from an account must carry
//! `account_sequence + 1`, and each successful submission bumps the
//! account's sequence by one. When several writes for the same source
//! account are built concurrently, each one independently fetches the
//! current sequence and adds one — so they all pick the *same* number and
//! all but one submission fails with `txBadSeq`, even though every
//! simulation succeeded.
//!
//! [`SequenceManager`] serialises sequence allocation for an account behind
//! a mutex and hands out a distinct, monotonically increasing number to
//! each caller. After a submission failure it can be resynchronised against
//! the network so a gap (from a dropped transaction) doesn't wedge the
//! account permanently.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::account;
use crate::errors::SdkError;
use crate::rpc::RpcClient;

/// Hands out per-account transaction sequence numbers that are unique even
/// across threads. Cheap to clone (`Arc` inside); share one instance
/// between every client/task that writes from the same account.
#[derive(Clone, Default)]
pub struct SequenceManager {
    /// Last sequence number handed out per account public key. The *next*
    /// transaction for that account uses this value; the entry is absent
    /// until the first reservation fetches the on-chain sequence.
    reserved: Arc<Mutex<HashMap<[u8; 32], i64>>>,
}

/// A reserved sequence number plus the hook to tell the manager how the
/// submission that used it turned out. Dropping it without calling
/// [`SequenceReservation::committed`] or [`SequenceReservation::failed`]
/// leaves the reservation as-is (treated as consumed).
#[must_use = "report the submission outcome via .committed() or .failed()"]
pub struct SequenceReservation {
    manager: SequenceManager,
    public_key: [u8; 32],
    sequence: i64,
}

impl SequenceReservation {
    /// The reserved sequence number to put in the transaction.
    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    /// The submission that used this sequence was accepted by the network.
    /// Nothing to do — the manager already advanced past it — but calling
    /// this documents intent and consumes the reservation.
    pub fn committed(self) {}

    /// The submission failed. Drop the cached sequence for this account so
    /// the next reservation re-reads it from the network, healing any gap a
    /// dropped transaction left behind.
    pub fn failed(self) {
        self.manager.resync(&self.public_key);
    }
}

impl SequenceManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wraps a fresh manager in an `Arc` for sharing.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Reserves the next sequence number for `public_key`'s account.
    ///
    /// The first call for an account fetches the current on-chain sequence
    /// via `rpc` and reserves `sequence + 1`; subsequent calls increment the
    /// reserved value under the lock, so two concurrent reservations can
    /// never collide. The RPC fetch happens while the lock is held, which
    /// keeps allocation strictly ordered at the cost of serialising the
    /// (rare) cold fetch.
    pub fn reserve(
        &self,
        rpc: &RpcClient,
        public_key: &[u8; 32],
    ) -> Result<SequenceReservation, SdkError> {
        let mut reserved = self.reserved.lock().unwrap_or_else(|e| e.into_inner());
        let next = match reserved.get(public_key).copied() {
            Some(last) => last.checked_add(1).ok_or_else(|| {
                SdkError::ValidationError("account sequence overflowed i64".into())
            })?,
            None => {
                let current = account::fetch_sequence_number(rpc, public_key)?;
                current.checked_add(1).ok_or_else(|| {
                    SdkError::ValidationError("account sequence overflowed i64".into())
                })?
            }
        };
        reserved.insert(*public_key, next);
        Ok(SequenceReservation {
            manager: self.clone(),
            public_key: *public_key,
            sequence: next,
        })
    }

    /// Forgets the cached sequence for `public_key` so the next
    /// [`reserve`](Self::reserve) re-reads it from the network. Call after a
    /// submission failure whose cause might be a bad/!contiguous sequence.
    pub fn resync(&self, public_key: &[u8; 32]) {
        self.reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(public_key);
    }

    /// The sequence number a subsequent transaction would use, if one has
    /// been reserved for `public_key` yet. Test/introspection helper.
    pub fn peek(&self, public_key: &[u8; 32]) -> Option<i64> {
        self.reserved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(public_key)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    /// Seeds the manager's cache directly, bypassing the RPC fetch, so unit
    /// tests don't need a live endpoint.
    fn seeded(public_key: [u8; 32], last: i64) -> SequenceManager {
        let m = SequenceManager::new();
        m.reserved.lock().unwrap().insert(public_key, last);
        m
    }

    #[test]
    fn sequential_reservations_are_contiguous_and_increasing() {
        let pk = [1u8; 32];
        let m = seeded(pk, 41);
        let a = m.reserve_cached(&pk).unwrap();
        let b = m.reserve_cached(&pk).unwrap();
        let c = m.reserve_cached(&pk).unwrap();
        assert_eq!((a.sequence(), b.sequence(), c.sequence()), (42, 43, 44));
    }

    #[test]
    fn concurrent_reservations_from_one_account_are_all_distinct() {
        let pk = [7u8; 32];
        let m = seeded(pk, 100);
        let threads = 16;
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let (m, barrier) = (m.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    m.reserve_cached(&pk).unwrap().sequence()
                })
            })
            .collect();
        let mut got: Vec<i64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        got.sort_unstable();
        let expected: Vec<i64> = (101..101 + threads as i64).collect();
        assert_eq!(got, expected, "sequence numbers collided under concurrency");
    }

    #[test]
    fn failed_reservation_resyncs_so_the_next_reserve_refetches() {
        let pk = [3u8; 32];
        let m = seeded(pk, 9);
        let r = m.reserve_cached(&pk).unwrap();
        assert_eq!(r.sequence(), 10);
        assert_eq!(m.peek(&pk), Some(10));
        r.failed();
        assert_eq!(m.peek(&pk), None, "resync should drop the cached sequence");
    }

    #[test]
    fn committed_reservation_keeps_the_manager_advancing() {
        let pk = [4u8; 32];
        let m = seeded(pk, 0);
        m.reserve_cached(&pk).unwrap().committed();
        assert_eq!(m.peek(&pk), Some(1));
        assert_eq!(m.reserve_cached(&pk).unwrap().sequence(), 2);
    }

    impl SequenceManager {
        /// Test-only: reserve without touching RPC. Requires the account's
        /// sequence to already be cached (via [`seeded`]).
        fn reserve_cached(&self, pk: &[u8; 32]) -> Result<SequenceReservation, SdkError> {
            let mut reserved = self.reserved.lock().unwrap_or_else(|e| e.into_inner());
            let last = reserved
                .get(pk)
                .copied()
                .expect("test must seed the sequence first");
            let next = last + 1;
            reserved.insert(*pk, next);
            Ok(SequenceReservation {
                manager: self.clone(),
                public_key: *pk,
                sequence: next,
            })
        }
    }
}
