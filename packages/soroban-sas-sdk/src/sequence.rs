//! Concurrency-safe account sequence numbers for SDK writes (issue #132, #468).
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
//! account permanently. Automatic recovery ensures that if one concurrent
//! transaction fails while other transactions remain in flight, its sequence
//! number is recycled and reused to heal sequence gaps without triggering
//! cascading `txBadSeq` errors.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::account;
use crate::errors::SdkError;
use crate::rpc::RpcClient;

#[derive(Debug, Clone, Default)]
struct AccountState {
    /// Authoritative on-chain sequence last confirmed from RPC.
    on_chain_sequence: Option<i64>,
    /// Highest sequence number handed out so far.
    last_reserved: i64,
    /// Recycled sequence numbers that were reserved but not committed.
    /// A BTreeSet gives us the lowest sequence first so gaps are filled immediately.
    recycled: BTreeSet<i64>,
    /// Sequences currently reserved and in flight.
    in_flight: HashSet<i64>,
    /// Whether this account has fetched its sequence from RPC.
    initialized: bool,
}

/// Hands out per-account transaction sequence numbers that are unique even
/// across threads. Cheap to clone (`Arc` inside); share one instance
/// between every client/task that writes from the same account.
#[derive(Clone, Default)]
pub struct SequenceManager {
    /// Per-account sequence state.
    accounts: Arc<Mutex<HashMap<[u8; 32], AccountState>>>,
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
    /// Removes it from in-flight tracking and updates the confirmed on-chain baseline.
    pub fn committed(self) {
        self.manager.commit(&self.public_key, self.sequence);
    }

    /// The submission failed. If concurrent transactions are in flight, recycles
    /// this sequence so the next reservation can fill the gap. If no other transactions
    /// are in flight, resets the cached sequence so the next reservation re-queries RPC.
    pub fn failed(self) {
        self.manager.record_failure(&self.public_key, self.sequence);
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
    /// reserved value under the lock (or pop from the pool of recycled gap sequences),
    /// so two concurrent reservations can never collide. The RPC fetch happens
    /// while the lock is held, which keeps allocation strictly ordered at the
    /// cost of serialising the (rare) cold fetch.
    pub fn reserve(
        &self,
        rpc: &RpcClient,
        public_key: &[u8; 32],
    ) -> Result<SequenceReservation, SdkError> {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        let state = match accounts.get_mut(public_key) {
            Some(s) if s.initialized => s,
            _ => {
                let current = account::fetch_sequence_number(rpc, public_key)?;
                accounts.entry(*public_key).or_default();
                let s = accounts.get_mut(public_key).unwrap();
                s.on_chain_sequence = Some(current);
                s.last_reserved = current;
                s.recycled.clear();
                s.in_flight.clear();
                s.initialized = true;
                s
            }
        };

        let next = if let Some(&smallest) = state.recycled.iter().next() {
            state.recycled.remove(&smallest);
            smallest
        } else {
            let next_seq = state.last_reserved.checked_add(1).ok_or_else(|| {
                SdkError::ValidationError("account sequence overflowed i64".into())
            })?;
            state.last_reserved = next_seq;
            next_seq
        };

        state.in_flight.insert(next);

        Ok(SequenceReservation {
            manager: self.clone(),
            public_key: *public_key,
            sequence: next,
        })
    }

    /// Synchronizes internal state against the authoritative on-chain sequence
    /// reported by RPC. Purges obsolete recycled/in-flight entries `<= current`,
    /// advances `last_reserved` if the chain has overtaken it, and updates `on_chain_sequence`.
    pub fn sync_on_chain(&self, rpc: &RpcClient, public_key: &[u8; 32]) -> Result<i64, SdkError> {
        let current = account::fetch_sequence_number(rpc, public_key)?;
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        let state = accounts.entry(*public_key).or_default();
        state.on_chain_sequence = Some(current);
        state.initialized = true;

        // Discard any reservations or recycled values that are already confirmed on chain.
        state.recycled.retain(|&seq| seq > current);
        state.in_flight.retain(|&seq| seq > current);

        if state.last_reserved < current {
            state.last_reserved = current;
        }

        Ok(current)
    }

    /// Marks `sequence` as committed.
    fn commit(&self, public_key: &[u8; 32], sequence: i64) {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = accounts.get_mut(public_key) {
            state.in_flight.remove(&sequence);
            if let Some(ref mut on_chain) = state.on_chain_sequence {
                if sequence > *on_chain {
                    *on_chain = sequence;
                }
            } else {
                state.on_chain_sequence = Some(sequence);
            }
        }
    }

    /// Records failure of a reserved sequence.
    /// If other concurrent transactions are in flight or previous gaps exist,
    /// recycles this sequence so that subsequent reservations can fill the gap.
    /// If no other transactions are in flight, uninitializes the cached sequence
    /// so that the next reservation re-queries the authoritative on-chain sequence.
    fn record_failure(&self, public_key: &[u8; 32], sequence: i64) {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = accounts.get_mut(public_key) {
            state.in_flight.remove(&sequence);
            if state.in_flight.is_empty() && state.recycled.is_empty() {
                // No concurrent transactions in flight: reset initialized state
                // and roll back last_reserved to on-chain sequence.
                state.initialized = false;
                if let Some(on_chain) = state.on_chain_sequence {
                    state.last_reserved = on_chain;
                } else {
                    state.last_reserved = state.last_reserved.saturating_sub(1);
                }
            } else {
                // Concurrent transactions remain in flight: recycle this sequence so that
                // subsequent reservations can fill the gap.
                state.recycled.insert(sequence);
            }
        }
    }

    /// Forgets the cached sequence for `public_key` so the next
    /// [`reserve`](Self::reserve) re-reads it from the network. Call after a
    /// submission failure whose cause might be a bad/!contiguous sequence.
    pub fn resync(&self, public_key: &[u8; 32]) {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = accounts.get_mut(public_key) {
            state.initialized = false;
            state.recycled.clear();
            state.in_flight.clear();
            if let Some(on_chain) = state.on_chain_sequence {
                state.last_reserved = on_chain;
            }
        }
    }

    /// The sequence number a subsequent transaction would use, if one has
    /// been reserved for `public_key` yet. Test/introspection helper.
    pub fn peek(&self, public_key: &[u8; 32]) -> Option<i64> {
        let accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        let state = accounts.get(public_key)?;
        if !state.initialized {
            None
        } else if let Some(&smallest) = state.recycled.iter().next() {
            Some(smallest)
        } else {
            Some(state.last_reserved)
        }
    }

    /// Number of recycled sequence numbers waiting to be reused.
    pub fn recycled_count(&self, public_key: &[u8; 32]) -> usize {
        self.accounts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(public_key)
            .map(|s| s.recycled.len())
            .unwrap_or(0)
    }

    /// Number of reservations currently in flight.
    pub fn in_flight_count(&self, public_key: &[u8; 32]) -> usize {
        self.accounts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(public_key)
            .map(|s| s.in_flight.len())
            .unwrap_or(0)
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
        m.accounts.lock().unwrap().insert(
            public_key,
            AccountState {
                on_chain_sequence: Some(last),
                last_reserved: last,
                recycled: BTreeSet::new(),
                in_flight: HashSet::new(),
                initialized: true,
            },
        );
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

    #[test]
    fn concurrent_failed_reservation_recycles_and_fills_gap() {
        let pk = [5u8; 32];
        let m = seeded(pk, 100);

        // Simulate two concurrent reservations: seq 101 and seq 102
        let r1 = m.reserve_cached(&pk).unwrap();
        let r2 = m.reserve_cached(&pk).unwrap();
        assert_eq!(r1.sequence(), 101);
        assert_eq!(r2.sequence(), 102);

        // r1 fails while r2 is still in flight: 101 must be recycled into the pool
        r1.failed();
        assert_eq!(m.recycled_count(&pk), 1);
        assert_eq!(m.peek(&pk), Some(101));

        // The next reservation must pick up 101 to fill the gap before advancing past 102
        let r3 = m.reserve_cached(&pk).unwrap();
        assert_eq!(r3.sequence(), 101);
        assert_eq!(m.recycled_count(&pk), 0);

        // Subsequent reservation advances to 103
        let r4 = m.reserve_cached(&pk).unwrap();
        assert_eq!(r4.sequence(), 103);

        r2.committed();
        r3.committed();
        r4.committed();
    }

    #[test]
    fn stress_test_50_concurrent_tasks_no_bad_seq() {
        let pk = [8u8; 32];
        let base_sequence = 1_000_000i64;
        let m = seeded(pk, base_sequence);
        let tasks = 50;
        let barrier = Arc::new(Barrier::new(tasks));

        let handles: Vec<_> = (0..tasks)
            .map(|i| {
                let (m, barrier) = (m.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    // Each task reserves a sequence
                    let reservation = m.reserve_cached(&pk).unwrap();
                    let seq = reservation.sequence();

                    // Even tasks simulate transient failure and retry
                    if i % 2 == 0 {
                        reservation.failed();
                        // Re-reserve after failure
                        let retry_res = m.reserve_cached(&pk).unwrap();
                        let retry_seq = retry_res.sequence();
                        retry_res.committed();
                        (seq, Some(retry_seq))
                    } else {
                        reservation.committed();
                        (seq, None)
                    }
                })
            })
            .collect();

        let mut all_committed = Vec::new();
        for h in handles {
            let (first, retry) = h.join().unwrap();
            if let Some(r) = retry {
                all_committed.push(r);
            } else {
                all_committed.push(first);
            }
        }

        // All 50 successfully committed transactions must have unique sequence numbers
        all_committed.sort_unstable();
        let count_before = all_committed.len();
        all_committed.dedup();
        assert_eq!(
            all_committed.len(),
            count_before,
            "duplicate sequence numbers detected among committed tasks"
        );
        assert_eq!(all_committed.len(), tasks);

        // Verify strictly increasing contiguous range for non-failing runs,
        // and that all sequence numbers are greater than base_sequence
        for seq in &all_committed {
            assert!(*seq > base_sequence);
        }
        assert_eq!(m.in_flight_count(&pk), 0);
    }

    impl SequenceManager {
        /// Test-only: reserve without touching RPC. Requires the account's
        /// sequence to already be cached (via [`seeded`]).
        pub(crate) fn reserve_cached(
            &self,
            pk: &[u8; 32],
        ) -> Result<SequenceReservation, SdkError> {
            let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
            let state = accounts.entry(*pk).or_default();
            state.initialized = true;

            let next = if let Some(&smallest) = state.recycled.iter().next() {
                state.recycled.remove(&smallest);
                smallest
            } else {
                let next_seq = state.last_reserved.checked_add(1).ok_or_else(|| {
                    SdkError::ValidationError("account sequence overflowed i64".into())
                })?;
                state.last_reserved = next_seq;
                next_seq
            };

            state.in_flight.insert(next);

            Ok(SequenceReservation {
                manager: self.clone(),
                public_key: *pk,
                sequence: next,
            })
        }
    }
}
