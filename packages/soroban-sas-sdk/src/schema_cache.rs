//! Thread-safe, bounded LRU cache for Schema Registry lookups.

use crate::events::SasEvent;
use crate::errors::SdkError;
use crate::simulate;
use soroban_sas_common::SchemaRecord;
use soroban_sdk::xdr::{Limits, WriteXdr};
use soroban_sdk::Env;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type SchemaUid = [u8; 32];

#[derive(Clone)]
struct CacheEntry {
    value: Option<String>,
    expires_at: Instant,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SchemaCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub expirations: u64,
    pub evictions: u64,
    pub refreshes: u64,
    pub refresh_errors: u64,
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<SchemaUid, CacheEntry>,
    lru: VecDeque<SchemaUid>,
    refreshing: HashMap<SchemaUid, u64>,
    next_refresh_token: u64,
    stats: SchemaCacheStats,
}

/// An in-memory, thread-safe LRU cache for schema records and missing UIDs.
///
/// Clones share the same cache state. Cache instances should be scoped to one
/// Schema Registry contract.
#[derive(Clone)]
pub struct SchemaCache {
    capacity: usize,
    ttl: Duration,
    state: Arc<Mutex<CacheState>>,
}

impl SchemaCache {
    /// Creates a cache with a maximum number of entries and a time-to-live.
    ///
    /// A zero capacity disables storage while preserving lookup statistics.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            ttl,
            state: Arc::new(Mutex::new(CacheState::default())),
        }
    }

    /// Gets a fresh entry, returning `None` for a cache miss or expired entry.
    pub fn get(&self, uid: &SchemaUid) -> Result<Option<Option<SchemaRecord>>, SdkError> {
        let (value, expired) = self.lookup(uid)?;
        if expired {
            Ok(None)
        } else {
            Ok(value)
        }
    }

    /// Inserts a schema or a negative (not found) lookup into the cache.
    /// Deprecated records are discarded rather than cached.
    pub fn insert(&self, uid: SchemaUid, value: Option<SchemaRecord>) -> Result<(), SdkError> {
        if matches!(value.as_ref(), Some(record) if record.deprecated) || self.capacity == 0 {
            self.invalidate(&uid);
            return Ok(());
        }
        let value = value.map(Self::encode).transpose()?;

        let mut state = self.state.lock().expect("schema cache lock poisoned");
        state.refreshing.remove(&uid);
        Self::insert_encoded(&mut state, uid, value, self.capacity, self.ttl);
        Ok(())
    }

    /// Removes a UID from the cache.
    pub fn invalidate(&self, uid: &SchemaUid) -> bool {
        let mut state = self.state.lock().expect("schema cache lock poisoned");
        state.refreshing.remove(uid);
        Self::remove_entry(&mut state, uid)
    }

    /// Invalidates entries affected by a parsed registry schema event.
    pub fn invalidate_for_event(&self, event: &SasEvent) -> bool {
        match event {
            SasEvent::SchemaRegistered(event) => self.invalidate(&event.schema_uid),
            SasEvent::SchemaDeprecated(event) => self.invalidate(&event.schema_uid),
            _ => false,
        }
    }

    /// Returns a snapshot of cache performance counters.
    pub fn stats(&self) -> SchemaCacheStats {
        self.state
            .lock()
            .expect("schema cache lock poisoned")
            .stats
            .clone()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub(crate) fn lookup(
        &self,
        uid: &SchemaUid,
    ) -> Result<(Option<Option<SchemaRecord>>, bool), SdkError> {
        let mut state = self.state.lock().expect("schema cache lock poisoned");
        let Some(entry) = state.entries.get(uid).cloned() else {
            state.stats.misses += 1;
            return Ok((None, false));
        };

        Self::touch(&mut state, uid);
        let expired = entry.expires_at <= Instant::now();
        if expired {
            state.stats.misses += 1;
            state.stats.expirations += 1;
        } else {
            state.stats.hits += 1;
        }
        drop(state);
        let value = entry.value.map(Self::decode).transpose()?;
        Ok((Some(value), expired))
    }

    pub(crate) fn start_refresh(&self, uid: SchemaUid) -> Option<u64> {
        let mut state = self.state.lock().expect("schema cache lock poisoned");
        if state.refreshing.contains_key(&uid) {
            return None;
        }
        let token = state.next_refresh_token;
        state.next_refresh_token = state.next_refresh_token.wrapping_add(1);
        state.refreshing.insert(uid, token);
        Some(token)
    }

    pub(crate) fn finish_refresh(
        &self,
        uid: SchemaUid,
        token: u64,
        result: Result<Option<SchemaRecord>, SdkError>,
    ) {
        let result = match result {
            Ok(Some(record)) if record.deprecated => Ok(None),
            Ok(value) => value.map(Self::encode).transpose().map(Some),
            Err(error) => Err(error),
        };
        let mut state = self.state.lock().expect("schema cache lock poisoned");
        if state.refreshing.get(&uid) != Some(&token) {
            return;
        }
        state.refreshing.remove(&uid);

        match result {
            Ok(Some(value)) => {
                Self::insert_encoded(&mut state, uid, value, self.capacity, self.ttl);
                state.stats.refreshes += 1;
            }
            Ok(None) => {
                Self::remove_entry(&mut state, &uid);
                state.stats.refreshes += 1;
            }
            Err(_) => state.stats.refresh_errors += 1,
        }
    }

    pub(crate) fn cancel_refresh(&self, uid: &SchemaUid, token: u64) {
        let mut state = self.state.lock().expect("schema cache lock poisoned");
        if state.refreshing.get(uid) == Some(&token) {
            state.refreshing.remove(uid);
        }
    }

    fn touch(state: &mut CacheState, uid: &SchemaUid) {
        state.lru.retain(|entry| entry != uid);
        state.lru.push_back(*uid);
    }

    fn remove_entry(state: &mut CacheState, uid: &SchemaUid) -> bool {
        state.lru.retain(|entry| entry != uid);
        state.entries.remove(uid).is_some()
    }

    fn insert_encoded(
        state: &mut CacheState,
        uid: SchemaUid,
        value: Option<String>,
        capacity: usize,
        ttl: Duration,
    ) {
        Self::remove_entry(state, &uid);
        while state.entries.len() >= capacity {
            if let Some(evicted) = state.lru.pop_front() {
                state.entries.remove(&evicted);
                state.stats.evictions += 1;
            } else {
                break;
            }
        }
        state.entries.insert(
            uid,
            CacheEntry {
                value,
                expires_at: Instant::now() + ttl,
            },
        );
        state.lru.push_back(uid);
    }

    fn encode(record: SchemaRecord) -> Result<String, SdkError> {
        let env = record.resolver.env();
        simulate::encode_arg(env, &record)?
            .to_xdr_base64(Limits::none())
            .map_err(|error| {
                SdkError::DecodingError(format!("failed to encode cached schema: {error:?}"))
            })
    }

    fn decode(xdr: String) -> Result<SchemaRecord, SdkError> {
        simulate::decode_result(&Env::default(), &xdr)
    }
}
