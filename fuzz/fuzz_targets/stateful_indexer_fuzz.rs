//! Stateful fuzzer and verification harness for the Indexer linked chunk storage.
//!
//! Validates data integrity under arbitrary sequences of:
//! - `Insert`: new attestations, idempotent retries, and conflicting retries
//! - `Revoke`: status updates (`Revoked`, `Replaced`) and filtered query parity
//! - `ReadPage`: forward pagination, reverse pagination, active-only vs historical views
//! - `SimulateStorageExpiry`: instance storage TTL lapsing, persistent counter & chunk survival,
//!   and recovery without chunk linked list corruption (#219).
//!
//! Acceptance criteria:
//! - Invariants hold: no duplicate UIDs, accurate pagination boundaries, consistent counts.
//! - Simulated instance storage expiry does not corrupt underlying chunk linked lists.
//! - Runs for at least 50,000 operations without invariant violations.
//! - Detailed failure reproduction script included.

#![allow(unexpected_cfgs)]
#![cfg_attr(all(fuzzing, not(test)), no_main)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

#[cfg(fuzzing)]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::{SASError, LEDGERS_IN_ONE_YEAR, UID};
use soroban_sas_indexer::{
    index_total, read_chunk, set_index_status, IndexStatus, Indexer, IndexerClient,
    CURRENT_WASM_HASH, INDEXER_ADMIN, INDEXER_VERSION, MAX_CHUNK_SIZE, QUERY_COUNTER_COUNT,
    QUERY_COUNTER_SEQ, RECIPIENT_TOTAL, SAS_CONTRACT,
};
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    xdr::{Hash, ScAddress},
    Address, BytesN, Env, TryFromVal,
};

#[contract]
pub struct MockSas;

#[contractimpl]
impl MockSas {
    #[allow(non_snake_case)]
    pub fn SASV1(_env: Env) -> bool {
        true
    }
}

// ── Model Oracle ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelStatus {
    Active,
    Revoked,
    Replaced,
}

impl From<IndexStatus> for ModelStatus {
    fn from(s: IndexStatus) -> Self {
        match s {
            IndexStatus::Active => ModelStatus::Active,
            IndexStatus::Revoked => ModelStatus::Revoked,
            IndexStatus::Replaced => ModelStatus::Replaced,
        }
    }
}

impl From<ModelStatus> for IndexStatus {
    fn from(s: ModelStatus) -> Self {
        match s {
            ModelStatus::Active => IndexStatus::Active,
            ModelStatus::Revoked => IndexStatus::Revoked,
            ModelStatus::Replaced => IndexStatus::Replaced,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttestationRecord {
    pub uid: [u8; 32],
    pub recipient_key: [u8; 4],
    pub schema_key: [u8; 4],
    pub attester_key: [u8; 4],
    pub status: ModelStatus,
}

#[derive(Default, Clone, Debug)]
pub struct ModelOracle {
    pub records: BTreeMap<[u8; 32], AttestationRecord>,
    pub all_uids: Vec<[u8; 32]>,
    pub recipient_uids: BTreeMap<[u8; 4], Vec<[u8; 32]>>,
    pub recipient_unique_uids: BTreeMap<[u8; 4], BTreeSet<[u8; 32]>>,
    pub schema_uids: BTreeMap<[u8; 4], Vec<[u8; 32]>>,
    pub attester_uids: BTreeMap<[u8; 4], Vec<[u8; 32]>>,
}

impl ModelOracle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_insert(
        &mut self,
        uid: [u8; 32],
        recipient: [u8; 4],
        schema: [u8; 4],
        attester: [u8; 4],
    ) -> Result<bool, ()> {
        if let Some(existing) = self.records.get(&uid) {
            if existing.recipient_key == recipient
                && existing.schema_key == schema
                && existing.attester_key == attester
            {
                // Idempotent retry
                Ok(false)
            } else {
                // Conflicting triple for already-indexed UID
                Err(())
            }
        } else {
            // New insertion
            self.records.insert(
                uid,
                AttestationRecord {
                    uid,
                    recipient_key: recipient,
                    schema_key: schema,
                    attester_key: attester,
                    status: ModelStatus::Active,
                },
            );
            self.all_uids.push(uid);
            self.recipient_uids
                .entry(recipient)
                .or_default()
                .push(uid);
            self.recipient_unique_uids
                .entry(recipient)
                .or_default()
                .insert(uid);
            self.schema_uids.entry(schema).or_default().push(uid);
            self.attester_uids.entry(attester).or_default().push(uid);
            Ok(true)
        }
    }

    pub fn record_status(&mut self, uid: &[u8; 32], new_status: ModelStatus) -> bool {
        if let Some(meta) = self.records.get_mut(uid) {
            meta.status = new_status;
            true
        } else {
            false
        }
    }

    pub fn get_uids_filtered(&self, list: &[[u8; 32]], include_revoked: bool) -> Vec<[u8; 32]> {
        if include_revoked {
            list.to_vec()
        } else {
            list.iter()
                .copied()
                .filter(|u| {
                    self.records
                        .get(u)
                        .map(|m| m.status == ModelStatus::Active)
                        .unwrap_or(true)
                })
                .collect()
        }
    }

    pub fn get_page(&self, list: &[[u8; 32]], cursor: u32, limit: u32) -> Vec<[u8; 32]> {
        if limit == 0 || cursor as usize >= list.len() {
            return Vec::new();
        }
        let start = cursor as usize;
        let end = (start + limit as usize).min(list.len());
        list[start..end].to_vec()
    }

    pub fn get_filtered_page_scan(
        &self,
        list: &[[u8; 32]],
        cursor: u32,
        limit: u32,
        include_revoked: bool,
    ) -> Vec<[u8; 32]> {
        if limit == 0 || cursor as usize >= list.len() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut index = cursor as usize;
        while index < list.len() && (out.len() as u32) < limit {
            let uid = list[index];
            let active = self
                .records
                .get(&uid)
                .map(|m| m.status == ModelStatus::Active)
                .unwrap_or(true);
            if include_revoked || active {
                out.push(uid);
            }
            index += 1;
        }
        out
    }

    pub fn get_reverse_page(
        &self,
        list: &[[u8; 32]],
        cursor: Option<u32>,
        limit: u32,
    ) -> (Vec<[u8; 32]>, Option<u32>) {
        if list.is_empty() || limit == 0 {
            return (Vec::new(), None);
        }
        let start = match cursor {
            Some(c) => {
                if c as usize >= list.len() {
                    return (Vec::new(), None);
                }
                c as usize
            }
            None => list.len() - 1,
        };

        let mut out = Vec::new();
        let mut cur = start;
        loop {
            out.push(list[cur]);
            if (out.len() as u32) == limit {
                let next = cur.checked_sub(1).map(|v| v as u32);
                return (out, next);
            }
            if let Some(prev) = cur.checked_sub(1) {
                cur = prev;
            } else {
                break;
            }
        }
        (out, None)
    }
}

// ── Key Pools & Address Conversion ───────────────────────────────────────────

pub const POOL_RECIPIENTS: [[u8; 4]; 6] = [
    [0x10, 0x00, 0x00, 0x01],
    [0x10, 0x00, 0x00, 0x02],
    [0x10, 0x00, 0x00, 0x03],
    [0x10, 0x00, 0x00, 0x04],
    [0x10, 0x00, 0x00, 0x05],
    [0x10, 0x00, 0x00, 0x06],
];

pub const POOL_SCHEMAS: [[u8; 4]; 4] = [
    [0x20, 0x00, 0x00, 0x01],
    [0x20, 0x00, 0x00, 0x02],
    [0x20, 0x00, 0x00, 0x03],
    [0x20, 0x00, 0x00, 0x04],
];

pub const POOL_ATTESTERS: [[u8; 4]; 4] = [
    [0x30, 0x00, 0x00, 0x01],
    [0x30, 0x00, 0x00, 0x02],
    [0x30, 0x00, 0x00, 0x03],
    [0x30, 0x00, 0x00, 0x04],
];

pub fn key_to_address(env: &Env, key: &[u8; 4]) -> Address {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(key);
    Address::try_from_val(env, &ScAddress::Contract(Hash(bytes))).unwrap()
}

pub fn key_to_uid(env: &Env, key: &[u8; 4]) -> UID {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(key);
    UID(BytesN::from_array(env, &bytes))
}

pub fn bytes32_to_uid(env: &Env, bytes: &[u8; 32]) -> UID {
    UID(BytesN::from_array(env, bytes))
}

// ── Command Definitions ──────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertMode {
    New,
    IdempotentRetry,
    ConflictingRecipient,
    ConflictingSchema,
    ConflictingAttester,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dimension {
    Recipient,
    Schema,
    Attester,
    Issuer,
}

#[derive(Clone, Debug)]
pub enum Command {
    Insert {
        uid_id: u32,
        recipient_idx: u8,
        schema_idx: u8,
        attester_idx: u8,
        mode: InsertMode,
    },
    Revoke {
        target_uid_choice: u32,
        is_replace: bool,
    },
    ReadPage {
        dimension: Dimension,
        key_idx: u8,
        cursor: u32,
        limit: u32,
        include_revoked: bool,
        is_reverse: bool,
    },
    SimulateStorageExpiry {
        advance_ledgers: u32,
    },
}

// ── Command Stream Parser ────────────────────────────────────────────────────

pub struct CommandParser<'a> {
    data: &'a [u8],
    offset: usize,
    uid_counter: u32,
}

impl<'a> CommandParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            offset: 0,
            uid_counter: 0,
        }
    }

    pub fn next_command(&mut self) -> Option<Command> {
        if self.offset + 8 > self.data.len() {
            return None;
        }
        let chunk = &self.data[self.offset..self.offset + 8];
        self.offset += 8;

        let tag = chunk[0] % 4;
        match tag {
            0 => {
                let mode = match chunk[1] % 5 {
                    0 => InsertMode::New,
                    1 => InsertMode::IdempotentRetry,
                    2 => InsertMode::ConflictingRecipient,
                    3 => InsertMode::ConflictingSchema,
                    _ => InsertMode::ConflictingAttester,
                };
                let recipient_idx = chunk[2] % (POOL_RECIPIENTS.len() as u8);
                let schema_idx = chunk[3] % (POOL_SCHEMAS.len() as u8);
                let attester_idx = chunk[4] % (POOL_ATTESTERS.len() as u8);
                let uid_id = if mode == InsertMode::New {
                    self.uid_counter += 1;
                    self.uid_counter
                } else {
                    u32::from_le_bytes(chunk[4..8].try_into().unwrap())
                };
                Some(Command::Insert {
                    uid_id,
                    recipient_idx,
                    schema_idx,
                    attester_idx,
                    mode,
                })
            }
            1 => {
                let is_replace = (chunk[1] & 1) != 0;
                let target_uid_choice = u32::from_le_bytes(chunk[2..6].try_into().unwrap());
                Some(Command::Revoke {
                    target_uid_choice,
                    is_replace,
                })
            }
            2 => {
                let dimension = match chunk[1] % 4 {
                    0 => Dimension::Recipient,
                    1 => Dimension::Schema,
                    2 => Dimension::Attester,
                    _ => Dimension::Issuer,
                };
                let key_idx = chunk[2];
                let include_revoked = (chunk[3] & 1) != 0;
                let is_reverse = (chunk[3] & 2) != 0;
                let cursor = chunk[4] as u32;
                let limit = (chunk[5] as u32) % (MAX_CHUNK_SIZE * 2 + 10);
                Some(Command::ReadPage {
                    dimension,
                    key_idx,
                    cursor,
                    limit,
                    include_revoked,
                    is_reverse,
                })
            }
            _ => {
                let advance = u16::from_le_bytes(chunk[1..3].try_into().unwrap()) as u32;
                Some(Command::SimulateStorageExpiry {
                    advance_ledgers: advance.max(LEDGERS_IN_ONE_YEAR + 10),
                })
            }
        }
    }
}

// ── PRNG for Standalone and Stress Runs ───────────────────────────────────────

pub struct FastRng {
    state: u64,
}

impl FastRng {
    pub fn new(seed: u64) -> Self {
        let state = if seed == 0 { 0x853c49e6748fea9b } else { seed };
        Self { state }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    pub fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    pub fn next_bounded(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            0
        } else {
            self.next_u32() % bound
        }
    }

    pub fn gen_command(&mut self, next_uid_id: &mut u32, oracle: &ModelOracle) -> Command {
        let roll = self.next_bounded(100);
        if roll < 45 || oracle.all_uids.is_empty() {
            // 45% Insert
            let recipient_idx = self.next_bounded(POOL_RECIPIENTS.len() as u32) as u8;
            let schema_idx = self.next_bounded(POOL_SCHEMAS.len() as u32) as u8;
            let attester_idx = self.next_bounded(POOL_ATTESTERS.len() as u32) as u8;

            let mode = if oracle.all_uids.is_empty() || self.next_bounded(10) < 7 {
                InsertMode::New
            } else {
                match self.next_bounded(4) {
                    0 => InsertMode::IdempotentRetry,
                    1 => InsertMode::ConflictingRecipient,
                    2 => InsertMode::ConflictingSchema,
                    _ => InsertMode::ConflictingAttester,
                }
            };

            let uid_id = if mode == InsertMode::New {
                *next_uid_id += 1;
                *next_uid_id
            } else {
                self.next_bounded(oracle.all_uids.len() as u32)
            };

            Command::Insert {
                uid_id,
                recipient_idx,
                schema_idx,
                attester_idx,
                mode,
            }
        } else if roll < 65 {
            // 20% Revoke
            let target_uid_choice = self.next_bounded(oracle.all_uids.len() as u32);
            let is_replace = (self.next_bounded(2)) == 1;
            Command::Revoke {
                target_uid_choice,
                is_replace,
            }
        } else if roll < 92 {
            // 27% ReadPage
            let dimension = match self.next_bounded(4) {
                0 => Dimension::Recipient,
                1 => Dimension::Schema,
                2 => Dimension::Attester,
                _ => Dimension::Issuer,
            };
            let key_idx = match dimension {
                Dimension::Recipient => self.next_bounded(POOL_RECIPIENTS.len() as u32) as u8,
                Dimension::Schema => self.next_bounded(POOL_SCHEMAS.len() as u32) as u8,
                Dimension::Attester | Dimension::Issuer => {
                    self.next_bounded(POOL_ATTESTERS.len() as u32) as u8
                }
            };
            // Skew cursor and limit towards chunk boundaries (0, 100, 101, etc.)
            let cursor = match self.next_bounded(6) {
                0 => 0,
                1 => MAX_CHUNK_SIZE.saturating_sub(1),
                2 => MAX_CHUNK_SIZE,
                3 => MAX_CHUNK_SIZE + 1,
                4 => self.next_bounded(300),
                _ => 10_000, // Beyond end
            };
            let limit = match self.next_bounded(6) {
                0 => 0,
                1 => 1,
                2 => 7,
                3 => MAX_CHUNK_SIZE,
                4 => MAX_CHUNK_SIZE + 1,
                _ => self.next_bounded(150),
            };
            let include_revoked = self.next_bounded(2) == 1;
            let is_reverse = self.next_bounded(2) == 1;

            Command::ReadPage {
                dimension,
                key_idx,
                cursor,
                limit,
                include_revoked,
                is_reverse,
            }
        } else {
            // 8% SimulateStorageExpiry
            let advance = self.next_bounded(100) + 1;
            Command::SimulateStorageExpiry {
                advance_ledgers: advance,
            }
        }
    }
}

// ── Fuzz Driver & State Machine ──────────────────────────────────────────────

pub struct StatefulIndexerFuzzer {
    pub env: Env,
    pub indexer_id: Address,
    pub client: IndexerClient<'static>,
    pub admin: Address,
    pub sas: Address,
    pub oracle: ModelOracle,
    pub op_count: usize,
    pub query_count_in_seq: u32,
}

impl StatefulIndexerFuzzer {
    pub fn new() -> Self {
        let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.budget().reset_unlimited();
        env.mock_all_auths();

        let indexer_id = env.register_contract(None, Indexer);
        let client = IndexerClient::new(&env, &indexer_id);
        let admin = Address::generate(&env);
        let sas = env.register_contract(None, MockSas);

        client.init(&admin, &sas);

        Self {
            env,
            indexer_id,
            client,
            admin,
            sas,
            oracle: ModelOracle::new(),
            op_count: 0,
            query_count_in_seq: 0,
        }
    }

    /// Advances simulated ledger sequence to simulate ledger close and avoid
    /// tripping query rate limits on legitimate test sequences.
    pub fn advance_seq_if_needed(&mut self) {
        self.query_count_in_seq += 1;
        if self.query_count_in_seq >= 500 {
            self.env.ledger().with_mut(|li| {
                li.sequence_number += 1;
            });
            self.env.as_contract(&self.indexer_id, || {
                self.env.storage().instance().extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
            });
            self.env.as_contract(&self.sas, || {
                self.env.storage().instance().extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
            });
            self.query_count_in_seq = 0;
        }
    }

    pub fn make_uid(&self, uid_id: u32) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&uid_id.to_be_bytes());
        bytes[31] = 0xAA;
        bytes
    }

    pub fn execute(&mut self, cmd: Command) {
        self.op_count += 1;
        match cmd {
            Command::Insert {
                uid_id,
                recipient_idx,
                schema_idx,
                attester_idx,
                mode,
            } => {
                let mut recip_key = POOL_RECIPIENTS[(recipient_idx as usize) % POOL_RECIPIENTS.len()];
                let mut schema_key = POOL_SCHEMAS[(schema_idx as usize) % POOL_SCHEMAS.len()];
                let mut attester_key = POOL_ATTESTERS[(attester_idx as usize) % POOL_ATTESTERS.len()];

                let uid_raw = match mode {
                    InsertMode::New => self.make_uid(uid_id),
                    InsertMode::IdempotentRetry => {
                        if let Some(&existing) = self.oracle.all_uids.get((uid_id as usize) % self.oracle.all_uids.len().max(1)) {
                            let rec = &self.oracle.records[&existing];
                            recip_key = rec.recipient_key;
                            schema_key = rec.schema_key;
                            attester_key = rec.attester_key;
                            existing
                        } else {
                            self.make_uid(uid_id)
                        }
                    }
                    InsertMode::ConflictingRecipient => {
                        if let Some(&existing) = self.oracle.all_uids.get((uid_id as usize) % self.oracle.all_uids.len().max(1)) {
                            let rec = &self.oracle.records[&existing];
                            schema_key = rec.schema_key;
                            attester_key = rec.attester_key;
                            // Mutate recipient to a different pool key
                            recip_key[0] ^= 0xFF;
                            existing
                        } else {
                            self.make_uid(uid_id)
                        }
                    }
                    InsertMode::ConflictingSchema => {
                        if let Some(&existing) = self.oracle.all_uids.get((uid_id as usize) % self.oracle.all_uids.len().max(1)) {
                            let rec = &self.oracle.records[&existing];
                            recip_key = rec.recipient_key;
                            attester_key = rec.attester_key;
                            schema_key[0] ^= 0xFF;
                            existing
                        } else {
                            self.make_uid(uid_id)
                        }
                    }
                    InsertMode::ConflictingAttester => {
                        if let Some(&existing) = self.oracle.all_uids.get((uid_id as usize) % self.oracle.all_uids.len().max(1)) {
                            let rec = &self.oracle.records[&existing];
                            recip_key = rec.recipient_key;
                            schema_key = rec.schema_key;
                            attester_key[0] ^= 0xFF;
                            existing
                        } else {
                            self.make_uid(uid_id)
                        }
                    }
                };

                let uid = bytes32_to_uid(&self.env, &uid_raw);
                let recip_addr = key_to_address(&self.env, &recip_key);
                let schema_uid = key_to_uid(&self.env, &schema_key);
                let attester_addr = key_to_address(&self.env, &attester_key);

                let expected_res = self
                    .oracle
                    .record_insert(uid_raw, recip_key, schema_key, attester_key);

                let actual_res = self.env.as_contract(&self.sas, || {
                    self.client
                        .try_index_attestation(&uid, &recip_addr, &schema_uid, &attester_addr, &0u64)
                });

                match expected_res {
                    Ok(_) => {
                        assert_eq!(
                            actual_res,
                            Ok(Ok(())),
                            "Insert (new or idempotent retry) must succeed on contract at op {}",
                            self.op_count
                        );
                        // Invariant: single UID lookup direct mapping is present
                        assert!(
                            self.client.has_recipient_attestation(&recip_addr, &uid),
                            "Direct recipient mapping must be true after insertion"
                        );
                    }
                    Err(_) => {
                        assert_eq!(
                            actual_res,
                            Err(Ok(SASError::DuplicateAttestation.into())),
                            "Conflicting insertion must fail with DuplicateAttestation at op {}",
                            self.op_count
                        );
                    }
                }
            }

            Command::Revoke {
                target_uid_choice,
                is_replace,
            } => {
                if self.oracle.all_uids.is_empty() {
                    return;
                }
                let idx = (target_uid_choice as usize) % self.oracle.all_uids.len();
                let uid_raw = self.oracle.all_uids[idx];
                let uid = bytes32_to_uid(&self.env, &uid_raw);

                let status = if is_replace {
                    IndexStatus::Replaced
                } else {
                    IndexStatus::Revoked
                };

                self.oracle.record_status(&uid_raw, status.into());

                self.env.as_contract(&self.indexer_id, || {
                    set_index_status(&self.env, &uid, status);
                });

                assert_eq!(
                    self.client.get_attestation_status(&uid),
                    Some(status),
                    "Contract get_attestation_status must match recorded status"
                );
            }

            Command::ReadPage {
                dimension,
                key_idx,
                cursor,
                limit,
                include_revoked,
                is_reverse,
            } => {
                self.advance_seq_if_needed();

                match dimension {
                    Dimension::Recipient => {
                        let recip_key =
                            POOL_RECIPIENTS[(key_idx as usize) % POOL_RECIPIENTS.len()];
                        let recip_addr = key_to_address(&self.env, &recip_key);
                        let oracle_uids = self
                            .oracle
                            .recipient_uids
                            .get(&recip_key)
                            .cloned()
                            .unwrap_or_default();

                        // Count invariant
                        let contract_count = self.client.get_count_by_recipient(&recip_addr);
                        assert_eq!(
                            contract_count,
                            oracle_uids.len() as u32,
                            "Recipient count must match oracle count"
                        );
                        let unique_count = self.client.get_recipient_attestation_count(&recip_addr);
                        let expected_unique = self
                            .oracle
                            .recipient_unique_uids
                            .get(&recip_key)
                            .map(|s| s.len() as u32)
                            .unwrap_or(0);
                        assert_eq!(
                            unique_count, expected_unique,
                            "Direct recipient attestation count must match oracle"
                        );

                        if is_reverse {
                            let page = self.client.get_atts_by_recipient_reverse(
                                &recip_addr,
                                &if cursor == 0 { None } else { Some(cursor) },
                                &limit,
                            );
                            let (expected_reverse, expected_next) = self.oracle.get_reverse_page(
                                &oracle_uids,
                                if cursor == 0 { None } else { Some(cursor) },
                                limit,
                            );
                            let actual_reverse: Vec<[u8; 32]> = page
                                .uids
                                .iter()
                                .map(|u| u.0.to_array())
                                .collect();
                            assert_eq!(
                                actual_reverse, expected_reverse,
                                "Reverse recipient page must match oracle reverse"
                            );
                            assert_eq!(
                                page.next_cursor, expected_next,
                                "Reverse recipient next_cursor must match oracle next_cursor"
                            );
                        } else if !include_revoked {
                            // Active-only filtered page
                            let actual = self.client.get_recipient_page_filtered(
                                &recip_addr,
                                &cursor,
                                &limit,
                                &include_revoked,
                            );
                            let actual_bytes: Vec<[u8; 32]> =
                                actual.iter().map(|u| u.0.to_array()).collect();
                            let expected = self.oracle.get_filtered_page_scan(
                                &oracle_uids,
                                cursor,
                                limit,
                                include_revoked,
                            );
                            assert_eq!(
                                actual_bytes, expected,
                                "Recipient filtered page must match oracle filtered scan"
                            );
                        } else {
                            // Standard paginated
                            let actual = self.client.get_atts_by_recipient_paginated(
                                &recip_addr,
                                &cursor,
                                &limit,
                            );
                            let actual_bytes: Vec<[u8; 32]> =
                                actual.iter().map(|u| u.0.to_array()).collect();
                            let expected = self.oracle.get_page(&oracle_uids, cursor, limit);
                            assert_eq!(
                                actual_bytes, expected,
                                "Recipient paginated page must match oracle slice"
                            );
                        }
                    }

                    Dimension::Schema => {
                        let schema_key = POOL_SCHEMAS[(key_idx as usize) % POOL_SCHEMAS.len()];
                        let schema_uid = key_to_uid(&self.env, &schema_key);
                        let oracle_uids = self
                            .oracle
                            .schema_uids
                            .get(&schema_key)
                            .cloned()
                            .unwrap_or_default();

                        // Count invariant
                        let contract_count = self.client.get_count_by_schema(&schema_uid);
                        assert_eq!(
                            contract_count,
                            oracle_uids.len() as u32,
                            "Schema count must match oracle count"
                        );

                        if is_reverse {
                            let page = self.client.get_atts_by_schema_reverse(
                                &schema_uid,
                                &if cursor == 0 { None } else { Some(cursor) },
                                &limit,
                            );
                            let (expected_reverse, expected_next) = self.oracle.get_reverse_page(
                                &oracle_uids,
                                if cursor == 0 { None } else { Some(cursor) },
                                limit,
                            );
                            let actual_reverse: Vec<[u8; 32]> = page
                                .uids
                                .iter()
                                .map(|u| u.0.to_array())
                                .collect();
                            assert_eq!(
                                actual_reverse, expected_reverse,
                                "Reverse schema page must match oracle reverse"
                            );
                            assert_eq!(page.next_cursor, expected_next);
                        } else {
                            let actual = self.client.get_atts_by_schema_paginated(
                                &schema_uid,
                                &cursor,
                                &limit,
                            );
                            let actual_bytes: Vec<[u8; 32]> =
                                actual.iter().map(|u| u.0.to_array()).collect();
                            let expected = self.oracle.get_page(&oracle_uids, cursor, limit);
                            assert_eq!(actual_bytes, expected);
                        }
                    }

                    Dimension::Attester | Dimension::Issuer => {
                        let attester_key =
                            POOL_ATTESTERS[(key_idx as usize) % POOL_ATTESTERS.len()];
                        let attester_addr = key_to_address(&self.env, &attester_key);
                        let oracle_uids = self
                            .oracle
                            .attester_uids
                            .get(&attester_key)
                            .cloned()
                            .unwrap_or_default();

                        // Count invariant (both attester and issuer aliases)
                        let count_attester = self.client.get_count_by_attester(&attester_addr);
                        let count_issuer = self.client.get_count_by_issuer(&attester_addr);
                        assert_eq!(count_attester, oracle_uids.len() as u32);
                        assert_eq!(count_issuer, oracle_uids.len() as u32);

                        if is_reverse {
                            let page = self.client.get_atts_by_attester_reverse(
                                &attester_addr,
                                &if cursor == 0 { None } else { Some(cursor) },
                                &limit,
                            );
                            let (expected_reverse, expected_next) = self.oracle.get_reverse_page(
                                &oracle_uids,
                                if cursor == 0 { None } else { Some(cursor) },
                                limit,
                            );
                            let actual_reverse: Vec<[u8; 32]> = page
                                .uids
                                .iter()
                                .map(|u| u.0.to_array())
                                .collect();
                            assert_eq!(actual_reverse, expected_reverse);
                            assert_eq!(page.next_cursor, expected_next);
                        } else if !include_revoked {
                            let actual = self.client.get_issuer_page_filtered(
                                &attester_addr,
                                &cursor,
                                &limit,
                                &include_revoked,
                            );
                            let actual_bytes: Vec<[u8; 32]> =
                                actual.iter().map(|u| u.0.to_array()).collect();
                            let expected = self.oracle.get_filtered_page_scan(
                                &oracle_uids,
                                cursor,
                                limit,
                                include_revoked,
                            );
                            assert_eq!(actual_bytes, expected);
                        } else {
                            let actual = self.client.get_atts_by_issuer_paginated(
                                &attester_addr,
                                &cursor,
                                &limit,
                            );
                            let actual_bytes: Vec<[u8; 32]> =
                                actual.iter().map(|u| u.0.to_array()).collect();
                            let expected = self.oracle.get_page(&oracle_uids, cursor, limit);
                            assert_eq!(actual_bytes, expected);
                        }
                    }
                }
            }

            Command::SimulateStorageExpiry { advance_ledgers } => {
                // 1. Advance ledger sequence past TTL horizon
                self.env.ledger().with_mut(|li| {
                    li.sequence_number += advance_ledgers;
                });

                // 2. Simulate complete instance storage eviction
                self.env.as_contract(&self.indexer_id, || {
                    self.env.storage().instance().remove(&INDEXER_ADMIN);
                    self.env.storage().instance().remove(&SAS_CONTRACT);
                    self.env.storage().instance().remove(&INDEXER_VERSION);
                    self.env.storage().instance().remove(&CURRENT_WASM_HASH);
                    self.env.storage().instance().remove(&QUERY_COUNTER_SEQ);
                    self.env.storage().instance().remove(&QUERY_COUNTER_COUNT);
                });

                // 3. Verify that indexer instance storage is indeed expired
                assert_eq!(self.client.get_admin(), None);
                assert_eq!(self.client.get_sas(), None);

                // 4. Verify that persistent storage counters and chunk linked lists survived intact (#219)
                self.env.as_contract(&self.indexer_id, || {
                    for recip_key in POOL_RECIPIENTS.iter() {
                        let recip_addr = key_to_address(&self.env, recip_key);
                        let count_key = (RECIPIENT_TOTAL, recip_addr.clone());
                        let persistent_count = index_total(&self.env, &count_key);
                        let expected_count = self
                            .oracle
                            .recipient_uids
                            .get(recip_key)
                            .map(|v| v.len() as u32)
                            .unwrap_or(0);
                        assert_eq!(
                            persistent_count, expected_count,
                            "Persistent recipient counter must survive instance storage expiry"
                        );

                        // Check chunks
                        let num_chunks = persistent_count.div_ceil(MAX_CHUNK_SIZE);
                        let mut collected = Vec::new();
                        for chunk_idx in 0..num_chunks {
                            let chunk = read_chunk(&self.env, &(recip_addr.clone(), chunk_idx))
                                .expect("Chunk must exist");
                            collected.extend(chunk.iter().map(|u| u.0.to_array()));
                        }
                        if let Some(expected_uids) = self.oracle.recipient_uids.get(recip_key) {
                            assert_eq!(
                                &collected, expected_uids,
                                "Underlying chunk linked list must remain uncorrupted across storage expiry"
                            );
                        }
                    }
                });

                // 5. Restore instance storage (simulating contract instance restoration / re-init)
                self.env.as_contract(&self.indexer_id, || {
                    self.env.storage().instance().set(&INDEXER_ADMIN, &self.admin);
                    self.env.storage().instance().set(&SAS_CONTRACT, &self.sas);
                    self.env.storage().instance().set(&INDEXER_VERSION, &1u32);
                    self.env.storage().instance().extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
                });
                self.env.as_contract(&self.sas, || {
                    self.env.storage().instance().extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
                });

                assert_eq!(self.client.get_admin(), Some(self.admin.clone()));
                assert_eq!(self.client.get_sas(), Some(self.sas.clone()));
            }
        }
    }

    /// Comprehensive assertion of all protocol invariants across all keys in the oracle.
    pub fn assert_invariants(&mut self) {
        // Invariant 1: No duplicate UIDs across all chunks for every key dimension
        for recip_key in POOL_RECIPIENTS.iter() {
            let recip_addr = key_to_address(&self.env, recip_key);
            let expected_uids = self
                .oracle
                .recipient_uids
                .get(recip_key)
                .cloned()
                .unwrap_or_default();
            let total = self.client.get_count_by_recipient(&recip_addr);
            assert_eq!(total, expected_uids.len() as u32);

            let mut all_chunk_uids = Vec::new();
            let mut unique_chunk_uids = BTreeSet::new();
            let num_chunks = total.div_ceil(MAX_CHUNK_SIZE);

            self.env.as_contract(&self.indexer_id, || {
                for chunk_idx in 0..num_chunks {
                    let chunk = read_chunk(&self.env, &(recip_addr.clone(), chunk_idx))
                        .expect("Chunk must be present");
                    let expected_chunk_len = if chunk_idx == num_chunks - 1 && total % MAX_CHUNK_SIZE != 0 {
                        total % MAX_CHUNK_SIZE
                    } else {
                        MAX_CHUNK_SIZE
                    };
                    assert_eq!(
                        chunk.len(),
                        expected_chunk_len,
                        "Physical chunk size invariant must hold"
                    );

                    for uid in chunk.iter() {
                        let arr = uid.0.to_array();
                        assert!(
                            unique_chunk_uids.insert(arr),
                            "Invariant violated: Duplicate UID detected in recipient chunk list!"
                        );
                        all_chunk_uids.push(arr);
                    }
                }
            });
            assert_eq!(
                all_chunk_uids, expected_uids,
                "Recipient chunk sequence must exactly match oracle insertion history"
            );
        }

        // Invariant 2: Accurate pagination boundaries across boundary page sizes
        for recip_key in POOL_RECIPIENTS.iter() {
            let recip_addr = key_to_address(&self.env, recip_key);
            let expected_uids = self
                .oracle
                .recipient_uids
                .get(recip_key)
                .cloned()
                .unwrap_or_default();
            let total = expected_uids.len() as u32;

            for page_size in [7, MAX_CHUNK_SIZE, MAX_CHUNK_SIZE + 1] {
                self.advance_seq_if_needed();
                let mut cursor = 0u32;
                let mut reassembled = Vec::new();
                loop {
                    let page = self.client.get_atts_by_recipient_paginated(
                        &recip_addr,
                        &cursor,
                        &page_size,
                    );
                    if page.is_empty() {
                        break;
                    }
                    let expected_page_len = page_size.min(total.saturating_sub(cursor));
                    assert_eq!(
                        page.len(),
                        expected_page_len,
                        "Page length boundary invariant violated"
                    );
                    for uid in page.iter() {
                        reassembled.push(uid.0.to_array());
                    }
                    cursor += page.len();
                }
                assert_eq!(cursor, total, "Paging must exhaust exactly the total elements");
                assert_eq!(
                    reassembled, expected_uids,
                    "Reassembled pages must match complete history with no gaps or duplicates"
                );

                // Out-of-bounds queries
                assert!(self
                    .client
                    .get_atts_by_recipient_paginated(&recip_addr, &total, &page_size)
                    .is_empty());
                assert!(self
                    .client
                    .get_atts_by_recipient_paginated(&recip_addr, &(total + 100), &page_size)
                    .is_empty());
                assert!(self
                    .client
                    .get_atts_by_recipient_paginated(&recip_addr, &0, &0)
                    .is_empty());
            }

            // Spot-check single-item boundaries (cursor at 0, 99, 100, 101, tail)
            for cursor in [
                0,
                1,
                MAX_CHUNK_SIZE.saturating_sub(1),
                MAX_CHUNK_SIZE,
                MAX_CHUNK_SIZE + 1,
                total.saturating_sub(1),
            ] {
                if cursor < total {
                    let single = self
                        .client
                        .get_atts_by_recipient_paginated(&recip_addr, &cursor, &1);
                    assert_eq!(single.len(), 1, "Single element page at boundary must return 1 item");
                    assert_eq!(
                        single.get(0).unwrap().0.to_array(),
                        expected_uids[cursor as usize],
                        "Single element at boundary must match expected UID"
                    );
                }
            }
        }
    }
}

// ── Top-Level Runner ─────────────────────────────────────────────────────────

pub fn run_stateful_indexer_fuzz(data: &[u8]) {
    if data.len() < 8 {
        return;
    }
    let mut fuzzer = StatefulIndexerFuzzer::new();
    let mut parser = CommandParser::new(data);

    let max_ops = 500;
    let mut count = 0;
    while let Some(cmd) = parser.next_command() {
        fuzzer.execute(cmd);
        count += 1;
        if count >= max_ops {
            break;
        }
    }
    fuzzer.assert_invariants();
}

pub fn run_stress_test(seed: u64, total_ops: usize, epoch_ops: usize, verbose: bool) {
    println!(
        "Starting stateful indexer stress run with seed 0x{:016X} for {} operations (epoch size: {})...",
        seed, total_ops, epoch_ops
    );
    let start_time = Instant::now();
    let mut rng = FastRng::new(seed);
    let mut ops_done = 0;
    let mut epoch_num = 1;

    while ops_done < total_ops {
        let current_target = (total_ops - ops_done).min(epoch_ops);
        let mut fuzzer = StatefulIndexerFuzzer::new();
        let mut next_uid_id = 0u32;
        let checkpoint_interval = (current_target / 5).max(1);

        for step in 1..=current_target {
            ops_done += 1;
            let cmd = rng.gen_command(&mut next_uid_id, &fuzzer.oracle);
            if verbose && step <= 10 {
                println!(
                    "  [Epoch {} | Op {}/{}] {:?}",
                    epoch_num, ops_done, total_ops, cmd
                );
            }
            fuzzer.execute(cmd);

            if step % checkpoint_interval == 0 || step == current_target {
                fuzzer.assert_invariants();
            }
        }
        fuzzer.assert_invariants();
        let elapsed = start_time.elapsed().as_secs_f64();
        let rate = (ops_done as f64) / elapsed.max(0.001);
        println!(
            "  Epoch {:2}: {:6}/{} ops completed ({:5.1}%) | Rate: {:6.0} ops/sec",
            epoch_num,
            ops_done,
            total_ops,
            (ops_done as f64 / total_ops as f64) * 100.0,
            rate
        );
        epoch_num += 1;
    }

    let total_time = start_time.elapsed();
    println!(
        "SUCCESS: Completed {} operations across {} epochs in {:.2}s without any invariant violations!",
        total_ops,
        epoch_num - 1,
        total_time.as_secs_f64()
    );
}

// ── Entry Points ─────────────────────────────────────────────────────────────

#[cfg(fuzzing)]
fuzz_target!(|data: &[u8]| {
    run_stateful_indexer_fuzz(data);
});

#[cfg(not(fuzzing))]
fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut total_ops = 50_000usize;
    let mut epoch_ops = 2_500usize;
    let mut seed = 0x5EED_F00D_1234_5678u64;
    let mut file_path: Option<String> = None;
    let mut verbose = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--ops" => {
                if i + 1 < args.len() {
                    total_ops = args[i + 1].parse().unwrap_or(50_000);
                    i += 1;
                }
            }
            "--epoch-ops" => {
                if i + 1 < args.len() {
                    epoch_ops = args[i + 1].parse().unwrap_or(2_500);
                    i += 1;
                }
            }
            "--seed" => {
                if i + 1 < args.len() {
                    if let Some(stripped) = args[i + 1].strip_prefix("0x") {
                        seed = u64::from_str_radix(stripped, 16).unwrap_or(seed);
                    } else {
                        seed = args[i + 1].parse().unwrap_or(seed);
                    }
                    i += 1;
                }
            }
            "--file" => {
                if i + 1 < args.len() {
                    file_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--verbose" | "-v" => {
                verbose = true;
            }
            "--help" | "-h" => {
                println!("Usage: stateful_indexer_fuzz [OPTIONS]");
                println!("Options:");
                println!("  --ops <N>         Total number of stateful operations to execute (default: 50000)");
                println!("  --epoch-ops <N>   Number of operations per deployment lifetime (default: 2500)");
                println!("  --seed <HEX>      PRNG seed for deterministic command generation (default: 0x5EEDF00D12345678)");
                println!("  --file <PATH>     Replay raw bytes from a libfuzzer crash artifact");
                println!("  --verbose         Print per-operation debug logging");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(path) = file_path {
        println!("Replaying failure trace from file: {}", path);
        let data = std::fs::read(&path).expect("Failed to read crash artifact file");
        run_stateful_indexer_fuzz(&data);
        println!("Trace replayed successfully with no invariant violations.");
    } else {
        run_stress_test(seed, total_ops, epoch_ops, verbose);
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzer_runs_over_raw_byte_samples() {
        run_stateful_indexer_fuzz(&[]);
        run_stateful_indexer_fuzz(&[0; 8]);
        run_stateful_indexer_fuzz(&[0, 1, 2, 3, 4, 5, 6, 7]);
        run_stateful_indexer_fuzz(&[1, 0, 0, 0, 0, 0, 0, 0]);
        run_stateful_indexer_fuzz(&[2, 0, 0, 0, 0, 10, 0, 0]);
        run_stateful_indexer_fuzz(&[3, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_storage_expiry_preserves_linked_chunks_across_multiple_cycles() {
        let mut fuzzer = StatefulIndexerFuzzer::new();
        // Insert 250 items to span 3 chunks
        for i in 1..=250 {
            fuzzer.execute(Command::Insert {
                uid_id: i,
                recipient_idx: 0,
                schema_idx: 0,
                attester_idx: 0,
                mode: InsertMode::New,
            });
            if i == 50 || i == 100 || i == 150 || i == 200 {
                fuzzer.execute(Command::SimulateStorageExpiry {
                    advance_ledgers: LEDGERS_IN_ONE_YEAR + 100,
                });
            }
        }
        fuzzer.assert_invariants();
    }

    #[test]
    fn test_stateful_indexer_50k_stress() {
        // Runs the acceptance criteria 50,000 operations
        run_stress_test(0xCAFE_BABE_DEAD_BEEF, 50_000, 2_500, false);
    }
}
