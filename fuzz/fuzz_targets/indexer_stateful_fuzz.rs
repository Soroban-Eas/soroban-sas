#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_indexer_test_support::{check_chunking, MAX_INSERTIONS};
use std::collections::{HashMap, HashSet, VecDeque};

const CHUNK_CAPACITY: usize = 50;

#[derive(Default)]
struct Oracle {
    per_key: HashMap<[u8; 4], VecDeque<[u8; 32]>>,
    uid_set: HashSet<[u8; 32]>,
}

impl Oracle {
    fn index_attestation(&mut self, key: [u8; 4], uid: [u8; 32]) {
        if !self.uid_set.insert(uid) { return; }
        self.per_key.entry(key).or_default().push_back(uid);
    }
    fn replace(&mut self, old_uid: [u8; 32], new_uid: [u8; 32]) {
        if !self.uid_set.contains(&old_uid) { return; }
        if self.uid_set.contains(&new_uid) { return; }
        for seq in self.per_key.values_mut() {
            if let Some(pos) = seq.iter().position(|x| x == &old_uid) {
                seq[pos] = new_uid;
                self.uid_set.remove(&old_uid);
                self.uid_set.insert(new_uid);
                break;
            }
        }
    }
    fn paginate(&self, key: &[u8; 4], start: usize, limit: usize) -> Vec<[u8; 32]> {
        self.per_key.get(key).map(|q| q.iter().skip(start).take(limit).cloned().collect()).unwrap_or_default()
    }
    fn assert_invariants(&self) {
        let mut seen = HashSet::new();
        for (key, seq) in &self.per_key {
            let len = seq.len();
            let chunks = (len + CHUNK_CAPACITY - 1) / CHUNK_CAPACITY;
            if chunks > 0 {
                assert!(len > (chunks - 1) * CHUNK_CAPACITY, "empty chunk {:?}", key);
            }
            for uid in seq {
                assert!(seen.insert(*uid), "corrupted pointer dup {:?}", uid);
                assert!(self.uid_set.contains(uid), "missing UID {:?}", uid);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut oracle = Oracle::default();
    let mut flat_pairs: Vec<([u8; 4], [u8; 32])> = Vec::new();
    let mut offset = 0;
    while offset + 37 <= data.len() && flat_pairs.len() < MAX_INSERTIONS * 4 {
        let op = data[offset] % 3;
        let key: [u8; 4] = data[offset+1..offset+5].try_into().unwrap();
        let uid: [u8; 32] = data[offset+5..offset+37].try_into().unwrap();
        offset += 37;
        match op {
            0 => { oracle.index_attestation(key, uid); flat_pairs.push((key, uid)); },
            1 => {
                if offset + 32 <= data.len() {
                    let new_uid: [u8; 32] = data[offset..offset+32].try_into().unwrap();
                    offset += 32;
                    oracle.replace(uid, new_uid);
                    for (_, u) in flat_pairs.iter_mut() { if u == &uid { *u = new_uid; break; } }
                }
            },
            2 => {
                let start = (uid[0] as usize) % 100;
                let limit = ((uid[1] % 20) + 1) as usize;
                let result = oracle.paginate(&key, start, limit);
                assert!(result.len() <= limit);
                if let Some(seq) = oracle.per_key.get(&key) {
                    let expected: Vec<_> = seq.iter().skip(start).take(limit).cloned().collect();
                    assert_eq!(result, expected, "pagination order mismatch");
                }
            },
            _ => {}
        }
        oracle.assert_invariants();
    }
    if !flat_pairs.is_empty() { check_chunking(&flat_pairs); }
    oracle.assert_invariants();
});
