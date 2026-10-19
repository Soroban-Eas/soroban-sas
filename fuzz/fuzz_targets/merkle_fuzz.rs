//! Fuzz test for the canonical Merkle batch-attestation format
//! (`soroban-sas-common::merkle`).
//!
//! Properties verified on every fuzz input:
//!
//! 1. **Determinism** – `merkle_root` of the same leaves always returns the
//!    same root.
//! 2. **Round-trip consistency** – every leaf that was included in the tree
//!    verifies with `verify_proof` against the root, using an inclusion proof
//!    derived by replaying the canonical tree construction.
//! 3. **Single-leaf root** – a single leaf's root equals `sha256(0x00 || data)`.
//! 4. **Non-membership rejection** – a proof for leaf `i` does NOT verify
//!    for a different leaf at the same position.
//!
//! The fuzz harness never panics regardless of input shape or byte contents.
#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::{merkle_root, verify_proof, MerkleProofStep};
use soroban_sdk::{Bytes, BytesN, Env, Vec as SorobanVec};

/// Maximum number of leaves to exercise per fuzz run.  Kept small so the
/// O(n log n) tree construction stays fast enough for the fuzzer's inner loop.
const MAX_LEAVES: usize = 16;
/// Fixed leaf size parsed from the fuzz input stream.
const LEAF_SIZE: usize = 16;

fuzz_target!(|data: &[u8]| {
    if data.len() < LEAF_SIZE {
        return;
    }

    let env = Env::default();

    // Parse raw bytes into a list of leaf payloads.
    let raw_leaves: Vec<&[u8]> = data.chunks_exact(LEAF_SIZE).take(MAX_LEAVES).collect();
    if raw_leaves.is_empty() {
        return;
    }

    // Build a Soroban Vec<Bytes> for merkle_root.
    let mut soroban_leaves: SorobanVec<Bytes> = SorobanVec::new(&env);
    for raw in &raw_leaves {
        soroban_leaves.push_back(Bytes::from_slice(&env, raw));
    }

    // ── Property 1: Determinism ──────────────────────────────────────────────
    let root1 = merkle_root(&env, &soroban_leaves);
    let root2 = merkle_root(&env, &soroban_leaves);
    assert_eq!(
        root1.0.to_array(),
        root2.0.to_array(),
        "merkle_root must be deterministic"
    );

    // ── Property 3: Single-leaf root equals sha256(0x00 || leaf_data) ────────
    if raw_leaves.len() == 1 {
        let leaf_bytes = Bytes::from_slice(&env, raw_leaves[0]);
        let mut buf = Bytes::new(&env);
        buf.push_back(0x00u8);
        buf.append(&leaf_bytes);
        let expected: BytesN<32> = env.crypto().sha256(&buf).into();
        assert_eq!(
            root1.0.to_array(),
            expected.to_array(),
            "single-leaf root must equal sha256(0x00 || leaf_data)"
        );
    }

    // ── Properties 2 & 4: Round-trip and non-membership ──────────────────────
    let proofs = build_proofs(&env, &raw_leaves);

    for (i, raw_leaf) in raw_leaves.iter().enumerate() {
        let leaf_bytes = Bytes::from_slice(&env, raw_leaf);

        // ── Property 2 ───────────────────────────────────────────────────────
        assert!(
            verify_proof(&env, &root1, &leaf_bytes, &proofs[i]),
            "leaf {} must verify against the root it was included in",
            i
        );

        // ── Property 4 ───────────────────────────────────────────────────────
        // A proof for leaf i must NOT verify for a genuinely different leaf.
        if raw_leaves.len() > 1 {
            let j = (i + 1) % raw_leaves.len();
            if raw_leaves[i] != raw_leaves[j] {
                let other_leaf = Bytes::from_slice(&env, raw_leaves[j]);
                assert!(
                    !verify_proof(&env, &root1, &other_leaf, &proofs[i]),
                    "proof for leaf {} must not verify a different leaf {}",
                    i,
                    j
                );
            }
        }
    }
});

// ── Proof builder ─────────────────────────────────────────────────────────────
//
// Mirrors the exact algorithm of `merkle_root` (leaf hash: 0x00 prefix,
// node hash: 0x01 prefix, min-first ordering, odd-node promotion) to
// record, for each leaf, the sibling hashes at every level.

fn leaf_hash_raw(env: &Env, data: &[u8]) -> [u8; 32] {
    let d = Bytes::from_slice(env, data);
    let mut buf = Bytes::new(env);
    buf.push_back(0x00u8);
    buf.append(&d);
    env.crypto().sha256(&buf).to_array()
}

fn node_hash_raw(env: &Env, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (left, right) = if a <= b { (a, b) } else { (b, a) };
    let mut buf = Bytes::new(env);
    buf.push_back(0x01u8);
    buf.append(&Bytes::from_slice(env, left));
    buf.append(&Bytes::from_slice(env, right));
    env.crypto().sha256(&buf).to_array()
}

/// For each leaf index, return its inclusion proof as a `Vec<MerkleProofStep>`
/// (one step per level above the leaf, up to but not including the root).
fn build_proofs(env: &Env, leaves: &[&[u8]]) -> Vec<SorobanVec<MerkleProofStep>> {
    let n = leaves.len();
    // Each leaf tracks its current position in the level being processed.
    let mut positions: Vec<usize> = (0..n).collect();

    // Compute the initial level of leaf hashes.
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|raw| leaf_hash_raw(env, raw)).collect();

    // For each leaf we accumulate sibling hashes encountered on its path.
    let mut paths: Vec<Vec<[u8; 32]>> = vec![Vec::new(); n];

    while level.len() > 1 {
        let mut next_level: Vec<[u8; 32]> = Vec::new();
        let level_len = level.len();

        // New positions for each leaf in the next (contracted) level.
        let mut next_positions: Vec<usize> = vec![0usize; n];

        let mut i = 0usize;
        while i < level_len {
            if i + 1 < level_len {
                // Paired nodes: each is the sibling of the other.
                let left = level[i];
                let right = level[i + 1];
                let parent = node_hash_raw(env, &left, &right);
                let parent_pos = next_level.len();
                next_level.push(parent);

                // Record siblings for any leaf currently at positions i or i+1.
                for leaf_idx in 0..n {
                    if positions[leaf_idx] == i {
                        paths[leaf_idx].push(right);
                        next_positions[leaf_idx] = parent_pos;
                    } else if positions[leaf_idx] == i + 1 {
                        paths[leaf_idx].push(left);
                        next_positions[leaf_idx] = parent_pos;
                    }
                }
            } else {
                // Odd node: promoted unchanged, no sibling.
                let promoted = level[i];
                let promoted_pos = next_level.len();
                next_level.push(promoted);

                for leaf_idx in 0..n {
                    if positions[leaf_idx] == i {
                        // No sibling at this level — the node is promoted as-is.
                        next_positions[leaf_idx] = promoted_pos;
                    }
                }
            }
            i += 2;
        }

        level = next_level;
        positions = next_positions;
    }

    // Convert the accumulated path vectors to Soroban `Vec<MerkleProofStep>`.
    paths
        .iter()
        .map(|sibs| {
            let mut v: SorobanVec<MerkleProofStep> = SorobanVec::new(env);
            for sib in sibs {
                v.push_back(MerkleProofStep {
                    sibling: BytesN::from_array(env, sib),
                });
            }
            v
        })
        .collect()
}
