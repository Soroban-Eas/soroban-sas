//! Tests for hash-agnostic Merkle inclusion proofs (issue #435).
//!
//! The fixed vectors below were produced by an independent Python
//! implementation of the documented tree (leaf = H(0x00 || data),
//! node = H(0x01 || min(l, r) || max(l, r)), odd node promoted unchanged), so
//! they check the contract-side verifier against code that shares nothing with
//! it. The generated-tree tests then sweep every leaf of every tree size from
//! 1 to 9 leaves, which covers single-leaf and odd-leaf-count shapes.

extern crate alloc;

use alloc::vec::Vec as StdVec;

use crate::merkle::{merkle_root, verify_proof_with, MerkleHash, MAX_MERKLE_PROOF_DEPTH};
use soroban_sdk::{Bytes, BytesN, Env, Vec};

const LEAVES: [&[u8]; 5] = [
    b"kyc:level=3",
    b"country=NG",
    b"accredited=true",
    b"age>=18",
    b"residency=GB",
];

const SHA_ROOT: &str = "211abc903daf3486cf347a01935392f1c526f7dacc089d62a026cca136a7a96d";
const SHA_PROOF_0: [&str; 3] = [
    "3c255eab0d473d225ac8a482d1daf39449242d4d14dadad759daa01f3592cb53",
    "8b99e0895cf51e18b54be281629fde82e959f588c187b25fbc38fdbe383aa60b",
    "ba06645adfc22fb462bebca1a8d7ecd98b73655b82a720bd4e992f48074a6cfa",
];
const SHA_PROOF_2: [&str; 3] = [
    "96529c4cfd165643fea61c303813854e6966d52c8f3c6c4bf7d98b1d6937f4c8",
    "ef822dd0513ef01ef5d6f9c88689c700f7ec53e2d36d34b82bf223a770be9e76",
    "ba06645adfc22fb462bebca1a8d7ecd98b73655b82a720bd4e992f48074a6cfa",
];
// Leaf 4 is the odd one out: it is promoted past two levels, so its proof has
// a single sibling.
const SHA_PROOF_4: [&str; 1] = ["002986a105ad6f154512529872c89828b31067fdd140940e3bf3298e8c6947da"];

const KECCAK_ROOT: &str = "2b81c85a3211a197a94b13bea775c931934a166fc84575af87d09aabb9455e66";
const KECCAK_PROOF_0: [&str; 3] = [
    "23ec60633adb84d0a26ae0bf40502e6b35bd339f156a9ce2639f36c612191107",
    "cd51e9183a7a2747f9b766d25c74b23a5c535218a7094ce3b5571c2656e99dad",
    "e15908cb10e33e8e863aaca9ae6e65d5650a42ba477aa0a4ac7cd3b70403cc30",
];
const KECCAK_PROOF_2: [&str; 3] = [
    "258eba2a0c1c430a5972f3fb1ff87904011e2253634a6a88ef6e00b0a08e5df8",
    "7897af054285b9e4155d48ffba74ae845396812ca63fa021bbc9f851b599a29a",
    "e15908cb10e33e8e863aaca9ae6e65d5650a42ba477aa0a4ac7cd3b70403cc30",
];
const KECCAK_PROOF_4: [&str; 1] =
    ["218eb4be9a29dca0d548923e8690526bf134e73f85d563f552ed18b138599289"];

fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not a lowercase hex digit"),
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert_eq!(b.len(), 64);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
    }
    out
}

fn root_of(env: &Env, hex: &str) -> BytesN<32> {
    BytesN::from_array(env, &hex32(hex))
}

fn proof_of(env: &Env, hexes: &[&str]) -> Vec<BytesN<32>> {
    let mut proof = Vec::new(env);
    for hex in hexes {
        proof.push_back(BytesN::from_array(env, &hex32(hex)));
    }
    proof
}

fn leaf(env: &Env, i: usize) -> Bytes {
    Bytes::from_slice(env, LEAVES[i])
}

/// Hashes the concatenation of `parts` with `algo`.
fn h(env: &Env, algo: MerkleHash, parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Bytes::new(env);
    for p in parts {
        buf.append(&Bytes::from_slice(env, p));
    }
    let digest: BytesN<32> = match algo {
        MerkleHash::Sha256 => env.crypto().sha256(&buf).into(),
        MerkleHash::Keccak256 => env.crypto().keccak256(&buf).into(),
    };
    digest.to_array()
}

/// Independent tree builder: every level, leaf hashes first, root last.
fn levels(env: &Env, algo: MerkleHash, leaves: &[&[u8]]) -> StdVec<StdVec<[u8; 32]>> {
    let mut current: StdVec<[u8; 32]> = leaves
        .iter()
        .map(|l| h(env, algo, &[&[0u8][..], *l]))
        .collect();
    let mut all = StdVec::new();
    all.push(current.clone());
    while current.len() > 1 {
        let mut next = StdVec::new();
        for pair in current.chunks(2) {
            if pair.len() == 2 {
                let (a, b) = if pair[0] <= pair[1] {
                    (pair[0], pair[1])
                } else {
                    (pair[1], pair[0])
                };
                next.push(h(env, algo, &[&[1u8][..], &a[..], &b[..]]));
            } else {
                next.push(pair[0]);
            }
        }
        all.push(next.clone());
        current = next;
    }
    all
}

fn proof_for(env: &Env, tree: &[StdVec<[u8; 32]>], mut index: usize) -> Vec<BytesN<32>> {
    let mut proof = Vec::new(env);
    for level in &tree[..tree.len() - 1] {
        let sibling = index ^ 1;
        if sibling < level.len() {
            proof.push_back(BytesN::from_array(env, &level[sibling]));
        }
        index /= 2;
    }
    proof
}

#[test]
fn sha256_vectors_verify_for_first_middle_and_odd_leaf() {
    let env = Env::default();
    let root = root_of(&env, SHA_ROOT);
    for (i, p) in [
        (0usize, &SHA_PROOF_0[..]),
        (2, &SHA_PROOF_2[..]),
        (4, &SHA_PROOF_4[..]),
    ] {
        assert!(
            verify_proof_with(
                &env,
                MerkleHash::Sha256,
                &root,
                &leaf(&env, i),
                &proof_of(&env, p)
            ),
            "leaf {i} must verify"
        );
    }
}

#[test]
fn keccak256_vectors_verify_for_first_middle_and_odd_leaf() {
    let env = Env::default();
    let root = root_of(&env, KECCAK_ROOT);
    for (i, p) in [
        (0usize, &KECCAK_PROOF_0[..]),
        (2, &KECCAK_PROOF_2[..]),
        (4, &KECCAK_PROOF_4[..]),
    ] {
        assert!(
            verify_proof_with(
                &env,
                MerkleHash::Keccak256,
                &root,
                &leaf(&env, i),
                &proof_of(&env, p)
            ),
            "leaf {i} must verify"
        );
    }
}

#[test]
fn a_proof_never_verifies_under_the_other_hash_function() {
    let env = Env::default();
    assert!(!verify_proof_with(
        &env,
        MerkleHash::Keccak256,
        &root_of(&env, SHA_ROOT),
        &leaf(&env, 0),
        &proof_of(&env, &SHA_PROOF_0)
    ));
    assert!(!verify_proof_with(
        &env,
        MerkleHash::Sha256,
        &root_of(&env, KECCAK_ROOT),
        &leaf(&env, 0),
        &proof_of(&env, &KECCAK_PROOF_0)
    ));
}

#[test]
fn tampered_leaf_sibling_or_root_is_rejected() {
    let env = Env::default();
    let root = root_of(&env, SHA_ROOT);
    let proof = proof_of(&env, &SHA_PROOF_0);
    let algo = MerkleHash::Sha256;

    assert!(verify_proof_with(&env, algo, &root, &leaf(&env, 0), &proof));

    // A leaf that was never committed to.
    let forged = Bytes::from_slice(&env, b"kyc:level=4");
    assert!(!verify_proof_with(&env, algo, &root, &forged, &proof));

    // One flipped bit in a sibling.
    let mut sibling = hex32(SHA_PROOF_0[1]);
    sibling[31] ^= 1;
    let mut tampered = proof.clone();
    tampered.set(1, BytesN::from_array(&env, &sibling));
    assert!(!verify_proof_with(
        &env,
        algo,
        &root,
        &leaf(&env, 0),
        &tampered
    ));

    // A root that was never attested.
    let mut wrong_root = hex32(SHA_ROOT);
    wrong_root[0] ^= 1;
    assert!(!verify_proof_with(
        &env,
        algo,
        &BytesN::from_array(&env, &wrong_root),
        &leaf(&env, 0),
        &proof
    ));
}

#[test]
fn proof_for_another_position_is_rejected() {
    let env = Env::default();
    let root = root_of(&env, SHA_ROOT);
    let algo = MerkleHash::Sha256;

    // The proof for leaf 2 does not open leaf 0, and vice versa: the
    // position a prover claims is implied by the proof, so a wrong "index"
    // can only be expressed as a wrong leaf/proof pairing.
    assert!(!verify_proof_with(
        &env,
        algo,
        &root,
        &leaf(&env, 0),
        &proof_of(&env, &SHA_PROOF_2)
    ));
    assert!(!verify_proof_with(
        &env,
        algo,
        &root,
        &leaf(&env, 2),
        &proof_of(&env, &SHA_PROOF_0)
    ));
    assert!(!verify_proof_with(
        &env,
        algo,
        &root,
        &leaf(&env, 4),
        &proof_of(&env, &SHA_PROOF_0)
    ));
}

#[test]
fn reordered_truncated_and_extended_proofs_are_rejected() {
    let env = Env::default();
    let root = root_of(&env, SHA_ROOT);
    let algo = MerkleHash::Sha256;
    let good = proof_of(&env, &SHA_PROOF_0);

    let mut swapped = Vec::new(&env);
    swapped.push_back(good.get(1).unwrap());
    swapped.push_back(good.get(0).unwrap());
    swapped.push_back(good.get(2).unwrap());
    assert!(!verify_proof_with(
        &env,
        algo,
        &root,
        &leaf(&env, 0),
        &swapped
    ));

    let mut truncated = good.clone();
    let _ = truncated.pop_back();
    assert!(!verify_proof_with(
        &env,
        algo,
        &root,
        &leaf(&env, 0),
        &truncated
    ));

    let mut extended = good.clone();
    extended.push_back(good.get(0).unwrap());
    assert!(!verify_proof_with(
        &env,
        algo,
        &root,
        &leaf(&env, 0),
        &extended
    ));

    // An empty proof only opens a single-leaf tree.
    assert!(!verify_proof_with(
        &env,
        algo,
        &root,
        &leaf(&env, 0),
        &Vec::new(&env)
    ));
}

#[test]
fn single_leaf_tree_opens_with_an_empty_proof_only() {
    let env = Env::default();
    let one = leaf(&env, 0);
    let mut leaves = Vec::new(&env);
    leaves.push_back(one.clone());
    let root = merkle_root(&env, &leaves).0;

    assert!(verify_proof_with(
        &env,
        MerkleHash::Sha256,
        &root,
        &one,
        &Vec::new(&env)
    ));

    let mut padded = Vec::new(&env);
    padded.push_back(root.clone());
    assert!(!verify_proof_with(
        &env,
        MerkleHash::Sha256,
        &root,
        &one,
        &padded
    ));
}

#[test]
fn a_leaf_cannot_be_replaced_by_an_interior_node() {
    let env = Env::default();
    let algo = MerkleHash::Sha256;
    let tree = levels(&env, algo, &LEAVES[..4]);
    let root = BytesN::from_array(&env, &tree.last().unwrap()[0]);

    // Second-preimage attempt: present the concatenation of the two interior
    // hashes just below the root as if it were a leaf of a one-leaf tree. The
    // 0x00 / 0x01 domain prefixes make the hashes differ, so it cannot open
    // the real root.
    let mut fake = Bytes::new(&env);
    fake.append(&Bytes::from_array(&env, &tree[tree.len() - 2][0]));
    fake.append(&Bytes::from_array(&env, &tree[tree.len() - 2][1]));
    assert!(!verify_proof_with(
        &env,
        algo,
        &root,
        &fake,
        &Vec::new(&env)
    ));
}

#[test]
fn over_long_proofs_are_rejected_without_hashing() {
    let env = Env::default();
    let root = root_of(&env, SHA_ROOT);
    let mut proof = Vec::new(&env);
    for _ in 0..=MAX_MERKLE_PROOF_DEPTH {
        proof.push_back(root.clone());
    }
    assert_eq!(proof.len(), MAX_MERKLE_PROOF_DEPTH + 1);
    assert!(!verify_proof_with(
        &env,
        MerkleHash::Sha256,
        &root,
        &leaf(&env, 0),
        &proof
    ));
}

#[test]
fn every_leaf_of_every_tree_size_up_to_nine_verifies_under_both_hashes() {
    let env = Env::default();
    let all: [&[u8]; 9] = [
        b"a=1", b"b=2", b"c=3", b"d=4", b"e=5", b"f=6", b"g=7", b"h=8", b"i=9",
    ];
    for algo in [MerkleHash::Sha256, MerkleHash::Keccak256] {
        for n in 1..=all.len() {
            let leaves = &all[..n];
            let tree = levels(&env, algo, leaves);
            let root = BytesN::from_array(&env, &tree.last().unwrap()[0]);

            if algo == MerkleHash::Sha256 {
                // The on-chain tree builder and the independent one agree.
                let mut raw = Vec::new(&env);
                for l in leaves {
                    raw.push_back(Bytes::from_slice(&env, l));
                }
                assert_eq!(merkle_root(&env, &raw).0, root, "root mismatch at n={n}");
            }

            for (i, leaf_bytes) in leaves.iter().enumerate() {
                let data = Bytes::from_slice(&env, leaf_bytes);
                let proof = proof_for(&env, &tree, i);
                assert!(
                    verify_proof_with(&env, algo, &root, &data, &proof),
                    "leaf {i} of {n} must verify"
                );

                // Every other leaf of the same tree must fail with this proof.
                for (j, other_bytes) in leaves.iter().enumerate() {
                    if j != i {
                        let other = Bytes::from_slice(&env, other_bytes);
                        assert!(
                            !verify_proof_with(&env, algo, &root, &other, &proof),
                            "proof for leaf {i} must not open leaf {j} (n={n})"
                        );
                    }
                }
            }
        }
    }
}
