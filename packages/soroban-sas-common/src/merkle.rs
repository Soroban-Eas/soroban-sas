//! Canonical Merkle batch-attestation format (issue #179) and the index-bound
//! variant used by SAS on-chain leaf verification (issue #529).
//!
//! ## Generic (unindexed) batches
//!
//! Leaf hash:  sha256(0x00 || leaf_data)
//! Node hash:  sha256(0x01 || left || right), left/right ordered by byte value
//!             (smaller first) so proof verification doesn't need a
//!             left/right side indicator.
//! Odd level:  an unpaired node is promoted to the next level unchanged
//!             (not duplicated), so `merkle_root` and `verify_proof` agree.
//! Domain separation prefixes (0x00 leaf, 0x01 node) stop a leaf hash from
//! ever colliding with a node hash of the same bytes.
//!
//! ## Index-bound attestation roots (`SAS::verify_merkle_leaf`)
//!
//! Merkle-root attestations commit to leaves together with their position:
//!
//! Leaf hash:  sha256(0x00 || index_be_u32 || leaf_data)
//!
//! Node hashing and odd-level promotion are identical to the generic format.
//! Binding the index into the leaf preimage means a valid inclusion proof
//! cannot be replayed for a different position, and a leaf cannot be moved
//! between indices without changing the root. The `0x00` / `0x01` domain
//! separation also prevents a proof from substituting an internal node for a
//! leaf (second-preimage resistance between the two hash domains), and the
//! fixed-width 4-byte index keeps the preimage unambiguous for any leaf
//! length.
//!
//! A Merkle-root attestation stores the root as the attestation's `data`
//! payload: exactly 32 raw bytes, with no prefix, encoding, or count. See
//! `docs/batch-attestations.md` for the full convention.

use soroban_sdk::{contracttype, Bytes, BytesN, Env, Vec};

/// Domain-separation tag prefixed to every hashed leaf.
pub const MERKLE_LEAF_PREFIX: u8 = 0x00;
/// Domain-separation tag prefixed to every hashed interior node.
pub const MERKLE_NODE_PREFIX: u8 = 0x01;
/// Exact byte length of a Merkle-root attestation payload (`Attestation.data`).
pub const MERKLE_ROOT_PAYLOAD_LEN: u32 = 32;
/// Maximum number of sibling steps accepted in one inclusion proof.
///
/// A proof of depth `d` supports up to `2^d` leaves; 32 steps therefore
/// supports the full `u32` index space at a fixed, small hashing budget.
/// Bounding the depth keeps a single `verify_merkle_leaf` call comfortably
/// below the Soroban instruction limit no matter what a caller submits.
pub const MAX_MERKLE_PROOF_DEPTH: u32 = 32;

/// Canonical schema string for a schema whose attestation payload is a
/// 32-byte Merkle root.
///
/// Registering this schema advertises the payload convention to off-chain
/// indexers and SDK consumers. It follows the registry's `type name` field
/// grammar (`bytes32` is the field type, `merkle_root` the field name), so it
/// passes `validate_schema_syntax` unchanged. The convention is advisory:
/// `SAS::verify_merkle_leaf` validates the 32-byte payload length directly
/// rather than performing a cross-contract schema lookup.
pub const MERKLE_ROOT_SCHEMA: &str = "bytes32 merkle_root";

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleRoot(pub BytesN<32>);

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchAttestation {
    pub root: MerkleRoot,
    pub count: u32,
}

/// One step of an inclusion proof: the sibling hash at that level.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProofStep {
    pub sibling: BytesN<32>,
}

fn leaf_hash(env: &Env, data: &Bytes) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.push_back(MERKLE_LEAF_PREFIX);
    buf.append(data);
    env.crypto().sha256(&buf).into()
}

/// Hashes `data` as the leaf at position `index` for the index-bound
/// attestation format:
/// `sha256(0x00 || index_be_u32 || data)`.
///
/// The index is fixed-width big-endian, so the preimage is unambiguous for
/// any leaf payload length. Off-chain tree builders must use this function
/// (or reproduce these exact bytes) for roots verified by
/// `SAS::verify_merkle_leaf`.
pub fn indexed_leaf_hash(env: &Env, index: u32, data: &Bytes) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.push_back(MERKLE_LEAF_PREFIX);
    buf.append(&Bytes::from_array(env, &index.to_be_bytes()));
    buf.append(data);
    env.crypto().sha256(&buf).into()
}

/// Hashes two child hashes into their parent:
/// `sha256(0x01 || smaller || larger)`.
///
/// Ordering the pair by raw byte value makes proof verification independent
/// of which side the sibling came from; the `0x01` prefix separates interior
/// nodes from leaves in the hash domain.
pub fn node_hash(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    let (left, right) = if a.to_array() <= b.to_array() {
        (a, b)
    } else {
        (b, a)
    };
    let mut buf = Bytes::new(env);
    buf.push_back(MERKLE_NODE_PREFIX);
    buf.append(&Bytes::from_array(env, &left.to_array()));
    buf.append(&Bytes::from_array(env, &right.to_array()));
    env.crypto().sha256(&buf).into()
}

/// Folds a bottom level up to its root, promoting odd nodes unchanged.
fn fold_root(env: &Env, mut level: Vec<BytesN<32>>) -> MerkleRoot {
    while level.len() > 1 {
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let mut i = 0u32;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push_back(node_hash(
                    env,
                    &level.get(i).unwrap(),
                    &level.get(i + 1).unwrap(),
                ));
            } else {
                // Odd node out: promote unchanged rather than duplicating it.
                next.push_back(level.get(i).unwrap());
            }
            i += 2;
        }
        level = next;
    }

    MerkleRoot(level.get(0).unwrap())
}

/// Builds the Merkle root over `leaves` (raw, unhashed leaf data). Duplicate
/// leaves are hashed and combined like any other value — callers that need
/// leaf uniqueness must enforce it themselves before calling this. An empty
/// input has no defined root; callers must not call this with zero leaves.
pub fn merkle_root(env: &Env, leaves: &Vec<Bytes>) -> MerkleRoot {
    let mut level: Vec<BytesN<32>> = Vec::new(env);
    for leaf in leaves.iter() {
        level.push_back(leaf_hash(env, &leaf));
    }
    fold_root(env, level)
}

/// Builds an index-bound Merkle root over `leaves`.
///
/// Leaf `i` is hashed as `indexed_leaf_hash(i, leaves[i])`; interior nodes
/// and odd-level promotion match the generic format. This is the tree format
/// `SAS::verify_merkle_leaf` verifies. An empty input has no defined root.
pub fn indexed_merkle_root(env: &Env, leaves: &Vec<Bytes>) -> MerkleRoot {
    let mut level: Vec<BytesN<32>> = Vec::new(env);
    for (index, leaf) in leaves.iter().enumerate() {
        level.push_back(indexed_leaf_hash(env, index as u32, &leaf));
    }
    fold_root(env, level)
}

/// Verifies that `leaf_data`, combined with `proof`, reproduces `root` under
/// the generic (unindexed) leaf format.
pub fn verify_proof(
    env: &Env,
    root: &MerkleRoot,
    leaf_data: &Bytes,
    proof: &Vec<MerkleProofStep>,
) -> bool {
    let mut current = leaf_hash(env, leaf_data);
    for step in proof.iter() {
        current = node_hash(env, &current, &step.sibling);
    }
    current == root.0
}

/// Verifies that `leaf_data` is the leaf at position `index` in `root` under
/// the index-bound attestation format.
///
/// Returns `false` (rather than panicking) for any mismatch, including a
/// tampered leaf, tampered sibling, wrong index, or a proof deeper than
/// [`MAX_MERKLE_PROOF_DEPTH`]. Because node hashing sorts its inputs, the
/// proof's steps need no left/right flags; the index is authenticated
/// cryptographically through the leaf preimage.
pub fn verify_indexed_proof(
    env: &Env,
    root: &MerkleRoot,
    index: u32,
    leaf_data: &Bytes,
    proof: &Vec<MerkleProofStep>,
) -> bool {
    if proof.len() > MAX_MERKLE_PROOF_DEPTH {
        return false;
    }

    let mut current = indexed_leaf_hash(env, index, leaf_data);
    for step in proof.iter() {
        current = node_hash(env, &current, &step.sibling);
    }
    current == root.0
}

/// Interprets an attestation's `data` payload as a Merkle root using the SAS
/// payload convention: exactly [`MERKLE_ROOT_PAYLOAD_LEN`] raw bytes.
///
/// Returns `None` for any other length, so a helper can reject a
/// non-Merkle payload without panicking or guessing at an encoding.
pub fn merkle_root_from_payload(env: &Env, data: &Bytes) -> Option<MerkleRoot> {
    if data.len() != MERKLE_ROOT_PAYLOAD_LEN {
        return None;
    }
    let mut buf = [0u8; MERKLE_ROOT_PAYLOAD_LEN as usize];
    data.copy_into_slice(&mut buf);
    Some(MerkleRoot(BytesN::from_array(env, &buf)))
}
