//! Canonical Merkle batch-attestation format (issue #179).
//!
//! Leaf hash:  sha256(0x00 || leaf_data)
//! Node hash:  sha256(0x01 || left || right), left/right ordered by byte value
//!             (smaller first) so proof verification doesn't need a
//!             left/right side indicator.
//! Odd level:  an unpaired node is promoted to the next level unchanged
//!             (not duplicated), so `merkle_root` and `verify_proof` agree.
//! Domain separation prefixes (0x00 leaf, 0x01 node) stop a leaf hash from
//! ever colliding with a node hash of the same bytes.

use soroban_sdk::{contracttype, Bytes, BytesN, Env, Vec};

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
    buf.push_back(0x00);
    buf.append(data);
    env.crypto().sha256(&buf).into()
}

fn node_hash(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    let (left, right) = if a.to_array() <= b.to_array() { (a, b) } else { (b, a) };
    let mut buf = Bytes::new(env);
    buf.push_back(0x01);
    buf.append(&Bytes::from_array(env, &left.to_array()));
    buf.append(&Bytes::from_array(env, &right.to_array()));
    env.crypto().sha256(&buf).into()
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

    while level.len() > 1 {
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let mut i = 0u32;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push_back(node_hash(env, &level.get(i).unwrap(), &level.get(i + 1).unwrap()));
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

/// Verifies that `leaf_data`, combined with `proof`, reproduces `root`.
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
