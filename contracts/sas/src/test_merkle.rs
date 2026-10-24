//! Tests for off-chain Merkle root attestations with on-chain leaf
//! verification (issue #529).
//!
//! A Merkle-root attestation stores exactly one 32-byte root as its `data`
//! payload. `SAS::verify_merkle_leaf(uid, leaf, proof, index)` checks that a
//! disclosed leaf sits at `index` under that root, but only while the parent
//! attestation is live: issued, not revoked, not expired, and past its
//! `valid_from` activation time.

use crate::{SASClient, SAS};
use soroban_sas_common::{
    attestation_uid, indexed_leaf_hash, indexed_merkle_root, node_hash, Attestation,
    MerkleProofStep, SchemaRecord, UID,
};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, BytesN, Env, String as SorobanString, Vec,
};

#[contract]
struct MockRegistry;

#[contractimpl]
impl MockRegistry {
    pub fn on_attest(_env: Env, _attestation: Attestation) {}

    pub fn on_revoke(_env: Env, _attestation: Attestation) {}

    pub fn is_authorized(_env: Env, _uid: UID, _attester: Address) -> bool {
        true
    }

    #[allow(non_snake_case)]
    pub fn SASREG(_env: Env) -> bool {
        true
    }

    pub fn get_schema(env: Env, uid: UID) -> Option<SchemaRecord> {
        Some(SchemaRecord {
            uid,
            resolver: env.current_contract_address(),
            revocable: true,
            schema: SorobanString::from_str(&env, soroban_sas_common::MERKLE_ROOT_SCHEMA),
            deprecated: false,
        })
    }
}

const NOW: u64 = 1_000;

fn setup(env: &Env) -> SASClient<'_> {
    let registry_id = env.register_contract(None, MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let client = SASClient::new(env, &sas_id);
    let admin = Address::generate(env);

    env.mock_all_auths();
    env.ledger().with_mut(|li| li.timestamp = NOW);
    client.init(&admin, &registry_id);
    client
}

fn schema_uid(env: &Env) -> UID {
    UID(BytesN::from_array(env, &[9u8; 32]))
}

fn leaves(env: &Env) -> Vec<Bytes> {
    Vec::from_array(
        env,
        [
            Bytes::from_slice(env, b"alice"),
            Bytes::from_slice(env, b"bob"),
            Bytes::from_slice(env, b"carol"),
            Bytes::from_slice(env, b"dave"),
            Bytes::from_slice(env, b"erin"),
        ],
    )
}

/// Builds the level-by-level indexed tree so tests can read off inclusion
/// proofs independently of `indexed_merkle_root`.
fn tree_levels(env: &Env, leaves: &Vec<Bytes>) -> Vec<Vec<BytesN<32>>> {
    let mut levels: Vec<Vec<BytesN<32>>> = Vec::new(env);
    let mut level: Vec<BytesN<32>> = Vec::new(env);
    for (index, leaf) in leaves.iter().enumerate() {
        level.push_back(indexed_leaf_hash(env, index as u32, &leaf));
    }
    levels.push_back(level.clone());

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
                next.push_back(level.get(i).unwrap());
            }
            i += 2;
        }
        levels.push_back(next.clone());
        level = next;
    }
    levels
}

/// Returns the sibling path for the leaf at `index`. A promoted (odd) node
/// contributes no step at that level.
fn proof_for(env: &Env, levels: &Vec<Vec<BytesN<32>>>, mut index: u32) -> Vec<MerkleProofStep> {
    let mut proof: Vec<MerkleProofStep> = Vec::new(env);
    for depth in 0..levels.len() - 1 {
        let level = levels.get(depth).unwrap();
        let sibling = if index % 2 == 0 {
            if index + 1 < level.len() {
                Some(index + 1)
            } else {
                None
            }
        } else {
            Some(index - 1)
        };
        if let Some(sibling_index) = sibling {
            proof.push_back(MerkleProofStep {
                sibling: level.get(sibling_index).unwrap(),
            });
        }
        index /= 2;
    }
    proof
}

/// Issues a Merkle-root attestation whose payload is `payload`, returning the
/// UID the contract stored it under.
fn issue(
    env: &Env,
    client: &SASClient<'_>,
    attester: &Address,
    recipient: &Address,
    payload: Bytes,
    expiration_time: u64,
    valid_from: u64,
) -> UID {
    let schema = schema_uid(env);
    let uid = attestation_uid(env, &schema, recipient, attester, &payload);
    client.attest(&Attestation {
        uid: uid.clone(),
        schema_uid: schema,
        time: NOW,
        expiration_time,
        valid_from,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: payload,
    });
    uid
}

#[test]
fn valid_proofs_verify_for_every_leaf_position() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaves = leaves(&env);
    let root = indexed_merkle_root(&env, &leaves);
    let levels = tree_levels(&env, &leaves);
    assert_eq!(
        root.0,
        levels.get(levels.len() - 1).unwrap().get(0).unwrap()
    );

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        0,
        0,
    );

    for index in 0..leaves.len() {
        let proof = proof_for(&env, &levels, index);
        assert!(
            client.verify_indexed_merkle_leaf(&uid, &leaves.get(index).unwrap(), &proof, &index),
            "leaf {index} must verify against its own proof"
        );
    }
}

#[test]
fn single_leaf_tree_verifies_with_an_empty_proof() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaf = Bytes::from_slice(&env, b"only-leaf");
    let single = Vec::from_array(&env, [leaf.clone()]);
    let root = indexed_merkle_root(&env, &single);

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        0,
        0,
    );

    let empty: Vec<MerkleProofStep> = Vec::new(&env);
    assert!(client.verify_indexed_merkle_leaf(&uid, &leaf, &empty, &0));
    // The same singleton tree has no leaf at index 1.
    assert!(!client.verify_indexed_merkle_leaf(&uid, &leaf, &empty, &1));
}

#[test]
fn tampered_leaf_fails() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaves = leaves(&env);
    let root = indexed_merkle_root(&env, &leaves);
    let levels = tree_levels(&env, &leaves);

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        0,
        0,
    );

    let index = 1u32;
    let proof = proof_for(&env, &levels, index);
    assert!(client.verify_indexed_merkle_leaf(&uid, &leaves.get(index).unwrap(), &proof, &index));
    assert!(!client.verify_indexed_merkle_leaf(&uid, &Bytes::from_slice(&env, b"bobby"), &proof, &index));
}

#[test]
fn tampered_sibling_fails() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaves = leaves(&env);
    let root = indexed_merkle_root(&env, &leaves);
    let levels = tree_levels(&env, &leaves);

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        0,
        0,
    );

    let index = 2u32;
    let proof = proof_for(&env, &levels, index);
    let first = proof.get(0).unwrap();
    let mut tampered = first.sibling.to_array();
    tampered[0] ^= 0xFF;
    let mut bad_proof: Vec<MerkleProofStep> = Vec::new(&env);
    bad_proof.push_back(MerkleProofStep {
        sibling: BytesN::from_array(&env, &tampered),
    });
    for step in proof.iter().skip(1) {
        bad_proof.push_back(step);
    }

    assert!(!client.verify_indexed_merkle_leaf(&uid, &leaves.get(index).unwrap(), &bad_proof, &index));
}

#[test]
fn incorrect_index_fails() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaves = leaves(&env);
    let root = indexed_merkle_root(&env, &leaves);
    let levels = tree_levels(&env, &leaves);

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        0,
        0,
    );

    // A proof that is valid for position 2 must not verify at position 3.
    let proof = proof_for(&env, &levels, 2);
    assert!(!client.verify_indexed_merkle_leaf(&uid, &leaves.get(2).unwrap(), &proof, &3));
}

#[test]
fn proof_against_a_different_root_fails() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaves = leaves(&env);
    let levels = tree_levels(&env, &leaves);

    // Commit to a different set, then present a proof from the original set.
    let other = Vec::from_array(
        &env,
        [
            Bytes::from_slice(&env, b"alice"),
            Bytes::from_slice(&env, b"bob"),
        ],
    );
    let other_root = indexed_merkle_root(&env, &other);
    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &other_root.0.to_array()),
        0,
        0,
    );

    let proof = proof_for(&env, &levels, 1);
    assert!(!client.verify_indexed_merkle_leaf(&uid, &leaves.get(1).unwrap(), &proof, &1));
}

#[test]
fn revoked_parent_invalidates_leaf_verification() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaves = leaves(&env);
    let root = indexed_merkle_root(&env, &leaves);
    let levels = tree_levels(&env, &leaves);

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        0,
        0,
    );
    let index = 0u32;
    let proof = proof_for(&env, &levels, index);
    assert!(client.verify_indexed_merkle_leaf(&uid, &leaves.get(index).unwrap(), &proof, &index));

    client.revoke(&uid);

    assert!(!client.verify_indexed_merkle_leaf(&uid, &leaves.get(index).unwrap(), &proof, &index));
}

#[test]
fn expired_parent_invalidates_leaf_verification() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaves = leaves(&env);
    let root = indexed_merkle_root(&env, &leaves);
    let levels = tree_levels(&env, &leaves);

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        NOW + 100,
        0,
    );
    let index = 3u32;
    let proof = proof_for(&env, &levels, index);
    assert!(client.verify_indexed_merkle_leaf(&uid, &leaves.get(index).unwrap(), &proof, &index));

    env.ledger().with_mut(|li| li.timestamp = NOW + 100);

    assert!(!client.verify_indexed_merkle_leaf(&uid, &leaves.get(index).unwrap(), &proof, &index));
}

#[test]
fn not_yet_valid_parent_invalidates_leaf_verification() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaves = leaves(&env);
    let root = indexed_merkle_root(&env, &leaves);
    let levels = tree_levels(&env, &leaves);

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        0,
        NOW + 100,
    );
    let index = 4u32;
    let proof = proof_for(&env, &levels, index);
    assert!(!client.verify_indexed_merkle_leaf(&uid, &leaves.get(index).unwrap(), &proof, &index));

    env.ledger().with_mut(|li| li.timestamp = NOW + 100);

    assert!(client.verify_indexed_merkle_leaf(&uid, &leaves.get(index).unwrap(), &proof, &index));
}

#[test]
fn unknown_attestation_fails() {
    let env = Env::default();
    let client = setup(&env);
    let leaf = Bytes::from_slice(&env, b"alice");
    let proof: Vec<MerkleProofStep> = Vec::new(&env);
    let unknown = UID(BytesN::from_array(&env, &[0x42u8; 32]));

    assert!(!client.verify_indexed_merkle_leaf(&unknown, &leaf, &proof, &0));
}

#[test]
fn non_root_payload_fails() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let payload = Bytes::from_slice(&env, b"not-a-32-byte-merkle-root");
    let uid = issue(&env, &client, &attester, &recipient, payload.clone(), 0, 0);
    let proof: Vec<MerkleProofStep> = Vec::new(&env);

    assert!(!client.verify_indexed_merkle_leaf(&uid, &payload, &proof, &0));
}

#[test]
fn oversized_proof_fails_without_panicking() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaf = Bytes::from_slice(&env, b"alice");
    let single = Vec::from_array(&env, [leaf.clone()]);
    let root = indexed_merkle_root(&env, &single);

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        0,
        0,
    );

    let mut proof: Vec<MerkleProofStep> = Vec::new(&env);
    for _ in 0..(soroban_sas_common::MAX_MERKLE_PROOF_DEPTH + 1) {
        proof.push_back(MerkleProofStep {
            sibling: BytesN::from_array(&env, &[0x7Fu8; 32]),
        });
    }

    assert!(!client.verify_indexed_merkle_leaf(&uid, &leaf, &proof, &0));
}

#[test]
fn empty_proof_fails_for_a_multi_leaf_root() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let leaves = leaves(&env);
    let root = indexed_merkle_root(&env, &leaves);

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &root.0.to_array()),
        0,
        0,
    );
    let empty: Vec<MerkleProofStep> = Vec::new(&env);

    assert!(!client.verify_indexed_merkle_leaf(&uid, &leaves.get(0).unwrap(), &empty, &0));
}

/// Worst-case gas: a 32-step proof (full `u32` index space). Verification is
/// read-only and performs exactly one SHA-256 per level after the leaf hash,
/// so the cost stays flat and well below the Soroban instruction limit.
#[test]
fn leaf_verification_gas_is_bounded() {
    let env = Env::default();
    let client = setup(&env);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let index = 0u32;
    let leaf = Bytes::from_slice(&env, b"gas-leaf");

    // Build a synthetic depth-32 path and derive the root it opens to.
    let mut proof: Vec<MerkleProofStep> = Vec::new(&env);
    let mut current = indexed_leaf_hash(&env, index, &leaf);
    for depth in 0..soroban_sas_common::MAX_MERKLE_PROOF_DEPTH {
        let sibling = BytesN::from_array(&env, &[(depth as u8).wrapping_add(1); 32]);
        current = node_hash(&env, &current, &sibling);
        proof.push_back(MerkleProofStep { sibling });
    }

    let uid = issue(
        &env,
        &client,
        &attester,
        &recipient,
        Bytes::from_array(&env, &current.to_array()),
        0,
        0,
    );

    env.budget().reset_unlimited();
    assert!(client.verify_indexed_merkle_leaf(&uid, &leaf, &proof, &index));
    let cpu = env.budget().cpu_instruction_cost();
    let mem = env.budget().memory_bytes_cost();

    println!("verify_merkle_leaf depth=32: cpu={cpu} mem={mem}");
    // The default test budget is 100M instructions; a 32-level proof costs a
    // fraction of that. Keep a generous ceiling so the assertion pins the
    // asymptotic shape rather than exact host accounting.
    assert!(
        cpu < 10_000_000,
        "32-step Merkle verification must stay well below the block instruction limit, got {cpu}"
    );
    assert!(
        mem < 1_000_000,
        "Merkle verification must stay memory-bounded, got {mem}"
    );
}
