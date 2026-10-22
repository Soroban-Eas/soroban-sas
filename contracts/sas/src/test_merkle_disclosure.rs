//! Tests for selective payload disclosure via Merkle root attestations (#435).
//!
//! The roots and proofs in the fixed vectors come from an independent Python
//! implementation of the documented tree, so these tests also pin the on-chain
//! verifier to what an off-chain generator produces. Tree shapes built from
//! `merkle_root` cover the single-leaf and odd-leaf-count cases.

use crate::{SASClient, SAS};
use soroban_sas_common::{merkle_root, Attestation, UID};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Vec};

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

    pub fn get_schema(env: Env, uid: UID) -> Option<soroban_sas_common::SchemaRecord> {
        Some(soroban_sas_common::SchemaRecord {
            uid,
            resolver: env.current_contract_address(),
            revocable: true,
            schema: soroban_sdk::String::from_str(&env, "bytes32 merkle_root"),
            deprecated: false,
        })
    }
}

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
// Leaf 4 is the odd leaf of a five-leaf tree: promoted twice, one sibling.
const SHA_PROOF_4: [&str; 1] = ["002986a105ad6f154512529872c89828b31067fdd140940e3bf3298e8c6947da"];

const KECCAK_ROOT: &str = "2b81c85a3211a197a94b13bea775c931934a166fc84575af87d09aabb9455e66";
const KECCAK_PROOF_0: [&str; 3] = [
    "23ec60633adb84d0a26ae0bf40502e6b35bd339f156a9ce2639f36c612191107",
    "cd51e9183a7a2747f9b766d25c74b23a5c535218a7094ce3b5571c2656e99dad",
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

struct Harness {
    env: Env,
    client: SASClient<'static>,
    attester: Address,
    recipient: Address,
}

impl Harness {
    fn new() -> Self {
        let env = Env::default();
        env.ledger().with_mut(|li| {
            li.sequence_number = 100;
            li.timestamp = 1_000;
        });

        let registry_id = env.register_contract(None, MockRegistry);
        let sas_id = env.register_contract(None, SAS);
        let client = SASClient::new(&env, &sas_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.init(&admin, &registry_id);

        Self {
            attester: Address::generate(&env),
            recipient: Address::generate(&env),
            env,
            client,
        }
    }

    fn leaf(&self, i: usize) -> Bytes {
        Bytes::from_slice(&self.env, LEAVES[i])
    }

    fn proof(&self, hexes: &[&str]) -> Vec<BytesN<32>> {
        let mut proof = Vec::new(&self.env);
        for hex in hexes {
            proof.push_back(BytesN::from_array(&self.env, &hex32(hex)));
        }
        proof
    }

    /// Issues an attestation whose `data` is `data`, expiring at `expiration`
    /// (0 = never). `seed` varies the schema so several can coexist.
    fn attest_data(&self, seed: u8, data: Bytes, expiration: u64) -> UID {
        let schema_uid = UID(BytesN::from_array(&self.env, &[seed; 32]));
        let uid = soroban_sas_common::attestation_uid(
            &self.env,
            &schema_uid,
            &self.recipient,
            &self.attester,
            &data,
        );
        let attestation = Attestation {
            uid: uid.clone(),
            schema_uid,
            time: 0,
            expiration_time: expiration,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&self.env, &[0u8; 32])),
            recipient: self.recipient.clone(),
            attester: self.attester.clone(),
            revocable: true,
            data,
        };
        assert_eq!(self.client.attest(&attestation), uid);
        uid
    }

    fn attest_root(&self, seed: u8, root_hex: &str) -> UID {
        let data = Bytes::from_array(&self.env, &hex32(root_hex));
        self.attest_data(seed, data, 0)
    }
}

#[test]
fn sha256_leaves_verify_against_the_attested_root() {
    let h = Harness::new();
    let uid = h.attest_root(1, SHA_ROOT);

    assert!(h
        .client
        .verify_merkle_leaf(&uid, &h.leaf(0), &h.proof(&SHA_PROOF_0)));
    assert!(h
        .client
        .verify_merkle_leaf(&uid, &h.leaf(2), &h.proof(&SHA_PROOF_2)));
    // The odd leaf, promoted past two levels.
    assert!(h
        .client
        .verify_merkle_leaf(&uid, &h.leaf(4), &h.proof(&SHA_PROOF_4)));
}

#[test]
fn keccak256_leaves_verify_against_the_attested_root() {
    let h = Harness::new();
    let uid = h.attest_root(2, KECCAK_ROOT);

    assert!(h
        .client
        .verify_merkle_leaf_keccak(&uid, &h.leaf(0), &h.proof(&KECCAK_PROOF_0)));
    assert!(h
        .client
        .verify_merkle_leaf_keccak(&uid, &h.leaf(4), &h.proof(&KECCAK_PROOF_4)));
}

#[test]
fn a_tree_built_with_one_hash_does_not_verify_under_the_other() {
    let h = Harness::new();
    let sha_uid = h.attest_root(3, SHA_ROOT);
    let keccak_uid = h.attest_root(4, KECCAK_ROOT);

    assert!(!h
        .client
        .verify_merkle_leaf_keccak(&sha_uid, &h.leaf(0), &h.proof(&SHA_PROOF_0)));
    assert!(!h
        .client
        .verify_merkle_leaf(&keccak_uid, &h.leaf(0), &h.proof(&KECCAK_PROOF_0)));
}

#[test]
fn tampered_leaf_proof_or_root_is_rejected() {
    let h = Harness::new();
    let uid = h.attest_root(5, SHA_ROOT);

    // A claim the attester never committed to.
    let forged = Bytes::from_slice(&h.env, b"kyc:level=4");
    assert!(!h
        .client
        .verify_merkle_leaf(&uid, &forged, &h.proof(&SHA_PROOF_0)));

    // One bit flipped in a sibling.
    let mut sibling = hex32(SHA_PROOF_0[0]);
    sibling[0] ^= 1;
    let mut tampered = h.proof(&SHA_PROOF_0);
    tampered.set(0, BytesN::from_array(&h.env, &sibling));
    assert!(!h.client.verify_merkle_leaf(&uid, &h.leaf(0), &tampered));

    // Attestation holding a different root.
    let mut other_root = hex32(SHA_ROOT);
    other_root[31] ^= 1;
    let other_uid = h.attest_data(6, Bytes::from_array(&h.env, &other_root), 0);
    assert!(!h
        .client
        .verify_merkle_leaf(&other_uid, &h.leaf(0), &h.proof(&SHA_PROOF_0)));
}

#[test]
fn proofs_for_the_wrong_position_are_rejected() {
    let h = Harness::new();
    let uid = h.attest_root(7, SHA_ROOT);

    // The proof fixes the leaf's position, so presenting leaf 0 with the
    // proof for position 2 (or 4) is a wrong-index claim and must fail.
    assert!(!h
        .client
        .verify_merkle_leaf(&uid, &h.leaf(0), &h.proof(&SHA_PROOF_2)));
    assert!(!h
        .client
        .verify_merkle_leaf(&uid, &h.leaf(2), &h.proof(&SHA_PROOF_0)));
    assert!(!h
        .client
        .verify_merkle_leaf(&uid, &h.leaf(4), &h.proof(&SHA_PROOF_0)));
}

#[test]
fn reordered_truncated_and_extended_proofs_are_rejected() {
    let h = Harness::new();
    let uid = h.attest_root(8, SHA_ROOT);
    let good = h.proof(&SHA_PROOF_0);

    let mut swapped = Vec::new(&h.env);
    swapped.push_back(good.get(2).unwrap());
    swapped.push_back(good.get(1).unwrap());
    swapped.push_back(good.get(0).unwrap());
    assert!(!h.client.verify_merkle_leaf(&uid, &h.leaf(0), &swapped));

    let mut truncated = good.clone();
    let _ = truncated.pop_back();
    assert!(!h.client.verify_merkle_leaf(&uid, &h.leaf(0), &truncated));

    let mut extended = good.clone();
    extended.push_back(good.get(0).unwrap());
    assert!(!h.client.verify_merkle_leaf(&uid, &h.leaf(0), &extended));

    assert!(!h
        .client
        .verify_merkle_leaf(&uid, &h.leaf(0), &Vec::new(&h.env)));
}

#[test]
fn single_leaf_tree_verifies_with_an_empty_proof_only() {
    let h = Harness::new();
    let only = h.leaf(1);
    let mut leaves = Vec::new(&h.env);
    leaves.push_back(only.clone());
    let root = merkle_root(&h.env, &leaves).0;
    let uid = h.attest_data(9, Bytes::from_array(&h.env, &root.to_array()), 0);

    assert!(h.client.verify_merkle_leaf(&uid, &only, &Vec::new(&h.env)));

    let mut padded = Vec::new(&h.env);
    padded.push_back(root);
    assert!(!h.client.verify_merkle_leaf(&uid, &only, &padded));
    assert!(!h
        .client
        .verify_merkle_leaf(&uid, &h.leaf(0), &Vec::new(&h.env)));
}

#[test]
fn three_leaf_tree_with_an_odd_leaf_verifies_at_every_position() {
    let h = Harness::new();
    let leaves: [Bytes; 3] = [h.leaf(0), h.leaf(1), h.leaf(2)];

    // `merkle_root` of a single leaf is that leaf's hash, and of two leaves is
    // their parent, so the siblings of the three-leaf tree can be read off it.
    let root_of = |items: &[&Bytes]| -> BytesN<32> {
        let mut v = Vec::new(&h.env);
        for item in items {
            v.push_back((*item).clone());
        }
        merkle_root(&h.env, &v).0
    };
    let tree_root = root_of(&[&leaves[0], &leaves[1], &leaves[2]]);
    let uid = h.attest_data(10, Bytes::from_array(&h.env, &tree_root.to_array()), 0);

    let hash0 = root_of(&[&leaves[0]]);
    let hash1 = root_of(&[&leaves[1]]);
    let hash2 = root_of(&[&leaves[2]]);
    let parent01 = root_of(&[&leaves[0], &leaves[1]]);

    let proofs: [[&BytesN<32>; 2]; 2] = [[&hash1, &hash2], [&hash0, &hash2]];
    for (i, siblings) in proofs.iter().enumerate() {
        let mut proof = Vec::new(&h.env);
        for s in siblings {
            proof.push_back((*s).clone());
        }
        assert!(
            h.client.verify_merkle_leaf(&uid, &leaves[i], &proof),
            "leaf {i} of three must verify"
        );
    }

    // The odd leaf is promoted past the first level: a single sibling.
    let mut odd_proof = Vec::new(&h.env);
    odd_proof.push_back(parent01);
    assert!(h.client.verify_merkle_leaf(&uid, &leaves[2], &odd_proof));
}

#[test]
fn attestations_that_are_not_a_32_byte_root_never_verify() {
    let h = Harness::new();

    let short = h.attest_data(11, Bytes::from_array(&h.env, &[7u8; 31]), 0);
    let long = h.attest_data(12, Bytes::from_array(&h.env, &[7u8; 33]), 0);
    let empty = h.attest_data(13, Bytes::new(&h.env), 0);

    for uid in [short, long, empty] {
        assert!(!h
            .client
            .verify_merkle_leaf(&uid, &h.leaf(0), &Vec::new(&h.env)));
    }
}

#[test]
fn unknown_revoked_and_expired_attestations_never_verify() {
    let h = Harness::new();

    let unknown = UID(BytesN::from_array(&h.env, &[0xEEu8; 32]));
    assert!(!h
        .client
        .verify_merkle_leaf(&unknown, &h.leaf(0), &h.proof(&SHA_PROOF_0)));

    let revoked = h.attest_root(14, SHA_ROOT);
    assert!(h
        .client
        .verify_merkle_leaf(&revoked, &h.leaf(0), &h.proof(&SHA_PROOF_0)));
    h.client.revoke(&revoked);
    assert!(!h
        .client
        .verify_merkle_leaf(&revoked, &h.leaf(0), &h.proof(&SHA_PROOF_0)));

    let data = Bytes::from_array(&h.env, &hex32(SHA_ROOT));
    let expiring = h.attest_data(15, data, 2_000);
    assert!(h
        .client
        .verify_merkle_leaf(&expiring, &h.leaf(0), &h.proof(&SHA_PROOF_0)));
    h.env.ledger().with_mut(|li| li.timestamp = 2_000);
    assert!(!h
        .client
        .verify_merkle_leaf(&expiring, &h.leaf(0), &h.proof(&SHA_PROOF_0)));
}

#[test]
fn oversized_proofs_and_leaves_are_rejected() {
    let h = Harness::new();
    let uid = h.attest_root(16, SHA_ROOT);

    let mut deep = Vec::new(&h.env);
    for _ in 0..33 {
        deep.push_back(BytesN::from_array(&h.env, &[1u8; 32]));
    }
    assert!(!h.client.verify_merkle_leaf(&uid, &h.leaf(0), &deep));

    let huge = Bytes::from_slice(&h.env, &[0u8; 10_001]);
    assert!(!h
        .client
        .verify_merkle_leaf(&uid, &huge, &h.proof(&SHA_PROOF_0)));
}
