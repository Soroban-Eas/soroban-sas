# Batch Attestations (Merkle Commitments)

`soroban-sas-common` exports Merkle tree primitives (`BatchAttestation`,
`MerkleRoot`, `merkle_root`, `verify_proof`, both defined in
[`packages/soroban-sas-common/src/merkle.rs`](../packages/soroban-sas-common/src/merkle.rs))
that let an off-chain service batch thousands of attestations into a single
32-byte on-chain commitment, instead of writing every attestation to contract
storage individually. This document covers when to reach for Merkle batching
instead of `multi_attest`, the exact hashing rules the primitives implement,
and a worked example of building a tree, generating a proof, and verifying
it.

For issuing attestations individually or in an on-chain batch, see the main
[README](../README.md) and [Off-Chain Attestations](offchain-attestations.md)
(for signed, unsubmitted single attestations). This document is specifically
about the Merkle commitment primitives.

## `multi_attest` vs. Merkle batch commitments

| | On-chain `multi_attest` | Merkle batch commitment |
|---|---|---|
| Where data lives | Every attestation is a full on-chain persistent storage entry | Only a single 32-byte `MerkleRoot` (plus a `count`) is stored on-chain; leaf data lives off-chain |
| Storage cost | Linear in the number of attestations (bounded to 100 per call by `MAX_MULTI_ATTEST`, `SASError::BatchTooLarge` above that) | Constant: one root regardless of batch size |
| On-chain queryability | Each attestation is individually readable via `verify_attestation`, indexer queries, etc. | Only the root and count are on-chain; an individual claim is only checked by supplying it plus an inclusion proof — nothing is enumerable purely from chain state |
| Resolver / event hooks | Every attestation triggers the schema's resolver and emits `AttestationIssued` | None of that runs for leaves — a Merkle commitment is a bare cryptographic commitment, not an attestation lifecycle object |
| Best for | Small-to-moderate batches where each item needs independent revocation, resolver logic, or indexer visibility | Large batches (thousands+) issued together where individual items are disclosed and verified selectively, off-chain, well after the batch is committed |

Rule of thumb: if your batch needs `revoke_attestation`, resolver callbacks,
or indexer enumeration per item, use `multi_attest`. If you're publishing a
large, mostly-static dataset (an airdrop allowlist, a KYC cohort, an
accreditation list) where verifiers only need to check "is this one entry in
the set," use a Merkle commitment — it moves the entire storage and
per-item-indexing cost off-chain while keeping the same cryptographic
guarantee.

Note that as of this writing, `soroban-sas-common` provides the Merkle
primitives themselves (root computation and proof verification) as a
library; there is no dedicated SAS contract entry point that stores a
`BatchAttestation` in contract storage on your behalf. Callers currently
persist the computed `MerkleRoot` themselves — for example inside their own
contract's storage, or as the `data` payload of a single on-chain attestation
issued via `attest` — and use `verify_proof` (on-chain or off-chain) to check
individual claims against it.

## Normative hash specification

Both `merkle_root` and `verify_proof` share the same leaf and node hashing
rules, so a proof built against one always verifies against the other.

**Leaf hash:**

```text
leaf_hash(data) = sha256(0x00 || data)
```

`data` is the raw, unhashed leaf payload the caller provides (for example the
XDR encoding of an attestation UID, or any other application-defined byte
string — `soroban-sas-common` does not impose a leaf schema).

**Interior node hash:**

```text
node_hash(a, b) = sha256(0x01 || left || right)
where (left, right) = (a, b) if a <= b else (b, a)
```

The pair is ordered by raw byte value (smaller first) before hashing. This
means proof verification does not need a left/right indicator bit per level
— the verifier always recomputes `node_hash` the same way regardless of
which side the proof's sibling came from.

The `0x00` / `0x01` prefixes are domain-separation tags: they guarantee a
leaf hash can never collide with a node hash of the same underlying bytes.

**Odd level handling:** if a level has an odd number of nodes, the final
unpaired node is promoted to the next level unchanged (it is not duplicated
against itself, which is a well-known technique to sidestep certain historic
Merkle tree forgery classes such as CVE-2012-2459-style duplication attacks).

**Empty batches:** `merkle_root` has no defined output for zero leaves;
callers must not call it with an empty `Vec`.

## Proof structure

An inclusion proof is a `Vec<MerkleProofStep>`, each step carrying only the
sibling hash at that level:

```rust
pub struct MerkleProofStep {
    pub sibling: BytesN<32>,
}
```

There is no explicit left/right flag or index bitmask in the proof — because
node hashing always sorts its two inputs by byte value, `verify_proof` can
recompute the parent hash unambiguously from `(current, sibling)` at every
step without knowing which side `current` was on originally.

`verify_proof` walks the proof from leaf to root:

```rust
let mut current = leaf_hash(leaf_data);
for step in proof {
    current = node_hash(current, step.sibling);
}
current == root
```

and returns whether the final `current` matches the claimed `MerkleRoot`.

## Building a batch, generating a proof, and verifying it

```rust
use soroban_sas_common::{merkle_root, verify_proof, MerkleProofStep, MerkleRoot};
use soroban_sdk::{Bytes, Env, Vec};

fn build_and_verify(env: &Env) {
    // 1. Off-chain: collect the raw leaf payloads for the batch. Each leaf
    //    is application-defined — here, the XDR-encoded UID of an
    //    attestation that was issued and signed off-chain (see
    //    docs/offchain-attestations.md), but it could be any byte string
    //    your verifier agrees on out of band.
    let leaves: Vec<Bytes> = Vec::from_array(
        env,
        [
            Bytes::from_array(env, &[1u8; 32]),
            Bytes::from_array(env, &[2u8; 32]),
            Bytes::from_array(env, &[3u8; 32]),
        ],
    );

    // 2. Off-chain: compute the root once for the whole batch.
    let root: MerkleRoot = merkle_root(env, &leaves);

    // 3. Publish `root` on-chain (e.g. in your own contract's storage, or as
    //    the `data` of a single attestation issued via `attest`), alongside
    //    `leaves.len()` if you want consumers to know the batch size without
    //    re-deriving it.

    // 4. Off-chain: to prove leaf index 1 (`[2u8; 32]`) is in the batch, the
    //    issuing service walks the tree it built and hands the holder the
    //    sibling hashes at each level as a `Vec<MerkleProofStep>`. For a
    //    3-leaf tree, index 1's proof is: sibling = leaf_hash(leaves[0]) at
    //    the first level, then sibling = the promoted leaf_hash(leaves[2])
    //    at the second (since 3 is odd, leaf 2 has no pair and is promoted
    //    unchanged per the odd-level rule above).

    // 5. Verification (on-chain or off-chain, by anyone holding the leaf
    //    data and the proof): no server round-trip required, no per-item
    //    storage read.
    // let ok = verify_proof(env, &root, &leaves.get(1).unwrap(), &proof);
    // assert!(ok);
}
```

In production, the off-chain service builds the full tree once (retaining
every intermediate level, not just the root) so it can answer "give me
index i's proof" for any `i` without recomputing the whole tree per request.

## Selective disclosure: proving membership without revealing the batch

A Merkle commitment's key privacy property is that verifying one leaf's
membership reveals nothing about any other leaf: the proof only contains
sibling hashes, not sibling leaf data.

Worked example — proving a user is in an accredited-investor batch without
revealing the rest of the cohort:

1. An issuer builds a batch of `N` accredited investors. Each leaf encodes
   that investor's identity commitment (e.g. `sha256(recipient_address ||
   accreditation_schema_uid || nonce)`), not their raw identity — so even
   someone with a proof for their own leaf cannot reverse another leaf back
   to an identity.
2. The issuer computes `merkle_root(leaves)` and publishes only that root
   on-chain (or in a widely distributed off-chain feed) along with `N`.
3. The issuer privately sends each investor their own leaf's preimage and
   its `MerkleProofStep` vector — nothing about any other investor's leaf.
4. To transact, an investor presents `(leaf_data, proof)` to a verifying
   contract or service, which runs `verify_proof(root, leaf_data, proof)`.
   A `true` result proves "this identity commitment is one of the `N`
   accredited investors in this batch" — without the verifier, or anyone
   observing the interaction, learning who any of the other `N - 1` members
   are, or even how many of them have transacted so far.
5. Because only the root is on-chain, there is no on-chain enumeration
   surface: an attacker watching the ledger cannot harvest the member list
   the way they could if every member were an individually stored, readable
   attestation.

This pattern generalizes to any "prove you're in set S without revealing S"
use case: allowlists, KYC cohorts, governance eligibility lists, and
airdrop claims all fit the same shape.
