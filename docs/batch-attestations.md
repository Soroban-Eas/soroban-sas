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
(for signed, unsubmitted single attestations). To drive many *on-chain*
issuances from a data file, see
[Bulk Attestation Creation from CSV](bulk-csv-attestations.md), which covers
the `attest bulk` subcommand. This document is specifically about the Merkle
commitment primitives.

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

`soroban-sas-common` provides the Merkle primitives themselves (root
computation and proof verification) as a library. Callers that want to keep
the commitment entirely in their own contract storage can persist a
`MerkleRoot` and use `verify_proof`. Callers that want the root anchored to an
SAS attestation — so its issuance time, expiry, and revocation govern the
commitment — can store the root as the `data` payload of a single attestation
and verify disclosed leaves on-chain with
[`SAS::verify_indexed_merkle_leaf`](#on-chain-merkle-root-attestations-sasverify_indexed_merkle_leaf).
The next section defines the payload and tree conventions that entry point
verifies.

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

## On-chain Merkle root attestations (`SAS::verify_indexed_merkle_leaf`)

A Merkle-root attestation commits to an off-chain batch without storing any
leaf data on-chain. The issuer creates one ordinary SAS attestation whose
`data` payload is the 32-byte root; verifying a disclosed member is then a
single read-only contract call:

```rust
pub fn verify_indexed_merkle_leaf(
    env: Env,
    attestation_uid: UID,
    leaf: Bytes,
    proof: Vec<MerkleProofStep>,
    index: u32,
) -> bool
```

The parent attestation's lifecycle controls the commitment: once it is
revoked or expired (or before its `valid_from`), every leaf proof against it
stops verifying. Replacing the attestation's data changes the UID, so the
root is as immutable as the attestation record itself.

### Payload convention: 32 raw bytes

`Attestation.data` must be **exactly 32 raw bytes**, the root itself, with no
prefix, length field, encoding wrapper, or leaf count. Anything else fails
verification (the helper returns `false`; it never guesses at a different
encoding). Off-chain clients can build the payload directly from the root
hash, for example `Bytes::from_array(env, &root.to_array())`.

The canonical schema string for such a schema is:

```text
bytes32 merkle_root
```

`MERKLE_ROOT_SCHEMA` in `soroban-sas-common` exports this literal. It follows
the registry's `type name` field grammar, so it registers unchanged. The
schema string is advisory — clients and indexers use it to recognise the
payload format — while the on-chain helper enforces the 32-byte length
directly rather than paying for a cross-contract schema lookup.

### Index-bound leaf format

SAS leaf verification uses an **index-bound** tree. The leaf preimage includes
the leaf's position, so the `index` argument is authenticated rather than
trusted:

```text
leaf_hash(index, data) = sha256(0x00 || index_be_u32 || data)
node_hash(left, right)  = sha256(0x01 || smaller || larger)
odd level               = last unpaired node promoted unchanged
```

`index` is a fixed-width big-endian `u32`, making the preimage unambiguous for
any leaf payload length. Node hashing sorts its two inputs by byte value,
so proofs need no left/right flags and the same proof layout as the generic
format applies.

The index binding is what makes the disclosed position meaningful:

- A valid proof for position `i` cannot be replayed as position `j`; the
  verifier hashes `(j, leaf)` and reaches a different root.
- Moving a leaf between positions changes the root, so a batch cannot be
  silently reordered after commitment.
- The `0x00` leaf / `0x01` node domain separation prevents an internal node
  hash from being presented as a leaf (second-preimage protection).
- Odd nodes are promoted, never duplicated, avoiding duplicated-leaf forgery
  classes.

Use `indexed_merkle_root` from `soroban-sas-common` to build a matching root;
it hashes leaf `i` with `indexed_leaf_hash(i, leaf)` and folds the tree with
the same promotion rule. Both functions are public so off-chain tooling can
reproduce the exact bytes without duplicating the algorithm.

> **Note:** this is deliberately a different leaf format from the generic
> `merkle_root` / `verify_proof` pair documented above, which hashes bare
> leaves (`sha256(0x00 || data)`) and has no notion of position. Build a
> Merkle-root attestation with `indexed_merkle_root` and verify it with
> `verify_indexed_merkle_leaf`; use `merkle_root` / `verify_proof` for commitments
> your own contract stores directly.

### Verification semantics

`verify_indexed_merkle_leaf` is read-only: it performs no storage writes and does not
renew TTLs, so it is cheap and safe in simulation or view contexts. It
returns `false` — never a panic — for every rejection:

| Condition | Result |
|---|---|
| Unknown / never-issued `attestation_uid` | `false` |
| Parent revoked (`revocation_time != 0`) | `false` |
| Parent expired at the current ledger time | `false` |
| Parent not yet valid (`valid_from` in the future) | `false` |
| `data` payload is not exactly 32 bytes | `false` |
| Proof deeper than `MAX_MERKLE_PROOF_DEPTH` (32) | `false` |
| Tampered leaf, tampered sibling, wrong index, or wrong root | `false` |

Archived parent entries trap at the host layer before the helper runs,
exactly as with `get_attestation` / `verify_attestation`; callers should map
an "archived" simulation error to a restore-footprint flow rather than to
`false`.

### Gas

The proof depth is capped at 32 (the full `u32` index space), and verification
performs one SHA-256 per level after the leaf hash with no storage access.
The contract test suite measures a worst-case 32-step proof at roughly
**563k CPU instructions and 30 KB of memory**, well under one percent of the
default 100M-instruction Soroban transaction budget. Shorter proofs (the
common case: 10–20 levels for realistic batch sizes) cost proportionally
less. The test `test_merkle::leaf_verification_gas_is_bounded` enforces the
ceiling and prints the measured values.

### Worked example

```rust
use soroban_sas_common::{indexed_merkle_root, MerkleProofStep};
use soroban_sdk::{Bytes, Env, Vec};

fn commit_batch(env: &Env, sas: &SASClient, leaf_data: [Bytes; 3]) {
    let leaves: Vec<Bytes> = Vec::from_array(env, leaf_data);
    let root = indexed_merkle_root(env, &leaves);

    // Issue one ordinary attestation whose payload is the root. Use the
    // canonical "bytes32 merkle_root" schema so clients recognise it.
    let attestation = /* build as usual, with data = Bytes::from_array(env, &root.0.to_array()) */;
    let uid = sas.attest(&attestation);

    // Off-chain: hand each member their raw leaf plus its sibling path.
    // On-chain, anyone can then check a disclosure:
    let proof: Vec<MerkleProofStep> = /* siblings from the builder */;
    let is_member = sas.verify_indexed_merkle_leaf(&uid, &leaves.get(1).unwrap(), &proof, &1);
    assert!(is_member);
}
```

Revoking the parent attestation (`SAS::revoke(uid)`) immediately invalidates
every outstanding leaf proof, which is the intended kill switch for a
compromised or superseded batch.

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
