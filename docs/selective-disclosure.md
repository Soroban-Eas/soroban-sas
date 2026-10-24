# Selective Disclosure with Merkle Root Attestations

Putting a large or private payload on-chain is expensive and publishes every
claim in it (see [Privacy Implications](privacy.md)). Instead, the attester
commits to a single 32-byte Merkle root as the attestation's `data`. The
holder keeps the leaves and later reveals only the ones a verifier needs, each
with a proof; the contract checks them against the root without the other
leaves ever being published.

The tree format is the one used by batch attestations
([Batch Attestations](batch-attestations.md)) and is implemented once in
[`packages/soroban-sas-common/src/merkle.rs`](../packages/soroban-sas-common/src/merkle.rs).
The entry points live in
[`contracts/sas/src/merkle_disclosure.rs`](../contracts/sas/src/merkle_disclosure.rs).

## Contract API

```text
verify_merkle_leaf(uid: UID, leaf: Bytes, proof: Vec<BytesN<32>>) -> bool
verify_merkle_leaf_keccak(uid: UID, leaf: Bytes, proof: Vec<BytesN<32>>) -> bool
```

- `leaf` is the raw leaf bytes exactly as the holder committed them. The
  contract applies the leaf hash itself.
- `proof` lists the sibling hashes from the leaf level up to, but not
  including, the root.
- The first function uses SHA-256, the second Keccak-256 for trees produced
  by Ethereum-style tooling. A tree verifies only under the hash it was built
  with.
- Both return `false`, and never trap, when the attestation does not exist, is
  revoked, expired or not yet valid, when its `data` is not exactly 32 bytes,
  when `proof` has more than 32 siblings, when `leaf` is longer than the
  protocol payload limit, or when the proof does not rebuild the root.
- They are reads in the same sense as `verify_attestation`: they renew TTLs
  and write nothing else.

Nothing here changes how attestations are issued. A Merkle root attestation is
an ordinary attestation whose `data` happens to be a root; a schema for it
should say so (for example `bytes32 merkle_root`).

## Tree format

| Item | Definition |
|---|---|
| Leaf hash | `H(0x00 \|\| leaf)` |
| Node hash | `H(0x01 \|\| min(a, b) \|\| max(a, b))`, children compared as big-endian byte strings |
| Odd node | promoted to the next level unchanged, never duplicated |
| Root | the single remaining hash; for one leaf, the leaf hash |
| Proof | sibling hashes, leaf level first; a promoted node contributes no sibling at that level |

Because the two children are sorted before hashing, a proof needs no
left/right flags and carries no position. The position a prover claims is
implied by the proof itself, so a proof built for one leaf never opens a
different leaf.

## Formatting leaves safely

A Merkle tree is only as binding as its leaf encoding. Follow these rules in
every generator:

1. **Keep the domain-separation prefixes.** The `0x00` leaf prefix and `0x01`
   node prefix are what stop an interior node from being passed off as a leaf
   (a second-preimage attack). Do not hash leaves without the prefix, and do
   not use the concatenation of two child hashes as a leaf.
2. **Encode fields unambiguously.** Never join fields with a bare
   concatenation: `"ab" + "c"` and `"a" + "bc"` collide. Length-prefix every
   variable-length field (this page uses a 2-byte big-endian length), or use a
   canonical serialization such as XDR.
3. **Put the field name inside the leaf.** A leaf that is only a value can be
   replayed as a different claim. Commit to `key` and `value` together, and
   include the schema or a version tag if several formats share a tree.
4. **Add a per-leaf random salt** of at least 16 bytes from a cryptographic
   random source, as the first field. Without it a verifier can guess
   low-entropy leaves by hashing candidates, and equal values across trees
   become linkable. Never reuse a salt.
5. **Fix the hash and the tree before publishing.** Decide SHA-256 or
   Keccak-256 once per schema; the on-chain function you call must match.
6. **Do not rely on leaf order.** The format has no index. If order matters to
   your application, put the index inside the leaf.
7. **Reject duplicate leaves when you build the tree**, so one claim cannot
   appear twice with different proofs.

## Rust example

On the attester side, build the root and attest to it. In a contract or test:

```rust
use soroban_sas_common::merkle_root;
use soroban_sdk::{Bytes, BytesN, Env, Vec};

fn commit(env: &Env, leaves: &Vec<Bytes>) -> Bytes {
    // 32-byte root, stored verbatim as the attestation's `data`.
    let root: BytesN<32> = merkle_root(env, leaves).0;
    Bytes::from_array(env, &root.to_array())
}

// attestation.data = commit(&env, &leaves); sas.attest(&attestation);
```

On the verifier side, a consuming contract checks one disclosed leaf:

```rust
use soroban_sas_common::UID;
use soroban_sdk::{Address, Bytes, BytesN, Env, Vec};

// `SASClient` is the generated client for the SAS contract.
fn accept_claim(
    env: &Env,
    sas: &Address,
    uid: &UID,
    leaf: Bytes,
    proof: Vec<BytesN<32>>,
) -> bool {
    SASClient::new(env, sas).verify_merkle_leaf(uid, &leaf, &proof)
}
```

For Keccak-256 trees call `verify_merkle_leaf_keccak` instead. To check a
proof against a root you hold without an attestation, use
`soroban_sas_common::verify_proof_with(env, MerkleHash::Sha256, &root, &leaf, &proof)`.

## TypeScript example

This generator builds the same tree off-chain, produces proofs, and checks
them locally before submitting. It uses only `node:crypto`; to target
`verify_merkle_leaf_keccak`, replace `hash` with `keccak_256` from
`@noble/hashes/sha3`.

```ts
import { createHash } from "node:crypto";

// Swap this one function for keccak_256 (from "@noble/hashes/sha3") to build
// trees for verify_merkle_leaf_keccak.
const hash = (data: Buffer): Buffer => createHash("sha256").update(data).digest();

const leafHash = (leaf: Buffer): Buffer => hash(Buffer.concat([Buffer.from([0x00]), leaf]));

const nodeHash = (a: Buffer, b: Buffer): Buffer => {
  const [left, right] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  return hash(Buffer.concat([Buffer.from([0x01]), left, right]));
};

/** Every level of the tree, leaf hashes first and the root last. */
export function buildTree(leaves: Buffer[]): Buffer[][] {
  if (leaves.length === 0) throw new Error("a Merkle tree needs at least one leaf");
  const levels: Buffer[][] = [leaves.map(leafHash)];
  while (levels[levels.length - 1].length > 1) {
    const level = levels[levels.length - 1];
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      // An odd node out is promoted unchanged, never duplicated.
      next.push(i + 1 < level.length ? nodeHash(level[i], level[i + 1]) : level[i]);
    }
    levels.push(next);
  }
  return levels;
}

export const rootOf = (levels: Buffer[][]): Buffer => levels[levels.length - 1][0];

/** Sibling hashes for the leaf at `index`, leaf level first. */
export function proofFor(levels: Buffer[][], index: number): Buffer[] {
  const proof: Buffer[] = [];
  let i = index;
  for (const level of levels.slice(0, -1)) {
    const sibling = i ^ 1;
    if (sibling < level.length) proof.push(level[sibling]);
    i >>= 1;
  }
  return proof;
}

/** The same check the contract runs, for verifying a proof before submitting it. */
export function verify(root: Buffer, leaf: Buffer, proof: Buffer[]): boolean {
  if (proof.length > 32) return false;
  return proof.reduce((acc, sibling) => nodeHash(acc, sibling), leafHash(leaf)).equals(root);
}

/**
 * Unambiguous, salted leaf encoding: salt || len(key) || key || len(value) || value,
 * with 2-byte big-endian lengths.
 */
export function encodeLeaf(salt: Buffer, key: string, value: string): Buffer {
  const k = Buffer.from(key, "utf8");
  const v = Buffer.from(value, "utf8");
  const len = (b: Buffer) => Buffer.from([b.length >> 8, b.length & 0xff]);
  return Buffer.concat([salt, len(k), k, len(v), v]);
}
```

Usage:

```ts
import { buildTree, rootOf, proofFor, verify, encodeLeaf } from "./merkle";
import { randomBytes } from "node:crypto";

const claims: [string, string][] = [
  ["kyc_level", "3"],
  ["country", "NG"],
  ["accredited", "true"],
];
const leaves = claims.map(([k, v]) => encodeLeaf(randomBytes(16), k, v));

const tree = buildTree(leaves);
const root = rootOf(tree); // 32 bytes: attest with this as `data`

// Later, disclose only the country claim:
const leaf = leaves[1];
const proof = proofFor(tree, 1); // pass as the `proof` argument
console.log(verify(root, leaf, proof)); // true
```

## Reference vector

Both implementations were checked against this five-leaf SHA-256 tree. The
leaves are the ASCII strings `kyc:level=3`, `country=NG`, `accredited=true`,
`age>=18` and `residency=GB`, hashed exactly as in the table above (no salt,
for reproducibility only):

```text
root     211abc903daf3486cf347a01935392f1c526f7dacc089d62a026cca136a7a96d
proof[4] 002986a105ad6f154512529872c89828b31067fdd140940e3bf3298e8c6947da
```

`residency=GB` is the odd leaf: it is promoted past two levels, so its proof
has a single sibling. The Rust tests in
`packages/soroban-sas-common/src/merkle_disclosure_test.rs` and
`contracts/sas/src/test_merkle_disclosure.rs` hold the full proofs, for both
SHA-256 and Keccak-256.

## Limits and failure behaviour

- Proofs are limited to 32 siblings (trees of up to 2^32 leaves). Longer
  proofs return `false` before any hashing.
- The verifier answers `false` for a revoked or expired attestation: a
  disclosure is only as good as the attestation that anchors it. Re-verify
  with `verify_attestation` if you need to distinguish those cases.
- A root attestation cannot be extended. To add or change a claim, issue a new
  attestation (for example with `replace_attestation`) over a new root.
- Disclosure is one-way. Once a leaf and its salt have been revealed, they
  are known to everyone who saw the transaction.
