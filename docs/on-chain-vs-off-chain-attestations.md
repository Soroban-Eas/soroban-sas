# On-Chain vs Off-Chain Attestations

SAS supports two ways to make a claim. Both use the same `Attestation`
structure and the same content-addressed UID. They differ in where the claim
lives and who pays to publish it.

| | On-chain | Off-chain |
|---|---|---|
| Created by | `attest`, `attest_by_delegation`, `multi_attest` | `soroban-sas offchain sign` |
| Stored in | Contract persistent storage | The holder's wallet or any file store |
| Needs a transaction to issue | Yes, with a fee | No |
| Revocation | `revoke` writes `revocation_time` | Only if the UID was also published on-chain |
| Expiration | Enforced by the contract against ledger time | Enforced at verification time |
| Discoverable via the indexer | Yes | No |
| Verified by | `verify_attestation` | `verify_offchain_attestation` or the CLI |
| Privacy | Payload is public | Holder chooses who sees it |

## On-chain attestations

The attester authorizes a transaction, the contract validates the payload and
the schema's resolver, then stores the record and emits an event. Anyone can
read the record, the indexer maps it to its recipient and schema, and the
attester can revoke it. Use this when other contracts must rely on the claim,
when public discoverability is acceptable, or when revocation must be
observable by everyone.

Expired records stay inactive without any transaction: `verify_attestation`,
`verify_attestation_view` and batch verification all treat a non-zero
`expiration_time` in the past as invalid. See
[Attestation Lifecycle](attestations.md) for pruning.

## Off-chain attestations

The issuer signs the typed-data hash of the attestation with an ed25519 key.
The result is a signed payload the holder keeps and presents on demand. No
fee is paid and nothing is public until the holder discloses it. The signature
binds the network, the SAS contract and a nonce, so it cannot be replayed on
another network or contract. The full byte layout is in
[Off-Chain Attestations](offchain-attestations.md).

Off-chain attestations cannot be revoked by changing storage that does not
exist. Revocation checks only work for UIDs that were also written on-chain,
so keep lifetimes short with `expiration_time` when revocation matters.

## Bridging the two

[Delegated issuance](delegation.md) lets an attester sign off-chain and a
relayer submit the signature on-chain later, producing a normal on-chain
attestation. [Batch attestations](batch-attestations.md) commit many claims
behind one on-chain Merkle root while keeping payloads off-chain.

## Choosing

1. Do other contracts need to read the claim? Use on-chain.
2. Must the claim be publicly revocable? Use on-chain.
3. Is volume high, cost sensitive or privacy sensitive? Use off-chain, or a
   Merkle batch.
4. Is the holder offline when issuing? Sign off-chain and relay with
   delegation.

## Security notes

- Always verify the public key belongs to the declared attester. The
  contract does this by comparing against the account address.
- Reject expired payloads before acting on them, even off-chain.
- Treat an off-chain attestation as unrevokable unless you have an on-chain
  status check.
- Never reuse a nonce for different content.
