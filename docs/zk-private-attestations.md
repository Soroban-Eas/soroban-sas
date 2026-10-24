# Zero-Knowledge Private Attestations

## Overview

The `soroban-sas-zk-verifier` contract enables zero-knowledge verification of private attestations on Stellar using Soroban smart contracts.

Certain credentials—such as financial solvency proofs, identity attributes (e.g., adult age verification, accredited investor status), or private health passes—require verifiability without revealing sensitive underlying data, recipient identity, or attester secrets on a public ledger.

## Architecture

```
+-------------------------------------------------------------+
|                     Prover / User Client                    |
+-------------------------------------------------------------+
                              |
       1. Generate Proof & Nullifier locally
          H(commitment || nullifier) challenge binding
                              |
                              v
+-------------------------------------------------------------+
|                soroban-sas-zk-verifier                      |
|                                                             |
|  - Validates proof structure & cryptographic binding        |
|  - Enforces nullifier uniqueness (replay / double-spending) |
|  - Validates maximum proof age (MAX_ZK_PROOF_AGE_SECONDS)   |
|  - Checks on-chain SAS attestation status & time-locks      |
|  - Stores spent nullifiers and verified commitments         |
|  - Emits PrivateAttestationVerifiedEvent                    |
+-------------------------------------------------------------+
                              |
       2. Query verify_attestation & get_valid_from
                              v
+-------------------------------------------------------------+
|                     SAS Core Contract                       |
+-------------------------------------------------------------+
```

## Security Properties

1. **Zero-Knowledge Privacy**: The recipient and credential contents remain hidden in the cryptographic commitment. The verifier verifies that the prover possesses a valid attestation without inspecting the cleartext data.
2. **Replay & Double-Spend Defense**: Every zero-knowledge verification consumes a unique 32-byte `nullifier`. Replaying the same proof or re-using a nullifier is rejected with `ZKError::NullifierSpent` (the contract error type is `ZkVerifierError`, aliased as `ZKError`). The check and the record of a nullifier are atomic: a nullifier is only spent when the whole verification succeeds, so a rejected proof never burns its nullifier.
3. **Temporal Validity & Time-Locks**: The verifier checks proof generation freshness against `MAX_ZK_PROOF_AGE_SECONDS` and cross-verifies on-chain time-locks (`valid_from` activation timestamps) against the SAS core contract.
4. **Revocation Synchronization**: If the private attestation references an on-chain SAS UID, revocations and expirations recorded in SAS immediately invalidate the proof.

## Data Structures

```rust
pub struct ZkAttestationProof {
    pub attestation_uid: UID,
    pub schema_uid: UID,
    pub nullifier: BytesN<32>,
    pub commitment: BytesN<32>,
    pub proof: Bytes,
    pub timestamp: u64,
}
```

## Nullifier Set Management

Spent nullifiers are the contract's replay-protection state. They live in
persistent storage, one entry per nullifier, and are renewed with the same
TTL policy as the contract's instance storage, so a nullifier never expires
before the instance that guards it.

| Call | Purpose |
|---|---|
| `verify_and_consume_proof(proof_data)` | Verifies a proof and consumes its nullifier. The check and the record are atomic: the nullifier is spent only if the whole verification succeeds. A nullifier that was already spent is rejected with `ZKError::NullifierSpent`. |
| `is_nullifier_used(nullifier)` | Whether a single nullifier was already spent. |
| `are_nullifiers_used(nullifiers)` | Batch query: one flag per nullifier, in the order the nullifiers were passed in. Lets off-chain clients reconcile a whole batch of nullifiers with a single contract call instead of one call per nullifier. |

### Nullifier Queries

Off-chain provers and relayers can check whether nullifiers were already
consumed before building a transaction:

```rust
/// One flag per input, in the same order.
pub fn are_nullifiers_used(
    env: Env,
    nullifiers: Vec<BytesN<32>>,
) -> Result<Vec<bool>, ZkVerifierError>
```

- The batch is bounded by `MAX_NULLIFIER_BATCH` (50); a larger input is
  rejected with `ZkVerifierError::BatchTooLarge` so a read-only simulation
  cannot be made arbitrarily expensive.
- Consumed nullifiers have their persistent TTL refreshed to match the contract
  instance, exactly like the single-nullifier `is_nullifier_used` query.
- A nullifier is scoped to the whole contract, not to a commitment: reusing the
  same 32-byte nullifier with a fresh commitment or proof is still rejected with
  `ZkVerifierError::NullifierSpent`.
