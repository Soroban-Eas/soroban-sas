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
2. **Replay & Double-Spend Defense**: Every zero-knowledge verification consumes a unique 32-byte `nullifier`. Replaying the same proof or re-using a nullifier is rejected with `ZkVerifierError::NullifierAlreadyUsed`.
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
