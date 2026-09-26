// Sign and verify delegated attestations off-chain, mirroring
// packages/soroban-sas-cli/src/offchain.rs's sign_offchain_attestation /
// verify_offchain_attestation. The attester signs `hashTypedData(...)` with
// their account's ed25519 key; any funded relayer can then submit the
// signature via `SASClient.attestByDelegation` without ever holding that key.

import { Keypair, StrKey } from "@stellar/stellar-sdk";
import { hashTypedData } from "./hashing.js";
import type { Attestation, AttestationDomain, DelegatedAttestation } from "./types.js";

/**
 * Signs `attestation` for delegated submission. `secret` is the attester's
 * ed25519 secret seed (strkey `S...`); throws if it does not match
 * `attestation.attester`, mirroring the Rust CLI's same check.
 */
export function signDelegatedAttestation(
  attestation: Attestation,
  domain: AttestationDomain,
  nonce: bigint,
  secret: string,
): DelegatedAttestation {
  const keypair = Keypair.fromSecret(secret);
  const expectedAttester = keypair.publicKey();
  if (attestation.attester !== expectedAttester) {
    throw new Error(
      `attester ${attestation.attester} does not match signing key account ${expectedAttester}`,
    );
  }

  const digest = hashTypedData(attestation, domain);
  const signature = keypair.sign(digest);

  return {
    attestation,
    nonce,
    signature,
    publicKey: keypair.rawPublicKey(),
  };
}

/**
 * Verifies a [`DelegatedAttestation`]: recomputes the typed-data digest,
 * confirms `publicKey` belongs to `attestation.attester`, and checks the
 * ed25519 signature. Returns `false` rather than throwing on any mismatch,
 * so callers can treat verification as a plain boolean gate.
 */
export function verifyDelegatedAttestation(
  delegated: DelegatedAttestation,
  domain: AttestationDomain,
): boolean {
  const { attestation, signature, publicKey } = delegated;

  const expectedAttester = StrKey.encodeEd25519PublicKey(Buffer.from(publicKey));
  if (attestation.attester !== expectedAttester) {
    return false;
  }

  const digest = hashTypedData(attestation, domain);
  const keypair = Keypair.fromPublicKey(expectedAttester);
  return keypair.verify(digest, Buffer.from(signature));
}
