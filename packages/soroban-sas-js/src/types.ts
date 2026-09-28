// TypeScript mirrors of the Rust structs defined in
// packages/soroban-sas-common/src/lib.rs, packages/soroban-sas-common/src/typed_data.rs,
// and the SAS contract's fee configuration. Field names and shapes follow the
// Rust source exactly so a consumer of both SDKs can map data between them
// without guessing at a translation.

/** A 32-byte content-addressed identifier, hex-encoded (no "0x" prefix). */
export type UID = string;

/**
 * Mirrors `soroban_sas_common::Attestation`.
 *
 * `uid` must equal `computeAttestationUid(schemaUid, recipient, attester,
 * data)` — the contract rejects any attestation whose `uid` does not match
 * its own content (see contracts/sas/src/lib.rs).
 */
export interface Attestation {
  uid: UID;
  schemaUid: UID;
  /** Ledger timestamp (seconds) the attestation was issued at. */
  time: bigint;
  /** Ledger timestamp the attestation expires at, or 0n for "never". */
  expirationTime: bigint;
  /** Ledger timestamp the attestation was revoked at, or 0n if active. */
  revocationTime: bigint;
  /** UID of a prior attestation this one references, or the zero UID. */
  refUid: UID;
  /** Recipient account or contract address (G... or C...). */
  recipient: string;
  /** Attester account or contract address (G... or C...). */
  attester: string;
  revocable: boolean;
  /** Attestation payload, as raw bytes. */
  data: Uint8Array;
}

/** Mirrors `soroban_sas_common::SchemaRecord`. */
export interface SchemaRecord {
  uid: UID;
  /** Resolver contract address invoked on attest/revoke, or the zero address. */
  resolver: string;
  revocable: boolean;
  schema: string;
}

/**
 * Mirrors the SAS contract's `(token, amount)` fee configuration pair
 * returned by `SAS::get_fee` — `null` means attestation is fee-free.
 */
export interface FeeConfig {
  token: string;
  amount: bigint;
}

/**
 * Mirrors `soroban_sas_common::typed_data::AttestationDomain`: binds a
 * delegated signature to one network, one verifying contract, and one nonce.
 */
export interface AttestationDomain {
  /** SHA-256 of the network passphrase (32 bytes). */
  networkId: Uint8Array;
  /** Contract address the signature is bound to (C...). */
  contract: string;
  nonce: bigint;
}

/**
 * Input to `SASClient.attest` / batched into `SASClient.multiAttest`: every
 * field `computeAttestationUid` needs, without requiring the caller to
 * precompute `uid` themselves (the client does that internally).
 */
export interface AttestationRequest {
  schemaUid: UID;
  recipient: string;
  attester: string;
  data: Uint8Array;
  expirationTime?: bigint;
  revocable?: boolean;
  refUid?: UID;
}

/** A signed delegated attestation, ready to hand to a relayer. */
export interface DelegatedAttestation {
  attestation: Attestation;
  nonce: bigint;
  /** 64-byte ed25519 signature over `hashTypedData(attestation, domain)`. */
  signature: Uint8Array;
  /** 32-byte ed25519 public key of the attester. */
  publicKey: Uint8Array;
}
