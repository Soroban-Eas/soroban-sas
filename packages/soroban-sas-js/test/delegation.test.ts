// Cross-language golden vector for delegation signing, mirroring
// packages/soroban-sas-common/src/typed_data.rs's
// `golden_vector_5_signature_verification`: the same fixed ed25519 seed,
// attestation, and domain must produce the exact same typed-data digest and
// ed25519 signature in both languages.

import { Keypair, StrKey } from "@stellar/stellar-sdk";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signDelegatedAttestation, verifyDelegatedAttestation } from "../src/delegation.js";
import { hashTypedData } from "../src/hashing.js";
import type { Attestation, AttestationDomain } from "../src/types.js";

function networkId(passphrase: string): Uint8Array {
  return createHash("sha256").update(passphrase, "ascii").digest();
}

const TESTNET = "Test SDF Network ; September 2015";

describe("signDelegatedAttestation golden vector (typed_data.rs::golden_vector_5)", () => {
  const seed = Buffer.alloc(32, 0x55);
  const keypair = Keypair.fromRawEd25519Seed(seed);
  const attester = keypair.publicKey();
  const recipient = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 0x22));
  const contract = StrKey.encodeContract(Buffer.alloc(32, 0x33));

  const attestation: Attestation = {
    uid: "01".repeat(32),
    schemaUid: "02".repeat(32),
    time: 1_700_000_000n,
    expirationTime: 1_800_000_000n,
    revocationTime: 0n,
    refUid: "00".repeat(32),
    recipient,
    attester,
    revocable: true,
    data: Buffer.from("test data", "utf8"),
  };
  const domain: AttestationDomain = {
    networkId: networkId(TESTNET),
    contract,
    nonce: 7n,
  };

  it("produces the pinned digest", () => {
    expect(hashTypedData(attestation, domain).toString("hex")).toBe(
      "3bc039e2b2e743f9d84a75d858808247d512f795c60148213a6625049f0c61f7",
    );
  });

  it("produces the pinned ed25519 signature", () => {
    const delegated = signDelegatedAttestation(attestation, domain, 7n, keypair.secret());
    expect(Buffer.from(delegated.signature).toString("hex")).toBe(
      "ed26fe73894a298c25631c4993194993e82689231fd27dae7b05af91a39d0f8e414c388130cd56cd5120bd6f495a3beb2ccf2c1c7b5274ae1d2d3c007064c60f",
    );
    expect(verifyDelegatedAttestation(delegated, domain)).toBe(true);
  });

  it("rejects a signature over a tampered attestation", () => {
    const delegated = signDelegatedAttestation(attestation, domain, 7n, keypair.secret());
    const tampered = { ...delegated, attestation: { ...attestation, data: Buffer.from("tampered") } };
    expect(verifyDelegatedAttestation(tampered, domain)).toBe(false);
  });

  it("throws when the secret does not match the declared attester", () => {
    const other = Keypair.random();
    expect(() =>
      signDelegatedAttestation(attestation, domain, 7n, other.secret()),
    ).toThrow(/does not match/);
  });
});
