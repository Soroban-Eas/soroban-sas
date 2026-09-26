// Golden-vector tests pinning byte-identical output with the Rust
// implementation. Every expected digest below was copied verbatim from a
// passing Rust test, so a mismatch here means the TS and Rust hashing
// schemes have diverged:
//
// - "typed data" vectors: packages/soroban-sas-common/src/typed_data.rs's
//   `golden_vectors` module (`golden_vector_1`.."golden_vector_4").
// - "uid" vectors: packages/soroban-sas-common/src/test.rs's
//   `uid_golden_vectors` module (added alongside this package).

import { StrKey } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import { computeAttestationUid, computeSchemaUid, hashTypedData } from "../src/hashing.js";
import type { Attestation, AttestationDomain } from "../src/types.js";
import { createHash } from "node:crypto";

function networkId(passphrase: string): Uint8Array {
  return createHash("sha256").update(passphrase, "ascii").digest();
}

function accountAddress(byte: number): string {
  return StrKey.encodeEd25519PublicKey(Buffer.alloc(32, byte));
}

function contractAddress(byte: number): string {
  return StrKey.encodeContract(Buffer.alloc(32, byte));
}

const TESTNET = "Test SDF Network ; September 2015";
const MAINNET = "Public Global Stellar Network ; September 2015";

function baseAttestation(): Attestation {
  return {
    uid: "01".repeat(32),
    schemaUid: "02".repeat(32),
    time: 1_700_000_000n,
    expirationTime: 1_800_000_000n,
    revocationTime: 0n,
    refUid: "00".repeat(32),
    recipient: accountAddress(0x22),
    attester: accountAddress(0x11),
    revocable: true,
    data: Buffer.from("test data", "utf8"),
  };
}

describe("hashTypedData golden vectors (packages/soroban-sas-common/src/typed_data.rs)", () => {
  it("golden vector 1: testnet attestation", () => {
    const domain: AttestationDomain = {
      networkId: networkId(TESTNET),
      contract: contractAddress(0x33),
      nonce: 1n,
    };
    const digest = hashTypedData(baseAttestation(), domain);
    expect(digest.toString("hex")).toBe(
      "34b51a63fbdac0ca4439f601756291f1fe8926ec850eadc8f0ff23a8373b85ca",
    );
  });

  it("golden vector 2: mainnet produces a different digest", () => {
    const domain: AttestationDomain = {
      networkId: networkId(MAINNET),
      contract: contractAddress(0x33),
      nonce: 1n,
    };
    const digest = hashTypedData(baseAttestation(), domain);
    expect(digest.toString("hex")).toBe(
      "5d7ee35cf9e353825ccdd9b615a58f22105b3d988cb9d8ca6377ba13d1832ae4",
    );
  });

  it("golden vector 3: a different contract produces a different digest", () => {
    const domain: AttestationDomain = {
      networkId: networkId(TESTNET),
      contract: contractAddress(0x44),
      nonce: 1n,
    };
    const digest = hashTypedData(baseAttestation(), domain);
    expect(digest.toString("hex")).toBe(
      "1e40bd4887c10d27940d33bed6a6b1f9309c3236204c8b75ee03fd4a8d79e72b",
    );
  });

  it("golden vector 4: a different nonce produces a different digest", () => {
    const domain: AttestationDomain = {
      networkId: networkId(TESTNET),
      contract: contractAddress(0x33),
      nonce: 42n,
    };
    const digest = hashTypedData(baseAttestation(), domain);
    expect(digest.toString("hex")).toBe(
      "00862bac7c294403c33b366793be6015be91aab4d719dd3117e89d9cb8dfc057",
    );
  });
});

describe("computeSchemaUid / computeAttestationUid golden vectors (packages/soroban-sas-common/src/test.rs)", () => {
  it("golden vector: schema_uid", () => {
    const uid = computeSchemaUid("bool verified", accountAddress(0x11), true);
    expect(uid).toBe(
      Buffer.from([
        146, 100, 182, 216, 54, 242, 50, 235, 155, 202, 243, 176, 169, 46, 166, 119, 188, 40, 43,
        56, 107, 202, 5, 219, 141, 246, 102, 45, 245, 237, 57, 121,
      ]).toString("hex"),
    );
  });

  it("golden vector: attestation_uid", () => {
    const uid = computeAttestationUid(
      "02".repeat(32),
      accountAddress(0x22),
      accountAddress(0x11),
      Buffer.from("golden vector data", "utf8"),
    );
    expect(uid).toBe(
      Buffer.from([
        69, 223, 100, 152, 78, 106, 147, 32, 181, 3, 111, 219, 137, 53, 251, 12, 219, 222, 253,
        33, 88, 253, 190, 86, 203, 201, 116, 113, 228, 193, 16, 142,
      ]).toString("hex"),
    );
  });

  it("is deterministic and content-addressed", () => {
    const resolver = accountAddress(0x99);
    const a = computeSchemaUid("bool x", resolver, true);
    const b = computeSchemaUid("bool x", resolver, true);
    const c = computeSchemaUid("bool x", resolver, false);
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});
