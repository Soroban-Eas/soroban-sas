import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { hashTypedData } from "../src/hashing.js";
import type { Attestation, AttestationDomain } from "../src/types.js";

type Fixture = {
  uid: string; schemaUid: string; refUid: string; time: string;
  expirationTime: string; recipient: string; attester: string;
  revocable: boolean; data: string; networkId: string;
  contract: string; nonce: string; expected: string;
};

const path = process.env.SAS_DIFFERENTIAL_FIXTURES;
const fixtures: Fixture[] = path
  ? readFileSync(path, "utf8").trim().split("\n")
      .filter(Boolean).map(line => JSON.parse(line) as Fixture)
  : [];

describe("Rust/common, Soroban contract and TypeScript hashing parity", () => {
  it.skipIf(!path)("matches the independent contract-verified fixture batch", () => {
    expect(fixtures.length).toBeGreaterThanOrEqual(100);
    for (const f of fixtures) {
      const a: Attestation = {
        uid: f.uid, schemaUid: f.schemaUid, refUid: f.refUid,
        time: BigInt(f.time), expirationTime: BigInt(f.expirationTime),
        revocationTime: 0n, recipient: f.recipient, attester: f.attester,
        revocable: f.revocable, data: Buffer.from(f.data, "hex"),
      };
      const domain: AttestationDomain = {
        networkId: Buffer.from(f.networkId, "hex"),
        contract: f.contract, nonce: BigInt(f.nonce),
      };
      expect(hashTypedData(a, domain).toString("hex"), f.uid).toBe(f.expected);
    }
  });
});
