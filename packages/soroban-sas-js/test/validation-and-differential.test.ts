import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import { computeAttestationUid, computeSchemaUid, hashDomain } from "../src/hashing.js";
import { scvAddress, scvBytes, scvString, scvVec } from "../src/soroban-xdr.js";
import { decodeAccount, decodeAddress, encodeAccount } from "../src/strkey.js";

function bytes(seed: number, length: number): Uint8Array {
  const output = new Uint8Array(length); let value = seed >>> 0;
  for (let i = 0; i < length; i += 1) { value = (value * 1664525 + 1013904223) >>> 0; output[i] = value & 0xff; }
  return output;
}

describe("canonical XDR differential checks", () => {
  it("matches the published SDK for deterministic boundary and random values", () => {
    for (let i = 0; i < 64; i += 1) {
      const account = StrKey.encodeEd25519PublicKey(Buffer.from(bytes(i + 1, 32)));
      const contract = StrKey.encodeContract(Buffer.from(bytes(i + 101, 32)));
      const text = `schema-${i}-✓`;
      const opaque = bytes(i + 201, i % 17);
      expect(Buffer.from(scvAddress(account)).toString("hex")).toBe(Address.fromString(account).toScVal().toXDR().toString("hex"));
      expect(Buffer.from(scvAddress(contract)).toString("hex")).toBe(Address.fromString(contract).toScVal().toXDR().toString("hex"));
      expect(Buffer.from(scvString(text)).toString("hex")).toBe(xdr.ScVal.scvString(text).toXDR().toString("hex"));
      expect(Buffer.from(scvBytes(opaque)).toString("hex")).toBe(xdr.ScVal.scvBytes(Buffer.from(opaque)).toXDR().toString("hex"));
      expect(Buffer.from(scvVec([scvBytes(opaque)])).toString("hex")).toBe(xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.from(opaque))]).toXDR().toString("hex"));
    }
  });
});

describe("strict browser-core validation", () => {
  const account = encodeAccount(new Uint8Array(32));
  it("rejects StrKey version, checksum, alphabet, and length errors", () => {
    expect(() => decodeAccount(account.slice(0, -1))).toThrow();
    expect(() => decodeAccount(`H${account.slice(1)}`)).toThrow();
    expect(() => decodeAccount(`${account.slice(0, -1)}A`)).toThrow();
    expect(() => decodeAddress("G0".repeat(28))).toThrow();
  });
  it("rejects malformed UTF-16 and malformed UIDs", () => {
    expect(() => scvString("\ud800")).toThrow();
    expect(() => computeSchemaUid("ok", account, true)).not.toThrow();
    expect(() => computeAttestationUid("ab", account, account, new Uint8Array())).toThrow();
    expect(() => computeAttestationUid("zz".repeat(32), account, account, new Uint8Array())).toThrow();
  });
  it("enforces unsigned 64-bit boundaries", () => {
    const domain = { networkId: new Uint8Array(32), contract: StrKey.encodeContract(Buffer.alloc(32)), nonce: 0n };
    expect(() => hashDomain(domain)).not.toThrow();
    expect(() => hashDomain({ ...domain, nonce: (1n << 64n) - 1n })).not.toThrow();
    expect(() => hashDomain({ ...domain, nonce: -1n })).toThrow();
    expect(() => hashDomain({ ...domain, nonce: 1n << 64n })).toThrow();
    expect(() => hashDomain({ ...domain, nonce: Number.MAX_SAFE_INTEGER + 1 as unknown as bigint })).toThrow();
  });
});
