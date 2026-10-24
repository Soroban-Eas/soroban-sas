import { describe, expect, expectTypeOf, it } from "vitest";
import { StrKey, xdr } from "@stellar/stellar-sdk";
import { parseSchema, type InferSchema } from "../src/schema.js";

describe("SAS schema codec", () => {
  it("infers primitive fields and round-trips contracttype map XDR", () => {
    const codec = parseSchema("bool verified, uint32 level, uint64 score, string id, bytes raw");
    expectTypeOf<InferSchema<"bool verified, uint32 level, uint64 score, string id, bytes raw">>()
      .toEqualTypeOf<{ verified: boolean; level: number; score: bigint; id: string; raw: Uint8Array }>();
    const claim = { verified: true, level: 3, score: 42n, id: "alice", raw: new Uint8Array([1, 2]) };
    const encoded = codec.encode(claim);
    const root = xdr.ScVal.fromXDR(encoded);
    expect(root.switch()).toBe(xdr.ScValType.scvMap());
    expect(root.map()?.map((entry) => Buffer.from(entry.key().sym()).toString())).toEqual(["id", "level", "raw", "score", "verified"]);
    expect(codec.decode(encoded)).toEqual(claim);
  });

  it("matches the Rust derive_schema XDR fixture", () => {
    const codec = parseSchema("bool verified, uint64 score, string id");
    expect(codec.encode({ verified: true, score: 42n, id: "alice" }).toString("hex")).toBe(
      "0000001100000001000000030000000f00000002696400000000000e00000005616c6963650000000000000f0000000573636f726500000000000005000000000000002a0000000f0000000876657269666965640000000000000001",
    );
  });

  it("supports registry ordering, nested vectors, options, fixed bytes, and addresses", () => {
    const address = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1));
    const codec = parseSchema("owner Address, tags Vec<Vec<String>>, digest BytesN<32>, maybe Option<u64>");
    const claim = { owner: address, tags: [["hello", "世界"]], digest: new Uint8Array(32), maybe: null };
    expect(codec.decode(codec.encode(claim))).toEqual(claim);
    expect(codec.decode(codec.encode({ ...claim, maybe: 9n }))).toEqual({ ...claim, maybe: 9n });
  });

  it("rejects malformed schemas and mismatched payloads", () => {
    for (const schema of ["", "verified", "bool verified,", "bool verified, bool verified", "bool  verified", "uint99 score", "bytes[0] value", "bool 1bad"]) {
      expect(() => parseSchema(schema)).toThrow();
    }
    const codec = parseSchema("bool verified, BytesN<32> digest");
    expect(() => codec.encode({ verified: true, digest: new Uint8Array(31) })).toThrow();
    expect(() => codec.encode({ verified: 1, digest: new Uint8Array(32) } as never)).toThrow();
    expect(() => codec.decode(xdr.ScVal.scvMap([]).toXDR())).toThrow();
    expect(() => codec.decode(Buffer.from("invalid"))).toThrow();
  });
});
