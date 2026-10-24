import { Address, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import { decodeSchemaValue, encodeSchemaValue, generateTypeScript, parseSchema } from "../src/typegen.js";

describe("SAS schema type generator", () => {
  it("generates the golden interface with precise field types and schema comments", () => {
    expect(generateTypeScript("name string, age uint32, verified bool, account address", "Profile"))
      .toBe(`export interface Profile {\n  /** SAS schema type: string */\n  name: string;\n  /** SAS schema type: uint32 */\n  age: number;\n  /** SAS schema type: bool */\n  verified: boolean;\n  /** SAS schema type: address */\n  account: string;\n}`);
  });

  it("parses nested SAS type forms", () => {
    const parsed = parseSchema("doc_id BytesN<32>, tags Vec<String>, maybe Option<u64>, pair Tuple(u32 u64), nested Map<String:u32>");
    expect(parsed.fields.map(({ type }) => type.kind)).toEqual(["primitive", "vector", "option", "tuple", "map"]);
    expect(generateTypeScript("tags Vec<String>, maybe Option<u64>, pair Tuple(u32 u64), nested Map<String:u32>"))
      .toContain("nested: Map<string, number>;");
  });

  it("matches manual Stellar SDK ScVal encoding and decodes it", () => {
    const schema = "name string, age uint32, verified bool, account address";
    const account = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const value = { name: "Ada", age: 37, verified: true, account };
    const expected = xdr.ScVal.scvVec([
      xdr.ScVal.scvString("Ada"),
      xdr.ScVal.scvU32(37),
      xdr.ScVal.scvBool(true),
      Address.fromString(account).toScVal(),
    ]).toXDR();
    const encoded = encodeSchemaValue(schema, value);
    expect(encoded.equals(expected)).toBe(true);
    expect(decodeSchemaValue(schema, encoded)).toEqual(value);
  });

  it("round trips nested collections and optional values", () => {
    const schema = "tags Vec<String>, maybe Option<u64>, pair Tuple(u32 u64), scores Map<String:u32>";
    const value = { tags: ["one", "two"], maybe: 9n, pair: [4, 5n], scores: new Map([["math", 99]]) };
    expect(decodeSchemaValue(schema, encodeSchemaValue(schema, value))).toEqual(value);
    const empty = { tags: [], maybe: null, pair: [0, 0n], scores: new Map() };
    expect(decodeSchemaValue(schema, encodeSchemaValue(schema, empty))).toEqual(empty);
  });

  it("rejects invalid schemas and payload shapes", () => {
    expect(() => parseSchema("name string,,age u32")).toThrow();
    expect(() => encodeSchemaValue("name string", { name: "Ada", extra: true })).toThrow("unexpected field: extra");
    expect(() => encodeSchemaValue("name string", {})).toThrow("missing field: name");
  });
});
