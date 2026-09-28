import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { MAX_SCHEMA_FIELDS, parseSchema } from "../src/schema.js";

const VECTORS = fileURLToPath(
  new URL("../../../packages/soroban-sas-common/test_vectors/schema_syntax.tsv", import.meta.url),
);

function loadVectors(): Array<{ expected: string; schema: string }> {
  return readFileSync(VECTORS, "utf8")
    .split(/\r?\n/)
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => {
      const [expected, hex] = line.split("\t");
      return { expected, schema: Buffer.from(hex, "hex").toString("utf8") };
    });
}

describe("parseSchema parity with soroban_sas_common::validate_schema_syntax", () => {
  const vectors = loadVectors();

  it("loads the shared vectors", () => {
    expect(vectors.length).toBeGreaterThan(30);
  });

  it.each(vectors.map((v) => [JSON.stringify(v.schema).slice(0, 60), v] as const))("%s", (_label, v) => {
    const result = parseSchema(v.schema);
    expect(result.ok ? "ok" : result.code).toBe(v.expected);
  });
});

describe("parseSchema details", () => {
  it("returns trimmed field names and types", () => {
    const result = parseSchema("  first_name   String ,\n\tscore  Option<u32>  ");
    expect(result).toEqual({
      ok: true,
      byteLength: 45,
      fields: [
        { name: "first_name", type: "String" },
        { name: "score", type: "Option<u32>" },
      ],
    });
  });

  it("keeps internal spaces inside a type", () => {
    const result = parseSchema("pair Tuple(u32 u64)");
    expect(result.ok && result.fields[0].type).toBe("Tuple(u32 u64)");
  });

  it("counts bytes as UTF-8, not UTF-16 code units", () => {
    expect(parseSchema("naïve String").byteLength).toBe(13);
  });

  it("explains the first error and keeps fields parsed before it", () => {
    const result = parseSchema("ok String, bad-name u32, later bool");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("InvalidSchema");
    expect(result.reason).toContain("Field 2");
    expect(result.reason).toContain("bad-name");
    expect(result.fields).toEqual([{ name: "ok", type: "String" }]);
  });

  it.each([
    ["", "EmptySchema", "empty"],
    ["   ", "InvalidSchema", "whitespace"],
    ["a B,", "InvalidSchema", "trailing comma"],
    ["a B,,b B", "InvalidSchema", "doubled commas"],
    ["lonely", "InvalidSchema", '"name Type"'],
    ["a 123", "InvalidSchema", "must contain a letter"],
    ["x".repeat(1025), "InvalidSchema", "1024"],
  ])("rejects %j as %s with a helpful reason", (schema, code, reason) => {
    const result = parseSchema(schema);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe(code);
    expect(result.reason).toContain(reason);
  });

  it("reports the field ceiling", () => {
    const schema = Array.from({ length: MAX_SCHEMA_FIELDS + 1 }, (_, i) => `f${i} B`).join(",");
    const result = parseSchema(schema);
    expect(!result.ok && result.reason).toContain(String(MAX_SCHEMA_FIELDS));
  });
});
