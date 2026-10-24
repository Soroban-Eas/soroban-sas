import { describe, it, expect } from "vitest";
import { StrKey } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { computeSchemaUidWasm, fromTemplate, fieldSchema, reorderFields, validateDraft, TEMPLATE_FIELDS } from "../src/designer.js";

const resolver = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 0x11));

describe("Visual schema editor state", () => {
  it("provides canonical KYC, POAP and Skill Certification templates", () => {
    expect(Object.keys(TEMPLATE_FIELDS)).toEqual(["KYC","POAP","Skill Certification"]);
    for (const name of Object.keys(TEMPLATE_FIELDS)) {
      const draft = fromTemplate(name, resolver);
      expect(validateDraft(draft).ok).toBe(true);
      expect(draft.fields.every(f=>f.description.length>0)).toBe(true);
    }
  });

  it("builds a canonical schema without incorporating description tags", () => {
    const draft = fromTemplate("KYC", resolver);
    expect(fieldSchema(draft.fields)).toBe("subject String, verified bool, jurisdiction String");
    const original = fieldSchema(draft.fields);
    draft.fields[0].description = "Different description";
    expect(fieldSchema(draft.fields)).toBe(original);
  });

  it("detects duplicates, illegal identifiers, invalid types and resolver addresses", () => {
    const draft = fromTemplate("KYC", resolver);
    draft.fields[1].name = "subject";
    expect(validateDraft(draft).duplicateNames).toEqual(["subject"]);
    draft.fields[1].name = "not-valid";
    expect(validateDraft(draft).ok).toBe(false);
    draft.fields[1].name = "verified";
    draft.fields[1].type = "!notType";
    expect(validateDraft(draft).ok).toBe(false);
    draft.fields[1].type = "bool";
    draft.resolver = "invalid";
    expect(validateDraft(draft).errors[0]).toContain("Resolver");
  });

  it("handles drag-and-drop reorder without mutating the previous fields array", () => {
    const fields = fromTemplate("POAP", resolver).fields;
    const result = reorderFields(fields, 0, 2);
    expect(result.map(f=>f.name)).toEqual(["attended","issued_at","event_id"]);
    expect(fields[0].name).toBe("event_id");
    expect(reorderFields(fields,-1,2)).toEqual(fields);
  });
});

describe("browser WASM schema UID parity with Rust golden vector", () => {
  it("matches Rust soroban_sas_common::schema_uid byte for byte", async () => {
    const draft = {
      fields: [{ id:"one", name:"bool", type:"verified", description:"" }],
      resolver, revocable:true,
    };
    expect(await computeSchemaUidWasm(draft)).toBe(
      "9264b6d836f232eb9bcaf3b0a92ea677bc282b386bca05db8df6662df5ed3979",
    );
  });

  it("changes the digest when revocability, resolver or field order changes", async () => {
    const draft = fromTemplate("POAP", resolver);
    const uid = await computeSchemaUidWasm(draft);
    expect(uid).toMatch(/^[a-f0-9]{64}$/);
    const toggled = await computeSchemaUidWasm({ ...draft, revocable: false });
    expect(toggled).not.toBe(uid);
    const reversed = await computeSchemaUidWasm({ ...draft, fields: reorderFields(draft.fields, 0, 2) });
    expect(reversed).not.toBe(uid);
    await expect(computeSchemaUidWasm({...draft,resolver:"CINVALID"})).rejects.toThrow(/Resolver/);
  });
});
