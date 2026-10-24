/**
 * Visual schema editor state. Description tags are UI-only notes: including
 * them in the canonical schema string would change the contract's UID.
 */
import { Address, StrKey, xdr } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { sha256 } from "hash-wasm";
import { parseSchema } from "./schema.js";

export interface DesignerField {
  id: string;
  name: string;
  type: string;
  description: string;
}
export interface SchemaDraft {
  fields: DesignerField[];
  resolver: string;
  revocable: boolean;
}

export const TEMPLATE_FIELDS: Readonly<Record<string, ReadonlyArray<Omit<DesignerField,"id">>>> = {
  KYC: [
    { name: "subject", type: "String", description: "Verified account identifier" },
    { name: "verified", type: "bool", description: "KYC verification status" },
    { name: "jurisdiction", type: "String", description: "Issuing jurisdiction" },
  ],
  POAP: [
    { name: "event_id", type: "String", description: "Event identifier" },
    { name: "attended", type: "bool", description: "Attendance confirmation" },
    { name: "issued_at", type: "u64", description: "Epoch seconds" },
  ],
  "Skill Certification": [
    { name: "skill", type: "String", description: "Certified skill" },
    { name: "level", type: "u32", description: "Competency level" },
    { name: "awarded_at", type: "u64", description: "Epoch seconds" },
  ],
};

export const DEFAULT_RESOLVER = StrKey.encodeEd25519PublicKey(Buffer.alloc(32));
const encoder = new TextEncoder();

export function fromTemplate(name: string, resolver = DEFAULT_RESOLVER): SchemaDraft {
  const template = TEMPLATE_FIELDS[name];
  if (!template) throw new Error("Unknown schema template");
  return { resolver, revocable: true, fields: template.map((f,i) => ({ ...f, id: `field-${i + 1}` })) };
}

export function fieldSchema(fields: readonly DesignerField[]): string {
  return fields.map(f => `${f.name.trim()} ${f.type.trim()}`).join(", ");
}

export interface DraftValidation {
  ok: boolean;
  schema: string;
  errors: string[];
  duplicateNames: string[];
}

export function validateDraft(draft: SchemaDraft): DraftValidation {
  const schema = fieldSchema(draft.fields);
  const result = parseSchema(schema);
  const errors: string[] = [];
  if (!result.ok) errors.push(result.reason);
  const known = new Set<string>();
  const duplicates = new Set<string>();
  for (const field of draft.fields) {
    if (known.has(field.name.trim())) duplicates.add(field.name.trim());
    known.add(field.name.trim());
  }
  if (duplicates.size) errors.push("Duplicate field names: " + [...duplicates].join(", "));
  if (!StrKey.isValidEd25519PublicKey(draft.resolver) && !StrKey.isValidContract(draft.resolver)) {
    errors.push("Resolver must be a valid G... account or C... contract address.");
  }
  return { ok: errors.length === 0, schema, errors, duplicateNames: [...duplicates] };
}

export function reorderFields<T>(fields: readonly T[], from: number, to: number): T[] {
  if (!Number.isInteger(from) || !Number.isInteger(to) ||
      from < 0 || to < 0 || from >= fields.length || to >= fields.length) {
    return [...fields];
  }
  const reordered = [...fields];
  reordered.splice(to, 0, reordered.splice(from, 1)[0]);
  return reordered;
}

/**
 * XDR encoding mirrors soroban_sas_common::schema_uid:
 * sha256(schema.to_xdr || resolver.to_xdr || revocable as u8).
 * SHA-256 executes inside hash-wasm's browser WebAssembly module, not Node crypto.
 */
export async function computeSchemaUidWasm(draft: SchemaDraft): Promise<string> {
  const check = validateDraft(draft);
  if (!check.ok) throw new Error(check.errors.join(" "));
  const payload = [
    xdr.ScVal.scvString(Buffer.from(encoder.encode(check.schema))).toXDR(),
    Address.fromString(draft.resolver).toScVal().toXDR(),
    Buffer.from([draft.revocable ? 1 : 0]),
  ];
  const total = payload.reduce((sum, part) => sum + part.length, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const part of payload) {
    bytes.set(part, offset);
    offset += part.length;
  }
  return await sha256(bytes);
}
