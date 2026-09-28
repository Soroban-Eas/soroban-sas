// A TypeScript port of `soroban_sas_common::validate_schema_syntax`
// (packages/soroban-sas-common/src/validation.rs), extended to return the
// parsed fields and a human-readable reason instead of a bare error code.
//
// It works on UTF-8 bytes and applies the same rules, in the same order, as
// the Rust validator. Parity is enforced by the shared golden vectors in
// packages/soroban-sas-common/test_vectors/schema_syntax.tsv, which both
// test suites replay. When the contract rules change, update both
// implementations and add a vector.

/** Byte-length ceiling (`MAX_SCHEMA_LENGTH`). */
export const MAX_SCHEMA_LENGTH = 1024;
/** Field-count ceiling (`MAX_SCHEMA_FIELDS`). */
export const MAX_SCHEMA_FIELDS = 64;
/** Per-field byte ceiling: `name Type` after trimming. */
export const MAX_FIELD_LENGTH = 64;
/** Identifier and type byte ceilings. */
export const MAX_IDENTIFIER_LENGTH = 32;
export const MAX_TYPE_LENGTH = 32;

/** The `SASError` variant the contract would return for this schema. */
export type SchemaErrorCode = "InvalidSchema" | "EmptySchema";

export interface SchemaField {
  name: string;
  type: string;
}

export type SchemaParseResult =
  | { ok: true; fields: SchemaField[]; byteLength: number }
  | {
      ok: false;
      code: SchemaErrorCode;
      reason: string;
      /** Fields successfully parsed before the first error. */
      fields: SchemaField[];
      byteLength: number;
    };

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function isWhitespace(byte: number): boolean {
  // Matches Rust's `is_ascii_whitespace` helper in validation.rs:
  // space, \n, \r, \t, vertical tab, form feed.
  return byte === 0x20 || byte === 0x0a || byte === 0x0d || byte === 0x09 || byte === 0x0b || byte === 0x0c;
}

function isAlpha(byte: number): boolean {
  return (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a);
}

function isDigit(byte: number): boolean {
  return byte >= 0x30 && byte <= 0x39;
}

const TYPE_PUNCTUATION = new Set([..."_<>[],:() ?"].map((c) => c.charCodeAt(0)));

function trimBounds(bytes: Uint8Array, start: number, end: number): [number, number] | null {
  while (start < end && isWhitespace(bytes[start])) start++;
  while (end > start && isWhitespace(bytes[end - 1])) end--;
  return start >= end ? null : [start, end];
}

function isValidIdentifier(bytes: Uint8Array, start: number, end: number): boolean {
  if (start >= end) return false;
  const first = bytes[start];
  if (!(isAlpha(first) || first === 0x5f)) return false;
  for (let i = start + 1; i < end; i++) {
    const b = bytes[i];
    if (!(isAlpha(b) || isDigit(b) || b === 0x5f)) return false;
  }
  return true;
}

function isValidType(bytes: Uint8Array, start: number, end: number): boolean {
  if (start >= end) return false;
  let hasAlpha = false;
  for (let i = start; i < end; i++) {
    const b = bytes[i];
    if (isAlpha(b)) hasAlpha = true;
    if (!(isAlpha(b) || isDigit(b) || TYPE_PUNCTUATION.has(b))) return false;
  }
  return hasAlpha;
}

const text = (bytes: Uint8Array, start: number, end: number) => decoder.decode(bytes.subarray(start, end));

/** Parses and validates a schema string exactly as the Schema Registry does. */
export function parseSchema(schema: string): SchemaParseResult {
  const bytes = encoder.encode(schema);
  const byteLength = bytes.length;
  const fields: SchemaField[] = [];
  const fail = (code: SchemaErrorCode, reason: string): SchemaParseResult => ({
    ok: false,
    code,
    reason,
    fields,
    byteLength,
  });

  if (byteLength === 0) return fail("EmptySchema", "Schema is empty.");
  if (byteLength > MAX_SCHEMA_LENGTH) {
    return fail("InvalidSchema", `Schema is ${byteLength} bytes; the limit is ${MAX_SCHEMA_LENGTH}.`);
  }

  const outer = trimBounds(bytes, 0, byteLength);
  if (!outer) return fail("InvalidSchema", "Schema contains only whitespace.");
  let [start] = outer;
  const end = outer[1];

  while (start < end) {
    const n = fields.length + 1;
    let fieldEnd = start;
    while (fieldEnd < end && bytes[fieldEnd] !== 0x2c) fieldEnd++;

    const field = trimBounds(bytes, start, fieldEnd);
    if (!field) return fail("InvalidSchema", `Field ${n} is empty (check for doubled commas).`);
    const [fieldStart, fe] = field;
    if (fe - fieldStart > MAX_FIELD_LENGTH) {
      return fail("InvalidSchema", `Field ${n} is ${fe - fieldStart} bytes; the limit is ${MAX_FIELD_LENGTH}.`);
    }

    let split = fieldStart;
    while (split < fe && !isWhitespace(bytes[split])) split++;
    if (split === fieldStart || split >= fe) {
      return fail("InvalidSchema", `Field ${n} ("${text(bytes, fieldStart, fe)}") must be "name Type".`);
    }
    if (split - fieldStart > MAX_IDENTIFIER_LENGTH) {
      return fail("InvalidSchema", `Field ${n} name is longer than ${MAX_IDENTIFIER_LENGTH} bytes.`);
    }

    let tyStart = split;
    while (tyStart < fe && isWhitespace(bytes[tyStart])) tyStart++;
    if (fe - tyStart > MAX_TYPE_LENGTH) {
      return fail("InvalidSchema", `Field ${n} type is longer than ${MAX_TYPE_LENGTH} bytes.`);
    }

    const name = text(bytes, fieldStart, split);
    const type = text(bytes, tyStart, fe);
    if (tyStart >= fe || !isValidIdentifier(bytes, fieldStart, split)) {
      return fail(
        "InvalidSchema",
        `Field ${n} name "${name}" must start with a letter or "_" and contain only ASCII letters, digits and "_".`,
      );
    }
    if (!isValidType(bytes, tyStart, fe)) {
      return fail(
        "InvalidSchema",
        `Field ${n} type "${type}" must contain a letter and only ASCII letters, digits, spaces and _<>[]:()?.`,
      );
    }
    fields.push({ name, type });
    if (fields.length > MAX_SCHEMA_FIELDS) {
      return fail("InvalidSchema", `Schema declares more than ${MAX_SCHEMA_FIELDS} fields.`);
    }

    if (fieldEnd >= end) break;
    start = fieldEnd + 1;
    while (start < end && isWhitespace(bytes[start])) start++;
    if (start >= end) return fail("InvalidSchema", "Schema ends with a trailing comma.");
  }

  if (fields.length === 0) return fail("EmptySchema", "Schema declares no fields.");
  return { ok: true, fields, byteLength };
}
