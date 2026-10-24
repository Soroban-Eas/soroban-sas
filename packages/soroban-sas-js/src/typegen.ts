import { Address, nativeToScVal, scValToNative, xdr } from "@stellar/stellar-sdk";

export type SchemaType =
  | { kind: "primitive"; name: string }
  | { kind: "array"; item: SchemaType }
  | { kind: "option"; item: SchemaType }
  | { kind: "vector"; item: SchemaType }
  | { kind: "map"; key: SchemaType; value: SchemaType }
  | { kind: "tuple"; items: SchemaType[] };

export interface SchemaField {
  name: string;
  type: SchemaType;
  sourceType: string;
}

export interface ParsedSchema {
  fields: SchemaField[];
}

type ScVal = xdr.ScVal;

/** Parse a SAS schema definition using the same field separators as the Rust validator. */
export function parseSchema(schema: string): ParsedSchema {
  if (schema.length === 0 || Buffer.byteLength(schema, "utf8") > 1024) {
    throw new Error("schema must contain between 1 and 1024 UTF-8 bytes");
  }
  if (/[\u0000-\u001f\u007f-\u009f\u00a0\u1680\u2000-\u200f\u2028\u2029\u202f\u205f\u3000\ufeff\u00ad]/u.test(schema)) {
    throw new Error("schema contains control characters or unsupported whitespace");
  }
  const trimmed = schema.trim();
  if (!trimmed) throw new Error("schema is empty");
  const parts = trimmed.split(",");
  if (parts.length > 64) throw new Error("schema cannot contain more than 64 fields");
  const fields = parts.map((part): SchemaField => {
    if (part.endsWith(" ")) throw new Error(`invalid schema field: ${part}`);
    const field = part.trim();
    const match = /^([A-Za-z_][A-Za-z0-9_]*) (.+)$/u.exec(field);
    if (!match || match[1].length > 32 || match[2].length > 32 || field.length > 64) {
      throw new Error(`invalid schema field: ${part}`);
    }
    return { name: match[1], sourceType: match[2], type: parseType(match[2]) };
  });
  if (new Set(fields.map(({ name }) => name)).size !== fields.length) {
    throw new Error("schema field names must be unique");
  }
  return { fields };
}

function parseType(source: string): SchemaType {
  if (!source || source.includes("  ")) throw new Error(`invalid schema type: ${source}`);
  if (source.endsWith("?")) return { kind: "option", item: parseType(source.slice(0, -1)) };
  const array = /^\[(.+)]$/u.exec(source);
  if (array) return { kind: "array", item: parseType(array[1]) };
  const generic = /^(Option|Vec|Map)<(.+)>$/u.exec(source);
  if (generic) {
    if (generic[1] === "Map") {
      const colon = findTopLevel(generic[2], ":");
      if (colon < 0) throw new Error(`Map type must use Map<Key:Value>: ${source}`);
      return { kind: "map", key: parseType(generic[2].slice(0, colon)), value: parseType(generic[2].slice(colon + 1)) };
    }
    const item = parseType(generic[2]);
    return generic[1] === "Option" ? { kind: "option", item } : { kind: "vector", item };
  }
  const bytesN = /^BytesN<(\d+)>$/u.exec(source);
  if (bytesN) return { kind: "primitive", name: `BytesN<${bytesN[1]}>` };
  const tuple = /^Tuple\((.*)\)$/u.exec(source);
  if (tuple) {
    const items = splitTopLevel(tuple[1], " ").map(parseType);
    if (items.length < 2) throw new Error(`Tuple must have at least two types: ${source}`);
    return { kind: "tuple", items };
  }
  if (!/^[A-Za-z][A-Za-z0-9_]*$/u.test(source)) throw new Error(`unsupported schema type: ${source}`);
  return { kind: "primitive", name: source };
}

function findTopLevel(source: string, delimiter: string): number {
  let depth = 0;
  for (let i = 0; i < source.length; i++) {
    if ("<[(".includes(source[i])) depth++;
    else if (">])".includes(source[i])) depth--;
    else if (source[i] === delimiter && depth === 0) return i;
  }
  return -1;
}

function splitTopLevel(source: string, delimiter: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let depth = 0;
  for (let i = 0; i < source.length; i++) {
    if ("<[(".includes(source[i])) depth++;
    else if (">])".includes(source[i])) depth--;
    else if (source[i] === delimiter && depth === 0) {
      parts.push(source.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(source.slice(start));
  if (parts.some((part) => !part)) throw new Error(`invalid nested type: ${source}`);
  return parts;
}

/** Generate a TypeScript interface; field comments retain their source SAS type. */
export function generateTypeScript(schema: string, interfaceName = "AttestationPayload"): string {
  if (!/^[$A-Z_a-z][$\w]*$/u.test(interfaceName)) throw new Error(`invalid interface name: ${interfaceName}`);
  const { fields } = parseSchema(schema);
  const properties = fields.map(({ name, sourceType, type }) =>
    `  /** SAS schema type: ${sourceType} */\n  ${name}: ${typescriptType(type)};`,
  );
  return `export interface ${interfaceName} {\n${properties.join("\n")}\n}`;
}

function typescriptType(type: SchemaType): string {
  switch (type.kind) {
    case "primitive": {
      const name = normalizePrimitive(type.name);
      if (["string", "symbol"].includes(name)) return "string";
      if (["bool", "boolean"].includes(name)) return "boolean";
      if (["address", "account"].includes(name)) return "string";
      if (["bytes"].includes(name) || name.startsWith("bytesn<")) return "Uint8Array";
      if (/^(u?int|uint|int)(8|16|32|64|128|256)$/u.test(name) || /^[ui](8|16|32|64|128|256)$/u.test(name)) {
        return /(?:8|16|32)$/.test(name) ? "number" : "bigint";
      }
      if (["f32", "f64", "number"].includes(name)) return "number";
      throw new Error(`unsupported schema type: ${type.name}`);
    }
    case "array": case "vector": return `${typescriptType(type.item)}[]`;
    case "option": return `${typescriptType(type.item)} | null`;
    case "map": return `Map<${typescriptType(type.key)}, ${typescriptType(type.value)}>`;
    case "tuple": return `[${type.items.map(typescriptType).join(", ")}]`;
  }
}

/** Encode an object in schema field order as Soroban's ScVal vector XDR. */
export function encodeSchemaValue(schema: string, value: Record<string, unknown>): Buffer {
  const { fields } = parseSchema(schema);
  const expected = new Set(fields.map((field) => field.name));
  for (const key of Object.keys(value)) if (!expected.has(key)) throw new Error(`unexpected field: ${key}`);
  const vals = fields.map((field) => {
    if (!(field.name in value)) throw new Error(`missing field: ${field.name}`);
    return encodeValue(field.type, value[field.name], field.name);
  });
  return xdr.ScVal.scvVec(vals).toXDR();
}

/** Decode Soroban ScVal vector XDR produced by encodeSchemaValue. */
export function decodeSchemaValue<T extends Record<string, unknown> = Record<string, unknown>>(
  schema: string,
  encoded: Uint8Array,
): T {
  const { fields } = parseSchema(schema);
  const scval = xdr.ScVal.fromXDR(Buffer.from(encoded));
  if (scval.switch().name !== "scvVec") throw new Error("encoded schema value must be a Soroban vector");
  const values = scval.vec();
  if (!values || values.length !== fields.length) throw new Error("encoded value field count does not match schema");
  const result: Record<string, unknown> = {};
  fields.forEach((field, index) => { result[field.name] = decodeValue(field.type, values[index]); });
  return result as T;
}

function encodeValue(type: SchemaType, value: unknown, path: string): ScVal {
  const invalid = (): never => { throw new Error(`invalid value for ${path} (${describe(type)})`); };
  if (type.kind === "option") {
    if (value === null || value === undefined) return xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("None")]);
    return xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Some"), encodeValue(type.item, value, path)]);
  }
  if (type.kind === "array" || type.kind === "vector" || type.kind === "tuple") {
    if (!Array.isArray(value)) return invalid();
    const types = type.kind === "tuple" ? type.items : value.map(() => type.item);
    if (type.kind === "tuple" && types.length !== value.length) return invalid();
    return xdr.ScVal.scvVec(value.map((item, i) => encodeValue(types[i], item, `${path}[${i}]`)));
  }
  if (type.kind === "map") {
    const entries = value instanceof Map ? [...value.entries()] : (value && typeof value === "object" ? Object.entries(value) : invalid());
    const encoded = entries.map(([key, item]) => ({ key: encodeValue(type.key, key, `${path}.key`), val: encodeValue(type.value, item, `${path}[${String(key)}]`) }));
    encoded.sort((a, b) => Buffer.compare(a.key.toXDR(), b.key.toXDR()));
    return xdr.ScVal.scvMap(encoded);
  }
  const name = normalizePrimitive(type.name);
  if (["string", "symbol"].includes(name) && typeof value === "string") return name === "symbol" ? xdr.ScVal.scvSymbol(value) : xdr.ScVal.scvString(value);
  if (["address", "account"].includes(name) && typeof value === "string") return Address.fromString(value).toScVal();
  if (["bool", "boolean"].includes(name) && typeof value === "boolean") return xdr.ScVal.scvBool(value);
  if (name === "bytes" && value instanceof Uint8Array) return xdr.ScVal.scvBytes(Buffer.from(value));
  const bytesN = /^bytesn<(\d+)>$/u.exec(name);
  if ((name === "bytesn" || bytesN) && value instanceof Uint8Array) {
    if (bytesN && value.length !== Number(bytesN[1])) return invalid();
    return xdr.ScVal.scvBytes(Buffer.from(value));
  }
  if (/^u32$/u.test(name) && Number.isInteger(value) && Number(value) >= 0 && Number(value) <= 0xffff_ffff) return xdr.ScVal.scvU32(Number(value));
  if (/^i32$/u.test(name) && Number.isInteger(value) && Number(value) >= -0x8000_0000 && Number(value) <= 0x7fff_ffff) return xdr.ScVal.scvI32(Number(value));
  if (/^[ui](64|128|256)$/u.test(name) && (typeof value === "bigint" || Number.isSafeInteger(value))) {
    if (name.startsWith("u") && BigInt(value as number | bigint) < 0n) return invalid();
    return nativeToScVal(value, { type: name as "u64" | "i64" | "u128" | "i128" | "u256" | "i256" });
  }
  return invalid();
}

function decodeValue(type: SchemaType, value: ScVal): unknown {
  if (type.kind === "option") {
    const vals = value.vec();
    if (!vals || vals.length === 1 && vals[0].sym() === "None") return null;
    if (!vals || vals.length !== 2 || vals[0].sym() !== "Some") throw new Error("invalid encoded Option");
    return decodeValue(type.item, vals[1]);
  }
  if (type.kind === "array" || type.kind === "vector" || type.kind === "tuple") {
    const vals = value.vec();
    if (!vals) throw new Error("expected encoded vector");
    const types = type.kind === "tuple" ? type.items : vals.map(() => type.item);
    if (type.kind === "tuple" && types.length !== vals.length) throw new Error("tuple length does not match schema");
    return vals.map((item, i) => decodeValue(types[i], item));
  }
  if (type.kind === "map") {
    const map = value.map();
    if (!map) throw new Error("expected encoded map");
    return new Map(map.map(({ key, val }) => [decodeValue(type.key, key), decodeValue(type.value, val)]));
  }
  const n = normalizePrimitive(type.name);
  if (["string", "symbol"].includes(n)) return n === "symbol" ? value.sym() : value.str().toString();
  if (["address", "account"].includes(n)) return Address.fromScVal(value).toString();
  if (["bool", "boolean"].includes(n)) return value.b();
  if (n === "bytes" || n === "bytesn" || n.startsWith("bytesn<")) return new Uint8Array(value.bytes());
  if (n === "u32") return value.u32();
  if (n === "i32") return value.i32();
  if (/^[ui](64|128|256)$/u.test(n)) return scValToNative(value);
  throw new Error(`unsupported schema type: ${type.name}`);
}

function describe(type: SchemaType): string {
  return type.kind === "primitive" ? type.name : type.kind;
}

function normalizePrimitive(source: string): string {
  const name = source.toLowerCase()
    .replace(/^uint(8|16|32|64|128|256)$/u, "u$1")
    .replace(/^int(8|16|32|64|128|256)$/u, "i$1");
  if (name === "u8" || name === "u16") return "u32";
  if (name === "i8" || name === "i16") return "i32";
  return name;
}
