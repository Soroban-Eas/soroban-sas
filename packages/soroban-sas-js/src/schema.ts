import { Address, xdr } from "@stellar/stellar-sdk";

type Trim<S extends string> = S extends ` ${infer R}` ? Trim<R> : S extends `${infer R} ` ? Trim<R> : S;
type SchemaValue<T extends string> =
  T extends "bool" ? boolean :
  T extends "uint32" | "u32" ? number :
  T extends "uint64" | "u64" ? bigint :
  T extends "string" | "String" | "address" | "Address" ? string :
  T extends "bytes" | "Bytes" | `BytesN<${number}>` ? Uint8Array :
  T extends `Vec<${infer E}>` ? SchemaValue<E>[] :
  T extends `Option<${infer E}>` ? SchemaValue<E> | null : never;
type FieldObject<F extends string> =
  F extends `${infer A} ${infer B}` ?
    [SchemaValue<A>] extends [never] ? { [K in A]: SchemaValue<B> } : { [K in B]: SchemaValue<A> } : never;
type Simplify<T> = { [K in keyof T]: T[K] };

/** Infer a typed payload from a literal schema string. Unsupported types become `never`. */
export type InferSchema<S extends string> = S extends `${infer F},${infer Rest}`
  ? Simplify<FieldObject<Trim<F>> & InferSchema<Trim<Rest>>>
  : FieldObject<Trim<S>>;

export type SchemaType =
  | { kind: "bool" | "uint32" | "uint64" | "string" | "bytes" | "address" }
  | { kind: "bytesN"; length: number }
  | { kind: "vec" | "option"; element: SchemaType };
export interface SchemaField { name: string; type: SchemaType }
export interface SchemaCodec<T> {
  readonly fields: readonly SchemaField[];
  encode(value: T): Buffer;
  decode(bytes: Uint8Array): T;
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_BYTES = 1024;
const MAX_FIELDS = 64;

function parseType(input: string): SchemaType {
  switch (input) {
    case "bool": return { kind: "bool" };
    case "uint32": case "u32": return { kind: "uint32" };
    case "uint64": case "u64": return { kind: "uint64" };
    case "string": case "String": return { kind: "string" };
    case "bytes": case "Bytes": return { kind: "bytes" };
    case "address": case "Address": return { kind: "address" };
  }
  const fixed = /^BytesN<([1-9][0-9]*)>$/.exec(input);
  if (fixed) {
    const length = Number(fixed[1]);
    if (length <= 32) return { kind: "bytesN", length };
  }
  for (const [prefix, kind] of [["Vec<", "vec"], ["Option<", "option"]] as const) {
    if (input.startsWith(prefix) && input.endsWith(">")) {
      return { kind, element: parseType(input.slice(prefix.length, -1)) };
    }
  }
  throw new Error(`Unsupported SAS schema type: ${input}`);
}

function parseFields(schema: string): SchemaField[] {
  if (!schema || Buffer.byteLength(schema, "utf8") > MAX_BYTES || /[\x00-\x1f\x7f]/.test(schema)) {
    throw new Error("Invalid SAS schema length or control character");
  }
  const parts = schema.split(",");
  if (parts.length > MAX_FIELDS) throw new Error("SAS schema exceeds 64 fields");
  const names = new Set<string>();
  return parts.map((part, index) => {
    if (part.startsWith("  ") || (index === 0 && part.startsWith(" ")) || part.endsWith(" ")) {
      throw new Error(`Invalid spacing in schema field ${index + 1}`);
    }
    const field = index ? part.replace(/^ /, "") : part;
    if (Buffer.byteLength(field, "utf8") > 64) throw new Error("SAS schema field exceeds 64 bytes");
    const tokens = field.split(" ");
    if (tokens.length !== 2 || tokens.some((token) => !token)) throw new Error(`Invalid schema field: ${field}`);
    let name: string;
    let type: SchemaType;
    try {
      type = parseType(tokens[0]);
      name = tokens[1];
    } catch {
      name = tokens[0];
      type = parseType(tokens[1]);
    }
    if (!IDENT.test(name) || name.length > 32) throw new Error(`Invalid schema field name: ${name}`);
    if (names.has(name)) throw new Error(`Duplicate schema field: ${name}`);
    names.add(name);
    return { name, type };
  });
}

function encodeValue(type: SchemaType, value: unknown): xdr.ScVal {
  switch (type.kind) {
    case "bool":
      if (typeof value !== "boolean") break;
      return xdr.ScVal.scvBool(value);
    case "uint32":
      if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 0xffffffff) break;
      return xdr.ScVal.scvU32(value);
    case "uint64":
      if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn) break;
      return xdr.ScVal.scvU64(new xdr.Uint64(value));
    case "string":
      if (typeof value !== "string") break;
      return xdr.ScVal.scvString(value);
    case "address":
      if (typeof value !== "string") break;
      return Address.fromString(value).toScVal();
    case "bytes": case "bytesN":
      if (!(value instanceof Uint8Array) || (type.kind === "bytesN" && value.length !== type.length)) break;
      return xdr.ScVal.scvBytes(Buffer.from(value));
    case "vec":
      if (!Array.isArray(value)) break;
      return xdr.ScVal.scvVec(value.map((element) => encodeValue(type.element, element)));
    case "option":
      return value == null ? xdr.ScVal.scvVoid() : encodeValue(type.element, value);
  }
  throw new TypeError(`Invalid value for SAS schema type ${type.kind}`);
}

function expect(value: xdr.ScVal, kind: xdr.ScValType): void {
  if (value.switch() !== kind) throw new TypeError("XDR value does not match SAS schema");
}

function decodeValue(type: SchemaType, value: xdr.ScVal): unknown {
  if (type.kind === "option") {
    return value.switch() === xdr.ScValType.scvVoid() ? null : decodeValue(type.element, value);
  }
  switch (type.kind) {
    case "bool": expect(value, xdr.ScValType.scvBool()); return value.b();
    case "uint32": expect(value, xdr.ScValType.scvU32()); return value.u32();
    case "uint64": expect(value, xdr.ScValType.scvU64()); return BigInt(value.u64().toString());
    case "string": expect(value, xdr.ScValType.scvString()); return Buffer.from(value.str()).toString("utf8");
    case "address": expect(value, xdr.ScValType.scvAddress()); return Address.fromScVal(value).toString();
    case "bytes": case "bytesN": {
      expect(value, xdr.ScValType.scvBytes());
      const bytes = value.bytes();
      if (type.kind === "bytesN" && bytes.length !== type.length) throw new TypeError("Invalid fixed byte array length");
      return new Uint8Array(bytes);
    }
    case "vec": {
      expect(value, xdr.ScValType.scvVec());
      const elements = value.vec();
      if (!elements) throw new TypeError("Invalid XDR vector");
      return elements.map((element) => decodeValue(type.element, element));
    }
  }
}

/** Parse a registered SAS schema and encode/decode `contracttype` payload XDR. */
export function parseSchema<const S extends string>(schemaString: S): SchemaCodec<InferSchema<S>>;
export function parseSchema<T>(schemaString: string): SchemaCodec<T>;
export function parseSchema(schemaString: string): SchemaCodec<unknown> {
  const fields = parseFields(schemaString);
  const ordered = [...fields].sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  return {
    fields,
    encode(value: unknown): Buffer {
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("SAS payload must be an object");
      const record = value as Record<string, unknown>;
      if (Object.keys(record).length !== fields.length || fields.some(({ name }) => !Object.hasOwn(record, name))) {
        throw new TypeError("SAS payload fields do not match schema");
      }
      return xdr.ScVal.scvMap(ordered.map(({ name, type }) => new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol(name), val: encodeValue(type, record[name]),
      }))).toXDR();
    },
    decode(bytes: Uint8Array): unknown {
      const root = xdr.ScVal.fromXDR(Buffer.from(bytes));
      expect(root, xdr.ScValType.scvMap());
      const entries = root.map();
      if (!entries || entries.length !== fields.length) throw new TypeError("XDR fields do not match SAS schema");
      const values = new Map<string, xdr.ScVal>();
      for (const entry of entries) {
        expect(entry.key(), xdr.ScValType.scvSymbol());
        const name = Buffer.from(entry.key().sym()).toString("utf8");
        if (values.has(name)) throw new TypeError("Duplicate XDR field");
        values.set(name, entry.val());
      }
      const result: Record<string, unknown> = {};
      for (const { name, type } of fields) {
        const entry = values.get(name);
        if (!entry) throw new TypeError(`Missing XDR field: ${name}`);
        result[name] = decodeValue(type, entry);
      }
      return result;
    },
  };
}
