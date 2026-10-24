import { decodeAddress } from "./strkey.js";

const SCV_BYTES = 13;
const SCV_STRING = 14;
const SCV_VEC = 16;
const SCV_ADDRESS = 18;

function padding(length: number): number { return (4 - (length % 4)) % 4; }
function i32(value: number): Uint8Array { const output = new Uint8Array(4); new DataView(output.buffer).setInt32(0, value, false); return output; }
function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0; for (const part of parts) { output.set(part, offset); offset += part.length; } return output;
}
function opaque(bytes: Uint8Array): Uint8Array { return concat(i32(bytes.length), bytes, new Uint8Array(padding(bytes.length))); }
export function scvBytes(bytes: Uint8Array): Uint8Array { return concat(i32(SCV_BYTES), opaque(bytes)); }

export function scvString(value: string): Uint8Array {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) { const next = value.charCodeAt(i + 1); if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) throw new Error("String contains invalid UTF-16"); i += 1; }
    else if (code >= 0xdc00 && code <= 0xdfff) throw new Error("String contains invalid UTF-16");
  }
  return concat(i32(SCV_STRING), opaque(new TextEncoder().encode(value)));
}

export function scvAddress(address: string): Uint8Array {
  const decoded = decodeAddress(address);
  return concat(i32(SCV_ADDRESS), i32(decoded.kind === "account" ? 0 : 1), decoded.kind === "account" ? i32(0) : new Uint8Array(0), decoded.payload);
}
export function scvVec(values: Uint8Array[]): Uint8Array { return concat(i32(SCV_VEC), i32(1), i32(values.length), ...values); }
