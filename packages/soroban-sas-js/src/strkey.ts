const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const REVERSE = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i += 1) REVERSE[ALPHABET.charCodeAt(i)] = i;

const VERSION_ACCOUNT = 6 << 3;
const VERSION_CONTRACT = 2 << 3;
const VERSION_SEED = 18 << 3;

function crc16(data: Uint8Array): number {
  let crc = 0;
  for (const byte of data) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 0x8000) !== 0 ? (crc << 1) ^ 0x1021 : crc << 1;
      crc &= 0xffff;
    }
  }
  return crc;
}

function encodeBase32(data: Uint8Array): string {
  let value = 0;
  let bits = 0;
  let result = "";
  for (const byte of data) {
    value = ((value << 8) | byte) & 0x7fffffff;
    bits += 8;
    while (bits >= 5) { bits -= 5; result += ALPHABET[(value >>> bits) & 31]; }
  }
  if (bits > 0) result += ALPHABET[(value << (5 - bits)) & 31];
  return result;
}

function decodeBase32(input: string): Uint8Array {
  let value = 0;
  let bits = 0;
  const result: number[] = [];
  for (const character of input) {
    const code = character.charCodeAt(0);
    if (code >= REVERSE.length || REVERSE[code] < 0) throw new Error("Invalid StrKey base32 character");
    value = ((value << 5) | REVERSE[code]) & 0x7fffffff;
    bits += 5;
    if (bits >= 8) { bits -= 8; result.push((value >>> bits) & 0xff); }
  }
  if (bits >= 5 || (value & ((1 << bits) - 1)) !== 0) throw new Error("Invalid StrKey base32 padding");
  return Uint8Array.from(result);
}

function encode(version: number, payload: Uint8Array): string {
  if (payload.length !== 32) throw new Error("StrKey payload must be exactly 32 bytes");
  const body = new Uint8Array(33); body[0] = version; body.set(payload, 1);
  const checksum = crc16(body); const complete = new Uint8Array(35); complete.set(body);
  complete[33] = checksum & 0xff; complete[34] = checksum >>> 8;
  return encodeBase32(complete);
}

function decode(input: string, version: number, label: string): Uint8Array {
  if (typeof input !== "string") throw new TypeError(`${label} must be a string`);
  const decoded = decodeBase32(input);
  if (decoded.length !== 35 || decoded[0] !== version) throw new Error(`Invalid ${label} version or length`);
  const expected = crc16(decoded.subarray(0, 33));
  if (decoded[33] !== (expected & 0xff) || decoded[34] !== (expected >>> 8)) throw new Error(`Invalid ${label} checksum`);
  return decoded.slice(1, 33);
}

export function encodeAccount(payload: Uint8Array): string { return encode(VERSION_ACCOUNT, payload); }
export function encodeContract(payload: Uint8Array): string { return encode(VERSION_CONTRACT, payload); }
export function decodeAccount(address: string): Uint8Array { return decode(address, VERSION_ACCOUNT, "account address"); }
export function decodeContract(address: string): Uint8Array { return decode(address, VERSION_CONTRACT, "contract address"); }
export function decodeSeed(seed: string): Uint8Array { return decode(seed, VERSION_SEED, "secret seed"); }

export function decodeAddress(address: string): { kind: "account" | "contract"; payload: Uint8Array } {
  if (typeof address !== "string" || address.length === 0) throw new Error("Address must be a non-empty string");
  if (address[0] === "G") return { kind: "account", payload: decodeAccount(address) };
  if (address[0] === "C") return { kind: "contract", payload: decodeContract(address) };
  throw new Error("Address must be a Stellar account (G...) or contract (C...)");
}
