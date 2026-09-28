const UID_PATTERN = /^[0-9a-f]{64}$/i;

/** True if `value` is a 32-byte UID written as 64 hex characters (no 0x prefix). */
export function isUidHex(value: string): boolean {
  return UID_PATTERN.test(value);
}

/** Normalizes user input: trims, drops an optional 0x prefix, lowercases. */
export function normalizeUid(value: string): string {
  const trimmed = value.trim();
  return (trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed).toLowerCase();
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new Error("invalid hex string");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** `aabbccdd…eeff` style shortening for long identifiers. */
export function shorten(value: string, head = 8, tail = 6): string {
  return value.length <= head + tail + 1 ? value : `${value.slice(0, head)}…${value.slice(-tail)}`;
}
