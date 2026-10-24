// Runtime implementation of the off-chain schema grammar for differential fuzzing.
// All input is base64-encoded raw bytes, one value per line.
import { createInterface } from "node:readline";
const invisible = new Set([0x85,0xa0,0x1680,0x200c,0x200d,0x2028,0x2029,0x202f,0x205f,0x2060,0x3000,0xfeff,0xad]);

export function classifySchema(data) {
  if (data.length === 0) return "empty";
  if (data.length > 1024) return "invalid";
  if (data.some(byte => byte < 32 || byte === 127)) return "invalid";
  let content;
  try { content = new TextDecoder("utf-8", { fatal: true }).decode(data); }
  catch { return "invalid"; }
  for (const char of content) {
    const n = char.codePointAt(0);
    if ((/\s/u.test(char) && char !== " ") || invisible.has(n) || (n >= 0x2000 && n <= 0x200b))
      return "invalid";
  }
  const parts = content.trim().split(",");
  if (parts.length > 64) return "invalid";
  if (parts.length === 0) return "empty";
  for (let i = 0; i < parts.length; i++) {
    // Rust permits one optional space following a comma, but none before.
    let field = parts[i];
    if (i > 0) {
      if (field.startsWith("  ")) return "invalid";
      if (field.startsWith(" ")) field = field.slice(1);
    }
    if (i < parts.length - 1 && field.endsWith(" ")) return "invalid";
    if (i === 0) field = field.trimStart();
    if (i === parts.length - 1) field = field.trimEnd();
    if (field.length > 64 || field.length === 0) return "invalid";
    const separator = field.indexOf(" ");
    if (separator <= 0 || separator === field.length - 1) return "invalid";
    const name = field.slice(0, separator);
    const type = field.slice(separator + 1);
    if (name.length > 32 || type.length > 32 || type.startsWith(" ")) return "invalid";
    if (!/^[A-Za-z_][A-Za-z_0-9]*$/.test(name)) return "invalid";
    if (!/[A-Za-z]/.test(type) || !/^[A-Za-z0-9_<>\[\],:()? ]+$/.test(type) || type.includes("  "))
      return "invalid";
  }
  return "valid";
}

if (process.argv[1]?.endsWith("schema-validator-runner.mjs")) {
  const reader = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of reader) {
    try { process.stdout.write(classifySchema(Buffer.from(line, "base64")) + "\n"); }
    catch { process.stdout.write("invalid\n"); }
  }
}
