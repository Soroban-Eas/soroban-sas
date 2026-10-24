import { sha256 } from "@noble/hashes/sha2.js";
import { Buffer } from "buffer";
import { scvAddress, scvBytes, scvString, scvVec } from "./soroban-xdr.js";
import type { Attestation, AttestationDomain, UID } from "./types.js";

const PAYLOAD_PREFIX = Buffer.from([0x19, ...Buffer.from("SorobanSAS", "ascii"), 0x01]);
const DOMAIN_TYPE_TAG = Buffer.from("SorobanSAS Domain v1(network_id,contract,nonce)", "ascii");
const ATTESTATION_TYPE_TAG = Buffer.from("SorobanSAS Attestation v1(uid,schema_uid,time,expiration_time,ref_uid,recipient,attester,revocable,data)", "ascii");
const MAX_U64 = (1n << 64n) - 1n;

function concat(parts: Uint8Array[]): Uint8Array { const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0)); let offset = 0; for (const part of parts) { output.set(part, offset); offset += part.length; } return output; }
function digest(...parts: Uint8Array[]): Buffer { return Buffer.from(sha256(concat(parts))); }
function u64BE(value: bigint | number): Uint8Array {
  const integer = typeof value === "bigint" ? value : Number.isSafeInteger(value) ? BigInt(value) : -1n;
  if (integer < 0n || integer > MAX_U64) throw new RangeError("u64 value must be an unsigned 64-bit integer");
  const output = new Uint8Array(8); new DataView(output.buffer).setBigUint64(0, integer, false); return output;
}
function hexToBytes(uid: UID): Uint8Array {
  const clean = typeof uid === "string" && uid.startsWith("0x") ? uid.slice(2) : uid;
  if (typeof clean !== "string" || clean.length !== 64 || !/^[0-9a-fA-F]+$/.test(clean)) throw new Error("UID must be exactly 32 bytes of hexadecimal");
  const output = new Uint8Array(32); for (let i = 0; i < 32; i += 1) output[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16); return output;
}
function bool(value: boolean): Uint8Array { if (typeof value !== "boolean") throw new TypeError("Expected boolean"); return Uint8Array.of(value ? 1 : 0); }

export function hashDomain(domain: AttestationDomain): Buffer {
  if (!(domain.networkId instanceof Uint8Array) || domain.networkId.length !== 32) throw new Error("networkId must be 32 bytes");
  return digest(DOMAIN_TYPE_TAG, domain.networkId, scvAddress(domain.contract), u64BE(domain.nonce));
}
export function hashAttestationStruct(attestation: Attestation): Buffer { return digest(ATTESTATION_TYPE_TAG, hexToBytes(attestation.uid), hexToBytes(attestation.schemaUid), u64BE(attestation.time), u64BE(attestation.expirationTime), hexToBytes(attestation.refUid), scvAddress(attestation.recipient), scvAddress(attestation.attester), bool(attestation.revocable), sha256(attestation.data)); }
export function hashTypedData(attestation: Attestation, domain: AttestationDomain): Buffer { return digest(PAYLOAD_PREFIX, hashDomain(domain), hashAttestationStruct(attestation)); }
export function computeSchemaUid(schema: string, resolver: string, revocable: boolean): UID { return digest(scvString(schema), scvAddress(resolver), bool(revocable)).toString("hex"); }
export function computeAttestationUid(schemaUid: UID, recipient: string, attester: string, data: Uint8Array): UID { return digest(scvVec([scvBytes(hexToBytes(schemaUid))]), scvAddress(recipient), scvAddress(attester), scvBytes(data)).toString("hex"); }
