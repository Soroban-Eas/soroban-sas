// Byte-identical port of the hashing scheme defined in
// packages/soroban-sas-common/src/lib.rs (schema_uid, attestation_uid) and
// packages/soroban-sas-common/src/typed_data.rs (hash_offchain_attestation).
//
// Every field that the Rust side hashes via `.to_xdr(env)` (a `String`,
// `Address`, `Bytes`, or `UID` newtype) is XDR-encoded here as the exact same
// `ScVal` shape using `@stellar/stellar-sdk`'s `xdr` and `Address` bindings,
// which implement the same Stellar XDR spec as the Rust `stellar-xdr` crate.
// Fields the Rust side hashes as raw bytes (`u64` big-endian, `BytesN<32>`
// arrays) are encoded the same way here — never wrapped in an `ScVal`.
//
// See packages/soroban-sas-js/README.md for the full preimage layouts, and
// test/hashing.test.ts for the golden vectors this file is pinned against.

import { Address, xdr } from "@stellar/stellar-sdk";
import { createHash } from "node:crypto";
import type { Attestation, AttestationDomain, UID } from "./types.js";

/** `b"\x19SorobanSAS\x01"` — analogous to EIP-191's `\x19\x01` prefix. */
const PAYLOAD_PREFIX = Buffer.from([
  0x19, ...Buffer.from("SorobanSAS", "ascii"), 0x01,
]);

/** `b"SorobanSAS Domain v1(network_id,contract,nonce)"`. */
const DOMAIN_TYPE_TAG = Buffer.from(
  "SorobanSAS Domain v1(network_id,contract,nonce)",
  "ascii",
);

/**
 * `b"SorobanSAS Attestation v1(uid,schema_uid,time,expiration_time,ref_uid,recipient,attester,revocable,data)"`.
 */
const ATTESTATION_TYPE_TAG = Buffer.from(
  "SorobanSAS Attestation v1(uid,schema_uid,time,expiration_time,ref_uid,recipient,attester,revocable,data)",
  "ascii",
);

function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

function u64BE(value: bigint | number): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(typeof value === "bigint" ? value : BigInt(value));
  return buf;
}

function hexToBytes(hex: UID): Buffer {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length !== 64) {
    throw new Error(`UID must be exactly 32 bytes (64 hex chars), got "${hex}"`);
  }
  return Buffer.from(clean, "hex");
}

/** Full `ScVal::Address(...)` XDR for a strkey account (G...) or contract (C...) address. */
function addressToXdr(address: string): Buffer {
  return Address.fromString(address).toScVal().toXDR();
}

/**
 * The XDR a `UID` newtype (`soroban_sas_common::UID(BytesN<32>)`) produces
 * via `.to_xdr(env)`: a single-element `ScVec` wrapping the 32 raw bytes
 * (see packages/soroban-sas-sdk/src/events.rs's `decode_uid` for the same
 * observation on the decoding side).
 */
function uidToXdr(uid: UID): Buffer {
  return xdr.ScVal.scvVec([xdr.ScVal.scvBytes(hexToBytes(uid))]).toXDR();
}

/** Hashes the domain separator: `TAG || network_id || contract.to_xdr() || nonce_be`. */
export function hashDomain(domain: AttestationDomain): Buffer {
  const buf = Buffer.concat([
    DOMAIN_TYPE_TAG,
    Buffer.from(domain.networkId),
    addressToXdr(domain.contract),
    u64BE(domain.nonce),
  ]);
  return sha256(buf);
}

/**
 * Hashes an `Attestation` with the fixed field layout `hash_attestation_struct`
 * uses: `TAG || uid || schema_uid || time || expiration_time || ref_uid ||
 * recipient.to_xdr() || attester.to_xdr() || revocable || sha256(data)`.
 * `uid`/`schema_uid`/`ref_uid` are hashed as raw 32-byte arrays here (not
 * XDR-wrapped) — this differs from `computeAttestationUid`, which does wrap
 * `schema_uid` in its XDR form; the two preimages are deliberately distinct.
 */
export function hashAttestationStruct(attestation: Attestation): Buffer {
  const buf = Buffer.concat([
    ATTESTATION_TYPE_TAG,
    hexToBytes(attestation.uid),
    hexToBytes(attestation.schemaUid),
    u64BE(attestation.time),
    u64BE(attestation.expirationTime),
    hexToBytes(attestation.refUid),
    addressToXdr(attestation.recipient),
    addressToXdr(attestation.attester),
    Buffer.from([attestation.revocable ? 1 : 0]),
    sha256(Buffer.from(attestation.data)),
  ]);
  return sha256(buf);
}

/**
 * The digest an attester signs off-chain and `SAS::attest_by_delegation`
 * re-derives on-chain: `sha256(PAYLOAD_PREFIX || hashDomain(domain) ||
 * hashAttestationStruct(attestation))`. Byte-identical to Rust's
 * `hash_offchain_attestation` — see test/hashing.test.ts's golden vectors,
 * pinned from `packages/soroban-sas-common/src/typed_data.rs`.
 */
export function hashTypedData(
  attestation: Attestation,
  domain: AttestationDomain,
): Buffer {
  const buf = Buffer.concat([
    PAYLOAD_PREFIX,
    hashDomain(domain),
    hashAttestationStruct(attestation),
  ]);
  return sha256(buf);
}

/**
 * Byte-identical port of `soroban_sas_common::schema_uid`:
 * `sha256(schema.to_xdr() || resolver.to_xdr() || [revocable as u8])`.
 */
export function computeSchemaUid(
  schema: string,
  resolver: string,
  revocable: boolean,
): UID {
  const payload = Buffer.concat([
    xdr.ScVal.scvString(Buffer.from(schema, "utf8")).toXDR(),
    addressToXdr(resolver),
    Buffer.from([revocable ? 1 : 0]),
  ]);
  return sha256(payload).toString("hex");
}

/**
 * Byte-identical port of `soroban_sas_common::attestation_uid`:
 * `sha256(schema_uid.to_xdr() || recipient.to_xdr() || attester.to_xdr() ||
 * data.to_xdr())`. Unlike `hashAttestationStruct`, every field here is the
 * full `ScVal` XDR encoding (including `data`, which is XDR-wrapped rather
 * than SHA-256'd) — this is the digest the contract checks `Attestation.uid`
 * against, not the typed-data signing digest.
 */
export function computeAttestationUid(
  schemaUid: UID,
  recipient: string,
  attester: string,
  data: Uint8Array,
): UID {
  const payload = Buffer.concat([
    uidToXdr(schemaUid),
    addressToXdr(recipient),
    addressToXdr(attester),
    xdr.ScVal.scvBytes(Buffer.from(data)).toXDR(),
  ]);
  return sha256(payload).toString("hex");
}
