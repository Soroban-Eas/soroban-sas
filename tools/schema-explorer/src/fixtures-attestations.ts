// Offline demo attestation data.
//
// `FixtureAttestationCaller` answers the same contract calls the real SAS and
// Indexer contracts do, with the same ScVal encodings, so demo mode (and unit
// tests) exercise the exact decode path used against a live node.

import { Buffer } from "buffer";
import { Address, nativeToScVal, scValToNative, xdr } from "@stellar/stellar-sdk";
import type { ContractCaller } from "./registry.js";
import { RegistryError } from "./registry.js";
import type { AttestationRecord } from "./attestation.js";
import { bytesToHex, hexToBytes } from "./hex.js";

// ---------------------------------------------------------------------------
// Well-known demo addresses (matching fixtures.ts for consistency)
// ---------------------------------------------------------------------------

export const DEMO_SAS_CONTRACT_ID = "CAXWQYPVOXU7625ASPQIAQCFNT45QQPEQGG3GMMQCSR5NAWZSFHKEI35";
export const DEMO_INDEXER_CONTRACT_ID = "CBP4L4C7PRFRTQ7SXGZBJWBLB5ULZA4LS47YOJLH5FHGWGZE5VIBSXZQ";

const RECIPIENT_A = "GCI7YTLFUAWQ2Y5MAWAOFICWUWC5MUMARISUEPVMB3KYUH46WII5MS7T";
const RECIPIENT_B = "GCSRJAYDZNAMOPK6DXLD5ZKAFGL2ZCUB4WNFTBZAUWHBEPCJ3KVLC7MD";
const RECIPIENT_C = "GAPOTHQU7LPZSGKYIU5JES5SKPKLUC7Y2YEHLXJJKPRJIKFEUIUK3ZE4";
const ATTESTER_A = "GCNYPY3ON6ATJ2SRQESUDQ73QZTPYDT7FIKJ5IDXXGBLAHQV7KVSCRU2";
const ATTESTER_B = "GB2AZMJBJRETF43UHYI2HAAD2MC34OCH6RXUEPF3XH55GTNNJSBBN2TL";

const SCHEMA_KYC = "15081fe68b1912539ccb82ca6929b0a7c47711c5c3615970c02da86005fc3557";
const SCHEMA_VOTE = "ca5088bb191888e8c76a60582a762da826dc81e450f57da7926439039f4adffd";
const SCHEMA_ENDORSE = "c4c8545f300f85768c62ce1e385c664202c70fd6b9852e1b00b3e5244ea22575";

// ---------------------------------------------------------------------------
// Demo attestation records
// ---------------------------------------------------------------------------

const NOW = Math.floor(Date.now() / 1000);

export const DEMO_ATTESTATIONS: readonly AttestationRecord[] = [
  // Active KYC attestation
  {
    uid: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    schemaUid: SCHEMA_KYC,
    time: NOW - 86400 * 30,
    expirationTime: NOW + 86400 * 335,
    revocationTime: 0,
    refUid: "",
    recipient: RECIPIENT_A,
    attester: ATTESTER_A,
    revocable: true,
    data: "01000000010000000000000001",
  },
  // Active governance vote
  {
    uid: "b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3d4e5f6a7b2c3",
    schemaUid: SCHEMA_VOTE,
    time: NOW - 86400 * 7,
    expirationTime: 0,
    revocationTime: 0,
    refUid: "",
    recipient: RECIPIENT_B,
    attester: ATTESTER_A,
    revocable: false,
    data: "deadbeef01020304",
  },
  // Expired KYC
  {
    uid: "c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4e5f6a7b8c3d4",
    schemaUid: SCHEMA_KYC,
    time: NOW - 86400 * 400,
    expirationTime: NOW - 86400 * 35,
    revocationTime: 0,
    refUid: "",
    recipient: RECIPIENT_C,
    attester: ATTESTER_B,
    revocable: true,
    data: "00",
  },
  // Revoked endorsement
  {
    uid: "d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5",
    schemaUid: SCHEMA_ENDORSE,
    time: NOW - 86400 * 60,
    expirationTime: 0,
    revocationTime: NOW - 86400 * 5,
    refUid: "",
    recipient: RECIPIENT_A,
    attester: ATTESTER_B,
    revocable: true,
    data: "0102030405060708",
  },
  // Active endorsement with ref
  {
    uid: "e5f6a7b8c9d0e5f6a7b8c9d0e5f6a7b8c9d0e5f6a7b8c9d0e5f6a7b8c9d0e5f6",
    schemaUid: SCHEMA_ENDORSE,
    time: NOW - 86400 * 2,
    expirationTime: NOW + 86400 * 90,
    revocationTime: 0,
    refUid: "d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5f6a7b8c9d4e5",
    recipient: RECIPIENT_B,
    attester: ATTESTER_A,
    revocable: true,
    data: "cafe",
  },
  // Active, no expiry, irrevocable (bare-bones)
  {
    uid: "f6a7b8c9d0e1f6a7b8c9d0e1f6a7b8c9d0e1f6a7b8c9d0e1f6a7b8c9d0e1f6a7",
    schemaUid: SCHEMA_KYC,
    time: NOW - 3600,
    expirationTime: 0,
    revocationTime: 0,
    refUid: "",
    recipient: RECIPIENT_C,
    attester: ATTESTER_A,
    revocable: false,
    data: "",
  },
];

// ---------------------------------------------------------------------------
// ScVal encoding helpers (mirror attestation.ts logic in reverse)
// ---------------------------------------------------------------------------

function uidScVal(hex: string): xdr.ScVal {
  return xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.from(hexToBytes(hex)))]);
}

function entry(key: string, val: xdr.ScVal): xdr.ScMapEntry {
  return new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });
}

function attestationToScVal(r: AttestationRecord): xdr.ScVal {
  const refBytes = r.refUid ? Buffer.from(hexToBytes(r.refUid)) : Buffer.alloc(32);
  return xdr.ScVal.scvMap([
    entry("attester", new Address(r.attester).toScVal()),
    entry("data", xdr.ScVal.scvBytes(r.data ? Buffer.from(hexToBytes(r.data)) : Buffer.alloc(0))),
    entry("expiration_time", nativeToScVal(BigInt(r.expirationTime), { type: "u64" })),
    entry("recipient", new Address(r.recipient).toScVal()),
    entry("ref_uid", uidScVal(bytesToHex(refBytes))),
    entry("revocable", xdr.ScVal.scvBool(r.revocable)),
    entry("revocation_time", nativeToScVal(BigInt(r.revocationTime), { type: "u64" })),
    entry("schema_uid", uidScVal(r.schemaUid)),
    entry("time", nativeToScVal(BigInt(r.time), { type: "u64" })),
    entry("uid", uidScVal(r.uid)),
  ]);
}

function argUid(args: xdr.ScVal[]): string {
  const native = scValToNative(args[0]) as unknown;
  if (!Array.isArray(native) || !(native[0] instanceof Uint8Array)) {
    throw new RegistryError("expected UID argument");
  }
  return bytesToHex(native[0] as Uint8Array);
}

function argAddress(args: xdr.ScVal[]): string {
  const native = scValToNative(args[0]) as unknown;
  if (typeof native === "string") return native;
  throw new RegistryError("expected address argument");
}

// ---------------------------------------------------------------------------
// FixtureAttestationCaller
// ---------------------------------------------------------------------------

/** In-memory stand-in for both the SAS contract and the Indexer contract. */
export class FixtureAttestationCaller implements ContractCaller {
  readonly calls: string[] = [];

  constructor(
    private readonly attestations: readonly AttestationRecord[] = DEMO_ATTESTATIONS,
    private readonly latencyMs = 0,
  ) {}

  async call(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    this.calls.push(method);
    if (this.latencyMs > 0) await new Promise((r) => setTimeout(r, this.latencyMs));

    switch (method) {
      case "get_attestation": {
        const uid = argUid(args);
        const record = this.attestations.find((a) => a.uid === uid);
        return record ? attestationToScVal(record) : xdr.ScVal.scvVoid();
      }

      case "get_attestations_by_recipient":
      case "get_attestations_by_attester":
      case "get_attestations_by_schema": {
        const cursor = Number(scValToNative(args[1]));
        const limit = Number(scValToNative(args[2]));
        let matches: string[];

        if (method === "get_attestations_by_recipient") {
          const addr = argAddress(args);
          matches = this.attestations.filter((a) => a.recipient === addr).map((a) => a.uid);
        } else if (method === "get_attestations_by_attester") {
          const addr = argAddress(args);
          matches = this.attestations.filter((a) => a.attester === addr).map((a) => a.uid);
        } else {
          // by_schema: first arg is a UID
          const schemaUid = argUid(args);
          matches = this.attestations.filter((a) => a.schemaUid === schemaUid).map((a) => a.uid);
        }

        const page = matches.slice(cursor, cursor + limit);
        const nextCursor = cursor + page.length;
        const uidVec = xdr.ScVal.scvVec(page.map(uidScVal));
        return xdr.ScVal.scvVec([uidVec, nativeToScVal(nextCursor, { type: "u32" })]);
      }

      default:
        throw new RegistryError(`FixtureAttestationCaller: unsupported method ${method}`);
    }
  }
}
