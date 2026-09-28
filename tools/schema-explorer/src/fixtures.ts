// Offline demo data. `FixtureCaller` answers the same contract calls the
// real registry does, with the same ScVal encodings and pagination rules, so
// demo mode (and the unit tests) exercise the exact decode path used against
// a live node.

import { Buffer } from "buffer";
import { Address, nativeToScVal, scValToNative, xdr } from "@stellar/stellar-sdk";
import type { ContractCaller, SchemaRecord } from "./registry.js";
import { bytesToHex, hexToBytes } from "./hex.js";

/** Registry passed to demo mode; any valid contract id works offline. */
export const DEMO_REGISTRY_ID = "CAKQQH7GRMMREU44ZOBMU2JJWCT4I5YRYXBWCWLQYAW2QYAF7Q2VPAPD";

export interface FixtureSchema extends SchemaRecord {
  creator: string;
}

const RESOLVER_A = "CAXWQYPVOXU7625ASPQIAQCFNT45QQPEQGG3GMMQCSR5NAWZSFHKEI35";
const RESOLVER_B = "CBP4L4C7PRFRTQ7SXGZBJWBLB5ULZA4LS47YOJLH5FHGWGZE5VIBSXZQ";
const OWNER_A = "GCI7YTLFUAWQ2Y5MAWAOFICWUWC5MUMARISUEPVMB3KYUH46WII5MS7T";
const OWNER_B = "GCSRJAYDZNAMOPK6DXLD5ZKAFGL2ZCUB4WNFTBZAUWHBEPCJ3KVLC7MD";

/** Registration order matters: it is the pagination order. */
export const DEMO_SCHEMAS: readonly FixtureSchema[] = [
  {
    uid: "15081fe68b1912539ccb82ca6929b0a7c47711c5c3615970c02da86005fc3557",
    schema: "verified bool, level u32, provider String, checked_at u64",
    resolver: RESOLVER_A,
    revocable: true,
    deprecated: false,
    creator: OWNER_A,
  },
  {
    uid: "ca5088bb191888e8c76a60582a762da826dc81e450f57da7926439039f4adffd",
    schema: "dao Address, proposal_id u64, vote_weight i128, reason String",
    resolver: RESOLVER_B,
    revocable: false,
    deprecated: false,
    creator: OWNER_B,
  },
  {
    uid: "130cb7f7a8dd3f112f75886337fe7f7fab2e2a052f74aa9e4ecd02e22ea1cbcf",
    schema: "old_flag bool",
    resolver: RESOLVER_A,
    revocable: true,
    // Deprecated: skipped by get_schemas_paginated, None from get_schema.
    deprecated: true,
    creator: OWNER_A,
  },
  {
    uid: "c4c8545f300f85768c62ce1e385c664202c70fd6b9852e1b00b3e5244ea22575",
    schema: "endorsed Address, skill String, note String, evidence Option<BytesN<32>>",
    resolver: RESOLVER_A,
    revocable: true,
    deprecated: false,
    creator: OWNER_B,
  },
  {
    uid: "ea386729ee708321f7d90f3f91871c336ff469df26010d601a1285c2fdb4ebc9",
    // Registered before on-chain syntax validation was enforced; the explorer
    // flags it rather than hiding it.
    schema: '{"first_name":"String","last_name":"String"}',
    resolver: RESOLVER_B,
    revocable: true,
    deprecated: false,
    creator: OWNER_A,
  },
];

const SCAN_BUDGET = 100;

function uidScVal(uidHex: string): xdr.ScVal {
  return xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.from(hexToBytes(uidHex)))]);
}

/** Encodes a record exactly as the contract's `#[contracttype]` struct does. */
export function schemaRecordToScVal(record: SchemaRecord): xdr.ScVal {
  // Struct fields are encoded as a map keyed by symbol, sorted by name.
  const entry = (key: string, val: xdr.ScVal) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(key), val });
  return xdr.ScVal.scvMap([
    entry("deprecated", xdr.ScVal.scvBool(record.deprecated)),
    entry("resolver", new Address(record.resolver).toScVal()),
    entry("revocable", xdr.ScVal.scvBool(record.revocable)),
    entry("schema", xdr.ScVal.scvString(record.schema)),
    entry("uid", uidScVal(record.uid)),
  ]);
}

function argUid(args: xdr.ScVal[]): string {
  const native = scValToNative(args[0]) as unknown;
  if (!Array.isArray(native) || !(native[0] instanceof Uint8Array)) throw new Error("expected UID argument");
  return bytesToHex(native[0]);
}

/** In-memory stand-in for the registry, following the contract's semantics. */
export class FixtureCaller implements ContractCaller {
  readonly calls: string[] = [];

  constructor(
    private readonly schemas: readonly FixtureSchema[] = DEMO_SCHEMAS,
    private readonly latencyMs = 0,
  ) {}

  async call(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    this.calls.push(method);
    if (this.latencyMs > 0) await new Promise((r) => setTimeout(r, this.latencyMs));
    switch (method) {
      case "get_schemas_paginated": {
        const start = Number(scValToNative(args[0]));
        const limit = Number(scValToNative(args[1]));
        const count = this.schemas.length;
        if (limit === 0 || start >= count) {
          const cursor = start >= count ? count : start;
          return xdr.ScVal.scvVec([xdr.ScVal.scvVec([]), nativeToScVal(cursor, { type: "u32" })]);
        }
        const page: xdr.ScVal[] = [];
        let index = start;
        let scanned = 0;
        while (index < count && page.length < limit && scanned < SCAN_BUDGET) {
          const record = this.schemas[index];
          if (!record.deprecated) page.push(schemaRecordToScVal(record));
          index++;
          scanned++;
        }
        return xdr.ScVal.scvVec([xdr.ScVal.scvVec(page), nativeToScVal(index, { type: "u32" })]);
      }
      case "get_schema": {
        const uid = argUid(args);
        const record = this.schemas.find((s) => s.uid === uid && !s.deprecated);
        return record ? schemaRecordToScVal(record) : xdr.ScVal.scvVoid();
      }
      case "get_creator": {
        const uid = argUid(args);
        const record = this.schemas.find((s) => s.uid === uid);
        return record ? new Address(record.creator).toScVal() : xdr.ScVal.scvVoid();
      }
      default:
        throw new Error(`FixtureCaller: unsupported method ${method}`);
    }
  }
}
