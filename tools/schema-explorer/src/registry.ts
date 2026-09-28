// Read-only access to a deployed SchemaRegistry contract
// (contracts/schema-registry/src/lib.rs).
//
// Every call is a `simulateTransaction` against Soroban RPC: nothing is
// signed or submitted, no account or key is needed, and no fee is paid. The
// simulated transaction uses the all-zero account as its source, the same
// placeholder `@stellar/stellar-sdk/contract`'s `Client` uses for read-only
// calls.
//
// Contract responses are treated as untrusted input: every decoded value is
// shape-checked before it reaches the UI.

import { Buffer } from "buffer";
import {
  Account,
  Address,
  BASE_FEE,
  Contract,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  scValToNative,
  xdr,
} from "@stellar/stellar-sdk";
import type { ExplorerConfig } from "./config.js";
import { bytesToHex, hexToBytes, isUidHex } from "./hex.js";

/** Mirrors `soroban_sas_common::SchemaRecord`. */
export interface SchemaRecord {
  /** 64-char lowercase hex. */
  uid: string;
  /** Resolver contract (or account) address. */
  resolver: string;
  revocable: boolean;
  schema: string;
  deprecated: boolean;
}

export interface SchemaPage {
  schemas: SchemaRecord[];
  /** Registration index to pass as `start` for the next page. */
  nextCursor: number;
  /** False once the registry reports no further registrations. */
  hasMore: boolean;
}

/**
 * The registry scans at most this many registrations per call
 * (`MAX_SCAN_BUDGET` in the contract), so larger page sizes gain nothing.
 */
export const MAX_PAGE_SIZE = 100;

/** Anything that can evaluate a read-only contract call. */
export interface ContractCaller {
  call(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal>;
}

export class RegistryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RegistryError";
  }
}

const NULL_ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/** Evaluates contract calls through Soroban RPC transaction simulation. */
export class RpcContractCaller implements ContractCaller {
  private readonly server: rpc.Server;
  private readonly contract: Contract;

  constructor(
    private readonly config: ExplorerConfig,
    timeoutMs = 15_000,
  ) {
    this.server = new rpc.Server(config.rpcUrl, {
      allowHttp: new URL(config.rpcUrl).protocol === "http:",
      timeout: timeoutMs,
    });
    this.contract = new Contract(config.registryContractId);
  }

  async call(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const tx = new TransactionBuilder(new Account(NULL_ACCOUNT, "0"), {
      fee: BASE_FEE,
      networkPassphrase: this.config.networkPassphrase,
    })
      .addOperation(this.contract.call(method, ...args))
      .setTimeout(30)
      .build();

    let sim: rpc.Api.SimulateTransactionResponse;
    try {
      sim = await this.server.simulateTransaction(tx);
    } catch (err) {
      throw new RegistryError(`RPC request failed: ${errorMessage(err)}`);
    }
    if (rpc.Api.isSimulationError(sim)) {
      throw new RegistryError(`Contract call ${method} failed: ${sim.error}`);
    }
    if (!sim.result) {
      throw new RegistryError(`Contract call ${method} returned no result.`);
    }
    return sim.result.retval;
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Encodes a 64-char hex UID as the contract's `UID(BytesN<32>)` tuple struct. */
export function uidToScVal(uidHex: string): xdr.ScVal {
  if (!isUidHex(uidHex)) throw new RegistryError("UID must be 64 hexadecimal characters.");
  return xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.from(hexToBytes(uidHex)))]);
}

function decodeUid(value: unknown): string {
  // `UID` is a single-field tuple struct, which decodes as a one-element array.
  if (Array.isArray(value) && value.length === 1 && value[0] instanceof Uint8Array && value[0].length === 32) {
    return bytesToHex(value[0]);
  }
  throw new RegistryError("Malformed UID in contract response.");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array);
}

/** Decodes and shape-checks one `SchemaRecord` from its native form. */
export function decodeSchemaRecord(value: unknown): SchemaRecord {
  if (!isRecord(value)) throw new RegistryError("Malformed SchemaRecord in contract response.");
  const { uid, resolver, revocable, schema, deprecated } = value;
  if (typeof resolver !== "string" || typeof schema !== "string" || typeof revocable !== "boolean") {
    throw new RegistryError("Malformed SchemaRecord in contract response.");
  }
  return {
    uid: decodeUid(uid),
    resolver,
    revocable,
    schema,
    // Records written before the `deprecated` field existed decode without it.
    deprecated: deprecated === true,
  };
}

/** Typed, read-only view over the SchemaRegistry contract. */
export class RegistryReader {
  constructor(private readonly caller: ContractCaller) {}

  /** `get_schemas_paginated(start, limit)`: one page of active schemas. */
  async listSchemas(start: number, limit: number): Promise<SchemaPage> {
    if (!Number.isInteger(start) || start < 0 || start > 0xffffffff) {
      throw new RegistryError("Cursor must be a u32.");
    }
    const pageSize = Math.min(Math.max(Math.trunc(limit), 1), MAX_PAGE_SIZE);
    const ret = await this.caller.call("get_schemas_paginated", [
      nativeToScVal(start, { type: "u32" }),
      nativeToScVal(pageSize, { type: "u32" }),
    ]);
    const native = scValToNative(ret) as unknown;
    if (!Array.isArray(native) || native.length !== 2 || !Array.isArray(native[0])) {
      throw new RegistryError("Malformed get_schemas_paginated response.");
    }
    const cursor = Number(native[1]);
    if (!Number.isInteger(cursor) || cursor < 0) {
      throw new RegistryError("Malformed cursor in get_schemas_paginated response.");
    }
    const schemas = (native[0] as unknown[]).map(decodeSchemaRecord);
    // The contract returns (empty, count) once `start` reaches the end, so a
    // cursor that did not advance means there is nothing left to scan.
    return { schemas, nextCursor: cursor, hasMore: cursor > start };
  }

  /** `get_schema(uid)`: the active record, or null if unknown or deprecated. */
  async getSchema(uidHex: string): Promise<SchemaRecord | null> {
    const ret = await this.caller.call("get_schema", [uidToScVal(uidHex)]);
    if (ret.switch() === xdr.ScValType.scvVoid()) return null;
    return decodeSchemaRecord(scValToNative(ret));
  }

  /** `get_creator(uid)`: the current owner address, if any. */
  async getCreator(uidHex: string): Promise<string | null> {
    const ret = await this.caller.call("get_creator", [uidToScVal(uidHex)]);
    if (ret.switch() === xdr.ScValType.scvVoid()) return null;
    try {
      return Address.fromScVal(ret).toString();
    } catch {
      throw new RegistryError("Malformed address in get_creator response.");
    }
  }
}
