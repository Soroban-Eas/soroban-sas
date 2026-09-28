import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Address, SorobanDataBuilder, TransactionBuilder, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { DEMO_REGISTRY_ID, DEMO_SCHEMAS, FixtureCaller, schemaRecordToScVal, type FixtureSchema } from "../src/fixtures.js";
import {
  MAX_PAGE_SIZE,
  RegistryError,
  RegistryReader,
  RpcContractCaller,
  decodeSchemaRecord,
  uidToScVal,
  type ContractCaller,
} from "../src/registry.js";

const active = DEMO_SCHEMAS.filter((s) => !s.deprecated);
const deprecated = DEMO_SCHEMAS.find((s) => s.deprecated)!;

function fixture(uidSeed: number, extra: Partial<FixtureSchema> = {}): FixtureSchema {
  return {
    ...DEMO_SCHEMAS[0],
    uid: uidSeed.toString(16).padStart(64, "0"),
    schema: `f${uidSeed} u32`,
    ...extra,
  };
}

describe("RegistryReader over FixtureCaller", () => {
  it("lists active schemas and skips deprecated ones", async () => {
    const reader = new RegistryReader(new FixtureCaller());
    const page = await reader.listSchemas(0, 25);
    expect(page.schemas.map((s) => s.uid)).toEqual(active.map((s) => s.uid));
    expect(page.nextCursor).toBe(DEMO_SCHEMAS.length);
    expect(page.hasMore).toBe(true);

    const end = await reader.listSchemas(page.nextCursor, 25);
    expect(end).toEqual({ schemas: [], nextCursor: DEMO_SCHEMAS.length, hasMore: false });
  });

  it("round-trips every field of a record", async () => {
    const reader = new RegistryReader(new FixtureCaller());
    const [first] = (await reader.listSchemas(0, 1)).schemas;
    const { creator: _creator, ...expected } = DEMO_SCHEMAS[0];
    expect(first).toEqual(expected);
  });

  it("pages through a registry larger than one page", async () => {
    const many = Array.from({ length: 23 }, (_, i) => fixture(i + 1, { deprecated: i % 5 === 0 }));
    const reader = new RegistryReader(new FixtureCaller(many));
    const seen: string[] = [];
    let cursor = 0;
    let pages = 0;
    for (;;) {
      const page = await reader.listSchemas(cursor, 4);
      seen.push(...page.schemas.map((s) => s.uid));
      pages++;
      if (!page.hasMore) break;
      cursor = page.nextCursor;
    }
    expect(seen).toEqual(many.filter((s) => !s.deprecated).map((s) => s.uid));
    expect(new Set(seen).size).toBe(seen.length);
    expect(pages).toBeGreaterThan(4);
  });

  it("clamps the requested page size to the contract's scan budget", async () => {
    const sizes: number[] = [];
    const recording: ContractCaller = {
      async call(method, args) {
        sizes.push(Number(args[1].u32()));
        return new FixtureCaller().call(method, args);
      },
    };
    const reader = new RegistryReader(recording);
    await reader.listSchemas(0, 10_000);
    await reader.listSchemas(0, 0);
    expect(sizes).toEqual([MAX_PAGE_SIZE, 1]);
  });

  it("rejects invalid cursors before calling the contract", async () => {
    const caller = new FixtureCaller();
    const reader = new RegistryReader(caller);
    await expect(reader.listSchemas(-1, 10)).rejects.toThrow(RegistryError);
    await expect(reader.listSchemas(1.5, 10)).rejects.toThrow(RegistryError);
    expect(caller.calls).toEqual([]);
  });

  it("looks up a schema by UID", async () => {
    const reader = new RegistryReader(new FixtureCaller());
    const record = await reader.getSchema(active[1].uid);
    expect(record?.schema).toBe(active[1].schema);
  });

  it("returns null for unknown and deprecated UIDs", async () => {
    const reader = new RegistryReader(new FixtureCaller());
    expect(await reader.getSchema("ff".repeat(32))).toBeNull();
    expect(await reader.getSchema(deprecated.uid)).toBeNull();
  });

  it("returns the recorded creator, or null", async () => {
    const reader = new RegistryReader(new FixtureCaller());
    expect(await reader.getCreator(DEMO_SCHEMAS[0].uid)).toBe(DEMO_SCHEMAS[0].creator);
    expect(await reader.getCreator("ff".repeat(32))).toBeNull();
  });

  it("validates UIDs before calling the contract", async () => {
    const caller = new FixtureCaller();
    const reader = new RegistryReader(caller);
    await expect(reader.getSchema("abc")).rejects.toThrow("64 hexadecimal");
    await expect(reader.getSchema("zz".repeat(32))).rejects.toThrow(RegistryError);
    expect(caller.calls).toEqual([]);
  });
});

describe("decodeSchemaRecord rejects malformed contract data", () => {
  const good = { uid: [new Uint8Array(32)], resolver: DEMO_REGISTRY_ID, revocable: true, schema: "a B", deprecated: false };

  it("accepts a well-formed record", () => {
    expect(decodeSchemaRecord(good).uid).toBe("00".repeat(32));
  });

  it("treats a missing deprecated flag as false", () => {
    const { deprecated: _d, ...legacy } = good;
    expect(decodeSchemaRecord(legacy).deprecated).toBe(false);
  });

  it.each([
    ["not an object", "schema"],
    ["array", []],
    ["null", null],
    ["short uid", { ...good, uid: [new Uint8Array(31)] }],
    ["bare uid bytes", { ...good, uid: new Uint8Array(32) }],
    ["numeric schema", { ...good, schema: 7 }],
    ["string revocable", { ...good, revocable: "yes" }],
    ["missing resolver", { ...good, resolver: undefined }],
  ])("%s", (_label, value) => {
    expect(() => decodeSchemaRecord(value)).toThrow(RegistryError);
  });

  it("rejects a malformed page response", async () => {
    const bogus: ContractCaller = { call: async () => nativeToScVal(42, { type: "u32" }) };
    await expect(new RegistryReader(bogus).listSchemas(0, 5)).rejects.toThrow("Malformed");
  });
});

// ---------------------------------------------------------------------------
// RpcContractCaller against a local JSON-RPC server speaking Soroban RPC.
// ---------------------------------------------------------------------------

interface Captured {
  method: string;
  contractId: string;
  functionName: string;
  args: xdr.ScVal[];
  networkPassphrase: string;
}

describe("RpcContractCaller", () => {
  const passphrase = "Standalone Network ; February 2017";
  let server: Server;
  let url: string;
  let captured: Captured[] = [];
  let respond: (fn: string) => unknown;

  beforeAll(async () => {
    server = createServer((req, res) => {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const request = JSON.parse(body);
        const tx = TransactionBuilder.fromXDR(request.params.transaction, passphrase);
        const op = (tx as unknown as { operations: Array<{ func: xdr.HostFunction }> }).operations[0];
        const invoke = op.func.invokeContract();
        const functionName = invoke.functionName().toString();
        captured.push({
          method: request.method,
          contractId: Address.fromScAddress(invoke.contractAddress()).toString(),
          functionName,
          args: invoke.args(),
          networkPassphrase: tx.networkPassphrase,
        });
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ jsonrpc: "2.0", id: request.id, result: respond(functionName) }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/soroban/rpc`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  const success = (retval: xdr.ScVal) => ({
    latestLedger: 100,
    minResourceFee: "100",
    results: [{ auth: [], xdr: retval.toXDR("base64") }],
    transactionData: new SorobanDataBuilder().build().toXDR("base64"),
  });

  function caller() {
    captured = [];
    return new RpcContractCaller({ rpcUrl: url, networkPassphrase: passphrase, registryContractId: DEMO_REGISTRY_ID });
  }

  it("simulates get_schema against the configured contract and decodes the result", async () => {
    respond = () => success(schemaRecordToScVal(DEMO_SCHEMAS[0]));
    const reader = new RegistryReader(caller());
    const record = await reader.getSchema(DEMO_SCHEMAS[0].uid);

    expect(record?.schema).toBe(DEMO_SCHEMAS[0].schema);
    expect(captured).toHaveLength(1);
    expect(captured[0]).toMatchObject({
      method: "simulateTransaction",
      contractId: DEMO_REGISTRY_ID,
      functionName: "get_schema",
      networkPassphrase: passphrase,
    });
    expect(captured[0].args[0].toXDR("base64")).toBe(uidToScVal(DEMO_SCHEMAS[0].uid).toXDR("base64"));
  });

  it("encodes pagination arguments as u32", async () => {
    respond = () =>
      success(xdr.ScVal.scvVec([xdr.ScVal.scvVec([]), nativeToScVal(9, { type: "u32" })]));
    const page = await new RegistryReader(caller()).listSchemas(9, 30);
    expect(page).toEqual({ schemas: [], nextCursor: 9, hasMore: false });
    expect(captured[0].functionName).toBe("get_schemas_paginated");
    expect(captured[0].args.map((a) => a.u32())).toEqual([9, 30]);
  });

  it("surfaces simulation errors as RegistryError", async () => {
    respond = () => ({ latestLedger: 100, error: "HostError: Error(Contract, #101)" });
    await expect(new RegistryReader(caller()).getSchema(DEMO_SCHEMAS[0].uid)).rejects.toThrow(
      /get_schema failed: HostError/,
    );
  });

  it("surfaces transport failures as RegistryError", async () => {
    const dead = new RpcContractCaller(
      { rpcUrl: "http://127.0.0.1:9/soroban/rpc", networkPassphrase: passphrase, registryContractId: DEMO_REGISTRY_ID },
      2_000,
    );
    await expect(dead.call("get_schema", [uidToScVal("00".repeat(32))])).rejects.toThrow(/RPC request failed/);
  });
});
