// SASClient routing: reads fail over between RPC endpoints; writes go to one.
import { beforeEach, describe, expect, it, vi } from "vitest";

const sendCalls: string[] = [];
const readCalls: string[] = [];
let failReadsOn = new Set<string>();
let failSendOn = new Set<string>();

vi.mock("@stellar/stellar-sdk/contract", () => ({
  basicNodeSigner: () => ({}),
  Client: {
    from: async ({ rpcUrl }: { rpcUrl: string }) => ({
      get_attestation: async () => {
        readCalls.push(rpcUrl);
        if (failReadsOn.has(rpcUrl)) throw Object.assign(new Error("Too Many Requests"), { status: 429 });
        return { result: null };
      },
      revoke: async () => ({
        signAndSend: async () => {
          sendCalls.push(rpcUrl);
          if (failSendOn.has(rpcUrl)) throw Object.assign(new Error("Gateway Timeout"), { status: 504 });
          return { sendTransactionResponse: { hash: "abc" } };
        },
      }),
    }),
  },
}));

import { SASClient } from "../src/client.js";

const uid = "11".repeat(32);
const PRIMARY = "https://primary.example";
const BACKUP = "https://backup.example";

function client() {
  return new SASClient({
    contractId: "CTEST",
    networkPassphrase: "Test SDF Network ; September 2015",
    publicKey: "GTEST",
    endpoints: [{ url: PRIMARY, weight: 10 }, { url: BACKUP, weight: 1 }],
    resilience: { sleep: async () => {}, random: () => 0 },
  });
}

describe("SASClient endpoint fallback", () => {
  beforeEach(() => {
    sendCalls.length = 0;
    readCalls.length = 0;
    failReadsOn = new Set();
    failSendOn = new Set();
  });

  it("reads transparently fall back to the backup on 429", async () => {
    failReadsOn.add(PRIMARY);
    await expect(client().getAttestation(uid)).resolves.toBeNull();
    expect(readCalls).toEqual([PRIMARY, BACKUP]);
  });

  it("writes are submitted to a single endpoint and not duplicated on failure", async () => {
    failSendOn.add(PRIMARY);
    await expect(client().revoke(uid)).rejects.toMatchObject({ status: 504 });
    expect(sendCalls).toEqual([PRIMARY]);
  });

  it("a successful write is sent once", async () => {
    await expect(client().revoke(uid)).resolves.toEqual({ hash: "abc" });
    expect(sendCalls).toEqual([PRIMARY]);
  });

  it("requires rpcUrl or endpoints", () => {
    expect(() => new SASClient({ contractId: "C", networkPassphrase: "x" })).toThrow(/rpcUrl or endpoints/);
  });

  it("still accepts a single rpcUrl", async () => {
    const c = new SASClient({ contractId: "C", networkPassphrase: "x", rpcUrl: PRIMARY });
    await expect(c.getAttestation(uid)).resolves.toBeNull();
  });
});
