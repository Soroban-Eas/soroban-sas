import { describe, expect, it, vi } from "vitest";
import type { SignTransaction } from "@stellar/stellar-sdk/contract";

const { contractFrom } = vi.hoisted(() => ({ contractFrom: vi.fn() }));
vi.mock("@stellar/stellar-sdk/contract", () => ({
  Client: { from: contractFrom },
}));

import { SASClient } from "../src/client.js";

describe("SASClient browser wallet integration", () => {
  it("passes the external wallet signer to the Stellar contract client", async () => {
    const signTransaction: SignTransaction = vi.fn();
    const signAndSend = vi.fn().mockResolvedValue({
      sendTransactionResponse: { hash: "submitted-hash" },
    });
    const attest = vi.fn().mockResolvedValue({ signAndSend });
    contractFrom.mockResolvedValue({ attest });

    const client = new SASClient({
      contractId: "CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      rpcUrl: "https://rpc.example",
      networkPassphrase: "Test SDF Network ; September 2015",
      publicKey: "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      signTransaction,
    });

    await expect(client.attest({
      uid: "01".repeat(32),
      schemaUid: "02".repeat(32),
      time: 1n,
      expirationTime: 0n,
      revocationTime: 0n,
      refUid: "00".repeat(32),
      recipient: "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      attester: "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      revocable: true,
      data: new Uint8Array([1, 2, 3]),
    })).resolves.toEqual({ hash: "submitted-hash" });

    expect(contractFrom).toHaveBeenCalledWith(expect.objectContaining({
      contractId: "CXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      publicKey: "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
      signTransaction,
    }));
    expect(signAndSend).toHaveBeenCalledOnce();
  });
});
