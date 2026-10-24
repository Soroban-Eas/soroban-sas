import { afterEach, describe, expect, it, vi } from "vitest";
import { Client as ContractClient } from "@stellar/stellar-sdk/contract";
import { SASClient } from "../src/client.js";

afterEach(() => vi.restoreAllMocks());

const config = {
  contractId: "C_SAS", indexerContractId: "C_INDEXER",
  rpcUrl: "https://rpc.example", networkPassphrase: "Test SDF Network ; September 2015",
};

describe("SASClient.getRecipientAttestations", () => {
  it("requires an indexer contract configuration", async () => {
    const client = new SASClient({ ...config, indexerContractId: undefined });
    await expect(client.getRecipientAttestations("G_ADDRESS")).rejects.toThrow(/indexerContractId/);
  });

  it("performs a read-only indexer call and decodes Vec<UID>", async () => {
    const indexer = {
      get_attestations_by_recipient: vi.fn(async () => ({
        result: [[new Uint8Array(32).fill(0xaa)], [new Uint8Array(32).fill(0xbb)]],
      })),
    };
    const spy = vi.spyOn(ContractClient, "from").mockResolvedValue(indexer as unknown as ContractClient);
    const client = new SASClient(config);
    expect(await client.getRecipientAttestations("G_ADDRESS")).toEqual(["aa".repeat(32), "bb".repeat(32)]);
    expect(indexer.get_attestations_by_recipient).toHaveBeenCalledWith({ recipient: "G_ADDRESS" });
    expect(spy).toHaveBeenCalledOnce();
    // Lazily cache the discovered contract ABI/client.
    await client.getRecipientAttestations("G_ADDRESS");
    expect(spy).toHaveBeenCalledOnce();
  });

  it("rejects malformed contract results instead of silently returning wrong identifiers", async () => {
    vi.spyOn(ContractClient, "from").mockResolvedValue({
      get_attestations_by_recipient: async () => ({ result: [["not a UID"]] }),
    } as unknown as ContractClient);
    await expect(new SASClient(config).getRecipientAttestations("G")).rejects.toThrow(/malformed attestation UID/);
  });
});
