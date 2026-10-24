import { afterEach, describe, expect, it, vi } from "vitest";
import { Account, BASE_FEE, Keypair, Networks, Operation, TransactionBuilder } from "@stellar/stellar-sdk";
import { Client as ContractClient, basicNodeSigner } from "@stellar/stellar-sdk/contract";
import { SASClient, type SASClientConfig } from "../src/client.js";

afterEach(() => vi.restoreAllMocks());

const base: SASClientConfig = {
  contractId: "C_SAS", registryContractId: "C_REGISTRY",
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: Networks.TESTNET,
};

function unsignedXdr(pair: Keypair) {
  return new TransactionBuilder(new Account(pair.publicKey(), "12345"), {
    fee: BASE_FEE, networkPassphrase: Networks.TESTNET,
  }).addOperation(Operation.manageData({ name: "issue-564", value: "signing-only" }))
    .setTimeout(60).build().toXDR();
}

describe("SEP-43 wallet signing integration", () => {
  it("verifies a real ed25519 envelope signature using the injected wallet callback", async () => {
    const pair = Keypair.random();
    const signer = basicNodeSigner(pair, Networks.TESTNET);
    const callback = vi.fn(signer.signTransaction);
    const request = unsignedXdr(pair);
    const signed = await callback(request, { networkPassphrase: Networks.TESTNET, address: pair.publicKey() });
    expect(signed.error).toBeUndefined();
    expect(signed.signerAddress).toBe(pair.publicKey());
    const envelope = TransactionBuilder.fromXDR(signed.signedTxXdr, Networks.TESTNET);
    expect(signed.signedTxXdr).not.toBe(request);
    expect(envelope.signatures.length).toBe(1);
    expect(pair.verify(envelope.hash(), envelope.signatures[0].signature())).toBe(true);
  });

  it("forwards wallet callbacks to the actual Stellar ContractClient", async () => {
    const pair = Keypair.random();
    const signer = basicNodeSigner(pair, Networks.TESTNET);
    const from = vi.spyOn(ContractClient, "from").mockResolvedValue({
      revoke: async () => ({ signAndSend: async () => ({ sendTransactionResponse: { hash: "mock-contract-hash" } }) }),
    } as unknown as ContractClient);
    const client = new SASClient({ ...base, publicKey: pair.publicKey(),
      signTransaction: signer.signTransaction, signAuthEntry: signer.signAuthEntry });
    expect(await client.revoke("aa".repeat(32))).toEqual({ hash: "mock-contract-hash" });
    expect(from).toHaveBeenCalledWith(expect.objectContaining({
      publicKey: pair.publicKey(), signTransaction: signer.signTransaction, signAuthEntry: signer.signAuthEntry,
      networkPassphrase: Networks.TESTNET,
    }));
  });

  it("rejects mixing raw secrets and external wallet callbacks", async () => {
    const pair = Keypair.random();
    const signer = basicNodeSigner(pair, Networks.TESTNET);
    vi.spyOn(ContractClient, "from");
    const client = new SASClient({ ...base, secret: pair.secret(), signTransaction: signer.signTransaction });
    await expect(client.revoke("aa".repeat(32))).rejects.toThrow(/either a Node secret signer or wallet callbacks/);
  });
});
