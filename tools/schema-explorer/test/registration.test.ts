import { describe, it, expect, vi } from "vitest";
import { Account, Keypair, Networks, StrKey, TransactionBuilder, type Transaction, rpc } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { fromTemplate, computeSchemaUidWasm } from "../src/designer.js";
import { registerSchema, type WalletSigner } from "../src/registration.js";
import type { ExplorerConfig } from "../src/config.js";

const id = StrKey.encodeContract(Buffer.alloc(32, 0x01));
const resolver = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 0x11));
const config: ExplorerConfig = {
  registryContractId: id,
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: Networks.TESTNET,
};
function harness(options: { wrongSigner?: boolean; wrongUid?: boolean; failOnChain?: boolean } = {}) {
  const signer = Keypair.random();
  const other = Keypair.random();
  const wallet: WalletSigner = {
    address: signer.publicKey(),
    async signTransaction(payload, { networkPassphrase, address }) {
      expect(networkPassphrase).toBe(Networks.TESTNET);
      expect(address).toBe(signer.publicKey());
      const tx = TransactionBuilder.fromXDR(payload, networkPassphrase);
      tx.sign(options.wrongSigner ? other : signer);
      return { signedTxXdr: tx.toXDR(), signerAddress: signer.publicKey() };
    },
  };
  const server = {
    getAccount: vi.fn(async () => new Account(signer.publicKey(), "100")),
    prepareTransaction: vi.fn(async (tx: Transaction) => tx),
    sendTransaction: vi.fn(async (tx: Transaction) => ({
      hash: tx.hash().toString("hex"), status: "PENDING", latestLedger: 1, latestLedgerCloseTime: "0",
    })),
  };
  const deps = {
    createServer: () => server as unknown as rpc.Server,
    getTransaction: vi.fn(async () => ({ status: options.failOnChain ? "FAILED" : "SUCCESS", ledger: 42 })),
    getSchema: vi.fn(async (_: ExplorerConfig, uid: string) => ({ uid: options.wrongUid ? "ff".repeat(32) : uid })),
    sleep: async () => undefined,
  };
  return { signer, wallet, server, deps };
}
describe("Stellar Testnet schema registration", () => {
  it("builds the register call, signs the exact XDR, submits, and checks on-chain UID", async () => {
    const draft = fromTemplate("POAP", resolver);
    const { wallet, server, deps } = harness();
    const expected = await computeSchemaUidWasm(draft);
    const receipt = await registerSchema(draft, config, wallet, deps);
    expect(receipt.uid).toBe(expected);
    expect(receipt.ledger).toBe(42);
    expect(receipt.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(server.prepareTransaction).toHaveBeenCalledOnce();
    expect(server.sendTransaction).toHaveBeenCalledOnce();
    expect(deps.getSchema).toHaveBeenCalledWith(config, expected);
  });
  it("rejects invalid or non-Testnet configuration before invoking wallet", async () => {
    const { wallet, server, deps } = harness();
    const draft = fromTemplate("KYC", resolver);
    await expect(registerSchema(draft, {...config,networkPassphrase:Networks.PUBLIC},wallet,deps)).rejects.toThrow(/Testnet only/);
    await expect(registerSchema(draft,{...config,registryContractId:"CNOTVALID"},wallet,deps)).rejects.toThrow(/valid deployed/);
    draft.fields[1].name = draft.fields[0].name;
    await expect(registerSchema(draft,config,wallet,deps)).rejects.toThrow(/Duplicate/);
    expect(server.getAccount).not.toHaveBeenCalled();
  });
  it("rejects a mismatched wallet signature, failed on-chain transaction and UID mismatch", async () => {
    const draft = fromTemplate("KYC",resolver);
    const invalid = harness({wrongSigner:true});
    await expect(registerSchema(draft,config,invalid.wallet,invalid.deps)).rejects.toThrow(/valid account signature/);
    expect(invalid.server.sendTransaction).not.toHaveBeenCalled();
    const failed = harness({failOnChain:true});
    await expect(registerSchema(draft,config,failed.wallet,failed.deps)).rejects.toThrow(/failed on Testnet/);
    const mismatch = harness({wrongUid:true});
    await expect(registerSchema(draft,config,mismatch.wallet,mismatch.deps)).rejects.toThrow(/UID does not match/);
  });
});