// @vitest-environment jsdom
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import { Keypair, Networks } from "@stellar/stellar-sdk";
import { connectWallet } from "../src/wallets.js";

const address = Keypair.random().publicKey();
const mockFreighter = vi.hoisted(() => ({
  requestAccess: vi.fn(),
  getNetwork: vi.fn(),
  signTransaction: vi.fn(),
}));
const mockAlbedo = vi.hoisted(() => ({
  publicKey: vi.fn(),
  tx: vi.fn(),
}));
vi.mock("@stellar/freighter-api", () => mockFreighter);
vi.mock("@albedo-link/intent", () => ({ default: mockAlbedo }));

beforeEach(() => {
  vi.clearAllMocks();
  mockFreighter.getNetwork.mockResolvedValue({networkPassphrase:Networks.TESTNET});
  mockFreighter.requestAccess.mockResolvedValue({ address });
  mockFreighter.signTransaction.mockResolvedValue({signedTxXdr:"signed-freighter",signerAddress:address});
  mockAlbedo.publicKey.mockResolvedValue({pubkey:address});
  mockAlbedo.tx.mockResolvedValue({signed_envelope_xdr:"signed-albedo"});
});
afterEach(() => { delete (window as typeof window & {xBullSDK?:unknown}).xBullSDK; });

describe("Testnet wallet signing adapters", () => {
  it("Freighter checks Testnet twice and requests a signature for the connected account", async () => {
    const wallet = await connectWallet("freighter");
    expect(wallet.address).toBe(address);
    const res = await wallet.signTransaction("unsigned", {networkPassphrase:Networks.TESTNET,address});
    expect(res.signedTxXdr).toBe("signed-freighter");
    expect(mockFreighter.signTransaction).toHaveBeenCalledWith("unsigned", {networkPassphrase:Networks.TESTNET,address});
    mockFreighter.getNetwork.mockResolvedValueOnce({networkPassphrase:Networks.PUBLIC});
    await expect(wallet.signTransaction("unsigned",{networkPassphrase:Networks.TESTNET,address})).rejects.toThrow(/network changed/);
  });
  it("Albedo signs without auto-submitting and enforces testnet", async () => {
    const wallet = await connectWallet("albedo");
    const response = await wallet.signTransaction("unsigned", {networkPassphrase:Networks.TESTNET,address});
    expect(response.signedTxXdr).toBe("signed-albedo");
    expect(mockAlbedo.tx).toHaveBeenCalledWith({xdr:"unsigned",pubkey:address,network:"testnet",submit:false});
    await expect(wallet.signTransaction("unsigned",{networkPassphrase:Networks.PUBLIC,address})).rejects.toThrow(/mismatch/);
  });
  it("xBull uses the injected extension and never auto-submits", async () => {
    const injected = {
      connect: vi.fn().mockResolvedValue(undefined),
      getPublicKey: vi.fn().mockResolvedValue(address),
      signXDR: vi.fn().mockResolvedValue({signedXDR:"signed-xbull"}),
    };
    (window as typeof window & {xBullSDK?:unknown}).xBullSDK = injected;
    const wallet = await connectWallet("xbull");
    expect(injected.connect).toHaveBeenCalledWith({canRequestPublicKey:true,canRequestSign:true});
    const response = await wallet.signTransaction("unsigned", {networkPassphrase:Networks.TESTNET,address});
    expect(response.signedTxXdr).toBe("signed-xbull");
    expect(injected.signXDR).toHaveBeenCalledWith("unsigned",{network:"TESTNET",publicKey:address});
  });
  it("rejects absent xBull or unsupported wallet", async () => {
    await expect(connectWallet("xbull")).rejects.toThrow(/not detected/);
    await expect(connectWallet("something" as "freighter")).rejects.toThrow(/Unsupported/);
  });
});
