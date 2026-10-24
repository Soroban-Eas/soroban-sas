import { requestAccess, getNetwork, signTransaction as freighterSign } from "@stellar/freighter-api";
import albedo from "@albedo-link/intent";
import { StrKey } from "@stellar/stellar-sdk";
import { TESTNET_PASSPHRASE, type WalletSigner } from "./registration.js";

export type SupportedWallet = "freighter" | "xbull" | "albedo";

interface XbullInjected {
  connect(options: { canRequestPublicKey: boolean; canRequestSign: boolean }): Promise<unknown>;
  getPublicKey(): Promise<string | { publicKey: string }>;
  signXDR(xdr: string, options: { network: string; publicKey: string }): Promise<string | { signedTxXdr?: string; signedXDR?: string; xdr?: string }>;
}

function xBullExtension(): XbullInjected {
  const provider = (window as Window & { xBullSDK?: XbullInjected }).xBullSDK;
  if (!provider) throw new Error("xBull extension SDK not detected. Install/enable xBull Wallet.");
  return provider;
}

/** SEP-43-style sign-only adapters. Registration itself handles RPC submission. */
export async function connectWallet(wallet: SupportedWallet): Promise<WalletSigner> {
  if (wallet === "freighter") {
    const network = await getNetwork();
    if (network.error) throw new Error("Freighter network request failed: " + network.error.message);
    if (network.networkPassphrase !== TESTNET_PASSPHRASE) throw new Error("Change Freighter to Testnet");
    const access = await requestAccess();
    if (access.error || !access.address) throw new Error("Freighter connection rejected");
    const address = access.address;
    return {
      address,
      async signTransaction(xdr, options) {
        if (options.networkPassphrase !== TESTNET_PASSPHRASE || options.address !== address) throw new Error("Freighter account/network changed");
        const current = await getNetwork();
        if (current.networkPassphrase !== TESTNET_PASSPHRASE) throw new Error("Freighter network changed");
        const signed = await freighterSign(xdr, { address, networkPassphrase: TESTNET_PASSPHRASE });
        if (signed.error || !signed.signedTxXdr) throw new Error("Freighter signature refused");
        return { signedTxXdr: signed.signedTxXdr, signerAddress: signed.signerAddress };
      },
    };
  }
  if (wallet === "albedo") {
    const result = await albedo.publicKey({});
    const address = result.pubkey;
    if (!StrKey.isValidEd25519PublicKey(address)) throw new Error("Albedo did not provide a valid account");
    return {
      address,
      async signTransaction(xdr, options) {
        if (options.networkPassphrase !== TESTNET_PASSPHRASE || options.address !== address) throw new Error("Albedo account/network mismatch");
        // submit:false is essential: the caller broadcasts only AFTER verifying signed XDR.
        const result = await albedo.tx({ xdr, pubkey: address, network: "testnet", submit: false });
        if (!result.signed_envelope_xdr) throw new Error("Albedo did not return a signed envelope");
        return { signedTxXdr: result.signed_envelope_xdr, signerAddress: address };
      },
    };
  }
  if (wallet === "xbull") {
    const provider = xBullExtension();
    await provider.connect({ canRequestPublicKey: true, canRequestSign: true });
    const value = await provider.getPublicKey();
    const address = typeof value === "string" ? value : value.publicKey;
    if (!StrKey.isValidEd25519PublicKey(address)) throw new Error("xBull did not provide a valid account");
    return {
      address,
      async signTransaction(xdr, options) {
        if (options.networkPassphrase !== TESTNET_PASSPHRASE || options.address !== address) throw new Error("xBull account/network mismatch");
        const res = await provider.signXDR(xdr, { network: "TESTNET", publicKey: address });
        const signed = typeof res === "string" ? res : res.signedTxXdr ?? res.signedXDR ?? res.xdr;
        if (!signed) throw new Error("xBull did not return a signed XDR");
        return { signedTxXdr: signed, signerAddress: address };
      },
    };
  }
  throw new Error("Unsupported wallet");
}
