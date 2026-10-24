"use client";

import { requestAccess, getNetwork, signTransaction, signAuthEntry } from "@stellar/freighter-api";
import { SASClient, type SASClientConfig } from "@soroban-sas/sdk";

function fail(label: string, error: unknown): never {
  const detail = error instanceof Error ? error.message
    : typeof error === "object" && error !== null && "message" in error
      ? String(error.message) : String(error);
  throw new Error(`Freighter ${label}: ${detail}`);
}

/**
 * Real Freighter browser-wallet adapter. This requires the extension and an
 * explicit user-initiated connection/signature approval; no seed is imported.
 */
export async function connectFreighter(config: SASClientConfig): Promise<{ client: SASClient; address: string }> {
  if (config.secret) throw new Error("Never use private keys in a browser wallet adapter");

  const network = await getNetwork();
  if (network.error) fail("getNetwork", network.error);
  if (network.networkPassphrase !== config.networkPassphrase) {
    throw new Error(`Freighter is on ${network.networkPassphrase || "an unknown network"}; switch to Testnet.`);
  }

  const access = await requestAccess();
  if (access.error) fail("requestAccess", access.error);
  if (!access.address) throw new Error("Freighter did not supply an account address");

  return { address: access.address, client: new SASClient({
    ...config, publicKey: access.address,
    signTransaction: (xdr) => signFreighterEnvelope(xdr, config.networkPassphrase, access.address),
    signAuthEntry: async (entry) => {
      const response = await signAuthEntry(entry, {
        networkPassphrase: config.networkPassphrase, address: access.address,
      });
      if (response.error) fail("signAuthEntry", response.error);
      if (!response.signedAuthEntry) throw new Error("Freighter did not sign the auth entry");
      if (response.signerAddress && response.signerAddress !== access.address) {
        throw new Error("Freighter signed an auth entry with an unexpected account");
      }
      return { signedAuthEntry: response.signedAuthEntry, signerAddress: access.address };
    },
  }) };
}

/** Freighter asks for an explicit signature. This function does not broadcast. */
export async function signFreighterEnvelope(xdr: string, networkPassphrase: string, address: string) {
  const network = await getNetwork();
  if (network.error) fail("getNetwork", network.error);
  if (network.networkPassphrase !== networkPassphrase) throw new Error("Freighter network changed; select Testnet");
  const response = await signTransaction(xdr, { networkPassphrase, address });
  if (response.error) fail("signTransaction", response.error);
  if (!response.signedTxXdr) throw new Error("Freighter did not sign the transaction");
  if (response.signerAddress && response.signerAddress !== address) {
    throw new Error("Freighter signed with an unexpected account");
  }
  return { signedTxXdr: response.signedTxXdr, signerAddress: address };
}
