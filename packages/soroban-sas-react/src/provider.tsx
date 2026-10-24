"use client";

import { createContext, useContext, useMemo, useRef, type ReactNode } from "react";
import type { SASClient, SASClientConfig } from "@soroban-sas/sdk";
import { SWRConfig } from "swr";

/** Injectable interface for a wallet-aware browser client or a mocked SDK. */
export type SasHooksClient = Pick<SASClient,
  "getAttestation" | "getSchema" | "getRecipientAttestations" | "attest" | "revoke">;

export interface SasContextValue {
  client: SasHooksClient;
  /** Resource keys remain isolated across client and network changes. */
  keyPrefix: readonly [string, string, number];
  config: SASClientConfig;
}

export interface SasProviderProps {
  children: ReactNode;
  /** RPC, SAS, Registry and optional Indexer contract configuration. */
  config: SASClientConfig;
  /** Override for browser wallet signing, testing, or custom RPC clients. */
  client?: SasHooksClient;
  /** Required if client is not provided. Produces a wallet-aware browser client. */
  createClient?: (config: SASClientConfig) => SasHooksClient;
}

const Context = createContext<SasContextValue | null>(null);

export function SasProvider({ children, config, client, createClient }: SasProviderProps) {
  if (config.secret) {
    throw new Error("SasProvider must never receive a secret key in browser code");
  }
  const createdClient = useMemo(
    () => client ? null : createClient?.(config) ?? null,
    [client, createClient, config.contractId, config.registryContractId,
      config.indexerContractId, config.rpcUrl, config.networkPassphrase,
      config.publicKey, config.secret],
  );
  const effectiveClient = client ?? createdClient;
  if (!effectiveClient) {
    throw new Error("SasProvider requires a client or createClient (wallet signer is never inferred)");
  }
  // An isolated cache per Provider prevents state from leaking between dApps.
  const cache = useMemo(() => new Map(), []);
  const generation = useRef({ client: effectiveClient, value: 0 });
  if (generation.current.client !== effectiveClient) {
    generation.current = { client: effectiveClient, value: generation.current.value + 1 };
  }
  const fingerprint = JSON.stringify([
    config.networkPassphrase, config.rpcUrl, config.contractId,
    config.registryContractId, config.indexerContractId, config.publicKey,
  ]);
  const value = useMemo<SasContextValue>(
    () => ({ client: effectiveClient, config, keyPrefix: ["sas", fingerprint, generation.current.value] }),
    [effectiveClient, config, fingerprint],
  );

  return (
    <SWRConfig value={{ provider: () => cache }}>
      <Context.Provider value={value}>{children}</Context.Provider>
    </SWRConfig>
  );
}

/** Throws immediately when a hook is used outside SasProvider. */
export function useSasContext(): SasContextValue {
  const ctx = useContext(Context);
  if (!ctx) throw new Error("Soroban SAS hooks must be used inside <SasProvider>");
  return ctx;
}
