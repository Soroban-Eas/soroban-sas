import type { QueryClient, UseQueryResult } from "@tanstack/react-query";
import type { ReactNode } from "react";

/** A 32-byte content-addressed identifier, hex-encoded (64 lowercase hex characters, no "0x" prefix). */
export type UID = string;

/**
 * Mirrors `soroban_sas_common::Attestation`.
 */
export interface Attestation {
  uid: UID;
  schemaUid: UID;
  /** Ledger timestamp (seconds) the attestation was issued at. */
  time: bigint;
  /** Ledger timestamp the attestation expires at, or 0n for "never". */
  expirationTime: bigint;
  /** Ledger timestamp the attestation was revoked at, or 0n if active. */
  revocationTime: bigint;
  /** UID of a prior attestation this one references, or the zero UID. */
  refUid: UID;
  /** Recipient account or contract address (G... or C...). */
  recipient: string;
  /** Attester account or contract address (G... or C...). */
  attester: string;
  revocable: boolean;
  /** Attestation payload, as raw bytes. */
  data: Uint8Array;
  /** Optional activation timestamp (seconds), 0n if active immediately. */
  validFrom?: bigint;
}

/**
 * Mirrors `soroban_sas_common::SchemaRecord`.
 */
export interface SchemaRecord {
  uid: UID;
  /** Resolver contract address invoked on attest/revoke, or the zero address. */
  resolver: string;
  revocable: boolean;
  schema: string;
  deprecated?: boolean;
}

/** Built-in network preset identifiers or a custom network name. */
export type NetworkName = "local" | "testnet" | "futurenet" | "mainnet" | (string & {});

/** Network and contract endpoint configuration for Soroban SAS. */
export interface SASNetworkConfig {
  id: string;
  label: string;
  rpcUrl: string;
  networkPassphrase: string;
  /** SAS core contract ID (C...). */
  contractId?: string;
  /** Schema Registry contract ID (C...). */
  registryContractId?: string;
  /** Indexer contract ID (C...). */
  indexerContractId?: string;
}

/** Options for querying attestations by recipient from the Indexer contract. */
export interface RecipientQueryOptions {
  /** Whether to include revoked and replaced attestations (defaults to true for complete history). */
  includeRevoked?: boolean;
  /** Optional zero-based pagination cursor. */
  cursor?: number;
  /** Optional maximum number of attestations to return in one page. */
  limit?: number;
}

/** Standardized SAS events for event-driven cache invalidation and UI triggers. */
export interface AttestationIssuedEvent {
  type: "AttestationIssued";
  uid: UID;
  schemaUid?: UID;
  attester?: string;
  recipient?: string;
  ledger?: number;
}

export interface AttestationRevokedEvent {
  type: "AttestationRevoked";
  uid: UID;
  recipient?: string;
  schemaUid?: UID;
  timestamp?: bigint | number;
  ledger?: number;
}

export interface SchemaRegisteredEvent {
  type: "SchemaRegistered";
  schemaUid: UID;
  owner?: string;
  ledger?: number;
}

export interface BatchAttestedEvent {
  type: "BatchAttested";
  count: number;
  attesterCount?: number;
  uids?: UID[];
  recipients?: string[];
  ledger?: number;
}

export interface BatchRevokedEvent {
  type: "BatchRevoked";
  count: number;
  attesterCount?: number;
  uids?: UID[];
  recipients?: string[];
  ledger?: number;
}

export interface AccountChangedEvent {
  type: "AccountChanged";
  account: string | null;
  previousAccount?: string | null;
}

export interface NetworkChangedEvent {
  type: "NetworkChanged";
  network: string;
  rpcUrl: string;
  networkPassphrase: string;
}

export type SASEvent =
  | AttestationIssuedEvent
  | AttestationRevokedEvent
  | SchemaRegisteredEvent
  | BatchAttestedEvent
  | BatchRevokedEvent
  | AccountChangedEvent
  | NetworkChangedEvent;

export type SASEventListener = (event: SASEvent) => void;

/**
 * Minimal client interface required by the SAS React hooks.
 * Satisfied by `SASRpcClient`, `@soroban-sas/sdk`'s `SASClient`, or custom test/demo clients.
 */
export interface SASClientLike {
  getAttestation(uid: UID): Promise<Attestation | null>;
  getSchema(schemaUid: UID): Promise<SchemaRecord | null>;
  getAttestationsByRecipient?(
    recipient: string,
    options?: RecipientQueryOptions,
  ): Promise<Attestation[] | UID[]>;
  getAttestationUidsByRecipient?(
    recipient: string,
    options?: RecipientQueryOptions,
  ): Promise<UID[]>;
  getEvents?(startLedger?: number): Promise<{ events: SASEvent[]; latestLedger: number }>;
}

/** Common TanStack Query hook options exposed by SAS hooks. */
export interface BaseSASHookOptions {
  /** Set to false to disable automatic query execution. */
  enabled?: boolean;
  /** Time in milliseconds before cached data is considered stale. */
  staleTime?: number;
  /** Optional polling interval in milliseconds. */
  refetchInterval?: number | false;
  /** Whether to re-fetch when the browser window regains focus (defaults to true). */
  refetchOnWindowFocus?: boolean | "always";
  /** Retry configuration on failure (defaults to false for immediate error reporting). */
  retry?: boolean | number;
}

export type UseAttestationOptions = BaseSASHookOptions;

export type UseSchemaOptions = BaseSASHookOptions;

export interface UseAttestationsByRecipientOptions
  extends BaseSASHookOptions,
    RecipientQueryOptions {}

export type UseAttestationResult = UseQueryResult<Attestation | null, Error> & {
  /** Convenient alias for `data`. */
  attestation: Attestation | null | undefined;
  /** Invalidates this attestation's cache entry and triggers a background refetch. */
  invalidate: () => Promise<void>;
};

export type UseSchemaResult = UseQueryResult<SchemaRecord | null, Error> & {
  /** Convenient alias for `data`. */
  schema: SchemaRecord | null | undefined;
  /** Invalidates this schema's cache entry and triggers a background refetch. */
  invalidate: () => Promise<void>;
};

export type UseAttestationsByRecipientResult = UseQueryResult<Attestation[], Error> & {
  /** Convenient alias for `data ?? []`. */
  attestations: Attestation[];
  /** Invalidates this recipient's attestations cache entry and triggers a background refetch. */
  invalidate: () => Promise<void>;
};

export interface SASProviderProps {
  children: ReactNode;
  /** Active network preset ("local", "testnet", "futurenet", "mainnet") or full network config. Defaults to "testnet". */
  network?: NetworkName | SASNetworkConfig;
  /** Explicit Soroban RPC URL override. */
  rpcUrl?: string;
  /** Explicit Stellar network passphrase override. */
  networkPassphrase?: string;
  /** SAS core contract address (C...). */
  contractId?: string;
  /** Schema Registry contract address (C...). */
  registryContractId?: string;
  /** Indexer contract address (C...). */
  indexerContractId?: string;
  /** Active wallet/account address (G...). Switching this value automatically revalidates active queries. */
  account?: string | null;
  /** Alias for `account`. */
  activeAccount?: string | null;
  /** Alias for `account`. */
  publicKey?: string | null;
  /** Optional pre-configured RPC client or mock client. */
  client?: SASClientLike;
  /** Alias for `client`. */
  rpcClient?: SASClientLike;
  /** Optional custom TanStack QueryClient instance. */
  queryClient?: QueryClient;
  /** Default stale time in milliseconds for SAS queries (defaults to 30_000). */
  staleTime?: number;
  /** Whether hooks automatically re-fetch on browser window focus (defaults to true). */
  refetchOnWindowFocus?: boolean | "always";
  /** Whether hooks automatically re-fetch when the active account switches (defaults to true). */
  refetchOnAccountSwitch?: boolean;
  /** Optional interval (ms) to poll Soroban RPC `getEvents` for contract events. */
  eventPollingInterval?: number | false;
}

export interface SASContextValue {
  /** Active network identifier (e.g. "testnet", "mainnet", "local", "futurenet"). */
  network: string;
  /** Full resolved network and contract configuration. */
  networkConfig: SASNetworkConfig;
  /** Active Soroban RPC endpoint URL. */
  rpcUrl: string;
  /** Active Stellar network passphrase. */
  networkPassphrase: string;
  /** Configured SAS contract ID (C...). */
  contractId?: string;
  /** Configured Schema Registry contract ID (C...). */
  registryContractId?: string;
  /** Configured Indexer contract ID (C...). */
  indexerContractId?: string;
  /** Currently active user/wallet account address (G...). */
  account: string | null;
  /** Alias for `account`. */
  activeAccount: string | null;
  /** Updates the active account and triggers automatic query revalidation. */
  setAccount: (account: string | null) => void;
  /** Alias for `setAccount`. */
  switchAccount: (account: string | null) => void;
  /** Updates the active network and triggers automatic query revalidation. */
  setNetwork: (network: NetworkName | SASNetworkConfig) => void;
  /** Alias for `setNetwork`. */
  switchNetwork: (network: NetworkName | SASNetworkConfig) => void;
  /** Active SAS RPC client. */
  client: SASClientLike;
  /** Alias for `client`. */
  rpcClient: SASClientLike;
  /** Underlying TanStack QueryClient. */
  queryClient: QueryClient;
  /** Dispatches a SAS event to subscribers and invalidates affected query caches. */
  emitEvent: (event: SASEvent) => void;
  /** Subscribes to SAS events within this provider. Returns an unsubscribe function. */
  subscribeToEvents: (listener: SASEventListener) => () => void;
  /** Invalidates a specific attestation (or all attestations if `uid` is omitted). */
  invalidateAttestation: (uid?: UID) => Promise<void>;
  /** Invalidates a specific schema (or all schemas if `schemaUid` is omitted). */
  invalidateSchema: (schemaUid?: UID) => Promise<void>;
  /** Invalidates attestations for a recipient (or all recipients if `address` is omitted). */
  invalidateRecipientAttestations: (address?: string) => Promise<void>;
  /** Invalidates all cached SAS queries. */
  invalidateAll: () => Promise<void>;
}
