import {
  QueryClient,
  QueryClientContext,
  QueryClientProvider,
} from "@tanstack/react-query";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { SASRpcClient, resolveNetworkConfig } from "./client.js";
import {
  SAS_DOM_EVENTS,
  SASEventBus,
  invalidateQueriesForEvent,
} from "./events.js";
import { sasQueryKeys } from "./queryKeys.js";
import type {
  NetworkName,
  SASClientLike,
  SASContextValue,
  SASEvent,
  SASEventListener,
  SASNetworkConfig,
  SASProviderProps,
  UID,
} from "./types.js";

export interface CreateSASQueryClientOptions {
  staleTime?: number;
  refetchOnWindowFocus?: boolean | "always";
  retry?: boolean | number;
}

/**
 * Creates a TanStack `QueryClient` pre-configured for Soroban SAS hooks.
 */
export function createSASQueryClient(
  options: CreateSASQueryClientOptions = {},
): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: options.staleTime ?? 30_000,
        refetchOnWindowFocus: options.refetchOnWindowFocus ?? true,
        refetchOnReconnect: true,
        retry: options.retry ?? false,
      },
    },
  });
}

const SASContext = createContext<SASContextValue | null>(null);

/**
 * React context provider configuring the active Soroban network, RPC client,
 * TanStack Query cache, account/network switching, window focus revalidation,
 * and event-driven cache triggers.
 */
export function SASProvider({
  children,
  network: networkProp = "testnet",
  rpcUrl,
  networkPassphrase,
  contractId,
  registryContractId,
  indexerContractId,
  account: accountProp,
  activeAccount: activeAccountProp,
  publicKey: publicKeyProp,
  client: clientProp,
  rpcClient: rpcClientProp,
  queryClient: queryClientProp,
  staleTime = 30_000,
  refetchOnWindowFocus = true,
  refetchOnAccountSwitch = true,
  eventPollingInterval = false,
}: SASProviderProps) {
  const parentQueryClient = useContext(QueryClientContext);
  const [internalQueryClient] = useState(() =>
    createSASQueryClient({ staleTime, refetchOnWindowFocus }),
  );
  const resolvedQueryClient =
    queryClientProp ?? parentQueryClient ?? internalQueryClient;

  const controlledAccount =
    accountProp !== undefined
      ? accountProp
      : activeAccountProp !== undefined
        ? activeAccountProp
        : publicKeyProp !== undefined
          ? publicKeyProp
          : undefined;

  const [accountState, setAccountState] = useState<string | null>(
    controlledAccount ?? null,
  );
  const [networkState, setNetworkState] = useState<
    NetworkName | SASNetworkConfig
  >(networkProp);

  const eventBusRef = useRef<SASEventBus | null>(null);
  if (!eventBusRef.current) {
    eventBusRef.current = new SASEventBus();
  }
  const eventBus = eventBusRef.current;

  const prevAccountRef = useRef<string | null>(accountState);
  const prevControlledAccountRef = useRef<string | null | undefined>(
    controlledAccount,
  );
  const prevNetworkPropRef = useRef<NetworkName | SASNetworkConfig>(networkProp);

  // Sync controlled account prop changes only when the prop itself changes
  useEffect(() => {
    if (controlledAccount !== prevControlledAccountRef.current) {
      const previousAccount = prevAccountRef.current;
      prevControlledAccountRef.current = controlledAccount;
      const nextAccount = controlledAccount ?? null;
      prevAccountRef.current = nextAccount;
      setAccountState(nextAccount);
      if (refetchOnAccountSwitch && nextAccount !== previousAccount) {
        void resolvedQueryClient.invalidateQueries({
          queryKey: sasQueryKeys.all,
          refetchType: "none",
        });
        eventBus.emit({
          type: "AccountChanged",
          account: nextAccount,
          previousAccount,
        });
      }
    }
  }, [
    controlledAccount,
    refetchOnAccountSwitch,
    resolvedQueryClient,
    eventBus,
  ]);

  // Sync controlled network prop changes only when the prop itself changes
  useEffect(() => {
    if (networkProp !== prevNetworkPropRef.current) {
      prevNetworkPropRef.current = networkProp;
      setNetworkState(networkProp);
      const nextConfig = resolveNetworkConfig(networkProp, {
        rpcUrl,
        networkPassphrase,
        contractId,
        registryContractId,
        indexerContractId,
      });
      void resolvedQueryClient.invalidateQueries({
        queryKey: sasQueryKeys.all,
        refetchType: "none",
      });
      eventBus.emit({
        type: "NetworkChanged",
        network: nextConfig.id,
        rpcUrl: nextConfig.rpcUrl,
        networkPassphrase: nextConfig.networkPassphrase,
      });
    }
  }, [
    networkProp,
    rpcUrl,
    networkPassphrase,
    contractId,
    registryContractId,
    indexerContractId,
    resolvedQueryClient,
    eventBus,
  ]);

  const networkConfig = useMemo(
    () =>
      resolveNetworkConfig(networkState, {
        rpcUrl,
        networkPassphrase,
        contractId,
        registryContractId,
        indexerContractId,
      }),
    [
      networkState,
      rpcUrl,
      networkPassphrase,
      contractId,
      registryContractId,
      indexerContractId,
    ],
  );

  const client: SASClientLike = useMemo(() => {
    if (clientProp) return clientProp;
    if (rpcClientProp) return rpcClientProp;
    return new SASRpcClient({
      rpcUrl: networkConfig.rpcUrl,
      networkPassphrase: networkConfig.networkPassphrase,
      contractId: networkConfig.contractId,
      registryContractId: networkConfig.registryContractId,
      indexerContractId: networkConfig.indexerContractId,
      account: accountState,
    });
  }, [clientProp, rpcClientProp, networkConfig, accountState]);

  const setAccount = useCallback(
    (nextAccount: string | null) => {
      const previousAccount = prevAccountRef.current;
      prevAccountRef.current = nextAccount;
      setAccountState(nextAccount);
      if (refetchOnAccountSwitch && nextAccount !== previousAccount) {
        // Mark previous account queries stale so switching back also re-fetches,
        // while the new account scope key triggers a single immediate fetch.
        void resolvedQueryClient.invalidateQueries({
          queryKey: sasQueryKeys.all,
          refetchType: "none",
        });
        eventBus.emit({
          type: "AccountChanged",
          account: nextAccount,
          previousAccount,
        });
      }
    },
    [refetchOnAccountSwitch, resolvedQueryClient, eventBus],
  );

  const setNetwork = useCallback(
    (nextNetwork: NetworkName | SASNetworkConfig) => {
      setNetworkState(nextNetwork);
      const nextConfig = resolveNetworkConfig(nextNetwork, {
        rpcUrl,
        networkPassphrase,
        contractId,
        registryContractId,
        indexerContractId,
      });
      void resolvedQueryClient.invalidateQueries({
        queryKey: sasQueryKeys.all,
        refetchType: "none",
      });
      eventBus.emit({
        type: "NetworkChanged",
        network: nextConfig.id,
        rpcUrl: nextConfig.rpcUrl,
        networkPassphrase: nextConfig.networkPassphrase,
      });
    },
    [
      rpcUrl,
      networkPassphrase,
      contractId,
      registryContractId,
      indexerContractId,
      resolvedQueryClient,
      eventBus,
    ],
  );

  const emitEvent = useCallback(
    (event: SASEvent) => {
      if (event.type === "AccountChanged") {
        setAccount(event.account);
        return;
      }
      void invalidateQueriesForEvent(resolvedQueryClient, event);
      eventBus.emit(event);
    },
    [resolvedQueryClient, eventBus, setAccount],
  );

  const subscribeToEvents = useCallback(
    (listener: SASEventListener) => eventBus.subscribe(listener),
    [eventBus],
  );

  // Automatic background re-fetch on window focus / visibilitychange
  useEffect(() => {
    if (typeof window === "undefined" || refetchOnWindowFocus === false) {
      return;
    }

    const handleWindowFocus = () => {
      void resolvedQueryClient.invalidateQueries({
        queryKey: sasQueryKeys.all,
        refetchType: "active",
      });
    };

    const handleVisibilityChange = () => {
      if (
        typeof document !== "undefined" &&
        document.visibilityState !== "hidden"
      ) {
        void resolvedQueryClient.invalidateQueries({
          queryKey: sasQueryKeys.all,
          refetchType: "active",
        });
      }
    };

    window.addEventListener("focus", handleWindowFocus);
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", handleVisibilityChange);
    }

    return () => {
      window.removeEventListener("focus", handleWindowFocus);
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", handleVisibilityChange);
      }
    };
  }, [refetchOnWindowFocus, resolvedQueryClient]);

  // Listen for DOM CustomEvents (wallet account switches, network switches, contract events)
  useEffect(() => {
    if (typeof window === "undefined") return;

    const extractAccountFromDetail = (
      detail: unknown,
    ): string | null | undefined => {
      if (typeof detail === "string" || detail === null) return detail;
      if (detail && typeof detail === "object") {
        const rec = detail as Record<string, unknown>;
        if (typeof rec.account === "string" || rec.account === null) {
          return rec.account;
        }
        if (typeof rec.publicKey === "string" || rec.publicKey === null) {
          return rec.publicKey;
        }
        if (typeof rec.address === "string" || rec.address === null) {
          return rec.address;
        }
      }
      return undefined;
    };

    const onAccountEvent = (evt: Event) => {
      const custom = evt as CustomEvent;
      const nextAcc = extractAccountFromDetail(custom.detail);
      if (nextAcc !== undefined) {
        setAccount(nextAcc);
      }
    };

    const onNetworkEvent = (evt: Event) => {
      const custom = evt as CustomEvent;
      const detail = custom.detail as
        | { network?: NetworkName | SASNetworkConfig }
        | NetworkName
        | SASNetworkConfig
        | undefined;
      if (!detail) return;
      if (
        typeof detail === "object" &&
        "network" in detail &&
        detail.network !== undefined
      ) {
        setNetwork(detail.network);
      } else {
        setNetwork(detail as NetworkName | SASNetworkConfig);
      }
    };

    const onGenericSASEvent = (evt: Event) => {
      const custom = evt as CustomEvent<SASEvent | undefined>;
      if (custom.detail && typeof custom.detail.type === "string") {
        emitEvent(custom.detail);
      }
    };

    const onAttestationIssued = (evt: Event) => {
      const custom = evt as CustomEvent<{
        uid: UID;
        schemaUid?: UID;
        attester?: string;
        recipient?: string;
      }>;
      if (custom.detail?.uid) {
        emitEvent({
          type: "AttestationIssued",
          uid: custom.detail.uid,
          schemaUid: custom.detail.schemaUid,
          attester: custom.detail.attester,
          recipient: custom.detail.recipient,
        });
      }
    };

    const onAttestationRevoked = (evt: Event) => {
      const custom = evt as CustomEvent<{
        uid: UID;
        recipient?: string;
        schemaUid?: UID;
        timestamp?: bigint | number;
      }>;
      if (custom.detail?.uid) {
        emitEvent({
          type: "AttestationRevoked",
          uid: custom.detail.uid,
          recipient: custom.detail.recipient,
          schemaUid: custom.detail.schemaUid,
          timestamp: custom.detail.timestamp,
        });
      }
    };

    const onSchemaRegistered = (evt: Event) => {
      const custom = evt as CustomEvent<{ schemaUid: UID; owner?: string }>;
      if (custom.detail?.schemaUid) {
        emitEvent({
          type: "SchemaRegistered",
          schemaUid: custom.detail.schemaUid,
          owner: custom.detail.owner,
        });
      }
    };

    window.addEventListener(SAS_DOM_EVENTS.ACCOUNT_CHANGED, onAccountEvent);
    window.addEventListener(
      SAS_DOM_EVENTS.STELLAR_ACCOUNT_CHANGED,
      onAccountEvent,
    );
    window.addEventListener(
      SAS_DOM_EVENTS.FREIGHTER_ACCOUNT_CHANGED,
      onAccountEvent,
    );
    window.addEventListener(SAS_DOM_EVENTS.NETWORK_CHANGED, onNetworkEvent);
    window.addEventListener(SAS_DOM_EVENTS.EVENT, onGenericSASEvent);
    window.addEventListener(
      SAS_DOM_EVENTS.ATTESTATION_ISSUED,
      onAttestationIssued,
    );
    window.addEventListener(
      SAS_DOM_EVENTS.ATTESTATION_REVOKED,
      onAttestationRevoked,
    );
    window.addEventListener(
      SAS_DOM_EVENTS.SCHEMA_REGISTERED,
      onSchemaRegistered,
    );

    return () => {
      window.removeEventListener(SAS_DOM_EVENTS.ACCOUNT_CHANGED, onAccountEvent);
      window.removeEventListener(
        SAS_DOM_EVENTS.STELLAR_ACCOUNT_CHANGED,
        onAccountEvent,
      );
      window.removeEventListener(
        SAS_DOM_EVENTS.FREIGHTER_ACCOUNT_CHANGED,
        onAccountEvent,
      );
      window.removeEventListener(SAS_DOM_EVENTS.NETWORK_CHANGED, onNetworkEvent);
      window.removeEventListener(SAS_DOM_EVENTS.EVENT, onGenericSASEvent);
      window.removeEventListener(
        SAS_DOM_EVENTS.ATTESTATION_ISSUED,
        onAttestationIssued,
      );
      window.removeEventListener(
        SAS_DOM_EVENTS.ATTESTATION_REVOKED,
        onAttestationRevoked,
      );
      window.removeEventListener(
        SAS_DOM_EVENTS.SCHEMA_REGISTERED,
        onSchemaRegistered,
      );
    };
  }, [setAccount, setNetwork, emitEvent]);

  // Optional Soroban RPC getEvents polling trigger
  useEffect(() => {
    if (
      !eventPollingInterval ||
      eventPollingInterval <= 0 ||
      typeof client.getEvents !== "function"
    ) {
      return;
    }

    let cancelled = false;
    let cursorLedger: number | undefined;

    const pollEvents = async () => {
      if (cancelled || typeof client.getEvents !== "function") return;
      try {
        const { events, latestLedger } = await client.getEvents(cursorLedger);
        if (cancelled) return;
        cursorLedger = latestLedger + 1;
        for (const ev of events) {
          emitEvent(ev);
        }
      } catch {
        // Ignore transient RPC polling errors so background event polling stays resilient
      }
    };

    const timer = setInterval(() => {
      void pollEvents();
    }, eventPollingInterval);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [eventPollingInterval, client, emitEvent]);

  const invalidateAttestation = useCallback(
    async (uid?: UID) => {
      await resolvedQueryClient.invalidateQueries({
        queryKey: uid
          ? sasQueryKeys.attestationByUid(uid)
          : sasQueryKeys.attestations(),
      });
    },
    [resolvedQueryClient],
  );

  const invalidateSchema = useCallback(
    async (schemaUid?: UID) => {
      await resolvedQueryClient.invalidateQueries({
        queryKey: schemaUid
          ? sasQueryKeys.schemaByUid(schemaUid)
          : sasQueryKeys.schemas(),
      });
    },
    [resolvedQueryClient],
  );

  const invalidateRecipientAttestations = useCallback(
    async (address?: string) => {
      await resolvedQueryClient.invalidateQueries({
        queryKey: address
          ? sasQueryKeys.recipientByAddress(address)
          : sasQueryKeys.recipientAttestationsAll(),
      });
    },
    [resolvedQueryClient],
  );

  const invalidateAll = useCallback(async () => {
    await resolvedQueryClient.invalidateQueries({
      queryKey: sasQueryKeys.all,
    });
  }, [resolvedQueryClient]);

  const contextValue = useMemo<SASContextValue>(
    () => ({
      network: networkConfig.id,
      networkConfig,
      rpcUrl: networkConfig.rpcUrl,
      networkPassphrase: networkConfig.networkPassphrase,
      contractId: networkConfig.contractId,
      registryContractId: networkConfig.registryContractId,
      indexerContractId: networkConfig.indexerContractId,
      account: accountState,
      activeAccount: accountState,
      setAccount,
      switchAccount: setAccount,
      setNetwork,
      switchNetwork: setNetwork,
      client,
      rpcClient: client,
      queryClient: resolvedQueryClient,
      emitEvent,
      subscribeToEvents,
      invalidateAttestation,
      invalidateSchema,
      invalidateRecipientAttestations,
      invalidateAll,
    }),
    [
      networkConfig,
      accountState,
      setAccount,
      setNetwork,
      client,
      resolvedQueryClient,
      emitEvent,
      subscribeToEvents,
      invalidateAttestation,
      invalidateSchema,
      invalidateRecipientAttestations,
      invalidateAll,
    ],
  );

  return (
    <QueryClientProvider client={resolvedQueryClient}>
      <SASContext.Provider value={contextValue}>{children}</SASContext.Provider>
    </QueryClientProvider>
  );
}

/**
 * Accesses the active `SASProvider` context (network config, RPC client, active account,
 * cache invalidation helpers, and event bus).
 */
export function useSAS(): SASContextValue {
  const ctx = useContext(SASContext);
  if (!ctx) {
    throw new Error("useSAS must be used within a SASProvider");
  }
  return ctx;
}

/** Alias for `useSAS`. */
export const useSASContext = useSAS;
