"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { Attestation, SubmitResult, UID } from "@soroban-sas/sdk";
import { useSWRConfig } from "swr";
import { useSasContext, type SasHooksClient } from "./provider.js";

export type TransactionStatus = "idle" | "pending" | "success" | "error";
export interface TransactionState {
  status: TransactionStatus;
  isLoading: boolean;
  error: Error | null;
  txHash: string | null;
}

const INITIAL: TransactionState = {
  status: "idle", isLoading: false, error: null, txHash: null,
};

/**
 * A mutation is resolved only after the injected client's submission settles.
 * Hook state changes are guarded against unmount and overlapping executions.
 */
function useTransaction<T>(submit: (client: SasHooksClient, input: T) => Promise<SubmitResult>) {
  const { client, keyPrefix } = useSasContext();
  const { mutate } = useSWRConfig();
  const [state, setState] = useState<TransactionState>(INITIAL);
  const mounted = useRef(false);
  const requestId = useRef(0);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      requestId.current += 1;
    };
  }, [client]);

  const execute = useCallback(async (input: T): Promise<SubmitResult> => {
    const id = ++requestId.current;
    if (mounted.current) setState({ status: "pending", isLoading: true, error: null, txHash: null });
    try {
      const result = await submit(client, input);
      if (mounted.current && id === requestId.current) {
        setState({ status: "success", isLoading: false, error: null, txHash: result.hash });
      }
      // Revalidate only while this hook is still mounted and this is the
      // latest request. Unmounted consumers must not trigger fresh RPC reads.
      if (mounted.current && id === requestId.current) {
        void mutate(
          (key: unknown) => Array.isArray(key)
            && key.length >= 5
            && key.slice(0, 3).every((part, index) => part === keyPrefix[index])
            && (key[3] === "attestation" || key[3] === "recipient"),
        ).catch(() => undefined);
      }
      return result;
    } catch (reason) {
      const error = reason instanceof Error ? reason : new Error(String(reason));
      if (mounted.current && id === requestId.current) {
        setState({ status: "error", isLoading: false, error, txHash: null });
      }
      throw error;
    }
  }, [client, keyPrefix, mutate, submit]);

  const reset = useCallback(() => {
    requestId.current += 1;
    if (mounted.current) setState(INITIAL);
  }, []);

  return { ...state, execute, reset };
}

const submitAttestation = (client: SasHooksClient, attestation: Attestation) => client.attest(attestation);
const submitRevocation = (client: SasHooksClient, uid: UID) => client.revoke(uid);

export function useAttest() {
  const { execute, ...state } = useTransaction(submitAttestation);
  return { ...state, attest: execute };
}

export function useRevoke() {
  const { execute, ...state } = useTransaction(submitRevocation);
  return { ...state, revoke: execute };
}
