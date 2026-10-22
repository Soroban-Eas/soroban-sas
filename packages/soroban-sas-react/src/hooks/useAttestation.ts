import { useQuery } from "@tanstack/react-query";
import { useCallback } from "react";
import { useSAS } from "../context.js";
import { normalizeKeyId, sasQueryKeys } from "../queryKeys.js";
import type {
  Attestation,
  UID,
  UseAttestationOptions,
  UseAttestationResult,
} from "../types.js";

/**
 * Fetches and caches a Soroban SAS attestation by its 32-byte hex `uid`.
 *
 * Automatically revalidates on window focus, account switch, network switch,
 * and `AttestationIssued` / `AttestationRevoked` events.
 */
export function useAttestation(
  uid: UID | null | undefined,
  options?: UseAttestationOptions,
): UseAttestationResult {
  const { client, network, rpcUrl, account, invalidateAttestation } = useSAS();
  const normalizedUid = normalizeKeyId(uid);
  const isEnabled = Boolean(normalizedUid) && (options?.enabled ?? true);

  const query = useQuery<Attestation | null, Error>({
    queryKey: sasQueryKeys.attestation(normalizedUid, {
      network,
      rpcUrl,
      account,
    }),
    queryFn: async () => client.getAttestation(normalizedUid),
    enabled: isEnabled,
    staleTime: options?.staleTime,
    refetchInterval: options?.refetchInterval,
    refetchOnWindowFocus: options?.refetchOnWindowFocus,
    retry: options?.retry ?? false,
  });

  const invalidate = useCallback(
    () => invalidateAttestation(normalizedUid),
    [invalidateAttestation, normalizedUid],
  );

  return {
    ...query,
    attestation: query.data,
    invalidate,
  };
}
