import { useQuery } from "@tanstack/react-query";
import { useCallback } from "react";
import { useSAS } from "../context.js";
import { normalizeKeyId, sasQueryKeys } from "../queryKeys.js";
import type {
  Attestation,
  RecipientQueryOptions,
  UseAttestationsByRecipientOptions,
  UseAttestationsByRecipientResult,
} from "../types.js";

/**
 * Fetches and caches all attestations issued to `address` (recipient account or contract).
 *
 * Automatically revalidates on window focus, account switch, network switch,
 * and `AttestationIssued` / `AttestationRevoked` events.
 */
export function useAttestationsByRecipient(
  address: string | null | undefined,
  options?: UseAttestationsByRecipientOptions,
): UseAttestationsByRecipientResult {
  const {
    client,
    network,
    rpcUrl,
    account,
    invalidateRecipientAttestations,
  } = useSAS();

  const trimmedAddress = address?.trim() ?? "";
  const isEnabled = Boolean(trimmedAddress) && (options?.enabled ?? true);

  const filterOptions: RecipientQueryOptions = {
    includeRevoked: options?.includeRevoked,
    cursor: options?.cursor,
    limit: options?.limit,
  };

  const query = useQuery<Attestation[], Error>({
    queryKey: sasQueryKeys.recipientAttestations(
      trimmedAddress,
      { network, rpcUrl, account },
      filterOptions,
    ),
    queryFn: async () => {
      if (typeof client.getAttestationsByRecipient === "function") {
        const result = await client.getAttestationsByRecipient(
          trimmedAddress,
          filterOptions,
        );
        if (result.length === 0) return [];
        if (typeof result[0] === "string") {
          const resolved = await Promise.all(
            (result as string[]).map((uid) =>
              client.getAttestation(normalizeKeyId(uid)),
            ),
          );
          return resolved.filter((item): item is Attestation => item !== null);
        }
        return result as Attestation[];
      }

      if (typeof client.getAttestationUidsByRecipient === "function") {
        const uids = await client.getAttestationUidsByRecipient(
          trimmedAddress,
          filterOptions,
        );
        if (uids.length === 0) return [];
        const resolved = await Promise.all(
          uids.map((uid) => client.getAttestation(normalizeKeyId(uid))),
        );
        return resolved.filter((item): item is Attestation => item !== null);
      }

      throw new Error(
        "Configured SAS client does not implement getAttestationsByRecipient or getAttestationUidsByRecipient.",
      );
    },
    enabled: isEnabled,
    staleTime: options?.staleTime,
    refetchInterval: options?.refetchInterval,
    refetchOnWindowFocus: options?.refetchOnWindowFocus,
    retry: options?.retry ?? false,
  });

  const invalidate = useCallback(
    () => invalidateRecipientAttestations(trimmedAddress),
    [invalidateRecipientAttestations, trimmedAddress],
  );

  return {
    ...query,
    attestations: query.data ?? [],
    invalidate,
  };
}
