import { useQuery } from "@tanstack/react-query";
import { useCallback } from "react";
import { useSAS } from "../context.js";
import { normalizeKeyId, sasQueryKeys } from "../queryKeys.js";
import type {
  SchemaRecord,
  UID,
  UseSchemaOptions,
  UseSchemaResult,
} from "../types.js";

/**
 * Fetches and caches a Soroban SAS schema record by its 32-byte hex `schemaUid`.
 *
 * Automatically revalidates on window focus, account switch, network switch,
 * and `SchemaRegistered` events.
 */
export function useSchema(
  schemaUid: UID | null | undefined,
  options?: UseSchemaOptions,
): UseSchemaResult {
  const { client, network, rpcUrl, account, invalidateSchema } = useSAS();
  const normalizedSchemaUid = normalizeKeyId(schemaUid);
  const isEnabled = Boolean(normalizedSchemaUid) && (options?.enabled ?? true);

  const query = useQuery<SchemaRecord | null, Error>({
    queryKey: sasQueryKeys.schema(normalizedSchemaUid, {
      network,
      rpcUrl,
      account,
    }),
    queryFn: async () => client.getSchema(normalizedSchemaUid),
    enabled: isEnabled,
    staleTime: options?.staleTime,
    refetchInterval: options?.refetchInterval,
    refetchOnWindowFocus: options?.refetchOnWindowFocus,
    retry: options?.retry ?? false,
  });

  const invalidate = useCallback(
    () => invalidateSchema(normalizedSchemaUid),
    [invalidateSchema, normalizedSchemaUid],
  );

  return {
    ...query,
    schema: query.data,
    invalidate,
  };
}
