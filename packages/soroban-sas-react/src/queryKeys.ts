import type { RecipientQueryOptions, UID } from "./types.js";

export interface QueryScope {
  network: string;
  rpcUrl: string;
  account: string | null;
}

/**
 * Normalizes a hex UID string for consistent cache keys (strips optional "0x" and lowercases).
 */
export function normalizeKeyId(id: string | null | undefined): string {
  if (!id) return "";
  const trimmed = id.trim();
  const stripped =
    trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
  return stripped.toLowerCase();
}

/**
 * Canonical TanStack Query key factory for Soroban SAS hooks.
 *
 * Hierarchy: `["sas", <domain>, <identifier>, <scope>, <options?>]`
 * This ordering enables prefix-based invalidation by domain or specific entity ID
 * while keeping cache entries isolated per network, RPC endpoint, and active account.
 */
export const sasQueryKeys = {
  all: ["sas"] as const,

  attestations: () => [...sasQueryKeys.all, "attestation"] as const,
  attestationByUid: (uid: UID) =>
    [...sasQueryKeys.attestations(), normalizeKeyId(uid)] as const,
  attestation: (uid: UID, scope: QueryScope) =>
    [...sasQueryKeys.attestationByUid(uid), scope] as const,

  schemas: () => [...sasQueryKeys.all, "schema"] as const,
  schemaByUid: (schemaUid: UID) =>
    [...sasQueryKeys.schemas(), normalizeKeyId(schemaUid)] as const,
  schema: (schemaUid: UID, scope: QueryScope) =>
    [...sasQueryKeys.schemaByUid(schemaUid), scope] as const,

  recipientAttestationsAll: () => [...sasQueryKeys.all, "recipientAttestations"] as const,
  recipientByAddress: (address: string) =>
    [...sasQueryKeys.recipientAttestationsAll(), address.trim()] as const,
  recipientAttestations: (
    address: string,
    scope: QueryScope,
    options?: RecipientQueryOptions,
  ) =>
    [
      ...sasQueryKeys.recipientByAddress(address),
      scope,
      {
        includeRevoked: options?.includeRevoked ?? true,
        cursor: options?.cursor ?? null,
        limit: options?.limit ?? null,
      },
    ] as const,
};
