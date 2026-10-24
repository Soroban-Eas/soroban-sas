"use client";

import useSWR from "swr";
import type { Attestation, SchemaRecord } from "@soroban-sas/sdk";
import { useSasContext } from "./provider.js";

/** Null or empty identifiers suspend reads without sending an RPC request. */
export function useAttestation(uid: string | null | undefined) {
  const { client, keyPrefix } = useSasContext();
  return useSWR<Attestation | null, Error>(
    uid ? [...keyPrefix, "attestation", uid] : null,
    () => client.getAttestation(uid!),
  );
}

/** Resolve indexed recipient UIDs into complete attestations through SAS. */
export function useRecipientAttestations(address: string | null | undefined) {
  const { client, keyPrefix } = useSasContext();
  return useSWR<Attestation[], Error>(
    address ? [...keyPrefix, "recipient", address] : null,
    async () => {
      const uids = await client.getRecipientAttestations(address!);
      const rows = await Promise.all(uids.map((uid) => client.getAttestation(uid)));
      return rows.filter((row): row is Attestation => row !== null);
    },
  );
}

export function useSchema(uid: string | null | undefined) {
  const { client, keyPrefix } = useSasContext();
  return useSWR<SchemaRecord | null, Error>(
    uid ? [...keyPrefix, "schema", uid] : null,
    () => client.getSchema(uid!),
  );
}
