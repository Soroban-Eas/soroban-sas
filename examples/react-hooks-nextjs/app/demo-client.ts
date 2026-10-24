import type { Attestation, SASClientConfig, SchemaRecord, UID } from "@soroban-sas/sdk";
import type { SasHooksClient } from "@soroban-sas/react";

export const demoUid: UID = "ab".repeat(32);
export const demoSchemaUid: UID = "cd".repeat(32);
export const demoAccount = "GDEMO_RECIPIENT";

const demo: Attestation = {
  uid: demoUid, schemaUid: demoSchemaUid,
  time: 1_700_000_000n, expirationTime: 0n, revocationTime: 0n,
  refUid: "00".repeat(32), recipient: demoAccount, attester: "GDEMO_ATTESTER",
  revocable: true, data: new TextEncoder().encode("KYC verified"),
};

const schema: SchemaRecord = {
  uid: demoSchemaUid,
  schema: "bool verified",
  resolver: "CDEMO_RESOLVER",
  revocable: true,
};

/**
 * In-memory example adapter; the UI never signs or sends live network traffic.
 * Replace this with an injected wallet-backed SasHooksClient for production.
 */
export function createDemoClient(_config: SASClientConfig): SasHooksClient {
  const records = new Map<string, Attestation>([[demo.uid, demo]]);
  let txCounter = 0;
  return {
    async getAttestation(uid) { return records.get(uid) ?? null; },
    async getRecipientAttestations(address) {
      return [...records.values()].filter((item) => item.recipient === address).map((item) => item.uid);
    },
    async getSchema(uid) { return uid === demoSchemaUid ? schema : null; },
    async attest(item) {
      records.set(item.uid, item);
      return { hash: `demo-attest-${++txCounter}` };
    },
    async revoke(uid) {
      const existing = records.get(uid);
      if (!existing) throw new Error("Demo attestation not found");
      if (!existing.revocable) throw new Error("This attestation cannot be revoked");
      records.set(uid, { ...existing, revocationTime: BigInt(Math.floor(Date.now() / 1_000)) });
      return { hash: `demo-revoke-${++txCounter}` };
    },
  };
}
