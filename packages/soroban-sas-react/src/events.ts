import { Buffer } from "buffer";
import { Address, scValToNative, xdr } from "@stellar/stellar-sdk";
import type { QueryClient } from "@tanstack/react-query";
import { normalizeKeyId, sasQueryKeys } from "./queryKeys.js";
import type { SASEvent, SASEventListener, SASNetworkConfig, UID } from "./types.js";

/** Custom DOM event names supported by `SASProvider` and `useSASEvents`. */
export const SAS_DOM_EVENTS = {
  EVENT: "sas:event",
  ATTESTATION_ISSUED: "sas:attestation-issued",
  ATTESTATION_REVOKED: "sas:attestation-revoked",
  SCHEMA_REGISTERED: "sas:schema-registered",
  ACCOUNT_CHANGED: "sas:account-changed",
  NETWORK_CHANGED: "sas:network-changed",
  STELLAR_ACCOUNT_CHANGED: "stellar:accountChanged",
  FREIGHTER_ACCOUNT_CHANGED: "freighter:accountChanged",
} as const;

/** Lightweight pub/sub event bus for SAS events. */
export class SASEventBus {
  private readonly listeners = new Set<SASEventListener>();

  subscribe(listener: SASEventListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  emit(event: SASEvent): void {
    for (const listener of Array.from(this.listeners)) {
      listener(event);
    }
  }
}

/** Dispatches a SAS event on `window` so any mounted `SASProvider` or listener reacts to it. */
export function dispatchSASEvent(event: SASEvent): void {
  if (typeof window === "undefined" || typeof CustomEvent === "undefined") return;
  window.dispatchEvent(new CustomEvent(SAS_DOM_EVENTS.EVENT, { detail: event }));
}

/** Dispatches an account-switch event on `window`. */
export function dispatchAccountSwitch(account: string | null): void {
  if (typeof window === "undefined" || typeof CustomEvent === "undefined") return;
  window.dispatchEvent(
    new CustomEvent(SAS_DOM_EVENTS.ACCOUNT_CHANGED, { detail: { account } }),
  );
}

/** Dispatches a network-switch event on `window`. */
export function dispatchNetworkSwitch(network: string | SASNetworkConfig): void {
  if (typeof window === "undefined" || typeof CustomEvent === "undefined") return;
  window.dispatchEvent(
    new CustomEvent(SAS_DOM_EVENTS.NETWORK_CHANGED, { detail: { network } }),
  );
}

/**
 * Invalidates the appropriate TanStack Query cache entries in response to a `SASEvent`.
 */
export async function invalidateQueriesForEvent(
  queryClient: QueryClient,
  event: SASEvent,
): Promise<void> {
  switch (event.type) {
    case "AttestationIssued": {
      const tasks: Promise<unknown>[] = [];
      if (event.uid) {
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.attestationByUid(event.uid),
          }),
        );
      } else {
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.attestations(),
          }),
        );
      }
      if (event.recipient) {
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.recipientByAddress(event.recipient),
          }),
        );
      } else {
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.recipientAttestationsAll(),
          }),
        );
      }
      await Promise.all(tasks);
      return;
    }

    case "AttestationRevoked": {
      const tasks: Promise<unknown>[] = [];
      if (event.uid) {
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.attestationByUid(event.uid),
          }),
        );
      } else {
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.attestations(),
          }),
        );
      }
      if (event.recipient) {
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.recipientByAddress(event.recipient),
          }),
        );
      } else {
        // On-chain REVOKED events only carry `{ uid, timestamp }`, so invalidate all recipient lists.
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.recipientAttestationsAll(),
          }),
        );
      }
      await Promise.all(tasks);
      return;
    }

    case "SchemaRegistered": {
      if (event.schemaUid) {
        await queryClient.invalidateQueries({
          queryKey: sasQueryKeys.schemaByUid(event.schemaUid),
        });
      } else {
        await queryClient.invalidateQueries({
          queryKey: sasQueryKeys.schemas(),
        });
      }
      return;
    }

    case "BatchAttested":
    case "BatchRevoked": {
      const tasks: Promise<unknown>[] = [];
      if (event.uids && event.uids.length > 0) {
        for (const uid of event.uids) {
          tasks.push(
            queryClient.invalidateQueries({
              queryKey: sasQueryKeys.attestationByUid(uid),
            }),
          );
        }
      } else {
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.attestations(),
          }),
        );
      }
      if (event.recipients && event.recipients.length > 0) {
        for (const recipient of event.recipients) {
          tasks.push(
            queryClient.invalidateQueries({
              queryKey: sasQueryKeys.recipientByAddress(recipient),
            }),
          );
        }
      } else {
        tasks.push(
          queryClient.invalidateQueries({
            queryKey: sasQueryKeys.recipientAttestationsAll(),
          }),
        );
      }
      await Promise.all(tasks);
      return;
    }

    case "AccountChanged":
    case "NetworkChanged": {
      await queryClient.invalidateQueries({
        queryKey: sasQueryKeys.all,
      });
      return;
    }
  }
}

function isByteView(val: unknown): val is Uint8Array {
  return (
    val instanceof Uint8Array ||
    Buffer.isBuffer(val) ||
    (typeof val === "object" && val !== null && ArrayBuffer.isView(val))
  );
}

function bytesToHex(bytes: Uint8Array | ArrayBufferView): UID {
  const view = new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Buffer.from(view).toString("hex").toLowerCase();
}

function extractUidFromNative(val: unknown): UID | undefined {
  if (typeof val === "string" && val.length >= 64) {
    return normalizeKeyId(val);
  }
  if (isByteView(val) && val.byteLength === 32) {
    return bytesToHex(val);
  }
  if (Array.isArray(val) && val.length === 1 && isByteView(val[0]) && val[0].byteLength === 32) {
    return bytesToHex(val[0]);
  }
  return undefined;
}

function extractAddressFromNative(val: unknown): string | undefined {
  if (typeof val === "string" && (val.startsWith("G") || val.startsWith("C"))) {
    return val;
  }
  return undefined;
}

function toScVal(item: xdr.ScVal | string): xdr.ScVal {
  if (typeof item === "string") {
    return xdr.ScVal.fromXDR(item, "base64");
  }
  return item;
}

/**
 * Raw Soroban RPC event shape (supports both pre-decoded `ScVal` objects and base64 XDR strings).
 */
export interface RawRpcEvent {
  topic?: Array<xdr.ScVal | string>;
  value?: xdr.ScVal | string | { xdr?: string };
  ledger?: number;
}

/**
 * Parses a raw Soroban RPC event (`ATTESTED`, `REVOKED`, `REGISTERED`, `BATCHATT`, `BATCHREV`)
 * into a strongly-typed `SASEvent`, or returns `null` if the event is not a recognized SAS event.
 */
export function parseRpcContractEvent(raw: RawRpcEvent): SASEvent | null {
  try {
    if (!raw.topic || raw.topic.length === 0 || !raw.value) return null;
    const topics = raw.topic.map(toScVal);
    const firstTopic = topics[0];
    if (firstTopic.switch() !== xdr.ScValType.scvSymbol()) return null;

    const topicSym = firstTopic.sym();
    const topicName =
      typeof topicSym === "string"
        ? topicSym
        : Buffer.from(topicSym).toString("utf8");
    const valueScVal =
      typeof raw.value === "object" && "xdr" in raw.value && typeof raw.value.xdr === "string"
        ? xdr.ScVal.fromXDR(raw.value.xdr, "base64")
        : toScVal(raw.value as xdr.ScVal | string);

    const payload = scValToNative(valueScVal) as Record<string, unknown> | null;
    if (!payload || typeof payload !== "object") return null;

    if (topicName === "ATTESTED") {
      const uid = extractUidFromNative(payload.uid);
      if (!uid) return null;
      return {
        type: "AttestationIssued",
        uid,
        schemaUid:
          extractUidFromNative(payload.schema_uid ?? payload.schemaUid) ??
          (topics[1] ? extractUidFromNative(scValToNative(topics[1])) : undefined),
        attester:
          extractAddressFromNative(payload.attester) ??
          (topics[2] && topics[2].switch() === xdr.ScValType.scvAddress()
            ? Address.fromScVal(topics[2]).toString()
            : undefined),
        recipient: extractAddressFromNative(payload.recipient),
        ledger: raw.ledger,
      };
    }

    if (topicName === "REVOKED") {
      const uid =
        extractUidFromNative(payload.uid) ??
        (topics[1] ? extractUidFromNative(scValToNative(topics[1])) : undefined);
      if (!uid) return null;
      return {
        type: "AttestationRevoked",
        uid,
        timestamp:
          typeof payload.timestamp === "bigint" || typeof payload.timestamp === "number"
            ? payload.timestamp
            : undefined,
        ledger: raw.ledger,
      };
    }

    if (topicName === "REGISTER" || topicName === "REGISTERED") {
      const schemaUid =
        extractUidFromNative(payload.schema_uid ?? payload.schemaUid) ??
        (topics[1] ? extractUidFromNative(scValToNative(topics[1])) : undefined);
      if (!schemaUid) return null;
      return {
        type: "SchemaRegistered",
        schemaUid,
        owner: extractAddressFromNative(payload.owner),
        ledger: raw.ledger,
      };
    }

    if (topicName === "BATCHATT") {
      return {
        type: "BatchAttested",
        count: Number(payload.count ?? 0),
        attesterCount:
          payload.attester_count !== undefined ? Number(payload.attester_count) : undefined,
        ledger: raw.ledger,
      };
    }

    if (topicName === "BATCHREV") {
      return {
        type: "BatchRevoked",
        count: Number(payload.count ?? 0),
        attesterCount:
          payload.attester_count !== undefined ? Number(payload.attester_count) : undefined,
        ledger: raw.ledger,
      };
    }

    return null;
  } catch {
    return null;
  }
}
