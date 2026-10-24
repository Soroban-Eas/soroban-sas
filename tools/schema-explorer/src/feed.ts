import type { RegistryReader } from "./registry.js";

/**
 * A single attestation as returned by the indexer.
 * Attestation status is derived from on-chain data (expiration and
 * revocation), not from a server-side label, so it always reflects the
 * current state.
 */
export type AttestationStatus = "active" | "expired" | "revoked";

export interface AttestationRecord {
  /** 64-hex attestation UID. */
  uid: string;
  /** 64-hex schema UID this attestation conforms to. */
  schemaUid: string;
  /** Stellar address (G…) that signed the attestation. */
  attester: string;
  /** Stellar address (G…) the attestation is about. */
  recipient: string;
  /** Unix seconds the attestation expires, 0 for never. */
  expiration: number;
  /** Unix seconds the attestation was created. */
  created: number;
  /** Whether the attestation has been revoked. */
  revoked: boolean;
  /** Raw payload as base64-encoded Soroban XDR. */
  payloadXdr: string;
  /** Decoded payload JSON, when available. */
  payloadJson: unknown | null;
}

/** Derive the display status from on-chain fields. */
export function attestationStatus(record: AttestationRecord, now: number = Math.floor(Date.now() / 1000)): AttestationStatus {
  if (record.revoked) return "revoked";
  if (record.expiration !== 0 && record.expiration <= now) return "expired";
  return "active";
}

/**
 * Polls the registry reader for new attestations and emits them to
 * subscribers. The registry contract has no push channel, and the
 * explorer is read-only, so "live" means polling the indexer at a
 * configurable interval and diffing against the UIDs already seen.
 */
export interface AttestationFeed {
  /** Start polling. Resolves once the first page has been delivered. */
  start(): Promise<void>;
  /** Stop polling and drop subscribers. */
  stop(): void;
  /** Force an immediate refresh. */
  refresh(): Promise<void>;
  /** Subscribe to new attestations. Returns an unsubscribe function. */
  on(cb: (records: AttestationRecord[]) => void): () => void;
  /** Subscribe to errors from the underlying reads. */
  onError(cb: (err: unknown) => void): () => void;
}

export interface AttestationFeedOptions {
  /** The registry reader to poll. */
  reader: RegistryReader;
  /** How many attestations to fetch per page. */
  pageSize?: number;
  /** Polling interval in milliseconds. */
  intervalMs?: number;
  /** Optional schema UID to restrict the feed to. */
  schemaUid?: string;
}

const DEFAULT_PAGE_SIZE = 20;
const DEFAULT_INTERVAL_MS = 5000;

/**
 * Create a polling attestation feed. The feed keeps the most recent
 * attestations in memory (newest first) and only emits records that
 * were not seen in a previous poll, so the UI can append without
 * duplicating.
 */
export function createAttestationFeed(options: AttestationFeedOptions): AttestationFeed {
  const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
  const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
  const reader = options.reader;

  const seen = new Set<string>();
  const listeners = new Set<(records: AttestationRecord[]) => void>();
  const errorListeners = new Set<(err: unknown) => void>();
  let timer: ReturnType<typeof setInterval> | null = null;
  let inflight: Promise<void> | null = null;
  let stopped = false;

  async function fetchOnce(): Promise<void> {
    if (stopped) return;
    try {
      const fetchFn = (reader as any).getRecentAttestations;
      const records: AttestationRecord[] =
        typeof fetchFn === "function"
          ? await fetchFn.call(reader, {
              limit: pageSize,
              schemaUid: options.schemaUid,
            })
          : [];
      const fresh = records.filter((r: AttestationRecord) => !seen.has(r.uid));
      if (fresh.length === 0) return;
      for (const record of fresh) seen.add(record.uid);
      // Newest first so the UI appends at the top.
      const ordered = [...fresh].sort((a, b) => b.created - a.created);
      for (const cb of listeners) {
        try {
          cb(ordered);
        } catch {
          // A broken subscriber must not stop the feed.
        }
      }
    } catch (err) {
      for (const cb of errorListeners) {
        try {
          cb(err);
        } catch {
          // Ignore subscriber failures.
        }
      }
    }
  }

  function schedule(): void {
    if (stopped) return;
    timer = setInterval(() => {
      // Serialize polls so a slow RPC call never overlaps the next tick.
      if (inflight) return;
      inflight = fetchOnce().finally(() => {
        inflight = null;
      });
    }, intervalMs);
  }

  return {
    async start() {
      if (timer !== null) return;
      stopped = false;
      await fetchOnce();
      schedule();
    },
    stop() {
      stopped = true;
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
      listeners.clear();
      errorListeners.clear();
    },
    async refresh() {
      if (inflight) await inflight;
      inflight = fetchOnce().finally(() => {
        inflight = null;
      });
      await inflight;
    },
    on(cb) {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    onError(cb) {
      errorListeners.add(cb);
      return () => errorListeners.delete(cb);
    },
  };
}
