// Resilient multi-endpoint transport: priority weights, health scores,
// jittered-backoff failover for reads, single-shot writes, and telemetry
// events. It is transport-agnostic: callers pass a function that performs one
// request against a given endpoint URL (an RPC call, an indexer GraphQL query).
//
// Safety rule for writes: `write()` sends to exactly ONE endpoint, exactly
// once. It never retries or fails over, because after a timeout or a 5xx the
// first node may still have accepted the transaction; resubmitting elsewhere
// could duplicate it. Callers that want to retry a write must look the
// transaction up by hash first.

export type EndpointKind = "rpc" | "indexer";

export interface EndpointConfig {
  url: string;
  /** Priority weight (> 0). Higher is preferred. Default 1. */
  weight?: number;
  /** Default "rpc". */
  kind?: EndpointKind;
}

export interface ResilienceOptions {
  /** Per-request timeout in ms. Default 10_000. */
  timeoutMs?: number;
  /** Max attempts for a read, across all endpoints. Default 3. */
  maxAttempts?: number;
  /** Base backoff in ms (full jitter, doubles per attempt). Default 200. */
  backoffBaseMs?: number;
  /** Backoff ceiling in ms. Default 5_000. */
  backoffMaxMs?: number;
  /** Consecutive failures that open an endpoint's circuit. Default 3. */
  failureThreshold?: number;
  /** How long an open circuit stays open before a probe is allowed. Default 30_000. */
  cooldownMs?: number;
  /** EWMA smoothing for health scores in (0, 1]. Default 0.3. */
  healthAlpha?: number;
  /** HTTP statuses treated as endpoint faults. Default [429, 502, 503, 504]. */
  retryableStatuses?: number[];
  /** Override fault classification. Return true if the error is the endpoint's fault. */
  isRetryable?: (error: unknown) => boolean;
  /** Receives every event (in addition to `on()` listeners). */
  onEvent?: (event: ResilienceEvent) => void;
  /** Test seams. */
  random?: () => number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

export type EndpointState = "healthy" | "degraded" | "down";
export type ConnectionState = "connected" | "degraded" | "disconnected";

export type ResilienceEvent =
  | { type: "endpointStateChange"; url: string; from: EndpointState; to: EndpointState; score: number }
  | { type: "connectionStateChange"; from: ConnectionState; to: ConnectionState }
  | { type: "retry"; url: string; attempt: number; delayMs: number; error: unknown }
  | { type: "failover"; from: string; to: string; error: unknown };

export interface EndpointHealth {
  url: string;
  kind: EndpointKind;
  weight: number;
  score: number;
  state: EndpointState;
  consecutiveFailures: number;
}

/** Thrown when a request exceeds `timeoutMs`. */
export class RequestTimeoutError extends Error {
  constructor(public readonly url: string, public readonly timeoutMs: number) {
    super(`Request to ${url} timed out after ${timeoutMs}ms`);
    this.name = "RequestTimeoutError";
  }
}

/** Thrown when every attempt failed. `errors` holds each attempt's error. */
export class AllEndpointsFailedError extends Error {
  constructor(public readonly errors: unknown[]) {
    super(`All endpoints failed after ${errors.length} attempt(s): ${errors.map(String).join("; ")}`);
    this.name = "AllEndpointsFailedError";
  }
}

const NETWORK_CODES = new Set([
  "ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND", "EAI_AGAIN", "EPIPE", "UND_ERR_CONNECT_TIMEOUT",
]);

interface Internal extends EndpointHealth {
  openUntil: number;
}

const HEALTHY_AT = 0.7;

function statusOf(error: unknown): number | undefined {
  const e = error as { status?: unknown; statusCode?: unknown; response?: { status?: unknown } } | null;
  const s = e?.status ?? e?.statusCode ?? e?.response?.status;
  if (typeof s === "number") return s;
  const m = /\b(429|502|503|504)\b/.exec(String((error as Error)?.message ?? ""));
  return m ? Number(m[1]) : undefined;
}

export class ResilientTransport {
  private readonly endpoints: Internal[];
  private readonly o: Required<Omit<ResilienceOptions, "isRetryable" | "onEvent">> &
    Pick<ResilienceOptions, "isRetryable" | "onEvent">;
  private readonly listeners = new Set<(e: ResilienceEvent) => void>();
  private connection: ConnectionState = "connected";

  constructor(endpoints: EndpointConfig[], options: ResilienceOptions = {}) {
    if (endpoints.length === 0) throw new Error("ResilientTransport requires at least one endpoint");
    const seen = new Set<string>();
    this.endpoints = endpoints.map((e) => {
      const weight = e.weight ?? 1;
      if (!(weight > 0)) throw new Error(`Endpoint weight must be > 0 (got ${weight} for ${e.url})`);
      if (seen.has(e.url)) throw new Error(`Duplicate endpoint ${e.url}`);
      seen.add(e.url);
      return { url: e.url, kind: e.kind ?? "rpc", weight, score: 1, state: "healthy", consecutiveFailures: 0, openUntil: 0 };
    });
    this.o = {
      timeoutMs: options.timeoutMs ?? 10_000,
      maxAttempts: Math.max(1, options.maxAttempts ?? 3),
      backoffBaseMs: options.backoffBaseMs ?? 200,
      backoffMaxMs: options.backoffMaxMs ?? 5_000,
      failureThreshold: Math.max(1, options.failureThreshold ?? 3),
      cooldownMs: options.cooldownMs ?? 30_000,
      healthAlpha: options.healthAlpha ?? 0.3,
      retryableStatuses: options.retryableStatuses ?? [429, 502, 503, 504],
      isRetryable: options.isRetryable,
      onEvent: options.onEvent,
      random: options.random ?? Math.random,
      sleep: options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))),
      now: options.now ?? Date.now,
    };
  }

  /** Subscribe to telemetry events. Returns an unsubscribe function. */
  on(listener: (e: ResilienceEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Snapshot of every endpoint's health. */
  health(): EndpointHealth[] {
    return this.endpoints.map(({ openUntil: _o, ...h }) => ({ ...h }));
  }

  connectionState(): ConnectionState {
    return this.connection;
  }

  /**
   * Run a read-only request, failing over to other endpoints with jittered
   * backoff on 429/502/503/504, timeouts and network errors.
   */
  async read<T>(fn: (url: string, signal: AbortSignal) => Promise<T>, opts: { kind?: EndpointKind } = {}): Promise<T> {
    const errors: unknown[] = [];
    let last: string | undefined;
    for (let attempt = 0; attempt < this.o.maxAttempts; attempt++) {
      const ep = this.pick(opts.kind, attempt);
      if (last && last !== ep.url) this.emit({ type: "failover", from: last, to: ep.url, error: errors[errors.length - 1] });
      try {
        return await this.run(ep, fn);
      } catch (err) {
        if (!this.isEndpointFault(err)) throw err; // e.g. contract error: not the node's fault
        errors.push(err);
        last = ep.url;
        if (attempt + 1 < this.o.maxAttempts) {
          const delayMs = this.backoff(attempt);
          this.emit({ type: "retry", url: ep.url, attempt: attempt + 1, delayMs, error: err });
          await this.o.sleep(delayMs);
        }
      }
    }
    throw new AllEndpointsFailedError(errors);
  }

  /**
   * Run a state-changing request against the single best endpoint, once.
   * Never retried and never sent to a second node (see file header).
   */
  async write<T>(fn: (url: string, signal: AbortSignal) => Promise<T>, opts: { kind?: EndpointKind } = {}): Promise<T> {
    return this.run(this.pick(opts.kind, 0), fn);
  }

  // ── internals ──────────────────────────────────────────────────────────────

  /** Best endpoint by weight × health; rotate through the ranking on later attempts. */
  private pick(kind: EndpointKind | undefined, attempt: number): Internal {
    const pool = this.endpoints.filter((e) => (kind ? e.kind === kind : e.kind === "rpc"));
    if (pool.length === 0) throw new Error(`No ${kind ?? "rpc"} endpoint configured`);
    const now = this.o.now();
    const open = (e: Internal) => e.openUntil > now;
    const usable = pool.filter((e) => !open(e));
    const ranked = (usable.length > 0 ? usable : pool).slice().sort((a, b) => b.weight * b.score - a.weight * a.score);
    return ranked[attempt % ranked.length];
  }

  private backoff(attempt: number): number {
    const cap = Math.min(this.o.backoffMaxMs, this.o.backoffBaseMs * 2 ** attempt);
    return Math.floor(this.o.random() * cap); // full jitter
  }

  private isEndpointFault(err: unknown): boolean {
    if (this.o.isRetryable) return this.o.isRetryable(err);
    if (err instanceof RequestTimeoutError) return true;
    const status = statusOf(err);
    if (status !== undefined) return this.o.retryableStatuses.includes(status);
    const code = (err as { code?: unknown })?.code;
    if (typeof code === "string" && NETWORK_CODES.has(code)) return true;
    return /fetch failed|network error|socket hang up/i.test(String((err as Error)?.message ?? ""));
  }

  private async run<T>(ep: Internal, fn: (url: string, signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new RequestTimeoutError(ep.url, this.o.timeoutMs));
      }, this.o.timeoutMs);
    });
    try {
      const result = await Promise.race([fn(ep.url, controller.signal), timeout]);
      this.record(ep, true);
      return result;
    } catch (err) {
      if (this.isEndpointFault(err)) this.record(ep, false);
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  private record(ep: Internal, ok: boolean): void {
    const a = this.o.healthAlpha;
    ep.score = ok ? ep.score + a * (1 - ep.score) : ep.score * (1 - a);
    ep.consecutiveFailures = ok ? 0 : ep.consecutiveFailures + 1;
    if (!ok && ep.consecutiveFailures >= this.o.failureThreshold) ep.openUntil = this.o.now() + this.o.cooldownMs;
    if (ok) ep.openUntil = 0;

    const to: EndpointState =
      ep.consecutiveFailures >= this.o.failureThreshold ? "down" : ep.score >= HEALTHY_AT ? "healthy" : "degraded";
    if (to !== ep.state) {
      const from = ep.state;
      ep.state = to;
      this.emit({ type: "endpointStateChange", url: ep.url, from, to, score: ep.score });
      this.updateConnection();
    }
  }

  private updateConnection(): void {
    const states = this.endpoints.map((e) => e.state);
    const next: ConnectionState = states.some((s) => s === "healthy")
      ? "connected"
      : states.some((s) => s === "degraded")
        ? "degraded"
        : "disconnected";
    if (next !== this.connection) {
      const from = this.connection;
      this.connection = next;
      this.emit({ type: "connectionStateChange", from, to: next });
    }
  }

  private emit(event: ResilienceEvent): void {
    for (const l of this.listeners) {
      try { l(event); } catch { /* telemetry must never break requests */ }
    }
    try { this.o.onEvent?.(event); } catch { /* ditto */ }
  }
}
