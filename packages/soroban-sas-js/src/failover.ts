// Automatic RPC failover for the SAS JavaScript SDK (#565).
//
// Public Soroban RPC endpoints are rate limited and occasionally unavailable.
// `FailoverRpcClient` fronts a pool of endpoints and:
//
// - sends each JSON-RPC request to the highest-priority healthy endpoint;
// - fails over to the next endpoint on HTTP errors, network errors or timeout;
// - opens a circuit after N consecutive failures so a dead endpoint is skipped
//   until its cooldown expires (prevents cascading request storms);
// - probes endpoints round-robin with lightweight `getHealth` calls;
// - emits failover / recovery / circuit diagnostics to listeners.
//
// Fetch, timers and the clock are injectable so the behaviour is testable
// without real network access.

export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_HEALTH_CHECK_INTERVAL_MS = 30_000;
export const DEFAULT_CIRCUIT_BREAKER_THRESHOLD = 3;
export const DEFAULT_CIRCUIT_COOLDOWN_MS = 30_000;

export type EndpointStatus = {
  url: string;
  healthy: boolean;
  /** Consecutive failed requests/health checks. */
  failures: number;
  /** Epoch ms until which the circuit stays open (0 when closed). */
  circuitOpenUntil: number;
  /** Last observed request latency in ms, or null before the first success. */
  latencyMs: number | null;
  lastCheckedAt: number | null;
};

export type FailoverEvent =
  | { type: "failover"; from: string; to: string; reason: string }
  | { type: "recovery"; endpoint: string; latencyMs: number | null }
  | { type: "circuit_open"; endpoint: string; retryAt: number; failures: number }
  | { type: "circuit_closed"; endpoint: string }
  | { type: "request_failed"; endpoint: string; reason: string };

export type FailoverListener = (event: FailoverEvent) => void;

export type FetchLike = (
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    signal?: AbortSignal;
  },
) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text?(): Promise<string>;
}>;

export interface FailoverRpcClientOptions {
  /** RPC endpoint URLs in priority order. At least one is required. */
  endpoints: string[];
  /** Override `fetch` (tests, non-standard runtimes). */
  fetchImpl?: FetchLike;
  /** Per-request timeout in ms (default 10 000). */
  timeoutMs?: number;
  /** Interval between round-robin health probes (default 30 000). */
  healthCheckIntervalMs?: number;
  /** Consecutive failures before a circuit opens (default 3). */
  circuitBreakerThreshold?: number;
  /** How long an open circuit stays open (default 30 000 ms). */
  circuitCooldownMs?: number;
  /** Clock override, mainly for tests. */
  now?: () => number;
  /** Timer override, mainly for tests. */
  setIntervalImpl?: (fn: () => void, ms: number) => unknown;
  clearIntervalImpl?: (handle: unknown) => void;
}

export class FailoverRpcError extends Error {
  readonly attempts: Array<{ endpoint: string; reason: string }>;

  constructor(message: string, attempts: Array<{ endpoint: string; reason: string }>) {
    super(message);
    this.name = "FailoverRpcError";
    this.attempts = attempts;
  }
}

type JsonRpcResponse = {
  jsonrpc?: string;
  id?: number | string | null;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
};

export class FailoverRpcClient {
  private readonly endpoints: string[];
  private readonly fetchImpl: FetchLike;
  private readonly timeoutMs: number;
  private readonly healthCheckIntervalMs: number;
  private readonly circuitBreakerThreshold: number;
  private readonly circuitCooldownMs: number;
  private readonly now: () => number;
  private readonly setIntervalImpl: (fn: () => void, ms: number) => unknown;
  private readonly clearIntervalImpl: (handle: unknown) => void;

  private readonly states: EndpointStatus[];
  private readonly listeners = new Set<FailoverListener>();

  private requestId = 0;
  /** Round-robin cursor for health checks. */
  private healthCursor = 0;
  private intervalHandle: unknown = null;
  private healthCheckInFlight: Promise<void> | null = null;

  constructor(options: FailoverRpcClientOptions) {
    if (!options.endpoints || options.endpoints.length === 0) {
      throw new Error("FailoverRpcClient requires at least one endpoint");
    }
    this.endpoints = options.endpoints.map((url) => url.replace(/\/+$/, ""));
    this.fetchImpl = options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
    if (!this.fetchImpl) {
      throw new Error("No fetch implementation available; pass fetchImpl");
    }
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.healthCheckIntervalMs =
      options.healthCheckIntervalMs ?? DEFAULT_HEALTH_CHECK_INTERVAL_MS;
    this.circuitBreakerThreshold =
      options.circuitBreakerThreshold ?? DEFAULT_CIRCUIT_BREAKER_THRESHOLD;
    this.circuitCooldownMs = options.circuitCooldownMs ?? DEFAULT_CIRCUIT_COOLDOWN_MS;
    this.now = options.now ?? (() => Date.now());
    this.setIntervalImpl =
      options.setIntervalImpl ??
      ((fn, ms) => {
        const handle = setInterval(fn, ms);
        // Do not keep a Node process alive just for health checks.
        (handle as { unref?: () => void }).unref?.();
        return handle;
      });
    this.clearIntervalImpl =
      options.clearIntervalImpl ??
      ((handle) => clearInterval(handle as ReturnType<typeof setInterval>));

    this.states = this.endpoints.map((url) => ({
      url,
      healthy: true,
      failures: 0,
      circuitOpenUntil: 0,
      latencyMs: null,
      lastCheckedAt: null,
    }));
  }

  /** Current endpoint state (a copy, safe to log). */
  get status(): EndpointStatus[] {
    return this.states.map((state) => ({ ...state }));
  }

  /** Subscribe to diagnostics. Returns an unsubscribe function. */
  on(listener: FailoverListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /**
   * Perform one JSON-RPC call, failing over across the pool.
   *
   * @throws {FailoverRpcError} when every endpoint fails.
   */
  async request<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
    const attempts: Array<{ endpoint: string; reason: string }> = [];
    const order = this.candidateOrder();

    if (order.length === 0) {
      // Fail fast: every circuit is open, so contacting the pool now would
      // only add load to endpoints already known to be down.
      throw new FailoverRpcError(
        `All RPC endpoints are in an open circuit for ${method}`,
        attempts,
      );
    }

    for (const index of order) {
      const state = this.states[index];
      const startedAt = this.now();
      let body: JsonRpcResponse;
      try {
        body = await this.postJson(state.url, {
          jsonrpc: "2.0",
          id: ++this.requestId,
          method,
          params,
        });
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        attempts.push({ endpoint: state.url, reason });
        this.markFailure(index, reason);

        const next = this.nextAvailableIndex(index);
        if (next !== null) {
          this.emit({
            type: "failover",
            from: state.url,
            to: this.states[next].url,
            reason,
          });
        }
        continue;
      }

      // The endpoint answered, so it is healthy even if the method errored.
      this.markSuccess(index, this.now() - startedAt);

      if (body && typeof body === "object" && "error" in body && body.error) {
        // A JSON-RPC application error is a valid response from a healthy
        // endpoint; surface it instead of failing over.
        throw new Error(
          (body.error as { message?: string }).message ?? "JSON-RPC error",
        );
      }
      return body.result as T;
    }

    throw new FailoverRpcError(
      `All RPC endpoints failed for ${method}: ${attempts
        .map((attempt) => `${attempt.endpoint} (${attempt.reason})`)
        .join(", ")}`,
      attempts,
    );
  }

  /** Probe every endpoint once, in round-robin order. */
  async checkHealth(): Promise<void> {
    // Single-flight: overlapping ticks must not multiply the probe load.
    if (this.healthCheckInFlight) return this.healthCheckInFlight;
    this.healthCheckInFlight = this.runHealthChecks().finally(() => {
      this.healthCheckInFlight = null;
    });
    return this.healthCheckInFlight;
  }

  /** Start periodic round-robin health checks. Idempotent. */
  startHealthChecks(): void {
    if (this.intervalHandle !== null) return;
    this.intervalHandle = this.setIntervalImpl(() => {
      void this.checkHealth();
    }, this.healthCheckIntervalMs);
  }

  /** Stop periodic health checks (safe to call repeatedly). */
  stopHealthChecks(): void {
    if (this.intervalHandle === null) return;
    this.clearIntervalImpl(this.intervalHandle);
    this.intervalHandle = null;
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private async runHealthChecks(): Promise<void> {
    const start = this.healthCursor;
    for (let offset = 0; offset < this.states.length; offset += 1) {
      const index = (start + offset) % this.states.length;
      this.healthCursor = (index + 1) % this.states.length;
      const state = this.states[index];
      const startedAt = this.now();
      try {
        const body = await this.postJson(state.url, {
          jsonrpc: "2.0",
          id: ++this.requestId,
          method: "getHealth",
          params: [],
        });
        if (body && typeof body === "object" && "error" in body && body.error) {
          throw new Error("getHealth returned a JSON-RPC error");
        }
        this.markSuccess(index, this.now() - startedAt);
      } catch (error) {
        this.markFailure(
          index,
          error instanceof Error ? error.message : String(error),
        );
      }
    }
  }

  private async postJson(url: string, payload: unknown): Promise<JsonRpcResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      return (await response.json()) as JsonRpcResponse;
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error(`timed out after ${this.timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Endpoints to try, in priority order, skipping open circuits. */
  private candidateOrder(): number[] {
    const now = this.now();
    const closed = this.states
      .map((state, index) => ({
        index,
        cooled: state.circuitOpenUntil === 0 || now >= state.circuitOpenUntil,
      }))
      .filter((entry) => entry.cooled)
      .map((entry) => entry.index);

    // Every circuit is open: fail fast instead of hammering dead endpoints.

    // Configured priority order. A failing endpoint keeps being tried until its
    // circuit opens, then it is skipped for the cooldown.
    return closed;
  }

  private nextAvailableIndex(current: number): number | null {
    const order = this.candidateOrder();
    const position = order.indexOf(current);
    const after = position >= 0 ? order.slice(position + 1) : order;
    return after.length > 0 ? after[0] : null;
  }

  private markSuccess(index: number, latencyMs: number): void {
    const state = this.states[index];
    const wasUnhealthy = !state.healthy || state.circuitOpenUntil > 0;

    state.healthy = true;
    state.failures = 0;
    state.latencyMs = latencyMs;
    state.lastCheckedAt = this.now();
    if (state.circuitOpenUntil > 0) {
      state.circuitOpenUntil = 0;
      this.emit({ type: "circuit_closed", endpoint: state.url });
    }
    if (wasUnhealthy) {
      this.emit({ type: "recovery", endpoint: state.url, latencyMs });
    }
  }

  private markFailure(index: number, reason: string): void {
    const state = this.states[index];
    state.healthy = false;
    state.failures += 1;
    state.lastCheckedAt = this.now();
    this.emit({ type: "request_failed", endpoint: state.url, reason });

    if (state.failures >= this.circuitBreakerThreshold) {
      state.circuitOpenUntil = this.now() + this.circuitCooldownMs;
      this.emit({
        type: "circuit_open",
        endpoint: state.url,
        retryAt: state.circuitOpenUntil,
        failures: state.failures,
      });
    }
  }

  private emit(event: FailoverEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Diagnostics must never break the request path.
      }
    }
  }
}
