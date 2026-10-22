import { describe, expect, it, vi } from "vitest";
import {
  FailoverRpcClient,
  FailoverRpcError,
  type FailoverEvent,
  type FetchLike,
} from "../src/failover.js";

type Reply = { ok: boolean; status: number; json(): Promise<unknown> };

function jsonReply(result: unknown): Reply {
  return {
    ok: true,
    status: 200,
    json: async () => ({ jsonrpc: "2.0", id: 1, result }),
  };
}

function httpError(status: number): Reply {
  return {
    ok: false,
    status,
    json: async () => ({}),
  };
}

const PRIMARY = "https://rpc-primary.example";
const SECONDARY = "https://rpc-secondary.example";

function client(
  fetchImpl: FetchLike,
  overrides: Partial<ConstructorParameters<typeof FailoverRpcClient>[0]> = {},
) {
  return new FailoverRpcClient({
    endpoints: [PRIMARY, SECONDARY],
    fetchImpl,
    timeoutMs: 50,
    ...overrides,
  });
}

describe("FailoverRpcClient", () => {
  it("fails over to the secondary endpoint when the primary returns an HTTP error", async () => {
    const fetchImpl = vi.fn<FetchLike>(async (url) =>
      url === PRIMARY ? httpError(503) : jsonReply({ status: "healthy" }),
    );
    const rpc = client(fetchImpl);
    const events: FailoverEvent[] = [];
    rpc.on((event) => events.push(event));

    const result = await rpc.request("getHealth");

    expect(result).toEqual({ status: "healthy" });
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([PRIMARY, SECONDARY]);
    expect(events).toContainEqual(
      expect.objectContaining({ type: "failover", from: PRIMARY, to: SECONDARY }),
    );
  });

  it("throws FailoverRpcError when every endpoint fails", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => httpError(429));
    const rpc = client(fetchImpl);

    await expect(rpc.request("getLatestLedger")).rejects.toBeInstanceOf(
      FailoverRpcError,
    );
    try {
      await rpc.request("getLatestLedger");
    } catch (error) {
      const failure = error as FailoverRpcError;
      expect(failure.attempts).toHaveLength(2);
      expect(failure.attempts[0].endpoint).toBe(PRIMARY);
      expect(failure.attempts[0].reason).toContain("HTTP 429");
    }
  });

  it("returns to the primary endpoint once a health check sees it recover", async () => {
    let primaryHealthy = false;
    const fetchImpl = vi.fn<FetchLike>(async (url) => {
      if (url === PRIMARY) {
        return primaryHealthy ? jsonReply({ status: "healthy" }) : httpError(500);
      }
      return jsonReply({ status: "healthy" });
    });
    const rpc = client(fetchImpl);
    const events: FailoverEvent[] = [];
    rpc.on((event) => events.push(event));

    // First request falls through to the secondary.
    await rpc.request("getHealth");
    expect(rpc.status.find((s) => s.url === PRIMARY)?.healthy).toBe(false);

    primaryHealthy = true;
    await rpc.checkHealth();

    const recovered = rpc.status.find((s) => s.url === PRIMARY);
    expect(recovered?.healthy).toBe(true);
    expect(recovered?.latencyMs).not.toBeNull();
    expect(events).toContainEqual(
      expect.objectContaining({ type: "recovery", endpoint: PRIMARY }),
    );

    // The primary is preferred again.
    fetchImpl.mockClear();
    await rpc.request("getHealth");
    expect(fetchImpl.mock.calls[0][0]).toBe(PRIMARY);
  });

  it("opens a circuit after the failure threshold and skips it until the cooldown", async () => {
    let now = 1_000;
    let primaryHealthy = false;
    const fetchImpl = vi.fn<FetchLike>(async (url) => {
      if (url === PRIMARY && !primaryHealthy) return httpError(503);
      return jsonReply({ status: "healthy" });
    });
    const rpc = client(fetchImpl, {
      now: () => now,
      circuitBreakerThreshold: 3,
      circuitCooldownMs: 5_000,
    });
    const events: FailoverEvent[] = [];
    rpc.on((event) => events.push(event));

    for (let i = 0; i < 3; i += 1) {
      await rpc.request("getHealth");
    }

    const primary = rpc.status.find((s) => s.url === PRIMARY);
    expect(primary?.failures).toBe(3);
    expect(primary?.circuitOpenUntil).toBe(6_000);
    expect(events).toContainEqual(
      expect.objectContaining({ type: "circuit_open", endpoint: PRIMARY }),
    );

    // While the circuit is open the dead endpoint is not contacted at all.
    fetchImpl.mockClear();
    await rpc.request("getHealth");
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([SECONDARY]);

    // After the cooldown it is probed again.
    now = 6_000;
    primaryHealthy = true;
    fetchImpl.mockClear();
    await rpc.request("getHealth");
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([PRIMARY]);

    // A successful probe after the cooldown closes the circuit and restores
    // primary priority.
    const recovered = rpc.status.find((s) => s.url === PRIMARY);
    expect(recovered?.circuitOpenUntil).toBe(0);
    expect(events).toContainEqual(
      expect.objectContaining({ type: "circuit_closed", endpoint: PRIMARY }),
    );
  });

  it("times out a hanging endpoint and fails over", async () => {
    const hanging: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          const error = new Error("aborted");
          error.name = "AbortError";
          reject(error);
        });
      });
    const fetchImpl = vi.fn<FetchLike>(async (url, init) =>
      url === PRIMARY ? hanging(url, init) : jsonReply({ status: "healthy" }),
    );
    const rpc = client(fetchImpl, { timeoutMs: 20 });

    const result = await rpc.request("getHealth");

    expect(result).toEqual({ status: "healthy" });
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([PRIMARY, SECONDARY]);
  });

  it("health-checks every endpoint once per tick in round-robin order", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => jsonReply({ status: "healthy" }));
    const rpc = client(fetchImpl);

    await rpc.checkHealth();
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([PRIMARY, SECONDARY]);

    fetchImpl.mockClear();
    await rpc.checkHealth();
    expect(fetchImpl.mock.calls.map(([url]) => url)).toEqual([PRIMARY, SECONDARY]);
  });

  it("coalesces concurrent health checks (no request storm)", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetchImpl = vi.fn<FetchLike>(async () => {
      await gate;
      return jsonReply({ status: "healthy" });
    });
    const rpc = client(fetchImpl);

    const first = rpc.checkHealth();
    const second = rpc.checkHealth();
    release();
    await Promise.all([first, second]);

    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("surfaces JSON-RPC errors from a healthy endpoint without failing over", async () => {
    const fetchImpl = vi.fn<FetchLike>(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32601, message: "method not found" },
      }),
    }));
    const rpc = client(fetchImpl);

    await expect(rpc.request("nope")).rejects.toThrow("method not found");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("retries the primary while its circuit is still closed", async () => {
    let primaryFails = true;
    const fetchImpl = vi.fn<FetchLike>(async (url) => {
      if (url === PRIMARY && primaryFails) return httpError(500);
      return jsonReply({ status: "healthy" });
    });
    const rpc = client(fetchImpl);

    await rpc.request("getHealth"); // primary fails, secondary serves
    primaryFails = false;

    // One failure is below the breaker threshold, so the primary is retried.
    fetchImpl.mockClear();
    await rpc.request("getHealth");
    expect(fetchImpl.mock.calls[0][0]).toBe(PRIMARY);
    expect(rpc.status.find((s) => s.url === PRIMARY)?.healthy).toBe(true);
  });

  it("unsubscribes listeners cleanly", async () => {
    const fetchImpl = vi.fn<FetchLike>(async (url) =>
      url === PRIMARY ? httpError(500) : jsonReply({ status: "healthy" }),
    );
    const rpc = client(fetchImpl);
    const listener = vi.fn();
    const unsubscribe = rpc.on(listener);

    await rpc.request("getHealth");
    expect(listener).toHaveBeenCalled();

    unsubscribe();
    listener.mockClear();
    await rpc.request("getHealth");
    expect(listener).not.toHaveBeenCalled();
  });
});
