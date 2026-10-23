import { describe, expect, it, vi } from "vitest";
import {
  AllEndpointsFailedError,
  RequestTimeoutError,
  ResilientTransport,
  type EndpointConfig,
  type ResilienceEvent,
} from "../src/resilient.js";

const A = "https://a.example";
const B = "https://b.example";
const C = "https://c.example";

const httpError = (status: number) => Object.assign(new Error(`HTTP ${status}`), { status });

function make(endpoints: EndpointConfig[] = [{ url: A, weight: 10 }, { url: B, weight: 1 }], extra: Record<string, unknown> = {}) {
  const sleeps: number[] = [];
  const events: ResilienceEvent[] = [];
  let t = 0;
  const transport = new ResilientTransport(endpoints, {
    random: () => 0.5,
    sleep: async (ms) => { sleeps.push(ms); },
    now: () => t,
    backoffBaseMs: 100,
    backoffMaxMs: 1000,
    onEvent: (e) => events.push(e),
    ...extra,
  });
  return { transport, sleeps, events, advance: (ms: number) => { t += ms; } };
}

describe("read failover", () => {
  it("uses the highest-weight endpoint when healthy", async () => {
    const { transport } = make();
    const fn = vi.fn(async (url: string) => url);
    expect(await transport.read(fn)).toBe(A);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it.each([429, 502, 503, 504])("switches to the backup on HTTP %i", async (status) => {
    const { transport, events } = make();
    const fn = vi.fn(async (url: string) => {
      if (url === A) throw httpError(status);
      return `ok:${url}`;
    });
    expect(await transport.read(fn)).toBe(`ok:${B}`);
    expect(fn.mock.calls.map((c) => c[0])).toEqual([A, B]);
    expect(events.some((e) => e.type === "failover" && e.from === A && e.to === B)).toBe(true);
  });

  it("switches to the backup on timeout and aborts the slow request", async () => {
    const { transport } = make(undefined, { timeoutMs: 20 });
    let aborted = false;
    const fn = async (url: string, signal: AbortSignal) => {
      if (url === A) {
        signal.addEventListener("abort", () => { aborted = true; });
        return new Promise<string>(() => {}); // never resolves
      }
      return "backup";
    };
    expect(await transport.read(fn)).toBe("backup");
    expect(aborted).toBe(true);
  });

  it("switches on network errors", async () => {
    const { transport } = make();
    const fn = async (url: string) => {
      if (url === A) throw Object.assign(new Error("connect"), { code: "ECONNREFUSED" });
      return "ok";
    };
    expect(await transport.read(fn)).toBe("ok");
  });

  it("applies jittered exponential backoff between attempts", async () => {
    const { transport, sleeps } = make(undefined, { maxAttempts: 4 });
    await expect(transport.read(async () => { throw httpError(503); })).rejects.toBeInstanceOf(AllEndpointsFailedError);
    // random()=0.5 → floor(0.5 * min(1000, 100 * 2^attempt))
    expect(sleeps).toEqual([50, 100, 200]);
  });

  it("does not retry or penalise non-endpoint errors", async () => {
    const { transport } = make();
    const fn = vi.fn(async () => { throw new Error("contract error #7"); });
    await expect(transport.read(fn)).rejects.toThrow("contract error #7");
    expect(fn).toHaveBeenCalledTimes(1);
    expect(transport.health().every((h) => h.score === 1)).toBe(true);
  });

  it("honours a custom isRetryable", async () => {
    const { transport } = make(undefined, { isRetryable: (e: unknown) => (e as Error).message === "flaky" });
    const fn = vi.fn(async (url: string) => {
      if (url === A) throw new Error("flaky");
      return "ok";
    });
    expect(await transport.read(fn)).toBe("ok");
  });

  it("gives up after maxAttempts", async () => {
    const { transport } = make(undefined, { maxAttempts: 2 });
    const fn = vi.fn(async () => { throw httpError(502); });
    await expect(transport.read(fn)).rejects.toBeInstanceOf(AllEndpointsFailedError);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("only uses endpoints of the requested kind", async () => {
    const { transport } = make([{ url: A, kind: "rpc" }, { url: B, kind: "indexer" }]);
    expect(await transport.read(async (u) => u, { kind: "indexer" })).toBe(B);
    expect(await transport.read(async (u) => u)).toBe(A);
  });
});

describe("writes", () => {
  it("send to exactly one endpoint, once, and never fail over", async () => {
    const { transport } = make();
    const fn = vi.fn(async (_url: string) => { throw httpError(504); });
    await expect(transport.write(fn)).rejects.toMatchObject({ status: 504 });
    expect(fn).toHaveBeenCalledTimes(1);
    expect(fn.mock.calls[0][0]).toBe(A);
  });

  it("do not retry after a timeout", async () => {
    const { transport } = make(undefined, { timeoutMs: 10 });
    const fn = vi.fn((_url: string) => new Promise<string>(() => {}));
    await expect(transport.write(fn)).rejects.toBeInstanceOf(RequestTimeoutError);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("prefer the healthiest endpoint", async () => {
    const { transport } = make([{ url: A, weight: 1 }, { url: B, weight: 1 }], { failureThreshold: 99 });
    for (let i = 0; i < 3; i++) await transport.read(async (u) => { if (u === A) throw httpError(429); return "ok"; });
    const fn = vi.fn(async (u: string) => u);
    expect(await transport.write(fn)).toBe(B);
  });
});

describe("health scores and circuit breaking", () => {
  it("lowers the score on failure and recovers on success", async () => {
    const { transport } = make(undefined, { failureThreshold: 99 });
    await transport.read(async (u) => { if (u === A) throw httpError(502); return "ok"; });
    const low = transport.health().find((h) => h.url === A)!.score;
    expect(low).toBeLessThan(1);
    // B is now preferred only if weight*score wins; A has weight 10 so it is still tried first.
    await transport.read(async () => "ok");
    expect(transport.health().find((h) => h.url === A)!.score).toBeGreaterThan(low);
  });

  it("deprioritises a faster-failing high-weight endpoint below a healthy one", async () => {
    const { transport } = make([{ url: A, weight: 2 }, { url: B, weight: 1 }], { failureThreshold: 99 });
    const calls: string[] = [];
    const fn = async (u: string) => { calls.push(u); if (u === A) throw httpError(503); return "ok"; };
    for (let i = 0; i < 6; i++) await transport.read(fn);
    calls.length = 0;
    await transport.read(fn);
    expect(calls[0]).toBe(B); // 2 * score(A) < 1 * score(B)
  });

  it("skips an endpoint whose circuit is open, then probes it after the cooldown", async () => {
    const { transport, advance } = make(undefined, { failureThreshold: 2, cooldownMs: 1000, maxAttempts: 3 });
    const bad = async (u: string) => { if (u === A) throw httpError(503); return "ok"; };
    await transport.read(bad); await transport.read(bad); // A opens after 2 failures
    expect(transport.health().find((h) => h.url === A)!.state).toBe("down");

    const seen: string[] = [];
    await transport.read(async (u) => { seen.push(u); return "ok"; });
    expect(seen).toEqual([B]); // A skipped while open

    advance(1001);
    seen.length = 0;
    await transport.read(async (u) => { seen.push(u); return "ok"; });
    expect(seen).toEqual([A]); // probe allowed; success closes the circuit
    expect(transport.health().find((h) => h.url === A)!.state).not.toBe("down");
  });

  it("still tries endpoints when every circuit is open", async () => {
    const { transport } = make([{ url: A }], { failureThreshold: 1, maxAttempts: 1 });
    await expect(transport.read(async () => { throw httpError(503); })).rejects.toBeInstanceOf(AllEndpointsFailedError);
    expect(await transport.read(async () => "recovered")).toBe("recovered");
  });
});

describe("telemetry events", () => {
  it("emits endpoint and connection state changes", async () => {
    const { transport, events } = make([{ url: A }, { url: B }], { failureThreshold: 1, maxAttempts: 2 });
    const unsub: ResilienceEvent[] = [];
    const off = transport.on((e) => unsub.push(e));

    await transport.read(async (u) => { if (u === A) throw httpError(503); return "ok"; });
    expect(events).toContainEqual(expect.objectContaining({ type: "endpointStateChange", url: A, from: "healthy", to: "down" }));
    expect(events.find((e) => e.type === "retry")).toBeDefined();
    expect(transport.connectionState()).toBe("connected"); // B still healthy

    await expect(transport.read(async () => { throw httpError(503); })).rejects.toBeInstanceOf(AllEndpointsFailedError);
    expect(transport.connectionState()).toBe("disconnected");
    expect(events).toContainEqual({ type: "connectionStateChange", from: "connected", to: "disconnected" });

    off();
    const n = unsub.length;
    await transport.read(async () => "ok").catch(() => {});
    expect(unsub.length).toBe(n);
  });

  it("a throwing listener never breaks a request", async () => {
    const { transport } = make();
    transport.on(() => { throw new Error("boom"); });
    expect(await transport.read(async (u) => { if (u === A) throw httpError(503); return "ok"; })).toBe("ok");
  });
});

describe("configuration", () => {
  it("rejects empty, duplicate and non-positive-weight endpoints", () => {
    expect(() => new ResilientTransport([])).toThrow();
    expect(() => new ResilientTransport([{ url: A }, { url: A }])).toThrow(/Duplicate/);
    expect(() => new ResilientTransport([{ url: A, weight: 0 }])).toThrow(/weight/);
  });

  it("reports health for every endpoint", () => {
    const { transport } = make([{ url: A, weight: 3 }, { url: C, kind: "indexer" }]);
    expect(transport.health()).toEqual([
      expect.objectContaining({ url: A, kind: "rpc", weight: 3, score: 1, state: "healthy" }),
      expect.objectContaining({ url: C, kind: "indexer", weight: 1, score: 1, state: "healthy" }),
    ]);
  });
});
