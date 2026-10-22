import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import {
  SASProvider,
  useAttestation,
  useAttestationsByRecipient,
  useSchema,
} from "../src/index.js";
import type {
  Attestation,
  SASClientLike,
  SchemaRecord,
} from "../src/types.js";

const SAMPLE_UID = "11".repeat(32);
const SAMPLE_UID_2 = "22".repeat(32);
const SAMPLE_SCHEMA_UID = "aa".repeat(32);
const ZERO_UID = "00".repeat(32);
const RECIPIENT = "GALICE55555555555555555555555555555555555555555555555555";
const ATTESTER = "GISSUER9999999999999999999999999999999999999999999999999";
const RESOLVER = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

function makeAttestation(overrides: Partial<Attestation> = {}): Attestation {
  return {
    uid: SAMPLE_UID,
    schemaUid: SAMPLE_SCHEMA_UID,
    time: 1_700_000_000n,
    expirationTime: 1_800_000_000n,
    revocationTime: 0n,
    refUid: ZERO_UID,
    recipient: RECIPIENT,
    attester: ATTESTER,
    revocable: true,
    data: new Uint8Array([1, 2, 3, 4]),
    ...overrides,
  };
}

function makeSchema(overrides: Partial<SchemaRecord> = {}): SchemaRecord {
  return {
    uid: SAMPLE_SCHEMA_UID,
    resolver: RESOLVER,
    revocable: true,
    schema: "verified bool, score u32",
    deprecated: false,
    ...overrides,
  };
}

function createWrapper(client: SASClientLike, account: string | null = RECIPIENT) {
  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <SASProvider network="testnet" account={account} client={client}>
        {children}
      </SASProvider>
    );
  };
}

describe("useAttestation", () => {
  it("provides intuitive isLoading, data, and error=null states on success", async () => {
    const attestation = makeAttestation();
    let resolvePromise!: (val: Attestation | null) => void;
    const client: SASClientLike = {
      getAttestation: vi.fn(
        () =>
          new Promise<Attestation | null>((resolve) => {
            resolvePromise = resolve;
          }),
      ),
      getSchema: vi.fn(),
    };

    const { result } = renderHook(() => useAttestation(SAMPLE_UID), {
      wrapper: createWrapper(client),
    });

    // Initial loading state
    expect(result.current.isLoading).toBe(true);
    expect(result.current.data).toBeUndefined();
    expect(result.current.attestation).toBeUndefined();
    expect(result.current.error).toBeNull();

    // Resolve the RPC call
    act(() => {
      resolvePromise(attestation);
    });

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.data).toEqual(attestation);
    expect(result.current.attestation).toEqual(attestation);
    expect(result.current.error).toBeNull();
    expect(client.getAttestation).toHaveBeenCalledTimes(1);
    expect(client.getAttestation).toHaveBeenCalledWith(SAMPLE_UID);
  });

  it("normalizes 0x-prefixed uppercase UIDs and deduplicates cached queries", async () => {
    const attestation = makeAttestation({ uid: "ab".repeat(32) });
    const client: SASClientLike = {
      getAttestation: vi.fn().mockResolvedValue(attestation),
      getSchema: vi.fn(),
    };

    const wrapper = createWrapper(client);
    const { result } = renderHook(
      () => ({
        first: useAttestation(`0x${"AB".repeat(32)}`),
        second: useAttestation("ab".repeat(32)),
      }),
      { wrapper },
    );

    await waitFor(() => {
      expect(result.current.first.isLoading).toBe(false);
      expect(result.current.second.isLoading).toBe(false);
    });

    expect(result.current.first.data).toEqual(attestation);
    expect(result.current.second.data).toEqual(attestation);
    // Deduplicated by TanStack Query cache!
    expect(client.getAttestation).toHaveBeenCalledTimes(1);
    expect(client.getAttestation).toHaveBeenCalledWith("ab".repeat(32));
  });

  it("surfaces error state when getAttestation rejects", async () => {
    const client: SASClientLike = {
      getAttestation: vi.fn().mockRejectedValue(new Error("RPC node unreachable")),
      getSchema: vi.fn(),
    };

    const { result } = renderHook(() => useAttestation(SAMPLE_UID), {
      wrapper: createWrapper(client),
    });

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.isError).toBe(true);
    expect(result.current.error?.message).toBe("RPC node unreachable");
    expect(result.current.data).toBeUndefined();
  });

  it("does not fetch when uid is null, undefined, or empty", () => {
    const client: SASClientLike = {
      getAttestation: vi.fn(),
      getSchema: vi.fn(),
    };

    const { result: r1 } = renderHook(() => useAttestation(null), {
      wrapper: createWrapper(client),
    });
    const { result: r2 } = renderHook(() => useAttestation(""), {
      wrapper: createWrapper(client),
    });

    expect(r1.current.isLoading).toBe(false);
    expect(r2.current.isLoading).toBe(false);
    expect(client.getAttestation).not.toHaveBeenCalled();
  });

  it("re-fetches when invalidate() is called on the hook result", async () => {
    const att1 = makeAttestation({ revocationTime: 0n });
    const att2 = makeAttestation({ revocationTime: 1_750_000_000n });
    const client: SASClientLike = {
      getAttestation: vi
        .fn()
        .mockResolvedValueOnce(att1)
        .mockResolvedValueOnce(att2),
      getSchema: vi.fn(),
    };

    const { result } = renderHook(() => useAttestation(SAMPLE_UID), {
      wrapper: createWrapper(client),
    });

    await waitFor(() => {
      expect(result.current.data?.revocationTime).toBe(0n);
    });

    await act(async () => {
      await result.current.invalidate();
    });

    await waitFor(() => {
      expect(result.current.data?.revocationTime).toBe(1_750_000_000n);
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(2);
  });
});

describe("useSchema", () => {
  it("provides intuitive isLoading, data, and error states", async () => {
    const schema = makeSchema();
    const client: SASClientLike = {
      getAttestation: vi.fn(),
      getSchema: vi.fn().mockResolvedValue(schema),
    };

    const { result } = renderHook(() => useSchema(SAMPLE_SCHEMA_UID), {
      wrapper: createWrapper(client),
    });

    expect(result.current.isLoading).toBe(true);

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.data).toEqual(schema);
    expect(result.current.schema).toEqual(schema);
    expect(result.current.error).toBeNull();
  });

  it("handles missing schema (null) and error states", async () => {
    const client: SASClientLike = {
      getAttestation: vi.fn(),
      getSchema: vi
        .fn()
        .mockResolvedValueOnce(null)
        .mockRejectedValueOnce(new Error("Registry contract error")),
    };

    const { result } = renderHook(() => useSchema(SAMPLE_SCHEMA_UID), {
      wrapper: createWrapper(client),
    });

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });
    expect(result.current.data).toBeNull();

    await act(async () => {
      await result.current.invalidate();
    });

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });
    expect(result.current.error?.message).toBe("Registry contract error");
  });

  it("stays idle when schemaUid is empty or disabled", () => {
    const client: SASClientLike = {
      getAttestation: vi.fn(),
      getSchema: vi.fn(),
    };

    const { result } = renderHook(
      () => useSchema(SAMPLE_SCHEMA_UID, { enabled: false }),
      { wrapper: createWrapper(client) },
    );

    expect(result.current.isLoading).toBe(false);
    expect(client.getSchema).not.toHaveBeenCalled();
  });
});

describe("useAttestationsByRecipient", () => {
  it("fetches and returns recipient attestations with intuitive states", async () => {
    const list = [
      makeAttestation({ uid: SAMPLE_UID }),
      makeAttestation({ uid: SAMPLE_UID_2 }),
    ];
    const client: SASClientLike = {
      getAttestation: vi.fn(),
      getSchema: vi.fn(),
      getAttestationsByRecipient: vi.fn().mockResolvedValue(list),
    };

    const { result } = renderHook(() => useAttestationsByRecipient(RECIPIENT), {
      wrapper: createWrapper(client),
    });

    expect(result.current.isLoading).toBe(true);
    expect(result.current.attestations).toEqual([]);

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.data).toEqual(list);
    expect(result.current.attestations).toEqual(list);
    expect(result.current.error).toBeNull();
  });

  it("resolves UIDs via getAttestation when client returns UID[] or implements getAttestationUidsByRecipient", async () => {
    const att1 = makeAttestation({ uid: SAMPLE_UID });
    const att2 = makeAttestation({ uid: SAMPLE_UID_2 });

    const clientWithUidsReturn: SASClientLike = {
      getAttestation: vi.fn(async (uid: string) =>
        uid === SAMPLE_UID ? att1 : uid === SAMPLE_UID_2 ? att2 : null,
      ),
      getSchema: vi.fn(),
      getAttestationsByRecipient: vi.fn().mockResolvedValue([SAMPLE_UID, SAMPLE_UID_2]),
    };

    const { result: r1 } = renderHook(
      () => useAttestationsByRecipient(RECIPIENT),
      { wrapper: createWrapper(clientWithUidsReturn) },
    );

    await waitFor(() => {
      expect(r1.current.isLoading).toBe(false);
    });
    expect(r1.current.data).toEqual([att1, att2]);

    const clientWithUidsMethodOnly: SASClientLike = {
      getAttestation: vi.fn(async (uid: string) =>
        uid === SAMPLE_UID ? att1 : null,
      ),
      getSchema: vi.fn(),
      getAttestationUidsByRecipient: vi.fn().mockResolvedValue([SAMPLE_UID]),
    };

    const { result: r2 } = renderHook(
      () => useAttestationsByRecipient(RECIPIENT),
      { wrapper: createWrapper(clientWithUidsMethodOnly) },
    );

    await waitFor(() => {
      expect(r2.current.isLoading).toBe(false);
    });
    expect(r2.current.data).toEqual([att1]);
  });

  it("surfaces error if client implements neither recipient query method", async () => {
    const client: SASClientLike = {
      getAttestation: vi.fn(),
      getSchema: vi.fn(),
    };

    const { result } = renderHook(() => useAttestationsByRecipient(RECIPIENT), {
      wrapper: createWrapper(client),
    });

    await waitFor(() => {
      expect(result.current.isError).toBe(true);
    });

    expect(result.current.error?.message).toMatch(
      /does not implement getAttestationsByRecipient/,
    );
  });

  it("re-fetches when invalidate() is called", async () => {
    const att1 = makeAttestation({ uid: SAMPLE_UID });
    const att2 = makeAttestation({ uid: SAMPLE_UID_2 });
    const client: SASClientLike = {
      getAttestation: vi.fn(),
      getSchema: vi.fn(),
      getAttestationsByRecipient: vi
        .fn()
        .mockResolvedValueOnce([att1])
        .mockResolvedValueOnce([att1, att2]),
    };

    const { result } = renderHook(() => useAttestationsByRecipient(RECIPIENT), {
      wrapper: createWrapper(client),
    });

    await waitFor(() => {
      expect(result.current.attestations).toHaveLength(1);
    });

    await act(async () => {
      await result.current.invalidate();
    });

    await waitFor(() => {
      expect(result.current.attestations).toHaveLength(2);
    });
  });
});
