// Tests for the offline test double in src/testing.ts. They exercise the mock
// the way a component test does — seed state, await the call, assert the UI
// state — and assert that no network is reached.

import { StrKey } from "@stellar/stellar-sdk";
import { describe, expect, it, vi } from "vitest";
import type { SASClient } from "../src/client.js";
import type { SASClientLike } from "../src/testing.js";
import { computeSchemaUid } from "../src/hashing.js";
import { MockSASProvider } from "../src/testing.js";
import type { Attestation, DelegatedAttestation, SchemaRecord } from "../src/types.js";

const FIXED_NOW = 1_700_000_000n;

const attester = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 0x11));
const recipient = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 0x22));
const resolver = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 0x99));

function attestation(overrides: Partial<Attestation> = {}): Attestation {
  return {
    uid: "01".repeat(32),
    schemaUid: "02".repeat(32),
    time: FIXED_NOW - 100n,
    expirationTime: 0n,
    revocationTime: 0n,
    refUid: "00".repeat(32),
    recipient,
    attester,
    revocable: true,
    data: new Uint8Array([1, 2, 3]),
    ...overrides,
  };
}

function schema(): SchemaRecord {
  return { uid: "02".repeat(32), resolver, revocable: true, schema: "bool verified" };
}

function delegated(overrides: Partial<Attestation> = {}): DelegatedAttestation {
  return {
    attestation: attestation(overrides),
    nonce: 1n,
    signature: new Uint8Array(64),
    publicKey: new Uint8Array(32),
  };
}

/** Every test gets a fixed ledger clock so expiry and revocation are deterministic. */
function provider(providerOptions: ConstructorParameters<typeof MockSASProvider>[0] = {}): MockSASProvider {
  return new MockSASProvider({ now: () => FIXED_NOW, ...providerOptions });
}

describe("MockSASProvider seeding", () => {
  it("seeds attestations, schemas, and verdicts", async () => {
    const mock = provider({
      attestations: [attestation()],
      schemas: [schema()],
      verdicts: { ["03".repeat(32)]: "expired" },
    });

    await expect(mock.getAttestation("01".repeat(32))).resolves.toEqual(attestation());
    await expect(mock.getSchema("02".repeat(32))).resolves.toEqual(schema());
    await expect(mock.verifyAttestation("01".repeat(32))).resolves.toBe("valid");
    await expect(mock.verifyAttestation("03".repeat(32))).resolves.toBe("expired");
  });

  it("answers unknown UIDs with null and an unknown verdict", async () => {
    const mock = provider();
    await expect(mock.getAttestation("ff".repeat(32))).resolves.toBeNull();
    await expect(mock.getSchema("ff".repeat(32))).resolves.toBeNull();
    await expect(mock.verifyAttestation("ff".repeat(32))).resolves.toBe("unknown");
  });

  it("hands out copies, so a caller cannot mutate the mock's state", async () => {
    const mock = provider({ attestations: [attestation()] });

    const read = await mock.getAttestation("01".repeat(32));
    read!.data[0] = 0xff;
    read!.recipient = "mutated";

    await expect(mock.getAttestation("01".repeat(32))).resolves.toEqual(attestation());
  });
});

describe("MockSASProvider attest / attestByDelegation", () => {
  it("stores an attested attestation and reports it as valid", async () => {
    const mock = provider();
    const input = attestation();

    const { hash } = await mock.attest(input);

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    await expect(mock.getAttestation(input.uid)).resolves.toEqual(input);
    await expect(mock.verifyAttestation(input.uid)).resolves.toBe("valid");
  });

  it("stores the attestation carried by a delegated submission", async () => {
    const mock = provider();
    await mock.attestByDelegation(delegated());

    await expect(mock.getAttestation("01".repeat(32))).resolves.toEqual(attestation());
    await expect(mock.verifyAttestation("01".repeat(32))).resolves.toBe("valid");
  });

  it("keeps the stored attestation independent of the caller's object", async () => {
    const mock = provider();
    const input = attestation();

    await mock.attest(input);
    input.revocationTime = 99n;

    await expect(mock.getAttestation(input.uid)).resolves.toEqual(attestation());
  });

  it("rejects a UID that already exists without overwriting it", async () => {
    const mock = provider();
    await mock.attest(attestation());

    await expect(mock.attest(attestation({ data: new Uint8Array([9]) }))).rejects.toThrow(/already exists/);
    await expect(mock.getAttestation("01".repeat(32))).resolves.toEqual(attestation());
  });
});

describe("MockSASProvider revoke", () => {
  it("stamps revocationTime from the clock and flips the verdict", async () => {
    const mock = provider({ attestations: [attestation()] });

    await mock.revoke("01".repeat(32));

    const stored = await mock.getAttestation("01".repeat(32));
    expect(stored!.revocationTime).toBe(FIXED_NOW);
    await expect(mock.verifyAttestation("01".repeat(32))).resolves.toBe("revoked");
  });

  it("rejects a second revocation", async () => {
    const mock = provider({ attestations: [attestation()] });
    await mock.revoke("01".repeat(32));

    await expect(mock.revoke("01".repeat(32))).rejects.toThrow(/already revoked/);
  });

  it("rejects revoking an unknown UID or a non-revocable attestation", async () => {
    const mock = provider({ attestations: [attestation({ uid: "04".repeat(32), revocable: false })] });

    await expect(mock.revoke("ff".repeat(32))).rejects.toThrow(/not found/);
    await expect(mock.revoke("04".repeat(32))).rejects.toThrow(/not revocable/);
  });

  it("simulateRevocation marks out-of-band revocations without recording a call", async () => {
    const mock = provider({ attestations: [attestation()] });

    mock.simulateRevocation("01".repeat(32));

    expect(mock.calls).toHaveLength(0);
    await expect(mock.getAttestation("01".repeat(32))).resolves.toMatchObject({ revocationTime: FIXED_NOW });
  });

  it("simulateRevocation rejects an unknown UID", () => {
    expect(() => provider().simulateRevocation("ff".repeat(32))).toThrow(/not found/);
  });
});

describe("MockSASProvider verifyAttestation verdicts", () => {
  it("derives the verdict from expirationTime against the injected clock", async () => {
    const mock = provider({
      attestations: [
        attestation({ uid: "0a".repeat(32), expirationTime: FIXED_NOW }),
        attestation({ uid: "0b".repeat(32), expirationTime: FIXED_NOW + 1n }),
        attestation({ uid: "0c".repeat(32), expirationTime: 0n }),
      ],
    });

    await expect(mock.verifyAttestation("0a".repeat(32))).resolves.toBe("expired");
    await expect(mock.verifyAttestation("0b".repeat(32))).resolves.toBe("valid");
    // expirationTime 0 means "never expires".
    await expect(mock.verifyAttestation("0c".repeat(32))).resolves.toBe("valid");
  });

  it("lets a seeded verdict stand in for state until that state changes", async () => {
    const mock = provider({ attestations: [attestation()] });
    mock.seedVerdict("01".repeat(32), "expired");
    await expect(mock.verifyAttestation("01".repeat(32))).resolves.toBe("expired");

    await mock.revoke("01".repeat(32));

    await expect(mock.verifyAttestation("01".repeat(32))).resolves.toBe("revoked");
  });
});

describe("MockSASProvider loading states", () => {
  it("keeps a held call pending until releaseHold", async () => {
    const mock = provider({ attestations: [attestation()] });
    mock.holdNext("getAttestation");

    let settled = false;
    const pending = mock.getAttestation("01".repeat(32)).then((value) => {
      settled = true;
      return value;
    });
    await Promise.resolve();
    expect(settled).toBe(false);

    mock.releaseHold();

    await expect(pending).resolves.toEqual(attestation());
  });

  it("holds the next call of any method when no method is named", async () => {
    const mock = provider();
    mock.holdNext();

    let settled = false;
    const pending = mock.verifyAttestation("01".repeat(32)).then((value) => {
      settled = true;
      return value;
    });
    await Promise.resolve();
    expect(settled).toBe(false);

    mock.releaseHold();
    await expect(pending).resolves.toBe("unknown");
  });

  it("delays every call by the configured latency", async () => {
    vi.useFakeTimers();
    try {
      const mock = provider({ latencyMs: 50 });
      let settled = false;
      const pending = mock.verifyAttestation("01".repeat(32)).then((value) => {
        settled = true;
        return value;
      });

      await vi.advanceTimersByTimeAsync(49);
      expect(settled).toBe(false);

      await vi.advanceTimersByTimeAsync(1);
      await expect(pending).resolves.toBe("unknown");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("MockSASProvider failures", () => {
  it("fails just the next call of the named method", async () => {
    const mock = provider({ attestations: [attestation()] });
    mock.failNext("getAttestation");

    await expect(mock.getAttestation("01".repeat(32))).rejects.toThrow(/simulated failure/);
    await expect(mock.getAttestation("01".repeat(32))).resolves.toEqual(attestation());
  });

  it("rejects with the exact error object a test supplies", async () => {
    const mock = provider();
    const boom = new Error("rpc unavailable");
    mock.failNext("verifyAttestation", boom);

    await expect(mock.verifyAttestation("01".repeat(32))).rejects.toBe(boom);
  });

  it("fails the next call of any method when no method is named", async () => {
    const mock = provider();
    mock.failNext(undefined, "offline");

    await expect(mock.getSchema("02".repeat(32))).rejects.toThrow("offline");
    await expect(mock.getSchema("02".repeat(32))).resolves.toBeNull();
  });

  it("does not apply a failed write to the mock's state", async () => {
    const mock = provider();
    mock.failNext("attest");

    await expect(mock.attest(attestation())).rejects.toThrow(/simulated failure/);
    await expect(mock.getAttestation("01".repeat(32))).resolves.toBeNull();

    await expect(mock.attest(attestation())).resolves.toMatchObject({ hash: expect.any(String) });
  });

  it("fails every call until clearNetworkFailure", async () => {
    const mock = provider({ attestations: [attestation()] });
    mock.setNetworkFailure();

    await expect(mock.getAttestation("01".repeat(32))).rejects.toThrow(/network failure/);
    await expect(mock.verifyAttestation("01".repeat(32))).rejects.toThrow(/network failure/);
    await expect(mock.attest(attestation({ uid: "05".repeat(32) }))).rejects.toThrow(/network failure/);

    mock.clearNetworkFailure();

    await expect(mock.getAttestation("01".repeat(32))).resolves.toEqual(attestation());
  });
});

describe("MockSASProvider registerSchema", () => {
  it("uses deriveSchemaUid to mint the real content-addressed UID", async () => {
    const mock = provider({ deriveSchemaUid: computeSchemaUid });

    const uid = await mock.registerSchema("bool verified", resolver, true);

    expect(uid).toBe(computeSchemaUid("bool verified", resolver, true));
    await expect(mock.getSchema(uid)).resolves.toEqual({
      uid,
      resolver,
      revocable: true,
      schema: "bool verified",
    });
  });

  it("returns the UID of a seeded schema with the same inputs", async () => {
    const mock = provider({ schemas: [schema()] });

    await expect(mock.registerSchema("bool verified", resolver, true)).resolves.toBe("02".repeat(32));
  });

  it("rejects rather than inventing a UID when nothing matches", async () => {
    const mock = provider({ schemas: [schema()] });

    await expect(mock.registerSchema("bool verified", resolver, false)).rejects.toThrow(
      /no seeded schema matches/,
    );
  });
});

describe("MockSASProvider bookkeeping", () => {
  it("records every call in order with its arguments", async () => {
    const mock = provider({ schemas: [schema()] });
    const input = attestation();

    await mock.registerSchema("bool verified", resolver, true);
    await mock.attest(input);
    await mock.revoke(input.uid);
    await mock.verifyAttestation(input.uid);

    expect(mock.calls.map((call) => call.method)).toEqual([
      "registerSchema",
      "attest",
      "revoke",
      "verifyAttestation",
    ]);
    expect(mock.calls[0].args).toEqual(["bool verified", resolver, true]);
    expect(mock.calls[1].args[0]).toBe(input);
  });

  it("reset clears state, calls, failures, holds, and latency", async () => {
    const mock = provider({ attestations: [attestation()], latencyMs: 10 });
    mock.failNext("getSchema");
    await expect(mock.getSchema("02".repeat(32))).rejects.toThrow();

    mock.reset();

    expect(mock.calls).toHaveLength(0);
    await expect(mock.getAttestation("01".repeat(32))).resolves.toBeNull();
    await expect(mock.getSchema("02".repeat(32))).resolves.toBeNull();
    await expect(mock.attest(attestation())).resolves.toMatchObject({ hash: expect.any(String) });
  });

  it("releases held calls on reset so a pending component test cannot hang", async () => {
    const mock = provider();
    mock.holdNext();
    const pending = mock.getAttestation("01".repeat(32));

    mock.reset();

    await expect(pending).resolves.toBeNull();
  });
});

describe("MockSASProvider packaging", () => {
  it("is not reachable from the package root, so app bundles never include it", async () => {
    const root = await import("../src/index.js");
    expect("MockSASProvider" in root).toBe(false);
  });

  it("never touches the network", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const mock = provider({ attestations: [attestation()], schemas: [schema()] });

    await mock.getAttestation("01".repeat(32));
    await mock.verifyAttestation("01".repeat(32));
    await mock.attest(attestation({ uid: "06".repeat(32) }));
    await mock.revoke("06".repeat(32));
    await mock.registerSchema("bool verified", resolver, true);
    mock.setNetworkFailure();
    await expect(mock.getAttestation("01".repeat(32))).rejects.toThrow();

    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });

  it("is a structural stand-in for the real client", () => {
    const realClient: SASClientLike = undefined as unknown as SASClient;
    expect(realClient).toBeUndefined();
  });
});
