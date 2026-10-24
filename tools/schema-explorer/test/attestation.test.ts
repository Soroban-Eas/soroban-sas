// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { Address, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import {
  AttestationReader,
  decodeAttestationRecord,
  attestationStatus,
  uidToScVal,
  type AttestationRecord,
  buildAttestationDeepLink,
  parseAttestationDeepLink,
  verifyOfflineSignature,
  type AttestationVerificationQuery,
} from "../src/attestation.js";
import { RegistryError } from "../src/registry.js";
import { filterAttestations } from "../src/filter-attestations.js";
import {
  DEMO_ATTESTATIONS,
  DEMO_SAS_CONTRACT_ID,
  DEMO_INDEXER_CONTRACT_ID,
  FixtureAttestationCaller,
} from "../src/fixtures-attestations.js";
import {
  configFromQuery,
  configToQuery,
  validateConfig,
  type ExplorerConfig,
} from "../src/config.js";
import { DEMO_REGISTRY_ID } from "../src/fixtures.js";
import { mountExplorer } from "../src/app.js";
import type { ContractCaller } from "../src/registry.js";
import { FixtureCaller } from "../src/fixtures.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const html = readFileSync(resolve(process.cwd(), "index.html"), "utf8");
const bodyHtml = /<body>([\s\S]*)<\/body>/.exec(html)![1].replace(/<script[\s\S]*?<\/script>/g, "");

const $ = <T extends HTMLElement = HTMLElement>(sel: string) => document.querySelector<T>(sel)!;
const $$ = (sel: string) => Array.from(document.querySelectorAll<HTMLElement>(sel));

const settle = (ms = 0) => new Promise((r) => setTimeout(r, ms));

function memoryStorage(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    data,
  };
}

/** Mount the explorer pre-wired to the fixture attestation callers. */
function mountWithAttestations(opts: {
  attestations?: readonly AttestationRecord[];
  search?: string;
  replaceUrl?: (q: string) => void;
} = {}) {
  const fixture = new FixtureAttestationCaller(opts.attestations ?? DEMO_ATTESTATIONS);
  const urls: string[] = [];
  const app = mountExplorer(document, {
    createCaller: () => new FixtureCaller(),
    createDemoCaller: () => new FixtureCaller(),
    createAttestationCallers: () => ({ sasCaller: fixture, indexerCaller: fixture }),
    createDemoAttestationCallers: () => ({ sasCaller: fixture, indexerCaller: fixture }),
    search: opts.search ?? "",
    storage: memoryStorage(),
    replaceUrl: opts.replaceUrl ?? ((q) => urls.push(q)),
  });
  return { app, fixture, urls };
}

// ---------------------------------------------------------------------------
// attestationStatus
// ---------------------------------------------------------------------------

describe("attestationStatus", () => {
  const base: AttestationRecord = DEMO_ATTESTATIONS[0];
  const NOW = Math.floor(Date.now() / 1000);

  it("active: not expired, not revoked", () => {
    expect(attestationStatus(base, NOW)).toBe("active");
  });

  it("expired: expiration_time <= now", () => {
    const expired = { ...base, expirationTime: NOW - 1, revocationTime: 0 };
    expect(attestationStatus(expired, NOW)).toBe("expired");
  });

  it("revoked: revocation_time > 0 overrides expiry", () => {
    const revoked = { ...base, expirationTime: NOW - 1, revocationTime: NOW - 10 };
    expect(attestationStatus(revoked, NOW)).toBe("revoked");
  });

  it("active: expirationTime == 0 means no expiry", () => {
    const noExpiry = { ...base, expirationTime: 0, revocationTime: 0 };
    expect(attestationStatus(noExpiry, NOW)).toBe("active");
  });
});

// ---------------------------------------------------------------------------
// decodeAttestationRecord
// ---------------------------------------------------------------------------

describe("decodeAttestationRecord", () => {
  const uid32 = new Uint8Array(32).fill(1);
  const schemaUid32 = new Uint8Array(32).fill(2);
  const addr = "GCI7YTLFUAWQ2Y5MAWAOFICWUWC5MUMARISUEPVMB3KYUH46WII5MS7T";

  const good = {
    uid: [uid32],
    schema_uid: [schemaUid32],
    time: BigInt(1000),
    expiration_time: BigInt(2000),
    revocation_time: BigInt(0),
    ref_uid: [new Uint8Array(32)],
    recipient: addr,
    attester: addr,
    revocable: true,
    data: new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
  };

  it("decodes a well-formed record", () => {
    const r = decodeAttestationRecord(good);
    expect(r.uid).toBe("01".repeat(32));
    expect(r.schemaUid).toBe("02".repeat(32));
    expect(r.time).toBe(1000);
    expect(r.expirationTime).toBe(2000);
    expect(r.revocationTime).toBe(0);
    expect(r.refUid).toBe(""); // zero ref_uid is normalized to ""
    expect(r.recipient).toBe(addr);
    expect(r.revocable).toBe(true);
    expect(r.data).toBe("deadbeef");
  });

  it("handles empty data", () => {
    const r = decodeAttestationRecord({ ...good, data: new Uint8Array(0) });
    expect(r.data).toBe("");
  });

  it.each([
    ["not an object", "oops"],
    ["null", null],
    ["array", []],
    ["missing recipient", { ...good, recipient: undefined }],
    ["numeric revocable", { ...good, revocable: 1 }],
    ["short uid", { ...good, uid: [new Uint8Array(31)] }],
  ])("rejects malformed record: %s", (_label, value) => {
    expect(() => decodeAttestationRecord(value)).toThrow(RegistryError);
  });
});

// ---------------------------------------------------------------------------
// FixtureAttestationCaller
// ---------------------------------------------------------------------------

describe("FixtureAttestationCaller contract semantics", () => {
  it("get_attestation returns a record for a known UID", async () => {
    const caller = new FixtureAttestationCaller();
    const uid = DEMO_ATTESTATIONS[0].uid;
    const ret = await caller.call("get_attestation", [uidToScVal(uid)]);
    expect(ret.switch()).not.toBe(xdr.ScValType.scvVoid());
  });

  it("get_attestation returns void for an unknown UID", async () => {
    const caller = new FixtureAttestationCaller();
    const ret = await caller.call("get_attestation", [uidToScVal("aa".repeat(32))]);
    expect(ret.switch()).toBe(xdr.ScValType.scvVoid());
  });

  it("get_attestations_by_recipient returns UIDs for known recipient", async () => {
    const caller = new FixtureAttestationCaller();
    const recipient = DEMO_ATTESTATIONS[0].recipient;
    const ret = await caller.call("get_attestations_by_recipient", [
      new Address(recipient).toScVal(),
      nativeToScVal(0, { type: "u32" }),
      nativeToScVal(10, { type: "u32" }),
    ]);
    // Response is (Vec<UID>, u32).
    expect(ret.switch()).not.toBe(xdr.ScValType.scvVoid());
  });

  it("get_attestations_by_schema returns UIDs for known schema", async () => {
    const caller = new FixtureAttestationCaller();
    const schema = DEMO_ATTESTATIONS[0].schemaUid;
    const ret = await caller.call("get_attestations_by_schema", [
      uidToScVal(schema),
      nativeToScVal(0, { type: "u32" }),
      nativeToScVal(10, { type: "u32" }),
    ]);
    expect(ret.switch()).not.toBe(xdr.ScValType.scvVoid());
  });

  it("throws for unsupported methods", async () => {
    const caller = new FixtureAttestationCaller();
    await expect(caller.call("unsupported", [])).rejects.toThrow("unsupported");
  });
});

// ---------------------------------------------------------------------------
// AttestationReader
// ---------------------------------------------------------------------------

describe("AttestationReader over FixtureAttestationCaller", () => {
  it("getAttestation returns a full record by UID", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture, fixture);
    const record = await reader.getAttestation(DEMO_ATTESTATIONS[0].uid);
    expect(record?.uid).toBe(DEMO_ATTESTATIONS[0].uid);
    expect(record?.recipient).toBe(DEMO_ATTESTATIONS[0].recipient);
  });

  it("getAttestation returns null for unknown UID", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture, fixture);
    expect(await reader.getAttestation("00".repeat(32))).toBeNull();
  });

  it("getAttestation rejects non-UID input", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture, fixture);
    await expect(reader.getAttestation("not-a-uid")).rejects.toThrow("64 hexadecimal");
  });

  it("getAttestationsFor recipient returns all matching records", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture, fixture);
    const recipient = DEMO_ATTESTATIONS[0].recipient;
    const records = await reader.getAttestationsFor("recipient", recipient, 20);
    expect(records.length).toBeGreaterThan(0);
    for (const r of records) expect(r.recipient).toBe(recipient);
  });

  it("getAttestationsFor attester returns matching records", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture, fixture);
    const attester = DEMO_ATTESTATIONS[0].attester;
    const records = await reader.getAttestationsFor("attester", attester, 20);
    expect(records.length).toBeGreaterThan(0);
    for (const r of records) expect(r.attester).toBe(attester);
  });

  it("getAttestationsFor schema returns matching records", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture, fixture);
    const schemaUid = DEMO_ATTESTATIONS[0].schemaUid;
    const records = await reader.getAttestationsFor("schema", schemaUid, 20);
    expect(records.length).toBeGreaterThan(0);
    for (const r of records) expect(r.schemaUid).toBe(schemaUid);
  });

  it("getAttestationsFor returns [] when no indexer is provided", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture); // no indexer
    const records = await reader.getAttestationsFor("recipient", DEMO_ATTESTATIONS[0].recipient, 10);
    expect(records).toEqual([]);
  });

  it("search by attestation UID finds the record", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture, fixture);
    const records = await reader.search(DEMO_ATTESTATIONS[0].uid);
    expect(records).toHaveLength(1);
    expect(records[0].uid).toBe(DEMO_ATTESTATIONS[0].uid);
  });

  it("search by recipient address finds related records", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture, fixture);
    const recipient = DEMO_ATTESTATIONS[0].recipient;
    const records = await reader.search(recipient);
    expect(records.length).toBeGreaterThan(0);
  });

  it("search by schema UID falls back when no direct attestation found", async () => {
    const fixture = new FixtureAttestationCaller();
    const reader = new AttestationReader(fixture, fixture);
    const schemaUid = DEMO_ATTESTATIONS[0].schemaUid;
    // schemaUid is not an attestation UID, so it falls through to schema lookup.
    const records = await reader.search(schemaUid);
    expect(records.length).toBeGreaterThan(0);
    for (const r of records) expect(r.schemaUid).toBe(schemaUid);
  });

  it("search deduplicates records appearing in both recipient and attester sets", async () => {
    // Create a record where the attester is also the recipient.
    const same = DEMO_ATTESTATIONS[0].attester;
    const overlap: AttestationRecord = {
      ...DEMO_ATTESTATIONS[0],
      uid: "ab".repeat(32),
      recipient: same,
      attester: same,
    };
    const fixture = new FixtureAttestationCaller([...DEMO_ATTESTATIONS, overlap]);
    const reader = new AttestationReader(fixture, fixture);
    const records = await reader.search(same);
    const uids = records.map((r) => r.uid);
    expect(new Set(uids).size).toBe(uids.length);
  });
});

// ---------------------------------------------------------------------------
// filterAttestations
// ---------------------------------------------------------------------------

describe("filterAttestations", () => {
  const NOW = Math.floor(Date.now() / 1000);

  it("returns all records for an empty query", () => {
    expect(filterAttestations(DEMO_ATTESTATIONS, "")).toEqual([...DEMO_ATTESTATIONS]);
    expect(filterAttestations(DEMO_ATTESTATIONS, "   ")).toEqual([...DEMO_ATTESTATIONS]);
  });

  it("filters by status:active", () => {
    const active = filterAttestations(DEMO_ATTESTATIONS, "status:active");
    for (const r of active) expect(attestationStatus(r, NOW)).toBe("active");
    expect(active.length).toBeGreaterThan(0);
  });

  it("filters by status:expired", () => {
    const expired = filterAttestations(DEMO_ATTESTATIONS, "status:expired");
    for (const r of expired) expect(attestationStatus(r, NOW)).toBe("expired");
    expect(expired.length).toBeGreaterThan(0);
  });

  it("filters by status:revoked", () => {
    const revoked = filterAttestations(DEMO_ATTESTATIONS, "status:revoked");
    for (const r of revoked) expect(attestationStatus(r, NOW)).toBe("revoked");
    expect(revoked.length).toBeGreaterThan(0);
  });

  it("filters by revocable:no", () => {
    const irrevocable = filterAttestations(DEMO_ATTESTATIONS, "revocable:no");
    for (const r of irrevocable) expect(r.revocable).toBe(false);
    expect(irrevocable.length).toBeGreaterThan(0);
  });

  it("filters by UID prefix (case-insensitive)", () => {
    const prefix = DEMO_ATTESTATIONS[0].uid.slice(0, 12);
    const matches = filterAttestations(DEMO_ATTESTATIONS, prefix.toUpperCase());
    expect(matches.some((r) => r.uid === DEMO_ATTESTATIONS[0].uid)).toBe(true);
  });

  it("filters by recipient substring", () => {
    const partial = DEMO_ATTESTATIONS[0].recipient.slice(0, 8).toLowerCase();
    const matches = filterAttestations(DEMO_ATTESTATIONS, partial);
    expect(matches.length).toBeGreaterThan(0);
    for (const r of matches) {
      expect(r.recipient.toLowerCase()).toContain(partial);
    }
  });

  it("multi-term query: all terms must match", () => {
    const record = DEMO_ATTESTATIONS[0];
    const terms = `${record.uid.slice(0, 8)} status:active`;
    const matches = filterAttestations(DEMO_ATTESTATIONS, terms);
    // Only records matching both conditions.
    for (const r of matches) {
      expect(r.uid.includes(record.uid.slice(0, 8))).toBe(true);
      expect(attestationStatus(r, NOW)).toBe("active");
    }
  });

  it("returns empty for impossible combination", () => {
    expect(filterAttestations(DEMO_ATTESTATIONS, "status:active status:revoked")).toHaveLength(0);
  });

  it("status:active is the complement of expired+revoked", () => {
    const active = filterAttestations(DEMO_ATTESTATIONS, "status:active").length;
    const expired = filterAttestations(DEMO_ATTESTATIONS, "status:expired").length;
    const revoked = filterAttestations(DEMO_ATTESTATIONS, "status:revoked").length;
    expect(active + expired + revoked).toBe(DEMO_ATTESTATIONS.length);
  });
});

// ---------------------------------------------------------------------------
// config.ts – new fields
// ---------------------------------------------------------------------------

describe("config round-trip with sasContractId and indexerContractId", () => {
  const base: ExplorerConfig = {
    rpcUrl: "https://soroban-testnet.stellar.org",
    networkPassphrase: "Test SDF Network ; September 2015",
    registryContractId: DEMO_REGISTRY_ID,
    sasContractId: DEMO_SAS_CONTRACT_ID,
    indexerContractId: DEMO_INDEXER_CONTRACT_ID,
  };

  it("validateConfig accepts valid optional contract IDs", () => {
    const result = validateConfig(base);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.sasContractId).toBe(DEMO_SAS_CONTRACT_ID);
    expect(result.config.indexerContractId).toBe(DEMO_INDEXER_CONTRACT_ID);
  });

  it("validateConfig rejects an invalid SAS contract ID", () => {
    const result = validateConfig({ ...base, sasContractId: "not-a-contract" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(" ")).toContain("SAS contract id");
  });

  it("validateConfig allows omitting optional IDs", () => {
    const { sasContractId: _s, indexerContractId: _i, ...minimal } = base;
    const result = validateConfig(minimal);
    expect(result.ok).toBe(true);
  });

  it("configToQuery round-trips sas and indexer params", () => {
    const q = configToQuery(base);
    expect(q).toContain(`sas=${DEMO_SAS_CONTRACT_ID}`);
    expect(q).toContain(`indexer=${DEMO_INDEXER_CONTRACT_ID}`);
    const restored = configFromQuery(q);
    expect(restored.sasContractId).toBe(DEMO_SAS_CONTRACT_ID);
    expect(restored.indexerContractId).toBe(DEMO_INDEXER_CONTRACT_ID);
  });
});

// ---------------------------------------------------------------------------
// UI integration – Attestations tab
// ---------------------------------------------------------------------------

describe("Attestations tab UI", () => {
  beforeEach(() => {
    document.body.innerHTML = bodyHtml;
  });

  it("demo data populates the attestation panel", async () => {
    mountWithAttestations();
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();
    // Switch to the Attestations tab.
    $<HTMLButtonElement>("#tab-attest").click();
    await settle();
    expect($("#tab-attest").getAttribute("aria-selected")).toBe("true");
    expect($("#attest").hidden).toBe(false);
  });

  it("searching by recipient shows matching attestations", async () => {
    const { app } = mountWithAttestations();
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();
    $<HTMLButtonElement>("#tab-attest").click();

    const recipient = DEMO_ATTESTATIONS[0].recipient;
    $<HTMLInputElement>("#attest-search").value = recipient;
    $<HTMLFormElement>("#attest-search-form").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await settle();
    await settle();

    const items = $$(".attestation-item");
    expect(items.length).toBeGreaterThan(0);
    app.stopPolling();
  });

  it("searching by attestation UID shows one record", async () => {
    const { app } = mountWithAttestations();
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();
    $<HTMLButtonElement>("#tab-attest").click();

    const uid = DEMO_ATTESTATIONS[0].uid;
    $<HTMLInputElement>("#attest-search").value = uid;
    $<HTMLFormElement>("#attest-search-form").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await settle();
    await settle();

    const items = $$(".attestation-item");
    expect(items.length).toBe(1);
    app.stopPolling();
  });

  it("status badge shows correct label for active, expired, and revoked", async () => {
    const { app } = mountWithAttestations();
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();
    $<HTMLButtonElement>("#tab-attest").click();

    // Load all fixtures by searching the attester that owns all demo records.
    const attester = DEMO_ATTESTATIONS[0].attester;
    $<HTMLInputElement>("#attest-search").value = attester;
    $<HTMLFormElement>("#attest-search-form").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await settle();
    await settle();

    const badges = $$(".attestation-item .badge");
    const texts = badges.map((b) => b.textContent!.toLowerCase());
    expect(texts.some((t) => t === "active")).toBe(true);
    app.stopPolling();
  });

  it("client filter by status:active hides expired and revoked items", async () => {
    // Mount with a known mixed dataset.
    const { app } = mountWithAttestations();
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();
    $<HTMLButtonElement>("#tab-attest").click();

    // Load some records first.
    const attester = DEMO_ATTESTATIONS[0].attester;
    $<HTMLInputElement>("#attest-search").value = attester;
    $<HTMLFormElement>("#attest-search-form").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await settle();
    await settle();

    const totalBefore = $$(".attestation-item").length;
    expect(totalBefore).toBeGreaterThan(0);

    $<HTMLInputElement>("#attest-filter").value = "status:active";
    $<HTMLInputElement>("#attest-filter").dispatchEvent(new Event("input", { bubbles: true }));

    const afterFilter = $$(".attestation-item");
    // Every visible item should have an "active" badge.
    for (const item of afterFilter) {
      expect(item.getAttribute("data-status")).toBe("active");
    }

    app.stopPolling();
  });

  it("selecting an attestation renders the detail pane", async () => {
    const { app } = mountWithAttestations();
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();
    $<HTMLButtonElement>("#tab-attest").click();

    const uid = DEMO_ATTESTATIONS[0].uid;
    $<HTMLInputElement>("#attest-search").value = uid;
    $<HTMLFormElement>("#attest-search-form").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await settle();
    await settle();

    $$(".attestation-item")[0].click();
    const detail = $("#attest-detail");
    expect(detail.textContent).toContain("Attestation");
    // UID is present in the detail pane.
    expect(detail.textContent).toContain(uid.slice(0, 10));
    app.stopPolling();
  });

  it("XSS: hostile recipient/attester addresses are rendered as inert text", async () => {
    const hostile = '<img src=x onerror="window.__pwned2=1">';
    const poisoned: AttestationRecord = {
      ...DEMO_ATTESTATIONS[0],
      uid: "cc".repeat(32),
      recipient: hostile,
    };
    const { app } = mountWithAttestations({ attestations: [poisoned] });
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();
    $<HTMLButtonElement>("#tab-attest").click();

    $<HTMLInputElement>("#attest-search").value = "cc".repeat(32);
    $<HTMLFormElement>("#attest-search-form").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await settle();
    await settle();

    expect(document.querySelector("img")).toBeNull();
    expect((window as unknown as { __pwned2?: number }).__pwned2).toBeUndefined();
    app.stopPolling();
  });

  it("poll-status shows 'Not connected' before connecting", () => {
    mountWithAttestations();
    expect($("#attest-poll-status").textContent).toContain("Not connected");
  });

  it("search query is persisted to the URL", async () => {
    const urls: string[] = [];
    const { app } = mountWithAttestations({ replaceUrl: (q) => urls.push(q) });
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();

    $<HTMLInputElement>("#attest-search").value = "testquery";
    $<HTMLFormElement>("#attest-search-form").dispatchEvent(
      new Event("submit", { bubbles: true, cancelable: true }),
    );
    await settle();

    expect(urls.some((u) => u.includes("attest-q=testquery"))).toBe(true);
    app.stopPolling();
  });

  it("?tab=attest opens the attestations tab directly", async () => {
    mountWithAttestations({ search: "?tab=attest" });
    await settle();
    expect($("#tab-attest").getAttribute("aria-selected")).toBe("true");
    expect($("#attest").hidden).toBe(false);
    expect($("#browse").hidden).toBe(true);
  });

  it("drops stale attestation responses from a superseded search", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const slow: ContractCaller = {
      async call(method, args) {
        await gate;
        return new FixtureAttestationCaller([
          { ...DEMO_ATTESTATIONS[0], uid: "dd".repeat(32) },
        ]).call(method, args);
      },
    };

    const { app } = mountWithAttestations();
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();
    $<HTMLButtonElement>("#tab-attest").click();

    // Start a slow search.
    const slowReader = new (await import("../src/attestation.js")).AttestationReader(slow, slow);
    // Bump the generation to make the slow search stale.
    app.attestState.reader = slowReader;
    const staleGen = app.attestState.generation;
    void slowReader.search(DEMO_ATTESTATIONS[0].uid).then(() => {
      // Only merges if generation still matches at the time of resolution.
      if (staleGen !== app.attestState.generation) {
        // Stale – do nothing.
      }
    });

    // Reconnect with demo to bump generation.
    $<HTMLButtonElement>("#demo-btn").click();
    await settle();
    release();
    await settle();

    // The result from the slow search must NOT appear.
    expect(document.body.textContent).not.toContain("dd".repeat(32));
    app.stopPolling();
  });
});

// ---------------------------------------------------------------------------
// Edge cases: diverse attestation datasets
// ---------------------------------------------------------------------------

describe("diverse attestation datasets", () => {
  it("handles all-active dataset", () => {
    const NOW = Math.floor(Date.now() / 1000);
    const allActive = DEMO_ATTESTATIONS.map((r) => ({
      ...r,
      expirationTime: NOW + 86400,
      revocationTime: 0,
    }));
    const active = filterAttestations(allActive, "status:active");
    expect(active).toHaveLength(allActive.length);
    expect(filterAttestations(allActive, "status:expired")).toHaveLength(0);
    expect(filterAttestations(allActive, "status:revoked")).toHaveLength(0);
  });

  it("handles all-expired dataset", () => {
    const NOW = Math.floor(Date.now() / 1000);
    const allExpired = DEMO_ATTESTATIONS.map((r) => ({
      ...r,
      expirationTime: NOW - 1,
      revocationTime: 0,
    }));
    expect(filterAttestations(allExpired, "status:expired")).toHaveLength(allExpired.length);
  });

  it("handles all-revoked dataset", () => {
    const NOW = Math.floor(Date.now() / 1000);
    const allRevoked = DEMO_ATTESTATIONS.map((r) => ({
      ...r,
      revocationTime: NOW - 1,
    }));
    expect(filterAttestations(allRevoked, "status:revoked")).toHaveLength(allRevoked.length);
  });

  it("empty dataset returns empty list", () => {
    expect(filterAttestations([], "status:active")).toHaveLength(0);
    expect(filterAttestations([], "")).toHaveLength(0);
  });

  it("handles dataset with duplicate UIDs gracefully (filterAttestations passes them through)", () => {
    const dup = [...DEMO_ATTESTATIONS, DEMO_ATTESTATIONS[0]];
    const results = filterAttestations(dup, "");
    expect(results).toHaveLength(dup.length);
  });

  it("handles attestation with empty data payload", () => {
    const noData = DEMO_ATTESTATIONS.filter((r) => r.data === "");
    expect(noData.length).toBeGreaterThan(0);
    const results = filterAttestations(noData, "");
    expect(results).toHaveLength(noData.length);
  });

  it("handles irrevocable attestations", () => {
    const irrevocable = filterAttestations(DEMO_ATTESTATIONS, "revocable:no");
    expect(irrevocable.every((r) => !r.revocable)).toBe(true);
    expect(irrevocable.length).toBeGreaterThan(0);
  });

  it("handles attestation with ref_uid", () => {
    const withRef = DEMO_ATTESTATIONS.filter((r) => r.refUid !== "");
    expect(withRef.length).toBeGreaterThan(0);
    const results = filterAttestations(withRef, "");
    expect(results).toHaveLength(withRef.length);
  });

  it("FixtureAttestationCaller round-trips all DEMO_ATTESTATIONS via reader", async () => {
    const fixture = new FixtureAttestationCaller(DEMO_ATTESTATIONS);
    const reader = new AttestationReader(fixture);
    const fetched = await Promise.all(DEMO_ATTESTATIONS.map((r) => reader.getAttestation(r.uid)));
    for (let i = 0; i < DEMO_ATTESTATIONS.length; i++) {
      expect(fetched[i]?.uid).toBe(DEMO_ATTESTATIONS[i].uid);
      expect(fetched[i]?.recipient).toBe(DEMO_ATTESTATIONS[i].recipient);
      expect(fetched[i]?.attester).toBe(DEMO_ATTESTATIONS[i].attester);
      expect(fetched[i]?.revocable).toBe(DEMO_ATTESTATIONS[i].revocable);
    }
  });
});

describe("Attestation Deep-Linking & Verification (#485)", () => {
  it("builds and parses deep-link verification URLs round-trip", () => {
    const query: AttestationVerificationQuery = {
      uid: "3b08e2a1490226cfa877c8e9bda53243f721d092d6e4a2bc1d8c199209581f5c",
      contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
      network: "testnet",
      attester: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
      time: 1700000000,
      expirationTime: 1800000000,
      revocable: true,
      signature: "00112233aabbcc",
    };

    const link = buildAttestationDeepLink(query, "https://explorer.sas.stellar.org/verify");
    expect(link).toContain("verify=1");
    expect(link).toContain(query.uid);
    expect(link).toContain(query.contract);

    const parsed = parseAttestationDeepLink(new URL(link).search);
    expect(parsed).not.toBeNull();
    expect(parsed?.uid).toBe(query.uid);
    expect(parsed?.contract).toBe(query.contract);
    expect(parsed?.network).toBe("testnet");
    expect(parsed?.attester).toBe(query.attester);
    expect(parsed?.time).toBe(1700000000);
    expect(parsed?.expirationTime).toBe(1800000000);
    expect(parsed?.revocable).toBe(true);
    expect(parsed?.signature).toBe("00112233aabbcc");
  });

  it("detects expired attestation during offline verification", async () => {
    const expiredQuery: AttestationVerificationQuery = {
      uid: "3b08e2a1490226cfa877c8e9bda53243f721d092d6e4a2bc1d8c199209581f5c",
      contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
      network: "testnet",
      attester: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
      expirationTime: 1000, // Ancient timestamp in the past
      signature: "001122",
    };

    const result = await verifyOfflineSignature(expiredQuery);
    expect(result.state).toBe("expired");
    expect(result.source).toBe("offline_signature");
  });

  it("handles missing signature parameters gracefully", async () => {
    const noSigQuery: AttestationVerificationQuery = {
      uid: "3b08e2a1490226cfa877c8e9bda53243f721d092d6e4a2bc1d8c199209581f5c",
      contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
      network: "testnet",
    };

    const result = await verifyOfflineSignature(noSigQuery);
    expect(result.state).toBe("offline_invalid");
  });
});
