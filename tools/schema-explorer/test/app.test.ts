// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { mountExplorer } from "../src/app.js";
import { DEMO_REGISTRY_ID, DEMO_SCHEMAS, FixtureCaller, type FixtureSchema } from "../src/fixtures.js";
import type { ContractCaller, ExplorerConfig } from "../src/index.js";

// jsdom replaces import.meta.url, so resolve from the package root (vitest's cwd).
const html = readFileSync(resolve(process.cwd(), "index.html"), "utf8");
const bodyHtml = /<body>([\s\S]*)<\/body>/.exec(html)![1].replace(/<script[\s\S]*?<\/script>/g, "");

const $ = <T extends HTMLElement = HTMLElement>(sel: string) => document.querySelector<T>(sel)!;
const $$ = (sel: string) => Array.from(document.querySelectorAll<HTMLElement>(sel));

/** Resolves once pending promise callbacks (fixture calls) have run. */
const settle = () => new Promise((r) => setTimeout(r, 0));

function memoryStorage(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial));
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
    data,
  };
}

function mount(opts: { schemas?: FixtureSchema[]; search?: string; storage?: ReturnType<typeof memoryStorage> } = {}) {
  const configs: ExplorerConfig[] = [];
  const urls: string[] = [];
  const createCaller = (config: ExplorerConfig): ContractCaller => {
    configs.push(config);
    return new FixtureCaller(opts.schemas);
  };
  const app = mountExplorer(document, {
    createCaller,
    createDemoCaller: () => new FixtureCaller(opts.schemas),
    search: opts.search ?? "",
    storage: opts.storage ?? memoryStorage(),
    replaceUrl: (q) => urls.push(q),
  });
  return { app, configs, urls };
}

function type(sel: string, value: string) {
  const el = $<HTMLInputElement>(sel);
  el.value = value;
  el.dispatchEvent(new Event("input", { bubbles: true }));
}

function submit(sel: string) {
  $<HTMLFormElement>(sel).dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
}

beforeEach(() => {
  document.body.innerHTML = bodyHtml;
});

describe("schema explorer UI", () => {
  it("defaults to the local network preset", () => {
    mount();
    expect($<HTMLSelectElement>("#preset").value).toBe("local");
    expect($<HTMLInputElement>("#rpc-url").value).toBe("http://localhost:8000/soroban/rpc");
  });

  it("prefills settings from the query string over stored settings", () => {
    const storage = memoryStorage({
      "sas-schema-explorer:config": JSON.stringify({ registryContractId: "CSTORED" }),
    });
    mount({ search: `?network=testnet&registry=${DEMO_REGISTRY_ID}`, storage });
    expect($<HTMLSelectElement>("#preset").value).toBe("testnet");
    expect($<HTMLInputElement>("#registry").value).toBe(DEMO_REGISTRY_ID);
  });

  it("opens straight into demo data with ?demo=1", async () => {
    const { configs } = mount({ search: "?demo=1" });
    await settle();
    expect($$(".schema-item")).toHaveLength(4);
    expect(configs).toHaveLength(0);
  });

  it("switches to Custom when the RPC URL is edited", () => {
    mount();
    type("#rpc-url", "https://rpc.example.com");
    expect($<HTMLSelectElement>("#preset").value).toBe("custom");
  });

  it("refuses to connect with an invalid config", async () => {
    const { configs } = mount();
    type("#registry", "not-a-contract");
    submit("#connect");
    await settle();
    expect(configs).toHaveLength(0);
    expect($("#status").textContent).toContain("valid C... contract address");
    expect($("#status").className).toContain("status-error");
  });

  it("connects, lists active schemas, and saves a shareable link", async () => {
    const storage = memoryStorage();
    const { configs, urls } = mount({ storage });
    type("#registry", DEMO_REGISTRY_ID);
    submit("#connect");
    await settle();

    expect(configs).toEqual([
      { rpcUrl: "http://localhost:8000/soroban/rpc", networkPassphrase: "Standalone Network ; February 2017", registryContractId: DEMO_REGISTRY_ID },
    ]);
    expect($$(".schema-item")).toHaveLength(DEMO_SCHEMAS.filter((s) => !s.deprecated).length);
    expect(urls[0]).toContain(`registry=${DEMO_REGISTRY_ID}`);
    expect(storage.data.get("sas-schema-explorer:config")).toContain(DEMO_REGISTRY_ID);
  });

  it("shows fields, flags and owner for a selected schema", async () => {
    mount();
    $("#demo-btn").click();
    await settle();
    $$(".schema-item")[0].click();
    await settle();

    const detail = $("#detail");
    expect(detail.querySelector(".schema-raw")!.textContent).toBe(DEMO_SCHEMAS[0].schema);
    const fieldNames = Array.from(detail.querySelectorAll("tbody tr td:nth-child(2)")).map((td) => td.textContent);
    expect(fieldNames).toEqual(["verified", "level", "provider", "checked_at"]);
    expect(detail.textContent).toContain(DEMO_SCHEMAS[0].creator);
    expect(detail.textContent).toContain("revocable");
    expect($$(".schema-item")[0].getAttribute("aria-selected")).toBe("true");
  });

  it("flags schemas that do not pass on-chain syntax rules", async () => {
    mount();
    $("#demo-btn").click();
    await settle();
    type("#filter", "valid:no");
    const items = $$(".schema-item");
    expect(items).toHaveLength(1);
    expect(items[0].textContent).toContain("InvalidSchema");
  });

  it("filters loaded schemas by field name and flag", async () => {
    mount();
    $("#demo-btn").click();
    await settle();
    type("#filter", "vote_weight");
    expect($$(".schema-item")).toHaveLength(1);
    type("#filter", "revocable:no");
    expect($$(".schema-item")).toHaveLength(1);
    expect($("#list-summary").textContent).toContain("1 of 4");
    type("#filter", "");
    expect($$(".schema-item")).toHaveLength(4);
  });

  it("loads further pages on demand and stops at the end of the registry", async () => {
    const many = Array.from({ length: 30 }, (_, i) => ({
      ...DEMO_SCHEMAS[0],
      uid: (i + 1).toString(16).padStart(64, "0"),
      schema: `field_${i} u32`,
    }));
    mount({ schemas: many });
    $("#demo-btn").click();
    await settle();
    expect($$(".schema-item")).toHaveLength(25);
    expect($<HTMLButtonElement>("#load-more").hidden).toBe(false);

    $("#load-more").click();
    await settle();
    expect($$(".schema-item")).toHaveLength(30);

    $("#load-more").click();
    await settle();
    expect($<HTMLButtonElement>("#load-more").hidden).toBe(true);
    expect($("#list-summary").textContent).toContain("end of registry");
  });

  it("looks up schemas by UID, including ones not yet loaded", async () => {
    mount();
    $("#demo-btn").click();
    await settle();

    type("#lookup-uid", `0x${DEMO_SCHEMAS[3].uid.toUpperCase()}`);
    submit("#lookup");
    await settle();
    await settle();
    expect($("#detail .schema-raw").textContent).toBe(DEMO_SCHEMAS[3].schema);

    type("#lookup-uid", "ab".repeat(32));
    submit("#lookup");
    await settle();
    expect($("#detail").textContent).toContain("No active schema");

    type("#lookup-uid", "xyz");
    submit("#lookup");
    expect($("#status").textContent).toContain("64 hexadecimal");
  });

  it("renders hostile schema strings as inert text", async () => {
    const hostile = '<img src=x onerror="window.__pwned=1"> String';
    mount({ schemas: [{ ...DEMO_SCHEMAS[0], schema: hostile }] });
    $("#demo-btn").click();
    await settle();
    $$(".schema-item")[0].click();
    await settle();

    expect(document.querySelector("img")).toBeNull();
    expect($("#detail .schema-raw").textContent).toBe(hostile);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("validates draft schemas live", () => {
    mount();
    expect($("#draft-result").textContent).toContain("valid syntax");
    type("#draft", "first_name String,");
    expect($("#draft-result").textContent).toContain("trailing comma");
    type("#draft", "a B, b C");
    expect($$("#draft-result tbody tr")).toHaveLength(2);
  });

  it("switches tabs", () => {
    mount();
    $("#tab-validate").click();
    expect($("#validate").hidden).toBe(false);
    expect($("#browse").hidden).toBe(true);
    expect($("#tab-validate").getAttribute("aria-selected")).toBe("true");
  });

  it("drops responses from a superseded connection", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const slow: ContractCaller = {
      async call(method, args) {
        await gate;
        return new FixtureCaller([{ ...DEMO_SCHEMAS[0], schema: "stale u32" }]).call(method, args);
      },
    };
    const { app } = mount();
    void app.connect(slow, "slow");
    $("#demo-btn").click();
    await settle();
    release();
    await settle();
    expect($$(".schema-item")).toHaveLength(4);
    expect(document.body.textContent).not.toContain("stale u32");
  });
});
