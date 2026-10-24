// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { mountExplorer } from "../src/app.js";

const html = readFileSync(resolve(process.cwd(), "index.html"), "utf8");
const body = /<body>([\s\S]*?)<\/body>/.exec(html)![1].replace(/<script[\s\S]*?<\/script>/g, "");
const $ = <T extends HTMLElement = HTMLElement>(selector:string):T => document.querySelector<T>(selector)!;
const $$ = (selector:string) => Array.from(document.querySelectorAll<HTMLElement>(selector));
beforeEach(() => { document.body.innerHTML = body; });

function input(selector: string, value: string) {
  const target = $<HTMLInputElement>(selector);
  target.value = value;
  target.dispatchEvent(new Event("input", { bubbles: true }));
}

describe("Visual Schema Designer UI", () => {
  it("has KYC, POAP, Skill Certification presets and previews a WASM UID", async () => {
    mountExplorer(document, { search: "" });
    $("#tab-designer").click();
    expect($("#designer").hidden).toBe(false);
    expect($("#validate").hidden).toBe(true);
    expect($$("#designer-rows .designer-row")).toHaveLength(3);
    await vi.waitFor(() => expect($("#designer-uid").textContent).toMatch(/^[0-9a-f]{64}$/), { timeout: 5000 });
    expect($("#designer-schema").textContent).toBe("subject String, verified bool, jurisdiction String");
    const preset = $<HTMLSelectElement>("#designer-template");
    preset.value = "POAP";
    preset.dispatchEvent(new Event("change", { bubbles: true }));
    expect($("#designer-schema").textContent).toBe("event_id String, attended bool, issued_at u64");
  });

  it("updates UID on field edits and flags invalid duplicate field names", async () => {
    mountExplorer(document);
    const initial = $("#designer-uid");
    await vi.waitFor(() => expect(initial.textContent).toMatch(/^[0-9a-f]{64}$/), { timeout: 5000 });
    const oldUid = initial.textContent;
    input('[aria-label="Field 1 name"]', "other");
    await vi.waitFor(() => expect(initial.textContent).toMatch(/^[0-9a-f]{64}$/), { timeout: 5000 });
    expect(initial.textContent).not.toBe(oldUid);
    input('[aria-label="Field 2 name"]', "other");
    expect($("#designer-validation").textContent).toContain("Duplicate field names");
    expect($<HTMLInputElement>('[aria-label="Field 2 name"]').getAttribute("aria-invalid")).toBe("true");
    expect($("#designer-uid").textContent).toContain("Unavailable");
  });

  it("moves fields without losing schema data and supports keyboard reorder", () => {
    mountExplorer(document);
    $("button[aria-label='Move field 1 down']").click();
    expect($("#designer-schema").textContent?.startsWith("verified bool, subject String")).toBe(true);
    $("#designer-add").click();
    expect($$("#designer-rows .designer-row")).toHaveLength(4);
    $("button[aria-label='Remove field 4']").click();
    expect($$("#designer-rows .designer-row")).toHaveLength(3);
  });
});
