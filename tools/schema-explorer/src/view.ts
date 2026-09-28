// DOM rendering. Everything that originates on-chain (schema strings,
// addresses) is inserted with `textContent` / attribute setters only — never
// `innerHTML` — so a malicious schema string renders as inert text.

import type { SchemaRecord } from "./registry.js";
import {
  MAX_SCHEMA_FIELDS,
  MAX_SCHEMA_LENGTH,
  parseSchema,
  type SchemaField,
  type SchemaParseResult,
} from "./schema.js";
import { shorten } from "./hex.js";

type Child = Node | string | null | undefined | false;

/** Minimal element builder: attributes via setAttribute, children as text nodes. */
export function h(tag: string, attrs: Record<string, string> = {}, ...children: Child[]): HTMLElement {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, value);
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    el.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return el;
}

function badge(text: string, kind: "ok" | "warn" | "muted" | "info"): HTMLElement {
  return h("span", { class: `badge badge-${kind}` }, text);
}

export function validationBadge(result: SchemaParseResult): HTMLElement {
  return result.ok ? badge("valid syntax", "ok") : badge(result.code, "warn");
}

export function renderFieldTable(fields: readonly SchemaField[]): HTMLElement {
  if (fields.length === 0) return h("p", { class: "muted" }, "No fields could be parsed.");
  const body = h("tbody");
  fields.forEach((field, i) => {
    body.append(h("tr", {}, h("td", { class: "num" }, String(i + 1)), h("td", {}, h("code", {}, field.name)), h("td", {}, h("code", {}, field.type))));
  });
  return h(
    "table",
    { class: "fields" },
    h("thead", {}, h("tr", {}, h("th", { class: "num" }, "#"), h("th", {}, "Field"), h("th", {}, "Type"))),
    body,
  );
}

/** Byte and field usage against the registry's ceilings. */
export function renderLimits(result: SchemaParseResult): HTMLElement {
  return h(
    "p",
    { class: "limits muted" },
    `${result.byteLength} / ${MAX_SCHEMA_LENGTH} bytes · ${result.fields.length} / ${MAX_SCHEMA_FIELDS} fields`,
  );
}

export function renderValidation(result: SchemaParseResult): HTMLElement {
  const box = h("div", { class: "validation" }, validationBadge(result), renderLimits(result));
  if (!result.ok) box.append(h("p", { class: "error-text", role: "alert" }, result.reason));
  return box;
}

export interface ListOptions {
  selectedUid?: string;
  onSelect: (record: SchemaRecord) => void;
}

export function renderSchemaList(records: readonly SchemaRecord[], options: ListOptions): HTMLElement {
  const list = h("ul", { class: "schema-list", role: "listbox", "aria-label": "Schemas" });
  for (const record of records) {
    const parsed = parseSchema(record.schema);
    const selected = record.uid === options.selectedUid;
    const button = h(
      "button",
      { type: "button", class: "schema-item", "aria-selected": String(selected), role: "option" },
      h("span", { class: "schema-item-head" }, h("code", { class: "uid" }, shorten(record.uid)), validationBadge(parsed)),
      h("span", { class: "schema-item-body" }, record.schema),
      h(
        "span",
        { class: "schema-item-meta muted" },
        `${parsed.fields.length} field${parsed.fields.length === 1 ? "" : "s"} · ${record.revocable ? "revocable" : "irrevocable"}`,
      ),
    );
    button.addEventListener("click", () => options.onSelect(record));
    list.append(h("li", {}, button));
  }
  return list;
}

function copyButton(value: string, label: string): HTMLElement {
  const button = h("button", { type: "button", class: "copy", "aria-label": `Copy ${label}` }, "Copy");
  button.addEventListener("click", () => {
    void navigator.clipboard?.writeText(value).then(
      () => {
        button.textContent = "Copied";
        setTimeout(() => (button.textContent = "Copy"), 1200);
      },
      () => undefined,
    );
  });
  return button;
}

function row(label: string, value: Node | string, copy?: string): HTMLElement {
  return h(
    "div",
    { class: "kv" },
    h("dt", {}, label),
    h("dd", {}, typeof value === "string" ? h("code", { class: "wrap" }, value) : value, copy ? copyButton(copy, label) : null),
  );
}

/** `creator`: an address, `null` when none is recorded, `undefined` while loading. */
export function renderSchemaDetail(record: SchemaRecord, creator: string | null | undefined): HTMLElement {
  const parsed = parseSchema(record.schema);
  const flags = h(
    "span",
    { class: "flags" },
    badge(record.revocable ? "revocable" : "irrevocable", record.revocable ? "info" : "muted"),
    record.deprecated ? badge("deprecated", "warn") : null,
  );
  const creatorValue =
    creator === undefined ? h("span", { class: "muted" }, "Loading…") : creator === null ? h("span", { class: "muted" }, "Not recorded") : creator;

  return h(
    "article",
    { class: "detail" },
    h("h2", {}, "Schema"),
    h(
      "dl",
      {},
      row("UID", record.uid, record.uid),
      row("Resolver", record.resolver, record.resolver),
      row("Owner", creatorValue, typeof creator === "string" ? creator : undefined),
      row("Flags", flags),
    ),
    h("h3", {}, "Definition"),
    h("pre", { class: "schema-raw" }, record.schema),
    renderValidation(parsed),
    h("h3", {}, "Fields"),
    renderFieldTable(parsed.fields),
  );
}
