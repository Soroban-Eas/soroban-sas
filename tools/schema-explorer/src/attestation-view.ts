// DOM rendering for the Attestations view.
//
// Follows the same patterns as view.ts: all on-chain strings go through
// textContent / setAttribute — never innerHTML.

import type { AttestationRecord, AttestationStatus } from "./attestation.js";
import { attestationStatus } from "./attestation.js";
import { h } from "./view.js";
import { shorten } from "./hex.js";

// ---------------------------------------------------------------------------
// Status badge
// ---------------------------------------------------------------------------

const STATUS_KIND: Record<AttestationStatus, "ok" | "warn" | "muted"> = {
  active: "ok",
  expired: "muted",
  revoked: "warn",
};

export function statusBadge(record: AttestationRecord, nowSeconds?: number): HTMLElement {
  const status = attestationStatus(record, nowSeconds);
  const kind = STATUS_KIND[status];
  return h("span", { class: `badge badge-${kind}` }, status);
}

// ---------------------------------------------------------------------------
// List item
// ---------------------------------------------------------------------------

export interface AttestationListOptions {
  selectedUid?: string;
  onSelect: (record: AttestationRecord) => void;
  nowSeconds?: number;
}

export function renderAttestationItem(record: AttestationRecord, options: AttestationListOptions): HTMLElement {
  const selected = record.uid === options.selectedUid;
  const status = attestationStatus(record, options.nowSeconds);

  const meta: string[] = [];
  if (record.time) meta.push(formatDate(record.time));
  if (!record.revocable) meta.push("irrevocable");

  const button = h(
    "button",
    {
      type: "button",
      class: "schema-item attestation-item",
      "aria-selected": String(selected),
      role: "option",
      "data-status": status,
    },
    h(
      "span",
      { class: "schema-item-head" },
      h("code", { class: "uid" }, shorten(record.uid)),
      statusBadge(record, options.nowSeconds),
    ),
    h(
      "span",
      { class: "schema-item-body attestation-item-addresses" },
      h("span", { class: "attestation-addr-label muted" }, "to "),
      h("code", {}, shorten(record.recipient, 10, 8)),
      h("span", { class: "attestation-addr-label muted" }, " by "),
      h("code", {}, shorten(record.attester, 10, 8)),
    ),
    h("span", { class: "schema-item-meta muted" }, meta.join(" · ")),
  );

  button.addEventListener("click", () => options.onSelect(record));
  return button;
}

// ---------------------------------------------------------------------------
// List container
// ---------------------------------------------------------------------------

export function renderAttestationList(
  records: readonly AttestationRecord[],
  options: AttestationListOptions,
): HTMLElement {
  if (records.length === 0) {
    return h("p", { class: "muted" }, "No attestations match your search.");
  }
  const list = h("ul", { class: "schema-list", role: "listbox", "aria-label": "Attestations" });
  for (const record of records) {
    list.append(h("li", {}, renderAttestationItem(record, options)));
  }
  return list;
}

// ---------------------------------------------------------------------------
// Detail pane
// ---------------------------------------------------------------------------

export function renderAttestationDetail(
  record: AttestationRecord,
  nowSeconds?: number,
): HTMLElement {
  const status = attestationStatus(record, nowSeconds);

  const flags = h(
    "span",
    { class: "flags" },
    statusBadge(record, nowSeconds),
    record.revocable ? null : h("span", { class: "badge badge-muted" }, "irrevocable"),
    record.refUid ? h("span", { class: "badge badge-info" }, "has ref") : null,
  );

  return h(
    "article",
    { class: "detail" },
    h("h2", {}, "Attestation"),
    h(
      "dl",
      {},
      kv("UID", record.uid, record.uid),
      kv("Status", flags),
      kv("Schema", record.schemaUid, record.schemaUid),
      kv("Recipient", record.recipient, record.recipient),
      kv("Attester", record.attester, record.attester),
      kv("Created", formatDate(record.time)),
      record.expirationTime
        ? kv(
            "Expires",
            `${formatDate(record.expirationTime)}${status === "expired" ? " (expired)" : ""}`,
          )
        : kv("Expires", h("span", { class: "muted" }, "never")),
      record.revocationTime
        ? kv("Revoked", formatDate(record.revocationTime))
        : null,
      record.refUid
        ? kv("Ref UID", record.refUid, record.refUid)
        : null,
    ),
    h("h3", {}, "Payload"),
    renderPayload(record.data),
  );
}

// ---------------------------------------------------------------------------
// Payload display
// ---------------------------------------------------------------------------

function renderPayload(data: string): HTMLElement {
  if (!data) {
    return h("p", { class: "muted" }, "Empty payload.");
  }
  const box = h("div", { class: "attestation-payload" });
  box.append(
    h("pre", { class: "schema-raw attestation-hex" }, data),
  );

  // Try to decode as UTF-8 for a human-readable hint.
  try {
    const bytes = hexToUint8Array(data);
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (isPrintable(text)) {
      box.append(
        h("p", { class: "muted attestation-decoded" }, `Decoded (UTF-8): `),
      );
      box.querySelector("p.attestation-decoded")!.append(h("code", {}, text));
    }
  } catch {
    // Not valid UTF-8; only show hex.
  }

  return box;
}

function hexToUint8Array(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function isPrintable(s: string): boolean {
  if (!s) return false;
  // Only allow common printable ranges (ASCII printable + extended Latin).
  return /^[\x20-\x7e\u00a0-\u00ff\n\r\t]*$/.test(s);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(unixSeconds: number): string {
  if (!unixSeconds) return "—";
  return new Date(unixSeconds * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
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

function kv(label: string, value: Node | string | null | undefined, copy?: string): HTMLElement | null {
  if (value === null || value === undefined) return null;
  return h(
    "div",
    { class: "kv" },
    h("dt", {}, label),
    h(
      "dd",
      {},
      typeof value === "string" ? h("code", { class: "wrap" }, value) : value,
      copy ? copyButton(copy, label) : null,
    ),
  );
}
