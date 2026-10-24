import type { AttestationRecord, AttestationStatus } from "./feed.js";
import { attestationStatus } from "./feed.js";

/**
 * Render the payload inspector for a single attestation: raw XDR and
 * decoded JSON side-by-side, plus the metadata and status tag.
 *
 * All values are untrusted (chain data) and are rendered with
 * textContent only. The JSON is prettified for readability but never
 * interpreted as HTML.
 */
export function renderInspector(container: HTMLElement, record: AttestationRecord): void {
  container.textContent = "";
  const frag = document.createDocumentFragment();

  const status = attestationStatus(record);
  const header = el("div", "inspector-header");
  header.appendChild(el("h2", "inspector-title", "Attestation"));
  header.appendChild(statusTag(status));
  frag.appendChild(header);

  const meta = el("dl", "inspector-meta");
  addMeta(meta, "UID", record.uid);
  addMeta(meta, "Schema UID", record.schemaUid);
  addMeta(meta, "Attester", record.attester);
  addMeta(meta, "Recipient", record.recipient);
  addMeta(meta, "Created", formatTimestamp(record.created));
  addMeta(meta, "Expires", record.expiration === 0 ? "Never" : formatTimestamp(record.expiration));
  frag.appendChild(meta);

  const panes = el("div", "inspector-panes");
  panes.appendChild(payloadPane("Raw XDR", record.payloadXdr, "xdr"));
  panes.appendChild(payloadPane("Decoded JSON", formatJson(record.payloadJson), "json"));
  frag.appendChild(panes);

  container.appendChild(frag);
}

function payloadPane(title: string, body: string, kind: "xdr" | "json"): HTMLElement {
  const pane = el("div", "inspector-pane");
  pane.appendChild(el("h3", "inspector-pane-title", title));
  const pre = el("pre", `inspector-code inspector-${kind}`);
  const code = el("code");
  code.textContent = body;
  pre.appendChild(code);
  pane.appendChild(pre);
  return pane;
}

function addMeta(dl: HTMLElement, label: string, value: string): void {
  const dt = el("dt");
  dt.textContent = label;
  const dd = el("dd");
  dd.textContent = value;
  dl.appendChild(dt);
  dl.appendChild(dd);
}

export function statusTag(status: AttestationStatus): HTMLElement {
  const tag = el("span", `status-tag status-${status}`);
  tag.setAttribute("data-status", status);
  tag.textContent = status.charAt(0).toUpperCase() + status.slice(1);
  return tag;
}

function formatJson(value: unknown | null): string {
  if (value === null || value === undefined) return "(no decoded payload)";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function formatTimestamp(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toISOString().replace("T", " ").replace(/\.\d+Z/, " UTC");
}

function el(tag: string, className?: string, text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
