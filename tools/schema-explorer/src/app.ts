// Wires the page in index.html to a RegistryReader. Kept separate from
// main.ts, and parameterized over the document and caller factory, so the
// whole UI can be driven in tests against FixtureCaller.

import { PRESETS, configFromQuery, configToQuery, findPreset, validateConfig, type ExplorerConfig } from "./config.js";
import { DEMO_REGISTRY_ID, FixtureCaller } from "./fixtures.js";
import { isUidHex, normalizeUid } from "./hex.js";
import { RegistryReader, RpcContractCaller, type ContractCaller, type SchemaRecord } from "./registry.js";
import { parseSchema } from "./schema.js";
import { filterSchemas } from "./search.js";
import { h, renderFieldTable, renderSchemaDetail, renderSchemaList, renderValidation } from "./view.js";

export const PAGE_SIZE = 25;
const STORAGE_KEY = "sas-schema-explorer:config";

export interface MountOptions {
  /** Builds the caller for a validated config. Defaults to Soroban RPC. */
  createCaller?: (config: ExplorerConfig) => ContractCaller;
  /** Caller used by "Use demo data". Defaults to the built-in fixtures. */
  createDemoCaller?: () => ContractCaller;
  /** Query string to read initial settings from (defaults to location.search). */
  search?: string;
  storage?: Pick<Storage, "getItem" | "setItem"> | null;
  /** Updates the address bar with a shareable link; no-op in tests. */
  replaceUrl?: (query: string) => void;
}

interface State {
  reader: RegistryReader | null;
  schemas: SchemaRecord[];
  cursor: number;
  hasMore: boolean;
  selectedUid?: string;
  /** Bumped on every (re)connect so late responses from an old connection are dropped. */
  generation: number;
}

function byId<T extends HTMLElement>(doc: Document, id: string): T {
  const el = doc.getElementById(id);
  if (!el) throw new Error(`schema explorer: missing #${id}`);
  return el as T;
}

function readStorage(storage: MountOptions["storage"]): Partial<ExplorerConfig> {
  try {
    const raw = storage?.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as Partial<ExplorerConfig>) : {};
  } catch {
    return {};
  }
}

function writeStorage(storage: MountOptions["storage"], config: ExplorerConfig): void {
  try {
    storage?.setItem(STORAGE_KEY, JSON.stringify(config));
  } catch {
    // Private mode or blocked storage: remembering settings is optional.
  }
}

export function mountExplorer(doc: Document, options: MountOptions = {}) {
  const createCaller = options.createCaller ?? ((config) => new RpcContractCaller(config));
  const createDemoCaller = options.createDemoCaller ?? (() => new FixtureCaller(undefined, 150));

  const form = byId<HTMLFormElement>(doc, "connect");
  const preset = byId<HTMLSelectElement>(doc, "preset");
  const rpcUrl = byId<HTMLInputElement>(doc, "rpc-url");
  const passphrase = byId<HTMLInputElement>(doc, "passphrase");
  const registry = byId<HTMLInputElement>(doc, "registry");
  const connectBtn = byId<HTMLButtonElement>(doc, "connect-btn");
  const demoBtn = byId<HTMLButtonElement>(doc, "demo-btn");
  const status = byId(doc, "status");
  const list = byId(doc, "list");
  const summary = byId(doc, "list-summary");
  const loadMore = byId<HTMLButtonElement>(doc, "load-more");
  const filter = byId<HTMLInputElement>(doc, "filter");
  const detail = byId(doc, "detail");
  const lookup = byId<HTMLFormElement>(doc, "lookup");
  const lookupUid = byId<HTMLInputElement>(doc, "lookup-uid");
  const draft = byId<HTMLTextAreaElement>(doc, "draft");
  const draftResult = byId(doc, "draft-result");

  const state: State = { reader: null, schemas: [], cursor: 0, hasMore: false, generation: 0 };

  // --- status line -------------------------------------------------------
  function setStatus(message: string, kind: "info" | "error" | "ok" = "info") {
    status.textContent = message;
    status.className = `status status-${kind}`;
  }

  // --- connection form ---------------------------------------------------
  for (const p of PRESETS) preset.append(h("option", { value: p.id }, p.label));
  preset.append(h("option", { value: "custom" }, "Custom"));

  function applyPreset(id: string) {
    const p = findPreset(id);
    if (p) {
      rpcUrl.value = p.rpcUrl;
      passphrase.value = p.networkPassphrase;
    }
  }
  function syncPresetSelect() {
    const match = PRESETS.find((p) => p.rpcUrl === rpcUrl.value.trim() && p.networkPassphrase === passphrase.value.trim());
    preset.value = match ? match.id : "custom";
  }

  const search = options.search ?? doc.defaultView?.location.search ?? "";
  const initial = { ...readStorage(options.storage), ...configFromQuery(search) };
  applyPreset("local");
  if (initial.rpcUrl) rpcUrl.value = initial.rpcUrl;
  if (initial.networkPassphrase) passphrase.value = initial.networkPassphrase;
  if (initial.registryContractId) registry.value = initial.registryContractId;
  syncPresetSelect();

  preset.addEventListener("change", () => applyPreset(preset.value));
  rpcUrl.addEventListener("input", syncPresetSelect);
  passphrase.addEventListener("input", syncPresetSelect);

  // --- list + detail -----------------------------------------------------
  function renderList() {
    const visible = filterSchemas(state.schemas, filter.value);
    list.replaceChildren(
      renderSchemaList(visible, { selectedUid: state.selectedUid, onSelect: (record) => void select(record) }),
    );
    const total = state.schemas.length;
    summary.textContent = filter.value.trim()
      ? `${visible.length} of ${total} loaded schema${total === 1 ? "" : "s"} match`
      : `${total} schema${total === 1 ? "" : "s"} loaded${state.hasMore ? "" : " (end of registry)"}`;
    loadMore.hidden = !state.hasMore;
  }

  async function select(record: SchemaRecord) {
    const reader = state.reader;
    const generation = state.generation;
    state.selectedUid = record.uid;
    renderList();
    detail.replaceChildren(renderSchemaDetail(record, undefined));
    if (!reader) return;
    let creator: string | null;
    try {
      creator = await reader.getCreator(record.uid);
    } catch (err) {
      creator = null;
      setStatus(`Could not load schema owner: ${(err as Error).message}`, "error");
    }
    if (generation === state.generation && state.selectedUid === record.uid) {
      detail.replaceChildren(renderSchemaDetail(record, creator));
    }
  }

  async function loadPage() {
    const reader = state.reader;
    if (!reader) return;
    const generation = state.generation;
    loadMore.disabled = true;
    try {
      const page = await reader.listSchemas(state.cursor, PAGE_SIZE);
      if (generation !== state.generation) return;
      const known = new Set(state.schemas.map((s) => s.uid));
      state.schemas.push(...page.schemas.filter((s) => !known.has(s.uid)));
      state.cursor = page.nextCursor;
      state.hasMore = page.hasMore;
      renderList();
      setStatus(`Loaded ${state.schemas.length} schema${state.schemas.length === 1 ? "" : "s"}.`, "ok");
    } catch (err) {
      if (generation === state.generation) setStatus((err as Error).message, "error");
    } finally {
      loadMore.disabled = false;
    }
  }

  async function connect(caller: ContractCaller, label: string) {
    state.generation++;
    state.reader = new RegistryReader(caller);
    state.schemas = [];
    state.cursor = 0;
    state.hasMore = false;
    state.selectedUid = undefined;
    list.replaceChildren();
    detail.replaceChildren(h("p", { class: "muted" }, "Select a schema to see its fields."));
    setStatus(`Connecting to ${label}…`);
    await loadPage();
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const result = validateConfig({
      rpcUrl: rpcUrl.value,
      networkPassphrase: passphrase.value,
      registryContractId: registry.value,
    });
    if (!result.ok) {
      setStatus(result.errors.join(" "), "error");
      return;
    }
    writeStorage(options.storage, result.config);
    options.replaceUrl?.(configToQuery(result.config));
    connectBtn.disabled = true;
    void connect(createCaller(result.config), result.config.rpcUrl).finally(() => (connectBtn.disabled = false));
  });

  demoBtn.addEventListener("click", () => {
    registry.value = DEMO_REGISTRY_ID;
    void connect(createDemoCaller(), "demo data (offline)");
  });

  loadMore.addEventListener("click", () => void loadPage());
  filter.addEventListener("input", renderList);

  lookup.addEventListener("submit", (event) => {
    event.preventDefault();
    const uid = normalizeUid(lookupUid.value);
    if (!isUidHex(uid)) {
      setStatus("A schema UID is 64 hexadecimal characters.", "error");
      return;
    }
    const reader = state.reader;
    if (!reader) {
      setStatus("Connect to a registry first.", "error");
      return;
    }
    const generation = state.generation;
    void reader.getSchema(uid).then(
      (record) => {
        if (generation !== state.generation) return;
        if (!record) {
          detail.replaceChildren(
            h("p", { class: "muted" }, "No active schema with that UID. It was never registered, or it has been deprecated."),
          );
          setStatus("Schema not found.", "info");
          return;
        }
        if (!state.schemas.some((s) => s.uid === record.uid)) state.schemas.push(record);
        void select(record);
        setStatus("Schema found.", "ok");
      },
      (err: Error) => setStatus(err.message, "error"),
    );
  });

  // --- tabs --------------------------------------------------------------
  const tabs = [
    { tab: byId<HTMLButtonElement>(doc, "tab-browse"), panel: byId(doc, "browse") },
    { tab: byId<HTMLButtonElement>(doc, "tab-validate"), panel: byId(doc, "validate") },
  ];
  for (const { tab } of tabs) {
    tab.addEventListener("click", () => {
      for (const t of tabs) {
        const active = t.tab === tab;
        t.tab.setAttribute("aria-selected", String(active));
        t.panel.hidden = !active;
      }
    });
  }

  // --- draft validator ---------------------------------------------------
  function renderDraft() {
    const result = parseSchema(draft.value);
    draftResult.replaceChildren(renderValidation(result), renderFieldTable(result.fields));
  }
  draft.addEventListener("input", renderDraft);
  renderDraft();

  // `?demo=1` opens straight into the offline fixtures (handy for sharing a preview).
  if (new URLSearchParams(search).get("demo") === "1") demoBtn.click();

  return { state, connect, loadPage };
}
