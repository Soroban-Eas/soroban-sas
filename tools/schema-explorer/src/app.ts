// Wires the page in index.html to a RegistryReader. Kept separate from
// main.ts, and parameterized over the document and caller factory, so the
// whole UI can be driven in tests against FixtureCaller.

import { parseAttestationDeepLink, type AttestationVerificationQuery } from "./attestation.js";
import { renderMobileVerificationView } from "./mobile-verify.js";
import { renderQrCodeGeneratorPanel } from "./qr-view.js";
import { PRESETS, configFromQuery, configToQuery, findPreset, validateConfig, type ExplorerConfig } from "./config.js";
import { mountDesigner } from "./designer-ui.js";
import { DEMO_REGISTRY_ID, FixtureCaller } from "./fixtures.js";
import { DEMO_SAS_CONTRACT_ID, DEMO_INDEXER_CONTRACT_ID, DEMO_ATTESTATIONS, FixtureAttestationCaller } from "./fixtures-attestations.js";
import { isUidHex, normalizeUid } from "./hex.js";
import { RegistryReader, RpcContractCaller, type ContractCaller, type SchemaRecord } from "./registry.js";
import { AttestationReader, RpcAttestationCaller, type AttestationRecord } from "./attestation.js";
import { parseSchema } from "./schema.js";
import { filterSchemas } from "./search.js";
import { filterAttestations } from "./filter-attestations.js";
import { h, renderFieldTable, renderSchemaDetail, renderSchemaList, renderValidation } from "./view.js";
import { renderAttestationList, renderAttestationDetail } from "./attestation-view.js";

export const PAGE_SIZE = 25;
const STORAGE_KEY = "sas-schema-explorer:config";
const POLL_INTERVAL_MS = 10_000;

export interface MountOptions {
  /** Builds the caller for a validated config. Defaults to Soroban RPC. */
  createCaller?: (config: ExplorerConfig) => ContractCaller;
  /** Caller used by "Use demo data". Defaults to the built-in fixtures. */
  createDemoCaller?: () => ContractCaller;
  /** Builds attestation callers for a validated config. */
  createAttestationCallers?: (config: ExplorerConfig) => { sasCaller: ContractCaller; indexerCaller?: ContractCaller };
  /** Attestation callers used by "Use demo data". */
  createDemoAttestationCallers?: () => { sasCaller: ContractCaller; indexerCaller?: ContractCaller };
  /** Query string to read initial settings from (defaults to location.search). */
  search?: string;
  storage?: Pick<Storage, "getItem" | "setItem"> | null;
  /** Updates the address bar with a shareable link; no-op in tests. */
  replaceUrl?: (query: string) => void;
}

interface SchemaState {
  reader: RegistryReader | null;
  schemas: SchemaRecord[];
  cursor: number;
  hasMore: boolean;
  selectedUid?: string;
  generation: number;
}

interface AttestationState {
  reader: AttestationReader | null;
  records: AttestationRecord[];
  selectedUid?: string;
  loading: boolean;
  /** Bumped on every (re)connect so late responses are dropped. */
  generation: number;
  /** Handle for the auto-refresh interval. */
  pollHandle: ReturnType<typeof setInterval> | null;
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
  const createCaller =
    options.createCaller ?? ((config) => new RpcContractCaller(config));
  const createDemoCaller =
    options.createDemoCaller ?? (() => new FixtureCaller(undefined, 150));
  const createAttestationCallers =
    options.createAttestationCallers ??
    ((config) => ({
      sasCaller: config.sasContractId
        ? new RpcAttestationCaller(config, config.sasContractId)
        : new RpcContractCaller(config),
      indexerCaller: config.indexerContractId
        ? new RpcAttestationCaller(config, config.indexerContractId)
        : undefined,
    }));
  const createDemoAttestationCallers =
    options.createDemoAttestationCallers ??
    (() => {
      const fixture = new FixtureAttestationCaller(DEMO_ATTESTATIONS, 150);
      return { sasCaller: fixture, indexerCaller: fixture };
    });

  // --- DOM refs ----------------------------------------------------------
  const form = byId<HTMLFormElement>(doc, "connect");
  const preset = byId<HTMLSelectElement>(doc, "preset");
  const rpcUrl = byId<HTMLInputElement>(doc, "rpc-url");
  const passphrase = byId<HTMLInputElement>(doc, "passphrase");
  const registry = byId<HTMLInputElement>(doc, "registry");
  const sasInput = byId<HTMLInputElement>(doc, "sas");
  const indexerInput = byId<HTMLInputElement>(doc, "indexer");
  const connectBtn = byId<HTMLButtonElement>(doc, "connect-btn");
  const demoBtn = byId<HTMLButtonElement>(doc, "demo-btn");
  const status = byId(doc, "status");

  // Browse tab
  const list = byId(doc, "list");
  const summary = byId(doc, "list-summary");
  const loadMore = byId<HTMLButtonElement>(doc, "load-more");
  const filter = byId<HTMLInputElement>(doc, "filter");
  const detail = byId(doc, "detail");
  const lookup = byId<HTMLFormElement>(doc, "lookup");
  const lookupUid = byId<HTMLInputElement>(doc, "lookup-uid");

  // Validate tab
  const draft = byId<HTMLTextAreaElement>(doc, "draft");
  const draftResult = byId(doc, "draft-result");

  // Attestations tab
  const attestSearch = byId<HTMLInputElement>(doc, "attest-search");
  const attestSearchForm = byId<HTMLFormElement>(doc, "attest-search-form");
  const attestFilter = byId<HTMLInputElement>(doc, "attest-filter");
  const attestList = byId(doc, "attest-list");
  const attestSummary = byId(doc, "attest-summary");
  const attestDetail = byId(doc, "attest-detail");
  const attestPollStatus = byId(doc, "attest-poll-status");

  // --- state -------------------------------------------------------------
  const schemaState: SchemaState = {
    reader: null,
    schemas: [],
    cursor: 0,
    hasMore: false,
    generation: 0,
  };

  const attestState: AttestationState = {
    reader: null,
    records: [],
    loading: false,
    generation: 0,
    pollHandle: null,
  };

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
    const match = PRESETS.find(
      (p) => p.rpcUrl === rpcUrl.value.trim() && p.networkPassphrase === passphrase.value.trim(),
    );
    preset.value = match ? match.id : "custom";
  }

  const search = options.search ?? doc.defaultView?.location.search ?? "";
  const initial = { ...readStorage(options.storage), ...configFromQuery(search) };
  applyPreset("local");
  if (initial.rpcUrl) rpcUrl.value = initial.rpcUrl;
  if (initial.networkPassphrase) passphrase.value = initial.networkPassphrase;
  if (initial.registryContractId) registry.value = initial.registryContractId;
  if (initial.sasContractId) sasInput.value = initial.sasContractId;
  if (initial.indexerContractId) indexerInput.value = initial.indexerContractId;

  // Pre-populate attestation search from ?attest-q=
  const initialAttestQ = new URLSearchParams(search).get("attest-q") ?? "";
  if (initialAttestQ) attestSearch.value = initialAttestQ;

  syncPresetSelect();
  preset.addEventListener("change", () => applyPreset(preset.value));
  rpcUrl.addEventListener("input", syncPresetSelect);
  passphrase.addEventListener("input", syncPresetSelect);

  // --- schema list + detail ----------------------------------------------
  function renderSchemaListPane() {
    const visible = filterSchemas(schemaState.schemas, filter.value);
    list.replaceChildren(
      renderSchemaList(visible, {
        selectedUid: schemaState.selectedUid,
        onSelect: (record) => void selectSchema(record),
      }),
    );
    const total = schemaState.schemas.length;
    summary.textContent = filter.value.trim()
      ? `${visible.length} of ${total} loaded schema${total === 1 ? "" : "s"} match`
      : `${total} schema${total === 1 ? "" : "s"} loaded${schemaState.hasMore ? "" : " (end of registry)"}`;
    loadMore.hidden = !schemaState.hasMore;
  }

  async function selectSchema(record: SchemaRecord) {
    const reader = schemaState.reader;
    const generation = schemaState.generation;
    schemaState.selectedUid = record.uid;
    renderSchemaListPane();
    detail.replaceChildren(renderSchemaDetail(record, undefined));
    if (!reader) return;
    let creator: string | null;
    try {
      creator = await reader.getCreator(record.uid);
    } catch (err) {
      creator = null;
      setStatus(`Could not load schema owner: ${(err as Error).message}`, "error");
    }
    if (generation === schemaState.generation && schemaState.selectedUid === record.uid) {
      detail.replaceChildren(renderSchemaDetail(record, creator));
    }
  }

  async function loadSchemaPage() {
    const reader = schemaState.reader;
    if (!reader) return;
    const generation = schemaState.generation;
    loadMore.disabled = true;
    try {
      const page = await reader.listSchemas(schemaState.cursor, PAGE_SIZE);
      if (generation !== schemaState.generation) return;
      const known = new Set(schemaState.schemas.map((s) => s.uid));
      schemaState.schemas.push(...page.schemas.filter((s) => !known.has(s.uid)));
      schemaState.cursor = page.nextCursor;
      schemaState.hasMore = page.hasMore;
      renderSchemaListPane();
      setStatus(`Loaded ${schemaState.schemas.length} schema${schemaState.schemas.length === 1 ? "" : "s"}.`, "ok");
    } catch (err) {
      if (generation === schemaState.generation) setStatus((err as Error).message, "error");
    } finally {
      loadMore.disabled = false;
    }
  }

  // --- attestation list + detail -----------------------------------------
  function renderAttestationListPane() {
    const visible = filterAttestations(attestState.records, attestFilter.value);
    attestList.replaceChildren(
      renderAttestationList(visible, {
        selectedUid: attestState.selectedUid,
        onSelect: (record) => selectAttestation(record),
      }),
    );
    const total = attestState.records.length;
    attestSummary.textContent = attestFilter.value.trim()
      ? `${visible.length} of ${total} attestation${total === 1 ? "" : "s"} match`
      : `${total} attestation${total === 1 ? "" : "s"} loaded`;
    updatePollStatus();
  }

  function selectAttestation(record: AttestationRecord) {
    attestState.selectedUid = record.uid;
    renderAttestationListPane();
    attestDetail.replaceChildren(renderAttestationDetail(record));
  }

  function updatePollStatus() {
    attestPollStatus.textContent = attestState.reader
      ? attestState.loading
        ? "Refreshing…"
        : `Live · auto-refresh every ${POLL_INTERVAL_MS / 1000}s`
      : "Not connected";
  }

  async function runAttestationSearch() {
    const reader = attestState.reader;
    if (!reader) return;
    const generation = attestState.generation;
    const query = attestSearch.value.trim();

    attestState.loading = true;
    updatePollStatus();

    try {
      const records = await reader.search(query, PAGE_SIZE);
      if (generation !== attestState.generation) return;

      // Merge with existing records (preserve any already loaded).
      const seen = new Set(attestState.records.map((r) => r.uid));
      for (const r of records) {
        if (!seen.has(r.uid)) {
          attestState.records.push(r);
          seen.add(r.uid);
        } else {
          // Update in place (revocation/expiry may have changed).
          const idx = attestState.records.findIndex((x) => x.uid === r.uid);
          if (idx >= 0) attestState.records[idx] = r;
        }
      }
      // When a new search query is issued replace the list entirely.
      if (query) {
        attestState.records = records;
      }
      renderAttestationListPane();
    } catch (err) {
      if (generation === attestState.generation) {
        setStatus(`Attestation search failed: ${(err as Error).message}`, "error");
      }
    } finally {
      if (generation === attestState.generation) {
        attestState.loading = false;
        updatePollStatus();
      }
    }
  }

  /** Connects the attestation panel to new callers; clears state and starts polling. */
  function connectAttestations(sasCaller: ContractCaller, indexerCaller?: ContractCaller) {
    stopPolling();
    attestState.generation++;
    attestState.reader = new AttestationReader(sasCaller, indexerCaller);
    attestState.records = [];
    attestState.selectedUid = undefined;
    attestState.loading = false;
    attestList.replaceChildren();
    attestDetail.replaceChildren(h("p", { class: "muted" }, "Search for attestations above."));
    updatePollStatus();
    // Kick off an initial load if there's a query pre-filled.
    if (attestSearch.value.trim()) void runAttestationSearch();
    startPolling();
  }

  function startPolling() {
    if (attestState.pollHandle !== null) return;
    attestState.pollHandle = setInterval(() => void runAttestationSearch(), POLL_INTERVAL_MS);
  }

  function stopPolling() {
    if (attestState.pollHandle !== null) {
      clearInterval(attestState.pollHandle);
      attestState.pollHandle = null;
    }
  }

  // --- connect -----------------------------------------------------------
  async function connect(caller: ContractCaller, label: string, attestationCallers?: { sasCaller: ContractCaller; indexerCaller?: ContractCaller }) {
    schemaState.generation++;
    schemaState.reader = new RegistryReader(caller);
    schemaState.schemas = [];
    schemaState.cursor = 0;
    schemaState.hasMore = false;
    schemaState.selectedUid = undefined;
    list.replaceChildren();
    detail.replaceChildren(h("p", { class: "muted" }, "Select a schema to see its fields."));
    setStatus(`Connecting to ${label}…`);
    await loadSchemaPage();

    if (attestationCallers) {
      connectAttestations(attestationCallers.sasCaller, attestationCallers.indexerCaller);
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const result = validateConfig({
      rpcUrl: rpcUrl.value,
      networkPassphrase: passphrase.value,
      registryContractId: registry.value,
      sasContractId: sasInput.value || undefined,
      indexerContractId: indexerInput.value || undefined,
    });
    if (!result.ok) {
      setStatus(result.errors.join(" "), "error");
      return;
    }
    writeStorage(options.storage, result.config);
    options.replaceUrl?.(configToQuery(result.config));
    connectBtn.disabled = true;
    const attestCallers = createAttestationCallers(result.config);
    void connect(createCaller(result.config), result.config.rpcUrl, attestCallers).finally(
      () => (connectBtn.disabled = false),
    );
  });

  demoBtn.addEventListener("click", () => {
    registry.value = DEMO_REGISTRY_ID;
    sasInput.value = DEMO_SAS_CONTRACT_ID;
    indexerInput.value = DEMO_INDEXER_CONTRACT_ID;
    const attestCallers = createDemoAttestationCallers();
    void connect(createDemoCaller(), "demo data (offline)", attestCallers);
  });

  loadMore.addEventListener("click", () => void loadSchemaPage());
  filter.addEventListener("input", renderSchemaListPane);

  lookup.addEventListener("submit", (event) => {
    event.preventDefault();
    const uid = normalizeUid(lookupUid.value);
    if (!isUidHex(uid)) {
      setStatus("A schema UID is 64 hexadecimal characters.", "error");
      return;
    }
    const reader = schemaState.reader;
    if (!reader) {
      setStatus("Connect to a registry first.", "error");
      return;
    }
    const generation = schemaState.generation;
    void reader.getSchema(uid).then(
      (record) => {
        if (generation !== schemaState.generation) return;
        if (!record) {
          detail.replaceChildren(
            h(
              "p",
              { class: "muted" },
              "No active schema with that UID. It was never registered, or it has been deprecated.",
            ),
          );
          setStatus("Schema not found.", "info");
          return;
        }
        if (!schemaState.schemas.some((s) => s.uid === record.uid)) schemaState.schemas.push(record);
        void selectSchema(record);
        setStatus("Schema found.", "ok");
      },
      (err: Error) => setStatus(err.message, "error"),
    );
  });

  // --- attestation search form -------------------------------------------
  attestSearchForm.addEventListener("submit", (event) => {
    event.preventDefault();
    // Persist search query in URL.
    const q = attestSearch.value.trim();
    const url = new URL(doc.defaultView?.location.href ?? "http://localhost/");
    if (q) {
      url.searchParams.set("attest-q", q);
    } else {
      url.searchParams.delete("attest-q");
    }
    options.replaceUrl?.(`?${url.searchParams.toString()}`);

    attestState.records = [];
    attestState.selectedUid = undefined;
    attestDetail.replaceChildren(h("p", { class: "muted" }, "Search for attestations above."));
    void runAttestationSearch();
  });

  attestFilter.addEventListener("input", renderAttestationListPane);

  // --- tabs --------------------------------------------------------------
  const verifyPanel = byId(doc, "verify");
  const tabVerify = byId<HTMLButtonElement>(doc, "tab-verify");

  const tabs = [
    { tab: byId<HTMLButtonElement>(doc, "tab-browse"), panel: byId(doc, "browse") },
    { tab: byId<HTMLButtonElement>(doc, "tab-validate"), panel: byId(doc, "validate") },
    { tab: byId<HTMLButtonElement>(doc, "tab-attest"), panel: byId(doc, "attest") },
    { tab: byId<HTMLButtonElement>(doc, "tab-designer"), panel: byId(doc, "designer") },
    { tab: tabVerify, panel: verifyPanel },
  ];

  const tabStream = doc.getElementById("tab-stream") as HTMLButtonElement | null;
  const panelStream = doc.getElementById("stream");
  if (tabStream && panelStream) {
    tabs.push({ tab: tabStream, panel: panelStream });
  }

  function switchTab(targetTab: HTMLButtonElement) {
    for (const t of tabs) {
      const active = t.tab === targetTab;
      t.tab.setAttribute("aria-selected", String(active));
      t.panel.hidden = !active;
    }
  }

  for (const { tab } of tabs) {
    tab.addEventListener("click", () => switchTab(tab));
  }

  function showQrPanel() {
    verifyPanel.replaceChildren(
      renderQrCodeGeneratorPanel(registry.value || undefined, (q) => showMobileVerify(q)),
    );
  }

  function showMobileVerify(query: AttestationVerificationQuery) {
    switchTab(tabVerify);
    verifyPanel.replaceChildren(renderMobileVerificationView(query, () => showQrPanel()));
  }

  showQrPanel();

  // Check for deep-link verification URL parameter (e.g. ?verify=1&uid=...)
  const deepLink = parseAttestationDeepLink(search);
  if (deepLink) {
    showMobileVerify(deepLink);
  }

  // --- draft validator ---------------------------------------------------
  function renderDraft() {
    const result = parseSchema(draft.value);
    draftResult.replaceChildren(renderValidation(result), renderFieldTable(result.fields));
  }
  draft.addEventListener("input", renderDraft);
  renderDraft();
  mountDesigner(doc);

  // `?demo=1` opens straight into the offline fixtures (handy for sharing a preview).
  if (new URLSearchParams(search).get("demo") === "1") demoBtn.click();

  // `?tab=attest` opens the attestations tab directly.
  if (new URLSearchParams(search).get("tab") === "attest") {
    byId<HTMLButtonElement>(doc, "tab-attest").click();
  }

  return { schemaState, attestState, connect, loadSchemaPage, stopPolling };
}
