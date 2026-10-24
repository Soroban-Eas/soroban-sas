// Visual schema builder. All user input is rendered as text or native input values.
// No unreviewed transaction is submitted by this editor.
import { h } from "./view.js";
import { validateConfig } from "./config.js";
import { registerSchema, TESTNET_PASSPHRASE } from "./registration.js";
import type { SupportedWallet } from "./wallets.js";
import { computeSchemaUidWasm, DEFAULT_RESOLVER, fromTemplate, reorderFields, TEMPLATE_FIELDS, validateDraft, type DesignerField, type SchemaDraft } from "./designer.js";

function required<T extends HTMLElement>(doc: Document, id: string): T {
  const el = doc.getElementById(id);
  if (!el) throw new Error("Missing schema designer element #" + id);
  return el as T;
}

export function mountDesigner(doc: Document) {
  const rows = required<HTMLElement>(doc, "designer-rows");
  const templates = required<HTMLSelectElement>(doc, "designer-template");
  const add = required<HTMLButtonElement>(doc, "designer-add");
  const resolver = required<HTMLInputElement>(doc, "designer-resolver");
  const revocable = required<HTMLInputElement>(doc, "designer-revocable");
  const schemaText = required<HTMLElement>(doc, "designer-schema");
  const uid = required<HTMLElement>(doc, "designer-uid");
  const validation = required<HTMLElement>(doc, "designer-validation");
  const walletSelect = required<HTMLSelectElement>(doc, "designer-wallet");
  const register = required<HTMLButtonElement>(doc, "designer-register");
  const registerStatus = required<HTMLElement>(doc, "designer-registration-status");
  const rpcInput = required<HTMLInputElement>(doc, "rpc-url");
  const passphraseInput = required<HTMLInputElement>(doc, "passphrase");
  const registryInput = required<HTMLInputElement>(doc, "registry");

  let draft = fromTemplate("KYC");
  let nextId = draft.fields.length + 1;
  let revision = 0;

  for (const name of Object.keys(TEMPLATE_FIELDS)) {
    templates.append(h("option", { value: name }, name));
  }
  templates.value = "KYC";

  async function updatePreview() {
    const current = ++revision;
    const result = validateDraft(draft);
    schemaText.textContent = result.schema;
    validation.replaceChildren();
    for (const item of result.errors) {
      validation.append(h("p", { class: "error-text", role: "alert" }, item));
    }
    if (!result.ok) {
      uid.textContent = "Unavailable until schema and resolver are valid";
      return;
    }
    uid.textContent = "Calculating WebAssembly SHA-256…";
    try {
      const value = await computeSchemaUidWasm(draft);
      if (current === revision) uid.textContent = value;
    } catch (error) {
      if (current === revision) uid.textContent = error instanceof Error ? error.message : String(error);
    }
  }

  function changeField(field: DesignerField, key: "name" | "type" | "description", value: string) {
    field[key] = value;
    const result = validateDraft(draft);
    for (const element of rows.querySelectorAll<HTMLInputElement>("input[data-field-name]")) {
      element.setAttribute("aria-invalid", String(result.duplicateNames.includes(element.value.trim()) || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(element.value)));
    }
    void updatePreview();
  }

  function move(from: number, to: number) {
    draft.fields = reorderFields(draft.fields, from, to);
    renderRows();
  }

  function fieldInput(field: DesignerField, key: "name" | "type" | "description", label: string) {
    const input = h("input", { type: "text", "aria-label": label, value: field[key], ...(key === "name" ? { "data-field-name": field.id } : {}) }) as HTMLInputElement;
    input.addEventListener("input", () => changeField(field, key, input.value));
    return input;
  }

  function renderRows() {
    rows.replaceChildren();
    draft.fields.forEach((field, position) => {
      const row = h("div", { class: "designer-row", draggable: "true", "data-field-id": field.id },
        h("span", { class: "drag-handle", title: "Drag to reorder" }, "↕"),
        fieldInput(field, "name", `Field ${position + 1} name`),
        fieldInput(field, "type", `Field ${position + 1} type`),
        fieldInput(field, "description", `Field ${position + 1} description tag (not on-chain)`),
      );
      const actions = h("span", { class: "designer-actions" });
      const up = h("button", { type: "button", "aria-label": `Move field ${position + 1} up` }, "↑") as HTMLButtonElement;
      up.disabled = position === 0;
      up.addEventListener("click", () => move(position, position - 1));
      const down = h("button", { type: "button", "aria-label": `Move field ${position + 1} down` }, "↓") as HTMLButtonElement;
      down.disabled = position === draft.fields.length - 1;
      down.addEventListener("click", () => move(position, position + 1));
      const remove = h("button", { type: "button", "aria-label": `Remove field ${position + 1}` }, "×");
      remove.addEventListener("click", () => {
        draft.fields.splice(position, 1);
        renderRows();
      });
      actions.append(up, down, remove);
      row.append(actions);
      row.addEventListener("dragstart", (event) => {
        event.dataTransfer?.setData("text/plain", String(position));
        if (event.dataTransfer) event.dataTransfer.effectAllowed = "move";
      });
      row.addEventListener("dragover", (event) => event.preventDefault());
      row.addEventListener("drop", (event) => {
        event.preventDefault();
        const source = Number(event.dataTransfer?.getData("text/plain"));
        if (Number.isInteger(source)) move(source, position);
      });
      rows.append(row);
    });
    void updatePreview();
  }

  templates.addEventListener("change", () => {
    draft = fromTemplate(templates.value, resolver.value.trim() || DEFAULT_RESOLVER);
    draft.revocable = revocable.checked;
    nextId = draft.fields.length + 1;
    renderRows();
  });
  add.addEventListener("click", () => {
    if (draft.fields.length >= 64) return;
    draft.fields.push({ id: `field-${nextId++}`, name: `field_${nextId - 1}`, type: "String", description: "" });
    renderRows();
  });
  resolver.addEventListener("input", () => {
    draft.resolver = resolver.value.trim();
    void updatePreview();
  });
  revocable.addEventListener("change", () => {
    draft.revocable = revocable.checked;
    void updatePreview();
  });

  register.addEventListener("click", async () => {
    const result = validateConfig({
      rpcUrl: rpcInput.value,
      networkPassphrase: passphraseInput.value,
      registryContractId: registryInput.value,
    });
    if (!result.ok) {
      registerStatus.textContent = result.errors.join(" ");
      return;
    }
    if (result.config.networkPassphrase !== TESTNET_PASSPHRASE) {
      registerStatus.textContent = "Select Testnet before registering a schema.";
      return;
    }
    const snapshot = { ...draft, fields: draft.fields.map(field => ({ ...field })) };
    if (!validateDraft(snapshot).ok) {
      registerStatus.textContent = "Correct schema validation errors before registration.";
      return;
    }
    // Explicit confirmation before requesting any wallet permission or sending a transaction.
    if (!doc.defaultView?.confirm("Register this schema with your selected wallet on Stellar Testnet? This will submit a real transaction.")) return;
    register.disabled = true;
    registerStatus.textContent = "Requesting wallet connection and Testnet transaction approval…";
    try {
      const { connectWallet } = await import("./wallets.js");
      const wallet = await connectWallet(walletSelect.value as SupportedWallet);
      registerStatus.textContent = "Preparing, simulating, and signing schema registration…";
      const submitted = await registerSchema(snapshot, result.config, wallet);
      registerStatus.textContent = "Registered UID " + submitted.uid + " · Transaction " + submitted.hash
        + " · ledger " + submitted.ledger;
    } catch (error) {
      registerStatus.textContent = "Registration not confirmed: " +
        (error instanceof Error ? error.message : String(error));
    } finally {
      register.disabled = false;
    }
  });

  resolver.value = draft.resolver;
  revocable.checked = draft.revocable;
  renderRows();
  return { getDraft: (): SchemaDraft => ({ ...draft, fields: draft.fields.map(field => ({ ...field })) }), updatePreview };
}
