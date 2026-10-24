// QR Code generator and deep-linking view for the Explorer.

import { buildAttestationDeepLink, type AttestationVerificationQuery } from "./attestation.js";
import { PRESETS } from "./config.js";
import { downloadQrPng, downloadQrSvg, generateQrSvg } from "./qrcode.js";
import { h } from "./view.js";

export function renderQrCodeGeneratorPanel(
  defaultContractId: string = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
  onOpenMobileView?: (query: AttestationVerificationQuery) => void,
): HTMLElement {
  const panel = h("section", { class: "qr-generator-panel", "aria-labelledby": "qr-gen-title" });

  const heading = h("h2", { id: "qr-gen-title" }, "QR Code Attestation Verification");
  const intro = h(
    "p",
    { class: "muted" },
    "Generate verifiable QR codes for ticketing, badges, and in-person proof checks. Scanning opens the mobile verification view with direct Soroban RPC verification.",
  );

  const form = h("form", { class: "qr-form", novalidate: "true" });

  const uidInput = h("input", {
    type: "text",
    id: "qr-uid",
    placeholder: "64-character Attestation UID hex",
    value: "3b08e2a1490226cfa877c8e9bda53243f721d092d6e4a2bc1d8c199209581f5c",
    required: "true",
    spellcheck: "false",
  }) as HTMLInputElement;

  const contractInput = h("input", {
    type: "text",
    id: "qr-contract",
    placeholder: "SAS Contract ID (C...)",
    value: defaultContractId,
    required: "true",
    spellcheck: "false",
  }) as HTMLInputElement;

  const networkSelect = h("select", { id: "qr-network" }) as HTMLSelectElement;
  for (const p of PRESETS) {
    networkSelect.append(h("option", { value: p.id }, p.label));
  }

  const attesterInput = h("input", {
    type: "text",
    id: "qr-attester",
    placeholder: "Attester Address (optional for offline proof)",
    value: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
    spellcheck: "false",
  }) as HTMLInputElement;

  const generateBtn = h("button", { type: "submit", class: "primary" }, "Generate QR Code");

  form.append(
    h("div", { class: "field-group" }, h("label", { for: "qr-uid" }, "Attestation UID"), uidInput),
    h(
      "div",
      { class: "field-row" },
      h("div", { class: "field-group grow" }, h("label", { for: "qr-contract" }, "SAS Contract ID"), contractInput),
      h("div", { class: "field-group" }, h("label", { for: "qr-network" }, "Network"), networkSelect),
    ),
    h("div", { class: "field-group" }, h("label", { for: "qr-attester" }, "Attester Address (Optional)"), attesterInput),
    generateBtn,
  );

  const resultCard = h("div", { class: "qr-result-card" });
  const qrDisplay = h("div", { class: "qr-display" });
  const deepLinkText = h("input", {
    type: "text",
    class: "qr-deeplink-input",
    readonly: "true",
    "aria-label": "Verification Deep Link",
  }) as HTMLInputElement;

  const exportActions = h(
    "div",
    { class: "qr-actions" },
    h("button", { type: "button", class: "btn-download-svg" }, "Export SVG"),
    h("button", { type: "button", class: "btn-download-png" }, "Export PNG"),
    h("button", { type: "button", class: "btn-copy-link" }, "Copy Deep Link"),
    h("button", { type: "button", class: "btn-test-mobile primary" }, "Open Mobile View"),
  );

  resultCard.append(qrDisplay, h("label", { class: "muted" }, "Deep-Link URL:"), deepLinkText, exportActions);

  function getQuery(): AttestationVerificationQuery {
    return {
      uid: uidInput.value.trim().toLowerCase(),
      contract: contractInput.value.trim(),
      network: networkSelect.value,
      attester: attesterInput.value.trim() || undefined,
    };
  }

  function updateQr() {
    const query = getQuery();
    if (!query.uid || !query.contract) return;

    const deepLinkUrl = buildAttestationDeepLink(query);
    deepLinkText.value = deepLinkUrl;

    const svgMarkup = generateQrSvg(deepLinkUrl, 260, 4);
    qrDisplay.innerHTML = svgMarkup;
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    updateQr();
  });

  const downloadSvgBtn = exportActions.querySelector(".btn-download-svg") as HTMLButtonElement;
  const downloadPngBtn = exportActions.querySelector(".btn-download-png") as HTMLButtonElement;
  const copyLinkBtn = exportActions.querySelector(".btn-copy-link") as HTMLButtonElement;
  const testMobileBtn = exportActions.querySelector(".btn-test-mobile") as HTMLButtonElement;

  downloadSvgBtn.addEventListener("click", () => {
    const url = deepLinkText.value;
    if (url) downloadQrSvg(url, `attestation-${getQuery().uid.slice(0, 10)}.svg`);
  });

  downloadPngBtn.addEventListener("click", () => {
    const url = deepLinkText.value;
    if (url) downloadQrPng(url, `attestation-${getQuery().uid.slice(0, 10)}.png`, 512);
  });

  copyLinkBtn.addEventListener("click", () => {
    if (deepLinkText.value) {
      void navigator.clipboard?.writeText(deepLinkText.value).then(() => {
        copyLinkBtn.textContent = "Copied!";
        setTimeout(() => (copyLinkBtn.textContent = "Copy Deep Link"), 1500);
      });
    }
  });

  testMobileBtn.addEventListener("click", () => {
    const query = getQuery();
    if (onOpenMobileView) {
      onOpenMobileView(query);
    } else {
      window.open(deepLinkText.value, "_blank");
    }
  });

  // Generate initial QR code
  updateQr();

  panel.append(heading, intro, form, resultCard);
  return panel;
}
