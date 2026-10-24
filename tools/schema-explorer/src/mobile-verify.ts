// Mobile-first, high-contrast attestation verification view.
// Optimized for handheld scanning at events, ticketing booths, and in-person checks.

import {
  verifyAttestation,
  type AttestationVerificationQuery,
  type VerificationResult,
  type VerificationState,
} from "./attestation.js";
import { shorten } from "./hex.js";
import { h } from "./view.js";

function getBadgeConfig(state: VerificationState) {
  switch (state) {
    case "valid":
      return {
        class: "badge-valid",
        icon: "✓",
        title: "VERIFIED VALID",
        subtitle: "Attestation is confirmed active on the Stellar/Soroban ledger.",
      };
    case "revoked":
      return {
        class: "badge-revoked",
        icon: "✕",
        title: "REVOKED",
        subtitle: "This attestation has been explicitly revoked by the issuer.",
      };
    case "expired":
      return {
        class: "badge-expired",
        icon: "⏱",
        title: "EXPIRED",
        subtitle: "This attestation has passed its recorded expiration timestamp.",
      };
    case "offline_valid":
      return {
        class: "badge-offline",
        icon: "🛡",
        title: "OFFLINE VERIFIED",
        subtitle: "Cryptographically verified offline via authentic Ed25519 signature.",
      };
    case "offline_invalid":
      return {
        class: "badge-revoked",
        icon: "⚠",
        title: "INVALID SIGNATURE",
        subtitle: "Cryptographic signature does not match attester key.",
      };
    case "not_found":
      return {
        class: "badge-not-found",
        icon: "?",
        title: "NOT FOUND",
        subtitle: "Attestation UID does not exist on-chain.",
      };
    case "error":
    default:
      return {
        class: "badge-error",
        icon: "!",
        title: "VERIFICATION ERROR",
        subtitle: "Unable to complete on-chain verification check.",
      };
  }
}

/** Renders the streamlined mobile verification screen. */
export function renderMobileVerificationView(
  query: AttestationVerificationQuery,
  onBack?: () => void,
): HTMLElement {
  const container = h("div", { class: "mobile-verify-container", role: "region", "aria-label": "Mobile Attestation Verification" });

  const header = h(
    "header",
    { class: "mobile-verify-header" },
    h("span", { class: "mobile-network-tag" }, query.network.toUpperCase()),
    h("h1", { class: "mobile-verify-title" }, "Attestation Check"),
    h("p", { class: "mobile-verify-sub" }, "Soroban Attestation Service"),
  );

  const statusCard = h(
    "div",
    { class: "status-badge-card badge-loading", "aria-live": "assertive" },
    h("div", { class: "badge-icon" }, "…"),
    h("h2", { class: "badge-headline" }, "VERIFYING…"),
    h("p", { class: "badge-description" }, "Querying Soroban contract state…"),
  );

  const detailsList = h("dl", { class: "mobile-details-list" });

  function addRow(label: string, value: string) {
    detailsList.append(
      h(
        "div",
        { class: "mobile-detail-row" },
        h("dt", {}, label),
        h("dd", {}, h("code", {}, value)),
      ),
    );
  }

  addRow("Attestation UID", shorten(query.uid));
  if (query.schemaUid) addRow("Schema UID", shorten(query.schemaUid));
  if (query.attester) addRow("Attester", shorten(query.attester));
  if (query.recipient) addRow("Recipient", shorten(query.recipient));
  addRow("Contract", shorten(query.contract));

  const actions = h(
    "div",
    { class: "mobile-verify-actions" },
    h("button", { type: "button", class: "btn-reverify primary" }, "Re-verify"),
    onBack ? h("button", { type: "button", class: "btn-back" }, "Exit to Explorer") : null,
  );

  const reverifyBtn = actions.querySelector(".btn-reverify") as HTMLButtonElement;
  const backBtn = actions.querySelector(".btn-back") as HTMLButtonElement | null;
  backBtn?.addEventListener("click", () => onBack?.());

  async function executeVerification() {
    statusCard.className = "status-badge-card badge-loading";
    statusCard.replaceChildren(
      h("div", { class: "badge-icon spinner" }, "◌"),
      h("h2", { class: "badge-headline" }, "VERIFYING…"),
      h("p", { class: "badge-description" }, "Checking contract state directly on Soroban RPC…"),
    );

    try {
      const result: VerificationResult = await verifyAttestation(query);
      const badgeConfig = getBadgeConfig(result.state);

      statusCard.className = `status-badge-card ${badgeConfig.class}`;
      statusCard.replaceChildren(
        h("div", { class: "badge-icon" }, badgeConfig.icon),
        h("h2", { class: "badge-headline" }, badgeConfig.title),
        h("p", { class: "badge-description" }, result.message || badgeConfig.subtitle),
        h(
          "div",
          { class: "badge-source-tag" },
          result.source === "on_chain_rpc" ? "⚡ Verified against Soroban RPC" : "🔒 Offline Cryptographic Proof",
        ),
      );

      // Append timestamp if available
      if (result.timestamp) {
        const timeStr = new Date(result.timestamp).toLocaleTimeString();
        statusCard.append(h("small", { class: "verified-timestamp" }, `Verified at ${timeStr}`));
      }
    } catch (err) {
      statusCard.className = "status-badge-card badge-error";
      statusCard.replaceChildren(
        h("div", { class: "badge-icon" }, "!"),
        h("h2", { class: "badge-headline" }, "VERIFICATION FAILED"),
        h("p", { class: "badge-description" }, (err as Error).message),
      );
    }
  }

  reverifyBtn.addEventListener("click", () => void executeVerification());
  void executeVerification();

  container.append(header, statusCard, detailsList, actions);
  return container;
}
