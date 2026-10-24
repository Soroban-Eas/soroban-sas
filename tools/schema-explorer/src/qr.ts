import QRCode from "qrcode";
import { isUidHex, normalizeUid } from "./hex.js";

export interface VerificationLink {
  uid: string;
  network: string;
  sasContractId: string;
}

export interface Branding {
  name: string;
  accent: string;
  qrDark: string;
  qrLight: string;
}

export const DEFAULT_BRANDING: Branding = {
  name: "SAS Credentials",
  accent: "#2f5bd3",
  qrDark: "#1c1d1f",
  qrLight: "#ffffff",
};

/** Builds the mobile verification URL encoded in a credential QR code. */
export function buildVerificationUrl(
  link: VerificationLink,
  base: string = "https://example.invalid/",
): string {
  const url = new URL(base);
  const params = new URLSearchParams({
    verify: "1",
    uid: normalizeUid(link.uid),
    network: link.network,
    sas: link.sasContractId,
  });
  url.search = params.toString();
  return url.toString();
}

/** Parses a verification URL query, returning null for non-verify or bad UIDs. */
export function parseVerificationSearch(
  search: string,
  allowedNetworks: readonly string[] = ["testnet", "futurenet", "mainnet", "local"],
): VerificationLink | null {
  const params = new URLSearchParams(search);
  if (params.get("verify") !== "1") return null;

  const uid = params.get("uid") ?? "";
  const network = params.get("network") ?? "";
  const sasContractId = params.get("sas") ?? "";
  if (!isUidHex(uid) || !network || !allowedNetworks.includes(network) || !sasContractId) {
    return null;
  }

  return { uid: normalizeUid(uid), network, sasContractId };
}

/** Returns a CSP-safe data URL containing an SVG QR code. */
export async function qrDataUrl(
  text: string,
  branding: Branding = DEFAULT_BRANDING,
): Promise<string> {
  const svg = await QRCode.toString(text, {
    type: "svg",
    errorCorrectionLevel: "M",
    margin: 2,
    width: 320,
    color: { dark: branding.qrDark, light: branding.qrLight },
  });
  return `data:image/svg+xml;base64,${Buffer.from(svg, "utf8").toString("base64")}`;
}
