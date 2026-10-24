import { describe, expect, it } from "vitest";
import {
  DEFAULT_BRANDING,
  buildVerificationUrl,
  parseVerificationSearch,
  qrDataUrl,
} from "../src/qr.js";

const UID = "a".repeat(64);

describe("verification QR links (#568)", () => {
  it("encodes the UID, network, and SAS contract in the verification URL", () => {
    const url = buildVerificationUrl(
      { uid: `0x${UID.toUpperCase()}`, network: "testnet", sasContractId: "CABC" },
      "https://explorer.example/",
    );

    expect(url).toBe(
      `https://explorer.example/?verify=1&uid=${UID}&network=testnet&sas=CABC`,
    );
    expect(parseVerificationSearch(new URL(url).search)).toEqual({
      uid: UID,
      network: "testnet",
      sasContractId: "CABC",
    });
  });

  it("rejects malformed or unknown verification parameters", () => {
    expect(parseVerificationSearch("?uid=" + UID)).toBeNull();
    expect(parseVerificationSearch(`?verify=1&uid=not-hex&network=testnet&sas=CABC`)).toBeNull();
    expect(parseVerificationSearch(`?verify=1&uid=${UID}&network=moon&sas=CABC`)).toBeNull();
    expect(parseVerificationSearch(`?verify=1&uid=${UID}&network=testnet`)).toBeNull();
  });

  it("renders a CSP-safe SVG data URL", async () => {
    const dataUrl = await qrDataUrl("https://explorer.example/?verify=1", DEFAULT_BRANDING);
    expect(dataUrl.startsWith("data:image/svg+xml;base64,")).toBe(true);
    expect(dataUrl.length).toBeGreaterThan(200);
  });
});
