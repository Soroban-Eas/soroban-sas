import { describe, expect, it } from "vitest";
import {
  buildAttestationDeepLink,
  parseAttestationDeepLink,
  verifyOfflineSignature,
  type AttestationVerificationQuery,
} from "../src/attestation.js";

describe("Attestation Deep-Linking & Verification (#485)", () => {
  it("builds and parses deep-link verification URLs round-trip", () => {
    const query: AttestationVerificationQuery = {
      uid: "3b08e2a1490226cfa877c8e9bda53243f721d092d6e4a2bc1d8c199209581f5c",
      contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
      network: "testnet",
      attester: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
      time: 1700000000,
      expirationTime: 1800000000,
      revocable: true,
      signature: "00112233aabbcc",
    };

    const link = buildAttestationDeepLink(query, "https://explorer.sas.stellar.org/verify");
    expect(link).toContain("verify=1");
    expect(link).toContain(query.uid);
    expect(link).toContain(query.contract);

    const parsed = parseAttestationDeepLink(new URL(link).search);
    expect(parsed).not.toBeNull();
    expect(parsed?.uid).toBe(query.uid);
    expect(parsed?.contract).toBe(query.contract);
    expect(parsed?.network).toBe("testnet");
    expect(parsed?.attester).toBe(query.attester);
    expect(parsed?.time).toBe(1700000000);
    expect(parsed?.expirationTime).toBe(1800000000);
    expect(parsed?.revocable).toBe(true);
    expect(parsed?.signature).toBe("00112233aabbcc");
  });

  it("detects expired attestation during offline verification", async () => {
    const expiredQuery: AttestationVerificationQuery = {
      uid: "3b08e2a1490226cfa877c8e9bda53243f721d092d6e4a2bc1d8c199209581f5c",
      contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
      network: "testnet",
      attester: "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
      expirationTime: 1000, // Ancient timestamp in the past
      signature: "001122",
    };

    const result = await verifyOfflineSignature(expiredQuery);
    expect(result.state).toBe("expired");
    expect(result.source).toBe("offline_signature");
  });

  it("handles missing signature parameters gracefully", async () => {
    const noSigQuery: AttestationVerificationQuery = {
      uid: "3b08e2a1490226cfa877c8e9bda53243f721d092d6e4a2bc1d8c199209581f5c",
      contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
      network: "testnet",
    };

    const result = await verifyOfflineSignature(noSigQuery);
    expect(result.state).toBe("offline_invalid");
  });
});
