import { describe, expect, it } from "vitest";
import { attestationStatus, verificationSummary, type VerifiableAttestation } from "../src/verification.js";

const base: VerifiableAttestation = {
  uid: "a".repeat(64),
  expirationTime: 2_000,
  revocationTime: 0,
  validFrom: 1_000,
};

describe("attestation verification status (#568)", () => {
  it("returns valid inside the validity window", () => {
    expect(attestationStatus(base, 1_500)).toBe("valid");
  });

  it("returns not-yet-valid before validFrom", () => {
    expect(attestationStatus(base, 999)).toBe("not-yet-valid");
  });

  it("returns expired at/after expirationTime", () => {
    expect(attestationStatus(base, 2_000)).toBe("expired");
  });

  it("treats a non-zero revocationTime as revoked", () => {
    expect(attestationStatus({ ...base, revocationTime: 1_700 }, 1_500)).toBe("revoked");
  });

  it("returns missing when no record exists", () => {
    expect(attestationStatus(null, 1_500)).toBe("missing");
    expect(verificationSummary("missing").label).toBe("Not found");
  });

  it("does not expire a zero expirationTime", () => {
    expect(attestationStatus({ ...base, expirationTime: 0 }, 9_999_999)).toBe("valid");
  });
});
