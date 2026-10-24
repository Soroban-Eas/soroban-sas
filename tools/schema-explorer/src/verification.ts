export interface VerifiableAttestation {
  uid: string;
  expirationTime: number;
  revocationTime: number;
  validFrom: number;
}

export type AttestationStatus =
  | "valid"
  | "expired"
  | "revoked"
  | "not-yet-valid"
  | "missing";

export interface VerificationSummary {
  status: AttestationStatus;
  label: string;
  detail: string;
}

export function attestationStatus(
  record: VerifiableAttestation | null,
  nowSeconds: number,
): AttestationStatus {
  if (!record) return "missing";
  if (record.revocationTime !== 0) return "revoked";
  if (record.validFrom !== 0 && nowSeconds < record.validFrom) return "not-yet-valid";
  if (record.expirationTime !== 0 && nowSeconds >= record.expirationTime) return "expired";
  return "valid";
}

/** Maps a status to the copy and tone used by the verification landing page. */
export function verificationSummary(status: AttestationStatus): VerificationSummary {
  switch (status) {
    case "valid":
      return {
        status,
        label: "Valid",
        detail: "This credential is active on-chain.",
      };
    case "expired":
      return {
        status,
        label: "Expired",
        detail: "This credential expired and is no longer valid.",
      };
    case "revoked":
      return {
        status,
        label: "Revoked",
        detail: "The issuer revoked this credential.",
      };
    case "not-yet-valid":
      return {
        status,
        label: "Not yet valid",
        detail: "This credential becomes valid at a future ledger time.",
      };
    case "missing":
      return {
        status,
        label: "Not found",
        detail: "No attestation with this UID exists on the selected network.",
      };
  }
}
