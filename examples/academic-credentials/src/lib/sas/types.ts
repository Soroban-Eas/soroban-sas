/**
 * Types and interfaces for the Soroban SAS Academic Credential dApp.
 */

export interface AcademicCredentialData {
  /** The degree title, e.g., "Bachelor of Science in Computer Science" */
  degree: string;
  /** The issuing university/institution name, e.g., "Stellar Institute of Technology" */
  institution: string;
  /** Year of graduation, e.g., 2024 */
  graduation_year: number;
  /** GPA or honors classification, e.g., "3.92 / 4.0" or "First Class Honours" */
  gpa: string;
  /** Full student name */
  student_name?: string;
  /** Academic honors (e.g. Summa Cum Laude, Dean's List) */
  honors?: string;
  /** Internal Student Information System (SIS) / diploma serial number */
  credential_id?: string;
}

/**
 * Standard Soroban SAS Attestation record matching `soroban_sas_common::Attestation`.
 */
export interface SASAttestation {
  /** 32-byte hash formatted as 64-char lowercase hex */
  uid: string;
  /** 32-byte schema hash */
  schema_uid: string;
  /** Issuance timestamp (Unix seconds) */
  time: number;
  /** Expiration timestamp (Unix seconds), 0 = no expiration */
  expiration_time: number;
  /** Revocation timestamp (Unix seconds), 0 = active / not revoked */
  revocation_time: number;
  /** Optional reference to a previous attestation UID */
  ref_uid: string;
  /** Student's Stellar address (G...) */
  recipient: string;
  /** University issuer Stellar address (G...) */
  attester: string;
  /** Non-transferable & revocability flag */
  revocable: boolean;
  /** Raw hexadecimal payload data */
  data: string;
  /** Timestamp after which attestation becomes valid (0 = immediate) */
  valid_from: number;
}

export type CredentialStatus = "VALID" | "REVOKED" | "EXPIRED" | "NOT_YET_VALID";

/**
 * Decoded Academic Attestation combining on-chain SAS fields and decoded payload.
 */
export interface AcademicAttestationRecord extends SASAttestation {
  credential: AcademicCredentialData;
  status: CredentialStatus;
  statusMessage: string;
}

/**
 * Result returned by the verification engine.
 */
export interface VerificationVerdict {
  valid: boolean;
  status: CredentialStatus;
  reason: string;
  attestation?: AcademicAttestationRecord;
  checkedAt: string;
  isMock: boolean;
  network: string;
}

/**
 * Request payload for server-side automated issuance API.
 */
export interface IssueCredentialRequest {
  recipient: string;
  degree: string;
  institution: string;
  graduation_year: number;
  gpa: string;
  student_name?: string;
  honors?: string;
  credential_id?: string;
  expiration_days?: number;
  revocable?: boolean;
}
