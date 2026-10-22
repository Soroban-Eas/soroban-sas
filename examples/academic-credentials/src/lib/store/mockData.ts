/**
 * Mock data store for offline demo mode and local development.
 * Contains pre-populated academic credentials with various states (Valid, Revoked, Expired).
 */

import { encodeAcademicData, ACADEMIC_CREDENTIAL_SCHEMA } from "../sas/schema";
import { AcademicAttestationRecord, CredentialStatus } from "../sas/types";

export const MOCK_UNIVERSITIES = [
  {
    name: "Massachusetts Institute of Technology (MIT)",
    address: "GDMITX4S5C6YJ7H8Z9N0123456789ABCDEFGHJKMNPQRSTUVWXYZA",
    logo: "🏛️",
    verified: true,
  },
  {
    name: "Stanford University",
    address: "GDSTANF7U8V9W0X1Y2Z3456789ABCDEFGHJKMNPQRSTUVWXYZA12",
    logo: "🌲",
    verified: true,
  },
  {
    name: "Harvard University",
    address: "GDHARV2A3B4C5D6E7F890123456789ABCDEFGHJKMNPQRSTUVWXY",
    logo: "🎓",
    verified: true,
  },
  {
    name: "Stellar Developer Academy",
    address: "GCAKQQH7GRMMREU44ZOBMU2JJWCT4I5YRYXBWCWLQYAW2QYAF7Q2",
    logo: "⭐",
    verified: true,
  },
];

export const MOCK_SCHEMA_UID =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

export const DEMO_STUDENT_ADDRESS_1 =
  "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVXYZ";
export const DEMO_STUDENT_ADDRESS_2 =
  "GBBM32U5N3L2Z5G4V6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5";

const now = Math.floor(Date.now() / 1000);
const oneYear = 365 * 24 * 60 * 60;

// Seed credentials
const INITIAL_CREDENTIALS: AcademicAttestationRecord[] = [
  {
    uid: "a1c8901f44e1837d99be8217354921dfbc85e78393c042078bb0920412df7189",
    schema_uid: MOCK_SCHEMA_UID,
    time: now - 30 * 24 * 3600, // 30 days ago
    expiration_time: 0, // Never expires
    revocation_time: 0,
    ref_uid: "0000000000000000000000000000000000000000000000000000000000000000",
    recipient: DEMO_STUDENT_ADDRESS_1,
    attester: MOCK_UNIVERSITIES[0].address, // MIT
    revocable: true,
    data: encodeAcademicData({
      degree: "Bachelor of Science in Computer Science",
      institution: "Massachusetts Institute of Technology (MIT)",
      graduation_year: 2024,
      gpa: "3.94 / 4.0",
      student_name: "Alex Thorne",
      honors: "Summa Cum Laude",
      credential_id: "MIT-EECS-2024-8842",
    }),
    valid_from: 0,
    credential: {
      degree: "Bachelor of Science in Computer Science",
      institution: "Massachusetts Institute of Technology (MIT)",
      graduation_year: 2024,
      gpa: "3.94 / 4.0",
      student_name: "Alex Thorne",
      honors: "Summa Cum Laude",
      credential_id: "MIT-EECS-2024-8842",
    },
    status: "VALID",
    statusMessage: "Active degree credential verified by issuing authority.",
  },
  {
    uid: "b890f551c4a2371289de0487561849aed0398410294821aefb90428174591a23",
    schema_uid: MOCK_SCHEMA_UID,
    time: now - 90 * 24 * 3600, // 90 days ago
    expiration_time: 0,
    revocation_time: 0,
    ref_uid: "0000000000000000000000000000000000000000000000000000000000000000",
    recipient: DEMO_STUDENT_ADDRESS_1,
    attester: MOCK_UNIVERSITIES[1].address, // Stanford
    revocable: true,
    data: encodeAcademicData({
      degree: "Master of Science in Artificial Intelligence",
      institution: "Stanford University",
      graduation_year: 2025,
      gpa: "4.0 / 4.0",
      student_name: "Alex Thorne",
      honors: "Dean's High Honors",
      credential_id: "STAN-CS-AI-9912",
    }),
    valid_from: 0,
    credential: {
      degree: "Master of Science in Artificial Intelligence",
      institution: "Stanford University",
      graduation_year: 2025,
      gpa: "4.0 / 4.0",
      student_name: "Alex Thorne",
      honors: "Dean's High Honors",
      credential_id: "STAN-CS-AI-9912",
    },
    status: "VALID",
    statusMessage: "Active degree credential verified by issuing authority.",
  },
  {
    uid: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    schema_uid: MOCK_SCHEMA_UID,
    time: now - 400 * 24 * 3600, // Issued over a year ago
    expiration_time: now - 35 * 24 * 3600, // Expired 35 days ago
    revocation_time: 0,
    ref_uid: "0000000000000000000000000000000000000000000000000000000000000000",
    recipient: DEMO_STUDENT_ADDRESS_2,
    attester: MOCK_UNIVERSITIES[2].address, // Harvard
    revocable: true,
    data: encodeAcademicData({
      degree: "Certificate in Quantitative Financial Modeling",
      institution: "Harvard University",
      graduation_year: 2023,
      gpa: "Pass with Distinction",
      student_name: "Elena Rostova",
      honors: "Executive Certificate",
      credential_id: "HVD-EXEC-2023-102",
    }),
    valid_from: 0,
    credential: {
      degree: "Certificate in Quantitative Financial Modeling",
      institution: "Harvard University",
      graduation_year: 2023,
      gpa: "Pass with Distinction",
      student_name: "Elena Rostova",
      honors: "Executive Certificate",
      credential_id: "HVD-EXEC-2023-102",
    },
    status: "EXPIRED",
    statusMessage: "Credential has expired and is no longer valid for compliance.",
  },
  {
    uid: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
    schema_uid: MOCK_SCHEMA_UID,
    time: now - 120 * 24 * 3600,
    expiration_time: 0,
    revocation_time: now - 10 * 24 * 3600, // Revoked 10 days ago
    ref_uid: "0000000000000000000000000000000000000000000000000000000000000000",
    recipient: DEMO_STUDENT_ADDRESS_2,
    attester: MOCK_UNIVERSITIES[3].address, // Stellar Academy
    revocable: true,
    data: encodeAcademicData({
      degree: "Certified Soroban Smart Contract Engineer",
      institution: "Stellar Developer Academy",
      graduation_year: 2024,
      gpa: "3.2 / 4.0",
      student_name: "Jordan Vance",
      honors: "Revoked for Academic Honor Code Violation",
      credential_id: "STA-CERT-2024-004",
    }),
    valid_from: 0,
    credential: {
      degree: "Certified Soroban Smart Contract Engineer",
      institution: "Stellar Developer Academy",
      graduation_year: 2024,
      gpa: "3.2 / 4.0",
      student_name: "Jordan Vance",
      honors: "Revoked for Academic Honor Code Violation",
      credential_id: "STA-CERT-2024-004",
    },
    status: "REVOKED",
    statusMessage: "Attestation was revoked by the issuing institution on-chain.",
  },
];

// In-memory store (persists across API calls in the same server runtime)
let credentialsStore: AcademicAttestationRecord[] = [...INITIAL_CREDENTIALS];

export function getMockCredentials(): AcademicAttestationRecord[] {
  return [...credentialsStore];
}

export function getMockCredentialByUid(uid: string): AcademicAttestationRecord | undefined {
  const clean = uid.trim().toLowerCase();
  return credentialsStore.find((c) => c.uid.toLowerCase() === clean);
}

export function getMockCredentialsByRecipient(recipient: string): AcademicAttestationRecord[] {
  const clean = recipient.trim();
  return credentialsStore.filter(
    (c) => c.recipient.toLowerCase() === clean.toLowerCase()
  );
}

export function addMockCredential(record: AcademicAttestationRecord): void {
  // Prepend so newest appears first
  credentialsStore = [record, ...credentialsStore.filter((c) => c.uid !== record.uid)];
}

export function revokeMockCredential(uid: string): boolean {
  const index = credentialsStore.findIndex((c) => c.uid.toLowerCase() === uid.toLowerCase());
  if (index >= 0) {
    const cred = credentialsStore[index];
    if (!cred.revocable) return false;
    cred.revocation_time = Math.floor(Date.now() / 1000);
    cred.status = "REVOKED";
    cred.statusMessage = "Attestation was revoked by the issuing institution.";
    return true;
  }
  return false;
}
