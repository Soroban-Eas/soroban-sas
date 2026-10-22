/**
 * Academic Credential Schema definitions and data encoders/decoders for Soroban SAS.
 */

import { AcademicCredentialData } from "./types";

/**
 * The canonical schema string registered in the Soroban SAS SchemaRegistry.
 * Matches the required fields: (degree, institution, graduation_year, gpa).
 */
export const ACADEMIC_CREDENTIAL_SCHEMA =
  "degree String, institution String, graduation_year u32, gpa String";

/**
 * Standard Resolver address for non-transferable academic credentials.
 * Defaults to zero address / no resolver hook needed.
 */
export const ZERO_ADDRESS = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/**
 * Encodes academic credential fields into a hex-encoded UTF-8 JSON payload
 * suitable for `SAS::attest`'s `data: Bytes` parameter.
 */
export function encodeAcademicData(data: AcademicCredentialData): string {
  const payload = {
    degree: data.degree.trim(),
    institution: data.institution.trim(),
    graduation_year: Number(data.graduation_year),
    gpa: data.gpa.trim(),
    student_name: data.student_name?.trim() || undefined,
    honors: data.honors?.trim() || undefined,
    credential_id: data.credential_id?.trim() || undefined,
    schema: ACADEMIC_CREDENTIAL_SCHEMA,
    standard: "SOROBAN-SAS-ACADEMIC-V1",
  };

  const jsonString = JSON.stringify(payload);
  const encoder = new TextEncoder();
  const bytes = encoder.encode(jsonString);

  // Return as lowercase hex string
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Decodes a hex string payload into structured AcademicCredentialData.
 */
export function decodeAcademicData(hexString: string): AcademicCredentialData | null {
  try {
    const cleanHex = hexString.startsWith("0x") ? hexString.slice(2) : hexString;
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
    }

    const decoder = new TextDecoder();
    const jsonString = decoder.decode(bytes);
    const parsed = JSON.parse(jsonString);

    if (
      typeof parsed.degree === "string" &&
      typeof parsed.institution === "string" &&
      typeof parsed.graduation_year !== "undefined" &&
      typeof parsed.gpa === "string"
    ) {
      return {
        degree: parsed.degree,
        institution: parsed.institution,
        graduation_year: Number(parsed.graduation_year),
        gpa: parsed.gpa,
        student_name: parsed.student_name,
        honors: parsed.honors,
        credential_id: parsed.credential_id,
      };
    }
    return null;
  } catch (err) {
    console.error("Failed to decode academic data:", err);
    return null;
  }
}
