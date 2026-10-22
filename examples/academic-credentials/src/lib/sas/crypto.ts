/**
 * Cryptographic helpers for deriving Soroban SAS UIDs in TypeScript.
 */

/**
 * Computes SHA-256 hash using the Web Crypto API or Node crypto.
 */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  if (typeof window === "undefined") {
    // Node.js environment
    const cryptoModule = await import("crypto");
    return cryptoModule.createHash("sha256").update(data).digest("hex");
  }

  // Browser environment
  const arrayBuffer = data.buffer.slice(
    data.byteOffset,
    data.byteOffset + data.byteLength
  ) as ArrayBuffer;
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Derives a deterministic Schema UID matching `soroban_sas_common::schema_uid`.
 */
export async function computeSchemaUid(
  schemaString: string,
  resolverAddress: string,
  revocable: boolean
): Promise<string> {
  const encoder = new TextEncoder();
  const schemaBytes = encoder.encode(schemaString);
  const resolverBytes = encoder.encode(resolverAddress);
  const flagBytes = new Uint8Array([revocable ? 1 : 0]);

  const combined = new Uint8Array(
    schemaBytes.length + resolverBytes.length + flagBytes.length
  );
  combined.set(schemaBytes, 0);
  combined.set(resolverBytes, schemaBytes.length);
  combined.set(flagBytes, schemaBytes.length + resolverBytes.length);

  return sha256Hex(combined);
}

/**
 * Derives a deterministic Attestation UID matching `soroban_sas_common::attestation_uid`.
 * Content-addressed on schemaUid, recipient, attester, and data payload.
 */
export async function computeAttestationUid(
  schemaUid: string,
  recipient: string,
  attester: string,
  dataHex: string
): Promise<string> {
  const encoder = new TextEncoder();
  const schemaBytes = encoder.encode(schemaUid.toLowerCase().trim());
  const recipientBytes = encoder.encode(recipient.trim());
  const attesterBytes = encoder.encode(attester.trim());
  const dataBytes = encoder.encode(dataHex.toLowerCase().trim());

  const combined = new Uint8Array(
    schemaBytes.length + recipientBytes.length + attesterBytes.length + dataBytes.length
  );
  let offset = 0;
  combined.set(schemaBytes, offset);
  offset += schemaBytes.length;
  combined.set(recipientBytes, offset);
  offset += recipientBytes.length;
  combined.set(attesterBytes, offset);
  offset += attesterBytes.length;
  combined.set(dataBytes, offset);

  return sha256Hex(combined);
}
