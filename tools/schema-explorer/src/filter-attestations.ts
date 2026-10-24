// Client-side filter for loaded attestation records.
//
// Every whitespace-separated term must match (case-insensitively) the UID,
// schema UID, recipient, attester, or the hex-encoded data payload.
//
// Special flag terms:
//   status:active    – only active (non-expired, non-revoked) records
//   status:expired   – only expired records
//   status:revoked   – only revoked records

import type { AttestationRecord } from "./attestation.js";
import { attestationStatus } from "./attestation.js";

export function filterAttestations(
  records: readonly AttestationRecord[],
  query: string,
): AttestationRecord[] {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [...records];

  return records.filter((record) => {
    const status = attestationStatus(record);
    const haystack = [
      record.uid,
      record.schemaUid,
      record.recipient.toLowerCase(),
      record.attester.toLowerCase(),
      record.data.toLowerCase(),
    ];

    return terms.every((term) => {
      const statusFlag = /^status:(active|expired|revoked)$/.exec(term);
      if (statusFlag) return status === statusFlag[1];

      const revocableFlag = /^revocable:(yes|no|true|false)$/.exec(term);
      if (revocableFlag) {
        const want = revocableFlag[1] === "yes" || revocableFlag[1] === "true";
        return record.revocable === want;
      }

      return haystack.some((h) => h.includes(term));
    });
  });
}
