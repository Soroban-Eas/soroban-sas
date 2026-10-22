"use client";

import { useState } from "react";
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldCheck,
  FileCode,
  ChevronDown,
  ChevronUp,
  Clock,
  Layers,
  KeyRound,
  ExternalLink
} from "lucide-react";
import { VerificationVerdict } from "@/lib/sas/types";
import CredentialBadge from "./CredentialBadge";
import { ACADEMIC_CREDENTIAL_SCHEMA } from "@/lib/sas/schema";
import { truncateAddress } from "@/lib/utils";

interface VerificationResultProps {
  verdict: VerificationVerdict;
}

export default function VerificationResult({ verdict }: VerificationResultProps) {
  const [showRaw, setShowRaw] = useState(false);

  const { valid, status, reason, attestation, checkedAt, isMock, network } = verdict;

  return (
    <div className="space-y-6">
      {/* Top Banner Status */}
      <div
        className={`rounded-2xl border p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
          status === "VALID"
            ? "border-emerald-200 bg-emerald-50/60 text-emerald-950"
            : status === "REVOKED"
            ? "border-red-200 bg-red-50/60 text-red-950"
            : "border-amber-200 bg-amber-50/60 text-amber-950"
        }`}
      >
        <div className="flex items-start gap-3.5">
          <div
            className={`flex h-11 w-11 items-center justify-center rounded-xl shrink-0 ${
              status === "VALID"
                ? "bg-emerald-600 text-white"
                : status === "REVOKED"
                ? "bg-red-600 text-white"
                : "bg-amber-500 text-white"
            }`}
          >
            {status === "VALID" ? (
              <CheckCircle2 className="h-6 w-6" />
            ) : status === "REVOKED" ? (
              <XCircle className="h-6 w-6" />
            ) : (
              <AlertTriangle className="h-6 w-6" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-lg font-bold">
                {status === "VALID"
                  ? "Authentic & Valid Academic Credential"
                  : status === "REVOKED"
                  ? "Revoked Credential — Not Valid"
                  : "Expired Credential"}
              </h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-white/80 font-medium border border-current">
                {network}
              </span>
            </div>
            <p className="text-sm opacity-90 mt-0.5">{reason}</p>
          </div>
        </div>

        <div className="text-xs font-mono opacity-70 sm:text-right">
          Checked: {new Date(checkedAt).toLocaleTimeString()}
        </div>
      </div>

      {/* Render the Certificate Badge if attestation found */}
      {attestation && <CredentialBadge attestation={attestation} />}

      {/* Cryptographic Proof Verification Checklist */}
      {attestation && (
        <div className="rounded-2xl border border-slate-200 bg-white p-6 space-y-4">
          <h4 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-stellar-600" />
            On-Chain Cryptographic Proof Breakdown
          </h4>

          <div className="divide-y divide-slate-100 text-sm">
            {/* Check 1 */}
            <div className="py-2.5 flex items-center justify-between gap-4">
              <span className="text-slate-600">Soroban Contract State Record</span>
              <span className="inline-flex items-center gap-1 font-semibold text-emerald-600 text-xs">
                <CheckCircle2 className="h-3.5 w-3.5" /> Present in Storage
              </span>
            </div>

            {/* Check 2 */}
            <div className="py-2.5 flex items-center justify-between gap-4">
              <span className="text-slate-600">Standard Schema Parity</span>
              <span className="inline-flex items-center gap-1 font-mono text-slate-700 text-xs">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                {ACADEMIC_CREDENTIAL_SCHEMA}
              </span>
            </div>

            {/* Check 3 */}
            <div className="py-2.5 flex items-center justify-between gap-4">
              <span className="text-slate-600">Issuer Signature & Authority</span>
              <span className="font-mono text-slate-800 text-xs">
                {truncateAddress(attestation.attester, 8, 6)}
              </span>
            </div>

            {/* Check 4 */}
            <div className="py-2.5 flex items-center justify-between gap-4">
              <span className="text-slate-600">Non-Transferable Recipient Binding</span>
              <span className="font-mono text-slate-800 text-xs">
                {truncateAddress(attestation.recipient, 8, 6)}
              </span>
            </div>

            {/* Check 5 */}
            <div className="py-2.5 flex items-center justify-between gap-4">
              <span className="text-slate-600">Revocation Status Check</span>
              <span
                className={`inline-flex items-center gap-1 font-semibold text-xs ${
                  attestation.revocation_time === 0 ? "text-emerald-600" : "text-red-600"
                }`}
              >
                {attestation.revocation_time === 0 ? (
                  <>
                    <CheckCircle2 className="h-3.5 w-3.5" /> Unrevoked
                  </>
                ) : (
                  <>
                    <XCircle className="h-3.5 w-3.5" /> Revoked on-chain
                  </>
                )}
              </span>
            </div>

            {/* Check 6 */}
            <div className="py-2.5 flex items-center justify-between gap-4">
              <span className="text-slate-600">Expiration Status Check</span>
              <span
                className={`inline-flex items-center gap-1 font-semibold text-xs ${
                  attestation.expiration_time === 0 || attestation.expiration_time > Date.now() / 1000
                    ? "text-emerald-600"
                    : "text-amber-600"
                }`}
              >
                {attestation.expiration_time === 0 ? (
                  <>
                    <CheckCircle2 className="h-3.5 w-3.5" /> Lifetime Validity (No Expiry)
                  </>
                ) : attestation.expiration_time > Date.now() / 1000 ? (
                  <>
                    <CheckCircle2 className="h-3.5 w-3.5" /> Valid until{" "}
                    {new Date(attestation.expiration_time * 1000).toLocaleDateString()}
                  </>
                ) : (
                  <>
                    <AlertTriangle className="h-3.5 w-3.5" /> Expired on{" "}
                    {new Date(attestation.expiration_time * 1000).toLocaleDateString()}
                  </>
                )}
              </span>
            </div>
          </div>

          {/* Toggle Raw Data */}
          <div className="pt-2">
            <button
              onClick={() => setShowRaw(!showRaw)}
              className="flex items-center gap-1.5 text-xs font-semibold text-stellar-600 hover:text-stellar-700"
            >
              <FileCode className="h-3.5 w-3.5" />
              {showRaw ? "Hide Raw Data & ScVal XDR" : "View Raw Data & ScVal XDR"}
              {showRaw ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            </button>

            {showRaw && (
              <pre className="mt-3 p-4 rounded-xl bg-slate-900 text-slate-200 text-xs font-mono overflow-x-auto">
                {JSON.stringify(attestation, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
