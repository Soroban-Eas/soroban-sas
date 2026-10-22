"use client";

import { useState } from "react";
import {
  ShieldCheck,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  Sparkles,
  QrCode
} from "lucide-react";
import VerificationResult from "@/components/VerificationResult";
import { VerificationVerdict } from "@/lib/sas/types";

// Pre-configured test UIDs for rapid evaluator testing
const SAMPLE_TEST_CASES = [
  {
    label: "Active Valid Degree (MIT CS)",
    uid: "a1c8901f44e1837d99be8217354921dfbc85e78393c042078bb0920412df7189",
    expected: "VALID",
    color: "border-emerald-300 text-emerald-800 bg-emerald-50/50",
  },
  {
    label: "Active Valid Degree (Stanford AI)",
    uid: "b890f551c4a2371289de0487561849aed0398410294821aefb90428174591a23",
    expected: "VALID",
    color: "border-emerald-300 text-emerald-800 bg-emerald-50/50",
  },
  {
    label: "Revoked Degree Case",
    uid: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
    expected: "REVOKED",
    color: "border-red-300 text-red-800 bg-red-50/50",
  },
  {
    label: "Expired Certificate Case",
    uid: "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    expected: "EXPIRED",
    color: "border-amber-300 text-amber-800 bg-amber-50/50",
  },
];

export default function VerifyPortalPage() {
  const [searchUid, setSearchUid] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [verdict, setVerdict] = useState<VerificationVerdict | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleVerify = async (uidToVerify?: string) => {
    const targetUid = (uidToVerify || searchUid).trim();
    if (!targetUid) return;

    setIsSearching(true);
    setError(null);
    setVerdict(null);

    try {
      const res = await fetch(`/api/verify?uid=${encodeURIComponent(targetUid)}`);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Verification failed");
      }

      setVerdict(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification request failed");
    } finally {
      setIsSearching(false);
    }
  };

  const handleSelectPreset = (uid: string) => {
    setSearchUid(uid);
    handleVerify(uid);
  };

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Page Title */}
      <div className="text-center space-y-3 max-w-2xl mx-auto">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-stellar-50 text-stellar-700 border border-stellar-200 text-xs font-semibold">
          <ShieldCheck className="h-4 w-4 text-stellar-600" />
          Employer & Public Verification Portal
        </div>
        <h1 className="text-3xl sm:text-4xl font-serif font-bold text-slate-900">
          Verify Academic Credentials
        </h1>
        <p className="text-sm text-slate-600">
          Inspect and authenticate degree validity directly against the Soroban SAS smart contracts.
          Verification checks signature authority, expiration, and revocation status in real-time.
        </p>
      </div>

      {/* Search Input Box */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 shadow-sm space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleVerify();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-3.5 h-5 w-5 text-slate-400" />
            <input
              type="text"
              value={searchUid}
              onChange={(e) => setSearchUid(e.target.value)}
              placeholder="Enter 64-character Attestation UID (e.g. a1c8901f...)"
              className="w-full rounded-xl border border-slate-300 pl-11 pr-4 py-3 text-sm font-mono text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
              required
            />
          </div>

          <button
            type="submit"
            disabled={isSearching}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-stellar-600 px-6 py-3 text-sm font-semibold text-white shadow-md shadow-stellar-500/20 hover:bg-stellar-700 disabled:opacity-50 transition-colors"
          >
            {isSearching ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Verifying...
              </>
            ) : (
              <>
                <ShieldCheck className="h-4 w-4" />
                Verify Credential
              </>
            )}
          </button>
        </form>

        {/* Quick Test Pill Buttons */}
        <div className="pt-2 border-t border-slate-100">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-500 mb-2">
            <Sparkles className="h-3.5 w-3.5 text-amber-500" />
            Try Pre-loaded Test Cases:
          </div>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_TEST_CASES.map((tc) => (
              <button
                key={tc.uid}
                type="button"
                onClick={() => handleSelectPreset(tc.uid)}
                className={`text-xs px-3 py-1.5 rounded-lg border font-medium hover:opacity-80 transition-all ${tc.color}`}
              >
                {tc.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-xl bg-red-50 border border-red-200 p-4 text-sm text-red-800 flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-red-500 shrink-0" />
          {error}
        </div>
      )}

      {/* Verification Result Breakdown */}
      {verdict && <VerificationResult verdict={verdict} />}
    </div>
  );
}
