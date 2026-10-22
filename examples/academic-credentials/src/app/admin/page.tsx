"use client";

import { useState, useEffect } from "react";
import {
  Building,
  PlusCircle,
  FileCheck2,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ShieldAlert,
  Loader2,
  Clock
} from "lucide-react";
import IssueForm from "@/components/IssueForm";
import { AcademicAttestationRecord } from "@/lib/sas/types";
import { truncateAddress, formatDate } from "@/lib/utils";
import Link from "next/link";

export default function AdminPortalPage() {
  const [credentials, setCredentials] = useState<AcademicAttestationRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [revokingUid, setRevokingUid] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchCredentials = async () => {
    try {
      const res = await fetch("/api/credentials");
      if (res.ok) {
        const data = await res.json();
        setCredentials(data);
      }
    } catch (err) {
      console.error("Failed to fetch credentials:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCredentials();
  }, []);

  const handleRevoke = async (uid: string) => {
    if (!confirm(`Are you sure you want to revoke attestation ${uid}? This is recorded on-chain.`)) {
      return;
    }

    setRevokingUid(uid);
    setActionMessage(null);

    try {
      const res = await fetch("/api/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uid }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to revoke attestation");
      }

      setActionMessage(`Attestation ${uid.slice(0, 10)}... successfully revoked on-chain.`);
      await fetchCredentials();
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to revoke");
    } finally {
      setRevokingUid(null);
    }
  };

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Page Header */}
      <div className="border-b border-slate-200 pb-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-serif font-bold text-slate-900 tracking-tight">
              University Registrar & Admin Portal
            </h1>
            <p className="text-sm text-slate-500 mt-1">
              Issue non-transferable degree attestations, manage student credentials, and administer revocations on Soroban SAS.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs px-3 py-1.5 rounded-full bg-slate-900 text-white font-medium">
              Authority: Registrar Office
            </span>
          </div>
        </div>
      </div>

      {actionMessage && (
        <div className="rounded-xl bg-emerald-50 border border-emerald-200 p-4 text-sm text-emerald-800 flex items-center gap-2">
          <CheckCircle2 className="h-5 w-5 text-emerald-600 shrink-0" />
          {actionMessage}
        </div>
      )}

      {/* Main Issuance Form */}
      <IssueForm />

      {/* Issued Credentials Management Table */}
      <div className="rounded-2xl border border-slate-200 bg-white overflow-hidden shadow-sm space-y-4 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-slate-900 flex items-center gap-2">
              <FileCheck2 className="h-5 w-5 text-stellar-600" />
              Issued Academic Attestations
            </h3>
            <p className="text-xs text-slate-500">
              List of all degrees and certifications issued under the standard academic schema.
            </p>
          </div>

          <button
            onClick={fetchCredentials}
            className="text-xs text-stellar-600 hover:text-stellar-700 font-semibold"
          >
            Refresh
          </button>
        </div>

        {loading ? (
          <div className="py-12 text-center text-slate-400 flex items-center justify-center gap-2">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading credentials...
          </div>
        ) : credentials.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm">
            No credentials issued yet. Use the form above to issue your first academic attestation.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-slate-600">
              <thead className="bg-slate-50 text-xs uppercase font-semibold text-slate-500">
                <tr>
                  <th className="py-3 px-4">Student & Degree</th>
                  <th className="py-3 px-4">Institution</th>
                  <th className="py-3 px-4">Class</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Attestation UID</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {credentials.map((cred) => (
                  <tr key={cred.uid} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-900">
                        {cred.credential.student_name || "Anonymous Graduate"}
                      </div>
                      <div className="text-xs text-slate-500">{cred.credential.degree}</div>
                    </td>
                    <td className="py-3 px-4 text-xs font-medium text-slate-700">
                      {cred.credential.institution}
                    </td>
                    <td className="py-3 px-4 text-xs font-semibold text-slate-700">
                      {cred.credential.graduation_year}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2.5 py-0.5 rounded-full ${
                          cred.status === "VALID"
                            ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                            : cred.status === "REVOKED"
                            ? "bg-red-50 text-red-700 border border-red-200"
                            : "bg-amber-50 text-amber-700 border border-amber-200"
                        }`}
                      >
                        {cred.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-xs">
                      <Link
                        href={`/badge/${cred.uid}`}
                        className="text-stellar-600 hover:underline flex items-center gap-1"
                      >
                        {truncateAddress(cred.uid, 6, 6)}
                        <ExternalLink className="h-3 w-3" />
                      </Link>
                    </td>
                    <td className="py-3 px-4 text-right">
                      {cred.status === "VALID" && cred.revocable && (
                        <button
                          onClick={() => handleRevoke(cred.uid)}
                          disabled={revokingUid === cred.uid}
                          className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium text-red-600 bg-red-50 hover:bg-red-100 rounded-lg transition-colors disabled:opacity-50"
                        >
                          {revokingUid === cred.uid ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          ) : (
                            <Trash2 className="h-3.5 w-3.5" />
                          )}
                          Revoke
                        </button>
                      )}
                      {cred.status === "REVOKED" && (
                        <span className="text-xs text-slate-400 italic">Revoked</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
