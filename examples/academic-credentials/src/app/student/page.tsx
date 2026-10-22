"use client";

import { useState, useEffect } from "react";
import {
  GraduationCap,
  Award,
  Search,
  ExternalLink,
  ShieldCheck,
  Building,
  Calendar,
  Sparkles,
  Loader2
} from "lucide-react";
import { DEMO_STUDENT_ADDRESS_1, DEMO_STUDENT_ADDRESS_2 } from "@/lib/store/mockData";
import { AcademicAttestationRecord } from "@/lib/sas/types";
import CredentialBadge from "@/components/CredentialBadge";
import { truncateAddress } from "@/lib/utils";

export default function StudentPortalPage() {
  const [studentAddress, setStudentAddress] = useState(DEMO_STUDENT_ADDRESS_1);
  const [credentials, setCredentials] = useState<AcademicAttestationRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

  const fetchStudentCredentials = async (addr: string) => {
    if (!addr.trim()) return;
    setLoading(true);
    setSearched(true);

    try {
      const res = await fetch(`/api/credentials?recipient=${encodeURIComponent(addr.trim())}`);
      if (res.ok) {
        const data = await res.json();
        setCredentials(data);
      } else {
        setCredentials([]);
      }
    } catch (err) {
      console.error("Failed to fetch student credentials:", err);
      setCredentials([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStudentCredentials(DEMO_STUDENT_ADDRESS_1);
  }, []);

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* Title */}
      <div className="text-center space-y-3 max-w-2xl mx-auto">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-stellar-50 text-stellar-700 border border-stellar-200 text-xs font-semibold">
          <GraduationCap className="h-4 w-4 text-stellar-600" />
          Graduate & Student Credential Backpack
        </div>
        <h1 className="text-3xl sm:text-4xl font-serif font-bold text-slate-900">
          My Academic Credentials
        </h1>
        <p className="text-sm text-slate-600">
          View and manage the non-transferable degree attestations issued to your Stellar address.
          Share verified digital badges with employers or embed them on your resume.
        </p>
      </div>

      {/* Address Switcher */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            fetchStudentCredentials(studentAddress);
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-3.5 h-5 w-5 text-slate-400" />
            <input
              type="text"
              value={studentAddress}
              onChange={(e) => setStudentAddress(e.target.value)}
              placeholder="Enter Student Stellar Public Key (G...)"
              className="w-full rounded-xl border border-slate-300 pl-11 pr-4 py-3 text-xs font-mono text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
              required
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-slate-900 px-6 py-3 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50 transition-colors"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Load Degrees"}
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-100 text-xs text-slate-500">
          <span>Sample Student Profiles:</span>
          <button
            type="button"
            onClick={() => {
              setStudentAddress(DEMO_STUDENT_ADDRESS_1);
              fetchStudentCredentials(DEMO_STUDENT_ADDRESS_1);
            }}
            className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium transition-colors"
          >
            Alex Thorne (MIT & Stanford)
          </button>
          <button
            type="button"
            onClick={() => {
              setStudentAddress(DEMO_STUDENT_ADDRESS_2);
              fetchStudentCredentials(DEMO_STUDENT_ADDRESS_2);
            }}
            className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium transition-colors"
          >
            Elena Rostova (Harvard & Academy)
          </button>
        </div>
      </div>

      {/* Credentials List */}
      <div className="space-y-6">
        <h3 className="text-xl font-bold text-slate-900 flex items-center gap-2 border-b border-slate-200 pb-3">
          <Award className="h-5 w-5 text-stellar-600" />
          Conferred Degrees & Certifications ({credentials.length})
        </h3>

        {loading ? (
          <div className="py-16 text-center text-slate-400 flex items-center justify-center gap-2">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading credentials from Soroban SAS...
          </div>
        ) : credentials.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-300 p-12 text-center text-slate-500 space-y-2">
            <GraduationCap className="h-10 w-10 text-slate-300 mx-auto" />
            <p className="font-semibold text-slate-700">No attestations found for this address</p>
            <p className="text-xs text-slate-400">
              Check that your Stellar address is spelled correctly or issue an attestation in the Admin Portal.
            </p>
          </div>
        ) : (
          <div className="space-y-8">
            {credentials.map((cred) => (
              <CredentialBadge key={cred.uid} attestation={cred} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
