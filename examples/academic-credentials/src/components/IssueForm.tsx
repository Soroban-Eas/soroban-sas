"use client";

import { useState } from "react";
import {
  GraduationCap,
  Building,
  Calendar,
  Award,
  User,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  Loader2,
  ExternalLink,
  ShieldCheck,
  Send
} from "lucide-react";
import { MOCK_UNIVERSITIES, DEMO_STUDENT_ADDRESS_1, DEMO_STUDENT_ADDRESS_2 } from "@/lib/store/mockData";
import { AcademicAttestationRecord, IssueCredentialRequest } from "@/lib/sas/types";
import CredentialBadge from "./CredentialBadge";

export default function IssueForm() {
  const [formData, setFormData] = useState<IssueCredentialRequest>({
    degree: "Bachelor of Science in Computer Science",
    institution: MOCK_UNIVERSITIES[0].name,
    graduation_year: 2024,
    gpa: "3.85 / 4.0",
    student_name: "Sarah Chen",
    honors: "Magna Cum Laude",
    credential_id: "SIS-2024-CSC-4412",
    recipient: DEMO_STUDENT_ADDRESS_1,
    expiration_days: 0,
    revocable: true,
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issuedRecord, setIssuedRecord] = useState<AcademicAttestationRecord | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      const res = await fetch("/api/issue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to issue credential");
      }

      setIssuedRecord(data.attestation);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to issue credential");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleQuickFill = (preset: "mit" | "stanford" | "academy") => {
    if (preset === "mit") {
      setFormData({
        degree: "Bachelor of Science in Aerospace Engineering",
        institution: "Massachusetts Institute of Technology (MIT)",
        graduation_year: 2024,
        gpa: "3.92 / 4.0",
        student_name: "Maya Lin",
        honors: "Tau Beta Pi Honors",
        credential_id: "MIT-AERO-2024-91",
        recipient: DEMO_STUDENT_ADDRESS_1,
        expiration_days: 0,
        revocable: true,
      });
    } else if (preset === "stanford") {
      setFormData({
        degree: "Master of Science in Computer Science",
        institution: "Stanford University",
        graduation_year: 2025,
        gpa: "3.98 / 4.0",
        student_name: "David K. Miller",
        honors: "Distinction in Research",
        credential_id: "STAN-MSCS-8819",
        recipient: DEMO_STUDENT_ADDRESS_2,
        expiration_days: 0,
        revocable: true,
      });
    } else {
      setFormData({
        degree: "Soroban Smart Contract Developer Certification",
        institution: "Stellar Developer Academy",
        graduation_year: 2024,
        gpa: "98% Score",
        student_name: "Liam O'Connor",
        honors: "Certified Security Auditor",
        credential_id: "STA-CERT-2024-102",
        recipient: DEMO_STUDENT_ADDRESS_1,
        expiration_days: 730, // 2 year validity
        revocable: true,
      });
    }
  };

  return (
    <div className="space-y-8">
      {/* Quick Fill Preset Pills */}
      <div className="rounded-xl bg-slate-50 border border-slate-200 p-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
            <Sparkles className="h-4 w-4 text-amber-500" />
            Quick-Fill Sample Data:
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => handleQuickFill("mit")}
              className="px-3 py-1 text-xs rounded-lg bg-white border border-slate-300 font-medium text-slate-700 hover:bg-slate-100 transition-colors"
            >
              MIT Aero Degree
            </button>
            <button
              type="button"
              onClick={() => handleQuickFill("stanford")}
              className="px-3 py-1 text-xs rounded-lg bg-white border border-slate-300 font-medium text-slate-700 hover:bg-slate-100 transition-colors"
            >
              Stanford MSCS
            </button>
            <button
              type="button"
              onClick={() => handleQuickFill("academy")}
              className="px-3 py-1 text-xs rounded-lg bg-white border border-slate-300 font-medium text-slate-700 hover:bg-slate-100 transition-colors"
            >
              Stellar Academy Cert
            </button>
          </div>
        </div>
      </div>

      {/* Main Issuance Form */}
      <form onSubmit={handleSubmit} className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 shadow-sm space-y-6">
        <div className="border-b border-slate-200 pb-4">
          <h2 className="text-xl font-bold text-slate-900 flex items-center gap-2">
            <GraduationCap className="h-5 w-5 text-stellar-600" />
            Issue Academic Credential
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Converts degree claims into a non-transferable on-chain attestation conforming to the Soroban SAS standard.
          </p>
        </div>

        {error && (
          <div className="rounded-lg bg-red-50 border border-red-200 p-4 flex items-start gap-3 text-sm text-red-800">
            <AlertCircle className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
            <div>
              <span className="font-semibold">Issuance Failed:</span> {error}
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* University / Institution */}
          <div className="space-y-1.5 md:col-span-2">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
              <Building className="h-3.5 w-3.5 text-slate-400" />
              Issuing University / Institution
            </label>
            <select
              value={formData.institution}
              onChange={(e) => setFormData({ ...formData, institution: e.target.value })}
              className="w-full rounded-lg border border-slate-300 bg-white px-3.5 py-2.5 text-sm text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
              required
            >
              {MOCK_UNIVERSITIES.map((u) => (
                <option key={u.name} value={u.name}>
                  {u.logo} {u.name}
                </option>
              ))}
            </select>
          </div>

          {/* Student Recipient Stellar Address */}
          <div className="space-y-1.5 md:col-span-2">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center justify-between">
              <span>Student Stellar Recipient Address (G...)</span>
              <span className="text-[11px] text-slate-400 font-normal">Non-transferable binding</span>
            </label>
            <input
              type="text"
              value={formData.recipient}
              onChange={(e) => setFormData({ ...formData, recipient: e.target.value.trim() })}
              placeholder="e.g. GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVXYZ"
              className="w-full font-mono text-xs rounded-lg border border-slate-300 px-3.5 py-2.5 text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
              required
            />
          </div>

          {/* Degree Title */}
          <div className="space-y-1.5 md:col-span-2">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-700">
              Degree / Program Title
            </label>
            <input
              type="text"
              value={formData.degree}
              onChange={(e) => setFormData({ ...formData, degree: e.target.value })}
              placeholder="e.g. Bachelor of Science in Computer Science"
              className="w-full rounded-lg border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
              required
            />
          </div>

          {/* Student Name */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
              <User className="h-3.5 w-3.5 text-slate-400" />
              Student Full Name
            </label>
            <input
              type="text"
              value={formData.student_name || ""}
              onChange={(e) => setFormData({ ...formData, student_name: e.target.value })}
              placeholder="e.g. Sarah Chen"
              className="w-full rounded-lg border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
            />
          </div>

          {/* Graduation Year */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
              <Calendar className="h-3.5 w-3.5 text-slate-400" />
              Graduation Year (u32)
            </label>
            <input
              type="number"
              value={formData.graduation_year}
              onChange={(e) => setFormData({ ...formData, graduation_year: parseInt(e.target.value) || 2024 })}
              min="1950"
              max="2100"
              className="w-full rounded-lg border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
              required
            />
          </div>

          {/* GPA / Grade Classification */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-700">
              GPA / Grade / Honors
            </label>
            <input
              type="text"
              value={formData.gpa}
              onChange={(e) => setFormData({ ...formData, gpa: e.target.value })}
              placeholder="e.g. 3.90 / 4.0 or First Class"
              className="w-full rounded-lg border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
              required
            />
          </div>

          {/* Honors */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
              <Award className="h-3.5 w-3.5 text-slate-400" />
              Academic Honors (Optional)
            </label>
            <input
              type="text"
              value={formData.honors || ""}
              onChange={(e) => setFormData({ ...formData, honors: e.target.value })}
              placeholder="e.g. Summa Cum Laude"
              className="w-full rounded-lg border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
            />
          </div>

          {/* Internal SIS / Credential ID */}
          <div className="space-y-1.5 md:col-span-2">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-700">
              Registrar Serial / SIS Credential ID
            </label>
            <input
              type="text"
              value={formData.credential_id || ""}
              onChange={(e) => setFormData({ ...formData, credential_id: e.target.value })}
              placeholder="e.g. SIS-DIPLOMA-2024-998"
              className="w-full font-mono text-xs rounded-lg border border-slate-300 px-3.5 py-2.5 text-slate-900 focus:border-stellar-500 focus:outline-none focus:ring-2 focus:ring-stellar-500/20"
            />
          </div>
        </div>

        {/* Submit Actions */}
        <div className="pt-4 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="text-xs text-slate-500 flex items-center gap-1.5">
            <ShieldCheck className="h-4 w-4 text-emerald-600" />
            Automated server-side signing via Soroban SAS Smart Contract
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full sm:w-auto inline-flex items-center justify-center gap-2 rounded-xl bg-stellar-600 px-6 py-3 text-sm font-semibold text-white shadow-md shadow-stellar-500/20 hover:bg-stellar-700 disabled:opacity-50 transition-colors"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Signing & Issuing Attestation...
              </>
            ) : (
              <>
                <Send className="h-4 w-4" />
                Issue Attestation
              </>
            )}
          </button>
        </div>
      </form>

      {/* Issuance Success Result View */}
      {issuedRecord && (
        <div className="rounded-2xl border-2 border-emerald-500/30 bg-emerald-50/20 p-6 sm:p-8 space-y-6">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-emerald-100 text-emerald-700">
              <CheckCircle2 className="h-6 w-6" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-slate-900">
                Academic Credential Successfully Attested!
              </h3>
              <p className="text-xs text-slate-600">
                Attestation UID: <span className="font-mono font-semibold">{issuedRecord.uid}</span>
              </p>
            </div>
          </div>

          <CredentialBadge attestation={issuedRecord} />
        </div>
      )}
    </div>
  );
}
