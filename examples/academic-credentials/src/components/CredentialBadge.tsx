"use client";

import { useState } from "react";
import {
  Award,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Copy,
  Check,
  Share2,
  ExternalLink,
  Code2,
  ShieldCheck,
  Calendar,
  Building,
  User,
  GraduationCap
} from "lucide-react";
import { AcademicAttestationRecord, CredentialStatus } from "@/lib/sas/types";
import { truncateAddress, formatDate } from "@/lib/utils";

interface CredentialBadgeProps {
  attestation: AcademicAttestationRecord;
  showActions?: boolean;
}

export default function CredentialBadge({
  attestation,
  showActions = true,
}: CredentialBadgeProps) {
  const [copiedUid, setCopiedUid] = useState(false);
  const [copiedEmbed, setCopiedEmbed] = useState(false);
  const [showEmbedCode, setShowEmbedCode] = useState(false);

  const { credential, status, uid, time, expiration_time, recipient, attester } = attestation;

  const handleCopyUid = () => {
    navigator.clipboard.writeText(uid);
    setCopiedUid(true);
    setTimeout(() => setCopiedUid(false), 2000);
  };

  const embedCode = `<iframe src="${typeof window !== "undefined" ? window.location.origin : ""}/badge/${uid}?embed=true" width="480" height="320" frameborder="0"></iframe>`;

  const handleCopyEmbed = () => {
    navigator.clipboard.writeText(embedCode);
    setCopiedEmbed(true);
    setTimeout(() => setCopiedEmbed(false), 2000);
  };

  const getStatusBadge = (s: CredentialStatus) => {
    switch (s) {
      case "VALID":
        return (
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-300 shadow-sm">
            <CheckCircle2 className="h-4 w-4 text-emerald-600" />
            VERIFIED DEGREE • ACTIVE
          </div>
        );
      case "REVOKED":
        return (
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-red-50 text-red-700 border border-red-300 shadow-sm">
            <XCircle className="h-4 w-4 text-red-600" />
            REVOKED BY ISSUER
          </div>
        );
      case "EXPIRED":
        return (
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-300 shadow-sm">
            <AlertTriangle className="h-4 w-4 text-amber-600" />
            CREDENTIAL EXPIRED
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      {/* Physical Diploma / Digital Certificate Card */}
      <div className="relative overflow-hidden rounded-2xl border-2 border-slate-200/90 bg-gradient-to-b from-white to-slate-50/50 p-6 sm:p-8 shadow-xl shadow-slate-200/50">
        {/* Subtle decorative border corners */}
        <div className="absolute top-0 left-0 w-8 h-8 border-t-4 border-l-4 border-stellar-600/30 rounded-tl-xl" />
        <div className="absolute top-0 right-0 w-8 h-8 border-t-4 border-r-4 border-stellar-600/30 rounded-tr-xl" />
        <div className="absolute bottom-0 left-0 w-8 h-8 border-b-4 border-l-4 border-stellar-600/30 rounded-bl-xl" />
        <div className="absolute bottom-0 right-0 w-8 h-8 border-b-4 border-r-4 border-stellar-600/30 rounded-br-xl" />

        {/* Top Header: Institution & Status */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-5">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-slate-900 text-white shadow-md">
              <Building className="h-6 w-6 text-amber-400" />
            </div>
            <div>
              <h3 className="font-serif text-lg sm:text-xl font-bold text-slate-900 tracking-wide">
                {credential.institution}
              </h3>
              <p className="text-xs text-slate-500 font-sans flex items-center gap-1">
                <ShieldCheck className="h-3.5 w-3.5 text-stellar-600" />
                Accredited Issuing Authority
              </p>
            </div>
          </div>

          <div>{getStatusBadge(status)}</div>
        </div>

        {/* Center: Degree & Award Details */}
        <div className="py-6 text-center space-y-4">
          <p className="text-xs uppercase tracking-widest text-slate-500 font-semibold font-sans">
            Official Non-Transferable Attestation
          </p>

          {credential.student_name && (
            <div>
              <p className="text-xs text-slate-500 font-serif italic">This certifies that</p>
              <h4 className="text-2xl sm:text-3xl font-serif font-bold text-slate-900 my-1">
                {credential.student_name}
              </h4>
              <p className="text-xs text-slate-500 font-serif italic">has been conferred the degree of</p>
            </div>
          )}

          <div className="bg-slate-100/70 py-4 px-6 rounded-xl border border-slate-200 inline-block max-w-xl mx-auto">
            <h2 className="text-xl sm:text-2xl font-serif font-extrabold text-stellar-900">
              {credential.degree}
            </h2>
            {credential.honors && (
              <p className="text-sm font-serif italic text-amber-800 font-medium mt-1">
                Honors: {credential.honors}
              </p>
            )}
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 max-w-lg mx-auto pt-2 text-left">
            <div className="rounded-lg bg-white p-3 border border-slate-200/80 shadow-sm">
              <span className="text-[11px] uppercase font-semibold text-slate-400 block">Class Of</span>
              <span className="text-base font-bold text-slate-800">{credential.graduation_year}</span>
            </div>
            <div className="rounded-lg bg-white p-3 border border-slate-200/80 shadow-sm">
              <span className="text-[11px] uppercase font-semibold text-slate-400 block">Grade / GPA</span>
              <span className="text-base font-bold text-slate-800">{credential.gpa}</span>
            </div>
            <div className="col-span-2 sm:col-span-1 rounded-lg bg-white p-3 border border-slate-200/80 shadow-sm">
              <span className="text-[11px] uppercase font-semibold text-slate-400 block">Issued On</span>
              <span className="text-sm font-semibold text-slate-800">{formatDate(time)}</span>
            </div>
          </div>
        </div>

        {/* Bottom Metadata & Cryptographic Fingerprint */}
        <div className="border-t border-slate-200 pt-5 space-y-3 font-mono text-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between text-slate-600 gap-1 bg-slate-100/80 p-2.5 rounded-lg border border-slate-200">
            <span className="text-slate-500 font-sans font-medium text-[11px] uppercase">
              Attestation UID:
            </span>
            <div className="flex items-center gap-2">
              <span className="text-slate-800 font-semibold select-all break-all sm:break-normal">
                {truncateAddress(uid, 12, 10)}
              </span>
              <button
                onClick={handleCopyUid}
                className="text-slate-500 hover:text-slate-900 p-1 rounded hover:bg-slate-200 transition-colors"
                title="Copy full UID"
              >
                {copiedUid ? <Check className="h-3.5 w-3.5 text-emerald-600" /> : <Copy className="h-3.5 w-3.5" />}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-500 font-sans">
            <div>
              <span className="font-semibold text-slate-700">Recipient (Student):</span>{" "}
              <span className="font-mono text-slate-800">{truncateAddress(recipient, 8, 6)}</span>
            </div>
            <div>
              <span className="font-semibold text-slate-700">Issuer (University):</span>{" "}
              <span className="font-mono text-slate-800">{truncateAddress(attester, 8, 6)}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Action Buttons: Copy link, Embed code, View Details */}
      {showActions && (
        <div className="mt-4 flex flex-wrap items-center justify-center gap-3">
          <button
            onClick={() => {
              if (typeof window !== "undefined") {
                navigator.clipboard.writeText(`${window.location.origin}/badge/${uid}`);
                setCopiedUid(true);
                setTimeout(() => setCopiedUid(false), 2000);
              }
            }}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-white border border-slate-300 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50 transition-colors"
          >
            <Share2 className="h-4 w-4 text-slate-500" />
            {copiedUid ? "Link Copied!" : "Share Verification Link"}
          </button>

          <button
            onClick={() => setShowEmbedCode(!showEmbedCode)}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-white border border-slate-300 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50 transition-colors"
          >
            <Code2 className="h-4 w-4 text-slate-500" />
            Embed Badge
          </button>
        </div>
      )}

      {/* Embed Code Modal / Snippet View */}
      {showEmbedCode && (
        <div className="mt-4 p-4 rounded-xl bg-slate-900 text-slate-200 text-xs font-mono space-y-2">
          <div className="flex items-center justify-between text-slate-400 font-sans">
            <span>Embed this badge on your website, resume, or LinkedIn:</span>
            <button
              onClick={handleCopyEmbed}
              className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 text-slate-200 hover:bg-slate-700 transition-colors"
            >
              {copiedEmbed ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              {copiedEmbed ? "Copied" : "Copy Code"}
            </button>
          </div>
          <pre className="p-2.5 rounded bg-slate-950 overflow-x-auto text-[11px] text-emerald-400">
            {embedCode}
          </pre>
        </div>
      )}
    </div>
  );
}
