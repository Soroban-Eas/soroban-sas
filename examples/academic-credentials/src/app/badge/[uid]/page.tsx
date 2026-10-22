import { defaultSasClient } from "@/lib/sas/client";
import CredentialBadge from "@/components/CredentialBadge";
import VerificationResult from "@/components/VerificationResult";
import Link from "next/link";
import { ArrowLeft, ShieldCheck, ExternalLink } from "lucide-react";
import { notFound } from "next/navigation";

interface BadgePageProps {
  params: {
    uid: string;
  };
  searchParams?: {
    embed?: string;
  };
}

export default async function BadgePage({ params, searchParams }: BadgePageProps) {
  const { uid } = params;
  const isEmbed = searchParams?.embed === "true";

  const verdict = await defaultSasClient.verifyAttestation(uid);

  // If embedded in an iframe, render compact clean badge
  if (isEmbed) {
    if (!verdict.attestation) {
      return (
        <div className="flex h-screen w-screen items-center justify-center p-4 bg-slate-50 text-slate-500 font-sans text-xs">
          Credential not found: {uid}
        </div>
      );
    }
    return (
      <div className="p-2 bg-transparent flex items-center justify-center min-h-screen">
        <CredentialBadge attestation={verdict.attestation} showActions={false} />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 py-10 space-y-8">
      {/* Back button */}
      <div>
        <Link
          href="/verify"
          className="inline-flex items-center gap-1.5 text-sm font-semibold text-slate-600 hover:text-slate-900 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Verification Portal
        </Link>
      </div>

      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-stellar-50 text-stellar-700 border border-stellar-200 text-xs font-semibold">
          <ShieldCheck className="h-4 w-4 text-stellar-600" />
          Public Credential Verification Record
        </div>
        <h1 className="text-3xl font-serif font-bold text-slate-900">
          Academic Attestation Verification
        </h1>
        <p className="text-xs font-mono text-slate-500">UID: {uid}</p>
      </div>

      <VerificationResult verdict={verdict} />
    </div>
  );
}
