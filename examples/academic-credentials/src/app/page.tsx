import Link from "next/link";
import {
  GraduationCap,
  ShieldCheck,
  PlusCircle,
  Search,
  CheckCircle2,
  FileCheck2,
  ArrowRight,
  ExternalLink,
  Layers,
  Sparkles,
  Lock
} from "lucide-react";
import { defaultSasClient } from "@/lib/sas/client";
import CredentialBadge from "@/components/CredentialBadge";

export default async function HomePage() {
  const sampleCredentials = await defaultSasClient.getAllCredentials();
  const featured = sampleCredentials[0];

  return (
    <div className="space-y-16 py-10">
      {/* Hero Section */}
      <section className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto space-y-6">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-stellar-50 border border-stellar-200 text-xs font-semibold text-stellar-700 shadow-sm">
            <Sparkles className="h-4 w-4 text-stellar-600" />
            Turnkey Reference dApp • Soroban SAS Example #574
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-slate-900 font-serif">
            Decentralized Academic Credentials on{" "}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-stellar-600 to-indigo-600">
              Stellar
            </span>
          </h1>

          <p className="text-lg text-slate-600 leading-relaxed font-sans max-w-2xl mx-auto">
            Issue verifiable, non-transferable degree and certification attestations with Soroban SAS.
            Empower students with self-sovereign diplomas and allow employers to verify academic credentials instantly with cryptographic certainty.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
            <Link
              href="/admin"
              className="inline-flex items-center gap-2 rounded-xl bg-stellar-600 px-6 py-3.5 text-base font-semibold text-white shadow-lg shadow-stellar-500/25 hover:bg-stellar-700 transition-all hover:-translate-y-0.5"
            >
              <PlusCircle className="h-5 w-5" />
              University Admin Portal
            </Link>
            <Link
              href="/verify"
              className="inline-flex items-center gap-2 rounded-xl bg-white border border-slate-300 px-6 py-3.5 text-base font-semibold text-slate-800 shadow-sm hover:bg-slate-50 transition-all hover:-translate-y-0.5"
            >
              <ShieldCheck className="h-5 w-5 text-stellar-600" />
              Public Verification Portal
            </Link>
          </div>
        </div>
      </section>

      {/* Feature Cards Grid */}
      <section className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="rounded-2xl border border-slate-200/80 bg-white p-6 shadow-sm space-y-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-stellar-50 text-stellar-600">
              <Lock className="h-6 w-6" />
            </div>
            <h3 className="text-lg font-bold text-slate-900">Non-Transferable Attestations</h3>
            <p className="text-sm text-slate-600 leading-relaxed">
              Bound cryptographically to the graduate's Stellar public key. Cannot be stolen, sold, or transferred to third parties.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-200/80 bg-white p-6 shadow-sm space-y-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-50 text-indigo-600">
              <Layers className="h-6 w-6" />
            </div>
            <h3 className="text-lg font-bold text-slate-900">Standard Academic Schema</h3>
            <p className="text-sm text-slate-600 leading-relaxed">
              Standardized format (<code className="text-xs bg-slate-100 px-1 py-0.5 rounded">degree, institution, graduation_year, gpa</code>) compatible with global education standards and Soroban SAS.
            </p>
          </div>

          <div className="rounded-2xl border border-slate-200/80 bg-white p-6 shadow-sm space-y-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-50 text-emerald-600">
              <ShieldCheck className="h-6 w-6" />
            </div>
            <h3 className="text-lg font-bold text-slate-900">Instant Public Verification Badge</h3>
            <p className="text-sm text-slate-600 leading-relaxed">
              Employers, recruiters, and background check agencies verify validity in milliseconds with embeddable cryptographic badges.
            </p>
          </div>
        </div>
      </section>

      {/* Featured Live Badge Preview */}
      {featured && (
        <section className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
          <div className="text-center space-y-2 mb-8">
            <span className="text-xs font-semibold uppercase tracking-wider text-stellar-600">
              Interactive Digital Badge Preview
            </span>
            <h2 className="text-2xl sm:text-3xl font-serif font-bold text-slate-900">
              Live Verified Academic Credential
            </h2>
            <p className="text-sm text-slate-500 max-w-lg mx-auto">
              This digital badge can be embedded on student resumes, LinkedIn, and personal portfolios with instant verification.
            </p>
          </div>

          <CredentialBadge attestation={featured} />
        </section>
      )}

      {/* Architecture & Flow */}
      <section className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="rounded-2xl border border-slate-200 bg-white p-8 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
            <div>
              <h3 className="text-xl font-bold text-slate-900">
                System Architecture & Automated Issuance Flow
              </h3>
              <p className="text-sm text-slate-500">
                How universities, Soroban smart contracts, and verification portals interact.
              </p>
            </div>
            <Link
              href="/admin"
              className="inline-flex items-center gap-1.5 text-sm font-semibold text-stellar-600 hover:text-stellar-700"
            >
              Try Issuance in Admin Portal <ArrowRight className="h-4 w-4" />
            </Link>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-center">
            <div className="rounded-xl bg-slate-50 p-4 border border-slate-200/80 space-y-2">
              <div className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-stellar-600 text-white font-bold text-xs">
                1
              </div>
              <h4 className="font-semibold text-sm text-slate-900">Schema Registration</h4>
              <p className="text-xs text-slate-500">
                Academic schema registered in Soroban SAS SchemaRegistry contract.
              </p>
            </div>

            <div className="rounded-xl bg-slate-50 p-4 border border-slate-200/80 space-y-2">
              <div className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-stellar-600 text-white font-bold text-xs">
                2
              </div>
              <h4 className="font-semibold text-sm text-slate-900">Automated Issuance</h4>
              <p className="text-xs text-slate-500">
                University SIS or registrar backend calls <code className="text-[11px] bg-slate-200 px-1 py-0.5 rounded">/api/issue</code> with degree metadata.
              </p>
            </div>

            <div className="rounded-xl bg-slate-50 p-4 border border-slate-200/80 space-y-2">
              <div className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-stellar-600 text-white font-bold text-xs">
                3
              </div>
              <h4 className="font-semibold text-sm text-slate-900">On-Chain Attestation</h4>
              <p className="text-xs text-slate-500">
                Attestation is recorded in the Soroban SAS contract with content-addressed UID.
              </p>
            </div>

            <div className="rounded-xl bg-slate-50 p-4 border border-slate-200/80 space-y-2">
              <div className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-stellar-600 text-white font-bold text-xs">
                4
              </div>
              <h4 className="font-semibold text-sm text-slate-900">Public Verification</h4>
              <p className="text-xs text-slate-500">
                Employers query validity via badge URL, QR code, or Soroban RPC.
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
