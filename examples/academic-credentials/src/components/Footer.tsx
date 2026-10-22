import Link from "next/link";
import { GraduationCap, ExternalLink, ShieldCheck } from "lucide-react";

export default function Footer() {
  return (
    <footer className="border-t border-slate-200 bg-slate-50 py-12">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-stellar-600 text-white">
                <GraduationCap className="h-5 w-5" />
              </div>
              <span className="font-bold text-slate-900">Soroban SAS Academic Credentials</span>
            </div>
            <p className="text-sm text-slate-600 max-w-md leading-relaxed">
              Decentralized, non-transferable degree and certification issuance on Stellar.
              Universities issue tamper-evident on-chain attestations; employers verify diplomas instantly with zero intermediaries.
            </p>
          </div>

          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-3">
              Standard Schema
            </h4>
            <div className="rounded-md bg-white p-3 border border-slate-200 text-xs font-mono text-slate-700 space-y-1">
              <div>degree String</div>
              <div>institution String</div>
              <div>graduation_year u32</div>
              <div>gpa String</div>
            </div>
          </div>

          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-3">
              Resources
            </h4>
            <ul className="space-y-2 text-sm text-slate-600">
              <li>
                <Link
                  href="https://github.com/APKLEO/soroban-sas"
                  target="_blank"
                  className="flex items-center gap-1 hover:text-stellar-600 transition-colors"
                >
                  GitHub Repository <ExternalLink className="h-3.5 w-3.5" />
                </Link>
              </li>
              <li>
                <Link
                  href="/verify"
                  className="flex items-center gap-1 hover:text-stellar-600 transition-colors"
                >
                  Verification Engine <ShieldCheck className="h-3.5 w-3.5" />
                </Link>
              </li>
              <li>
                <Link
                  href="/admin"
                  className="hover:text-stellar-600 transition-colors"
                >
                  Registrar Portal
                </Link>
              </li>
            </ul>
          </div>
        </div>

        <div className="border-t border-slate-200 pt-6 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-4">
          <p>© 2026 Soroban SAS Academic Credential Reference Architecture. MIT License.</p>
          <div className="flex items-center gap-4">
            <span>Powered by Soroban Smart Contracts</span>
            <span>•</span>
            <span>Stellar Network</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
