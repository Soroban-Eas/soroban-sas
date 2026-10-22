import type { Metadata } from "next";
import "./globals.css";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";

export const metadata: Metadata = {
  title: "Soroban SAS — Academic Credential Issuance & Verification",
  description:
    "Turnkey reference dApp demonstrating decentralized academic degree and certification issuance on Stellar via Soroban SAS attestations.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="flex min-h-screen flex-col font-sans antialiased text-slate-900 bg-slate-50/50">
        <Navbar />
        <main className="flex-1">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
