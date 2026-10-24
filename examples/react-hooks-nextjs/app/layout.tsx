import "./style.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "Soroban SAS React hooks demo",
  description: "Demonstrates reactive SAS attestation queries and transaction state in Next.js.",
};

export default function Layout({ children }: { children: ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
