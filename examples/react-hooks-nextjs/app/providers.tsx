"use client";

import type { ReactNode } from "react";
import { SasProvider } from "@soroban-sas/react";
import { createDemoClient } from "./demo-client";

const config = {
  contractId: "CDEMO_SAS",
  registryContractId: "CDEMO_REGISTRY",
  indexerContractId: "CDEMO_INDEXER",
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
};

export function Providers({ children }: { children: ReactNode }) {
  return <SasProvider config={config} createClient={createDemoClient}>{children}</SasProvider>;
}
