# @soroban-sas/react

React query and mutation hooks for Soroban SAS attestation applications.

## Install

```sh
npm install @soroban-sas/sdk @soroban-sas/react react swr
```

The package requires React 18/19 and an installed `@soroban-sas/sdk`.
SWR v2 automatically deduplicates in-flight requests, caches responses,
revalidates on focus and discards results after components unmount.

## Provider

```tsx
"use client";
import { SasProvider } from "@soroban-sas/react";
import { createDemoClient } from "./demo-client";
// Copy demo-client.ts from examples/react-hooks-nextjs/app for this sample.
// In production replace createDemoClient with your wallet-aware client factory.

const config = {
  contractId: process.env.NEXT_PUBLIC_SAS_CONTRACT_ID!,
  registryContractId: process.env.NEXT_PUBLIC_REGISTRY_CONTRACT_ID!,
  indexerContractId: process.env.NEXT_PUBLIC_INDEXER_CONTRACT_ID!,
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
};

export function Providers({ children }: { children: React.ReactNode }) {
  return <SasProvider config={config} createClient={createDemoClient}>{children}</SasProvider>;
}
```

The provider requires an injected `client={walletAwareClient}` or
`createClient={(config) => new MyWalletClient(config)}`.
For a working mock-based example, see the referenced Next.js demo.
No default Node signer is instantiated inside browser bundles. The injected client must implement
`getAttestation`, `getSchema`, `getRecipientAttestations`, `attest`,
and `revoke`. **Never pass a secret key into a browser/Next.js client.**
The default SDK's Node keypair signer is not a browser wallet; for live
mutations inject a client wired to the user's wallet.

## Query hooks

```tsx
const { data, error, isLoading, mutate } = useAttestation(uid);
const { data: recipientRows } = useRecipientAttestations(account);
const { data: schema } = useSchema(schemaUid);
```

- Null or empty identifiers disable the query.
- `useRecipientAttestations` gets UIDs from the configured Indexer
  contract and resolves their full attestation records from the SAS contract.
- All query keys are scoped to the provider and network configuration.
- A successful mutation revalidates the attestation and recipient caches;
  a failed refetch never changes a successfully submitted transaction into an error.

## Mutations

```tsx
const { attest, status, isLoading, error, txHash, reset } = useAttest();
const revocation = useRevoke();

await attest(attestation);   // a complete Attestation matching the on-chain schema
await revocation.revoke(attestation.uid);
```

`status` transitions `idle -> pending -> success` or `idle -> pending -> error`.
`txHash` is provided by the injected client's confirmed submission result.
Errors (including wallet rejection) are retained and rethrown for the caller to handle.
Unmounts and overlapping mutations do not update stale React state.

## Next.js example

See [examples/react-hooks-nextjs](../../examples/react-hooks-nextjs)
for a React client-page example showing query and mutation hooks. Fill in
testnet contract IDs and provide a wallet-aware implementation for signing.

## Local development

```sh
cd packages/soroban-sas-js && npm ci && npm run build
cd ../soroban-sas-react && npm ci && npm run typecheck && npm test && npm run build
```

SDK contract-call argument shapes require testnet integration verification
before a real transaction is broadcast. The unit tests exercise deterministic
mock clients, cache revalidation, mutation states and unmount handling.
