# @soroban-sas/react

React hooks and TanStack Query integration for the Soroban Attestation Service (SAS).

`@soroban-sas/react` eliminates repetitive frontend boilerplate for state management, loading states, error handling, account/network switching, window focus revalidation, and event-driven cache invalidation when building web3 dApps on Soroban SAS.

## Features

- **`SASProvider` context**: Configures the active Soroban network (`local`, `testnet`, `futurenet`, `mainnet`, or custom), RPC client, contract addresses, and TanStack Query client.
- **Core data hooks**:
  - `useAttestation(uid, options?)` — fetches and caches an `Attestation` record by its 32-byte UID.
  - `useSchema(schemaUid, options?)` — fetches and caches a `SchemaRecord` from the Schema Registry by its 32-byte UID.
  - `useAttestationsByRecipient(address, options?)` — queries the Indexer contract for a recipient's attestations and resolves their full records.
- **TanStack Query integration**: Automatic request deduplication, caching, and background revalidation.
- **Automatic re-fetching**:
  - Revalidates active queries automatically when the active wallet account switches (`account` prop, `switchAccount()`, or `sas:account-changed` / `stellar:accountChanged` / `freighter:accountChanged` window events).
  - Revalidates active queries automatically when the browser window regains focus (`focus` and `visibilitychange` events).
- **Event-based triggers (`useSASEvents`)**: Subscribes to SAS contract events (`AttestationIssued`, `AttestationRevoked`, `SchemaRegistered`, `BatchAttested`, `BatchRevoked`) via provider emission, DOM `CustomEvent`s, or Soroban RPC `getEvents` polling, and automatically invalidates affected query caches.
- **Sample Demo App & Storybook Stories**: Includes an interactive Vite demo app (`src/demo/SASDemoApp.tsx`) and Storybook stories (`src/stories/SAS.stories.tsx`).

## Install

```bash
npm install @soroban-sas/react @tanstack/react-query react react-dom
```

## Quick Start

### 1. Wrap your application in `SASProvider`

```tsx
import { SASProvider } from "@soroban-sas/react";

export function App() {
  return (
    <SASProvider
      network="testnet"
      contractId="C..."
      registryContractId="C..."
      indexerContractId="C..."
      account={connectedWalletAddress}
    >
      <ProfileAttestations />
    </SASProvider>
  );
}
```

### 2. Query attestations and schemas with hooks

```tsx
import {
  useAttestation,
  useSchema,
  useAttestationsByRecipient,
  useSAS,
} from "@soroban-sas/react";

export function ProfileAttestations() {
  const { account, switchAccount } = useSAS();
  const {
    data: attestations,
    isLoading,
    error,
  } = useAttestationsByRecipient(account);

  if (isLoading) return <p>Loading attestations...</p>;
  if (error) return <p>Error: {error.message}</p>;

  return (
    <div>
      {attestations?.map((att) => (
        <AttestationCard key={att.uid} uid={att.uid} schemaUid={att.schemaUid} />
      ))}
    </div>
  );
}

function AttestationCard({ uid, schemaUid }: { uid: string; schemaUid: string }) {
  const { data: attestation, isLoading: loadingAtt } = useAttestation(uid);
  const { data: schema, isLoading: loadingSchema } = useSchema(schemaUid);

  if (loadingAtt || loadingSchema) return <div>Loading claim...</div>;

  return (
    <article>
      <h3>Schema: {schema?.schema}</h3>
      <p>Attester: {attestation?.attester}</p>
      <p>Status: {attestation && attestation.revocationTime > 0n ? "Revoked" : "Active"}</p>
    </article>
  );
}
```

### 3. Event-based triggers

```tsx
import { useSASEvents, dispatchSASEvent } from "@soroban-sas/react";

export function AttestationActivityFeed() {
  const { lastEvent, events, emitEvent } = useSASEvents({
    onAttestationIssued: (ev) => {
      console.log("New attestation issued:", ev.uid);
    },
    onAttestationRevoked: (ev) => {
      console.log("Attestation revoked:", ev.uid);
    },
  });

  return (
    <div>
      <p>Total events received: {events.length}</p>
      {lastEvent && <p>Latest: {lastEvent.type}</p>}
    </div>
  );
}
```

## Sample Demo App

Run the interactive demo application locally with Vite:

```bash
cd packages/soroban-sas-react
npm ci
npm run dev
```

Or build the library and demo app:

```bash
npm run build
npm run build:demo
```

## Testing

Run the unit test suite (Vitest + React Testing Library):

```bash
cd packages/soroban-sas-react
npm test
npm run test:coverage
npm run typecheck
```
