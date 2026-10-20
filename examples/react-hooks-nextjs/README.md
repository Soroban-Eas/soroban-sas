# Next.js example: Soroban SAS React hooks

A minimal App Router application demonstrating all five hooks:
`useAttestation(uid)`, `useRecipientAttestations(address)`,
`useSchema(uid)`, `useAttest()`, `useRevoke()`.

## Run

```sh
cd packages/soroban-sas-js && npm ci && npm run build
cd ../soroban-sas-react && npm ci && npm run build
cd ../../examples/react-hooks-nextjs && npm install && npm run dev
```

Then visit http://localhost:3000.

**Demo mode:** `app/demo-client.ts` implements the exact
`SasHooksClient` contract entirely in memory. It exercises reactive cache
invalidation and mutation states without wallet prompts, RPC requests or
real transactions. The `demo-` prefix in displayed hashes means simulated.

**Production integration:** replace `createDemoClient` in
`app/providers.tsx` with a client that uses the authenticated Soroban
RPC/indexer and a real browser wallet signing adapter. Do not ship Node
secret-key signing or embed mnemonic/seed material into `NEXT_PUBLIC_*`
or browser code. Use real contract IDs and verify submission against a
testnet node before real funds or credentials are involved.
