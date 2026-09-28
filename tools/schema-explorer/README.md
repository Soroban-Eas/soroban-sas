# Schema Explorer (prototype)

A small read-only web dashboard for browsing the schemas registered in a
deployed `schema-registry` contract (`contracts/schema-registry`) and for
checking draft schema strings before registering them.

- **Browse**: pages through `get_schemas_paginated`, filters the loaded
  schemas client-side, and shows each schema's UID, resolver, owner
  (`get_creator`), revocability and parsed field table.
- **Look up by UID**: calls `get_schema` for any 64-hex-character UID,
  including schemas not loaded yet.
- **Validate a schema**: checks a draft string live, using the same rules as
  `SchemaRegistry::register`, and reports the first problem plus byte and
  field usage against the 1024-byte and 64-field limits.
- **Demo data**: "Use demo data" (or `?demo=1`) loads built-in fixtures with
  no network access, so you can try the UI without deploying anything.

Every contract read is a Soroban RPC `simulateTransaction`. Nothing is
signed or submitted, no key or funded account is needed, and it costs
nothing.

## Run it

Requires Node.js 18+.

```bash
cd tools/schema-explorer
npm ci
npm run dev        # http://localhost:5173
```

To browse a local deployment, start the node and deploy the contracts first
(see [docs/local-development.md](../../docs/local-development.md)), then pick
the **Local** preset and paste `SCHEMA_REGISTRY_CONTRACT_ID` from `.env`.
Settings are kept in the page URL, so a link such as
`http://localhost:5173/?network=testnet&registry=C...` opens a specific
registry directly.

Other scripts:

| Command | What it does |
| --- | --- |
| `npm test` | Unit and UI tests (Vitest, jsdom) |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run build` | Type-check, then build a static site into `dist/` |
| `npm run preview` | Serve the built `dist/` locally |

`dist/` is a plain static site with relative asset paths, so any static host
can serve it.

## Layout

| File | Role |
| --- | --- |
| `src/schema.ts` | Port of `soroban_sas_common::validate_schema_syntax` that also returns the parsed fields and a readable error |
| `src/registry.ts` | `RegistryReader` (typed contract reads) and `RpcContractCaller` (Soroban RPC simulation) |
| `src/config.ts` | Network presets, connection validation, shareable query strings |
| `src/fixtures.ts` | Demo data, and `FixtureCaller`, an in-memory registry with the contract's encoding and pagination rules |
| `src/view.ts`, `src/app.ts` | DOM rendering and page wiring |

## Keeping the validator in sync with the contract

`src/schema.ts` has to accept and reject exactly what the contract does.
Both sides replay the same golden vectors,
[`packages/soroban-sas-common/test_vectors/schema_syntax.tsv`](../../packages/soroban-sas-common/test_vectors/schema_syntax.tsv):

- Rust: `test_validate_schema_syntax_matches_shared_vectors` in
  `packages/soroban-sas-common/src/test.rs`
- TypeScript: `test/schema.test.ts`

If you change `validate_schema_syntax`, add vectors for the new behaviour
and update `src/schema.ts` until both suites pass.

## Security notes

- **Untrusted data.** Schema strings and addresses come from the chain and
  anyone can register a schema, so they are treated as untrusted. They are
  rendered with `textContent` only (never `innerHTML`), and every decoded
  contract value is shape-checked before it is used. `test/app.test.ts`
  checks that a schema containing HTML stays inert text.
- **Transport.** `http://` RPC URLs are accepted only for loopback hosts.
  Remote endpoints must use `https://`, and URLs containing credentials are
  rejected.
- **Content Security Policy.** `index.html` sets a CSP that allows scripts
  only from the page's own origin. `connect-src` stays open to http(s)
  because the RPC endpoint is chosen by the user.
- **Data kept.** Only the connection settings are stored, in
  `localStorage`. There are no keys or secrets to store.

## Limitations

This is a prototype:

- The registry cannot list deprecated schemas: `get_schemas_paginated`
  skips them, and `get_schema` returns nothing for them.
- The filter searches only the schemas loaded so far. There is no
  server-side search.
- The schema UID is shown as stored and is not recomputed from the schema
  contents.
- It does not show attestations. Browsing them through the indexer
  (`get_attestations_by_schema`) is the natural next step.
