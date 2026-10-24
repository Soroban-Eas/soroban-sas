# @soroban-sas/sdk

TypeScript SDK for the Soroban Solidity Attestation Service (SAS). This is a
companion to the Rust SDK at `packages/soroban-sas-sdk` for JS/TS
applications (wallets, indexers, relayers, frontends) that need to compute
the same content-addressed UIDs and typed-data signatures the Rust contracts
and Rust SDK use, and to submit transactions against a deployed SAS /
Schema Registry contract.

## Install

```bash
npm install @soroban-sas/sdk
```

The SDK requires Node.js 20.19.0 or newer for Node/CommonJS consumers. This
is required by the published Noble 2.4.0 packages used for SHA-256 and Ed25519;
browser consumers are unaffected. Node 18 is not supported because the Noble
2.x packages are ESM-only and the CJS entry cannot load them there.

## Hashing (byte-identical with the Rust contracts)

`computeSchemaUid`, `computeAttestationUid`, and `hashTypedData` are ports of
`soroban_sas_common::schema_uid`, `soroban_sas_common::attestation_uid`, and
`soroban_sas_common::typed_data::hash_offchain_attestation` respectively.
Every field the Rust side hashes via `.to_xdr(env)` — a `String`, `Address`,
`Bytes`, or the `UID` newtype — is encoded here as the identical canonical
`ScVal` XDR shape by the lightweight browser core; fields Rust hashes as raw bytes (`u64`
big-endian, `BytesN<32>` arrays) are encoded the same way here, never
XDR-wrapped. See `src/hashing.ts`'s doc comments for the exact preimage
layout of each function, and `test/hashing.test.ts` for golden vectors
copied verbatim from passing Rust tests in
`packages/soroban-sas-common/src/typed_data.rs` and
`packages/soroban-sas-common/src/test.rs`.

```ts
import { computeSchemaUid, computeAttestationUid, hashTypedData } from "@soroban-sas/sdk";

const schemaUid = computeSchemaUid("bool verified", resolverAddress, true);

const attestationUid = computeAttestationUid(
  schemaUid,
  recipientAddress,
  attesterAddress,
  new TextEncoder().encode("payload"),
);

const digest = hashTypedData(attestation, domain);
```

## Typed schema payloads

`parseSchema` validates supported SAS schema fields and returns an encoder and
decoder for the Soroban `contracttype` ScVal-map XDR payload. Literal schema
strings infer object types automatically. The registry's `name Type` order and
the SDK's `Type name` order are both accepted. `uint64` decodes to `bigint`;
`bytes` and `BytesN<N>` use `Uint8Array`; addresses use Stellar strkeys.
Nested `Vec<T>` and `Option<T>` are supported.

```ts
import { parseSchema } from "@soroban-sas/sdk/schema";

const claim = parseSchema("bool verified, uint64 score, string id");
const data = claim.encode({ verified: true, score: 42n, id: "alice" });
const decoded = claim.decode(data); // { verified: boolean; score: bigint; id: string }
```

For Rust, `#[derive_schema("...")]` generates an SDK `SchemaType` from an
empty struct declaration. The generated fields use Soroban SDK types for
`String`, `Bytes`, and `Address` so the payload bytes match the JS codec.

```rust
use soroban_sas_sdk::derive_schema;

#[derive_schema("bool verified, uint64 score, string id")]
pub struct Claim {}
```

The registry validates schema syntax but does not enforce payload field types
on-chain. Both codecs validate their supported types before encoding.

## Schema type generation

The SDK exports `parseSchema`, `generateTypeScript`, `encodeSchemaValue`, and
`decodeSchemaValue`. Generated interfaces preserve field order and include a
comment with each source schema type. Payload values encode as a Soroban
`ScVal` vector in schema field order, matching a Soroban struct's XDR shape.

```ts
import { encodeSchemaValue, generateTypeScript } from "@soroban-sas/sdk/typegen";

const schema = "name string, age uint32, verified bool, account address";
const source = generateTypeScript(schema, "Profile");
const xdr = encodeSchemaValue(schema, {
  name: "Ada",
  age: 37,
  verified: true,
  account: "G...",
});
```

Install the package to use the `sas-typegen` CLI:

```sh
sas-typegen "name string, age uint32, verified bool, account address" --name Profile
sas-typegen --schema-file schema.txt --name Profile --out profile.ts
```

Supported schema forms include primitives, `Option<T>` / `T?`, `Vec<T>`,
`[T]`, `Map<K:V>`, and `Tuple(T1 T2 ...)`. Numeric values wider than 32 bits
use JavaScript `bigint`; byte values use `Uint8Array`.

## Delegated attestations

`signDelegatedAttestation` signs `hashTypedData(attestation, domain)` with
the attester's ed25519 secret key (mirroring
`packages/soroban-sas-cli/src/offchain.rs::sign_offchain_attestation`);
`verifyDelegatedAttestation` recomputes the digest and checks the signature
without needing network access.

```ts
import { signDelegatedAttestation, verifyDelegatedAttestation } from "@soroban-sas/sdk";

const delegated = signDelegatedAttestation(attestation, domain, nonce, attesterSecret);
verifyDelegatedAttestation(delegated, domain); // true

// Any funded relayer account can now submit it without holding attesterSecret:
await client.attestByDelegation(delegated);
```

## Client

`SASClient` wraps `@stellar/stellar-sdk/contract`'s `Client`, which fetches
the deployed contract's on-chain XDR spec and uses it to build the
`InvokeHostFunction` operation for each call, rather than this package
hand-encoding argument layouts.

```ts
import { SASClient } from "@soroban-sas/sdk/client";

const client = new SASClient({
  contractId: "C...", // SAS contract id
  registryContractId: "C...", // Schema Registry contract id
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
  publicKey: walletAddress,
  signTransaction: (xdr, options) => wallet.signTransaction(xdr, options),
});

const schemaUid = await client.registerSchema("bool verified", resolverAddress, true);
const { hash } = await client.attest(attestation);
const stored = await client.getAttestation(attestation.uid);
await client.revoke(attestation.uid);
```

## Testing components offline

`@soroban-sas/sdk/testing` is an in-memory stand-in for `SASClient` aimed at
component tests — badge displays, verification checks, empty/loading/error
states — that would otherwise need a live RPC node plus network mocks. It is a
separate entry point: nothing in `index.ts` imports it, so application bundles
that import the package root never include it.

`MockSASProvider` answers the same calls as `SASClient` (`attest`,
`attestByDelegation`, `revoke`, `getAttestation`, `registerSchema`,
`getSchema`) and mutates its state the way the contract does — `attest`
inserts and rejects a duplicate UID, `revoke` stamps `revocationTime` and
rejects a second revocation. It is typed as `SASClientLike`, which the real
client also satisfies, so a component prop can accept either.
On top of the client surface it exposes `verifyAttestation(uid)`, which
reports the verdict the contract's `SAS::verify_attestation` would reach, as a
UI state: `"valid" | "revoked" | "expired" | "unknown"` (`"valid"` is the only
verdict that means the contract's `true`).

The mock uses no test-runner API and no Node-only built-in (`node:crypto`,
`Buffer`), so the same code runs under Vitest, Jest, and Cypress (which
executes specs in a browser). It reaches no network at all — including when a
call is made to fail.

| Knob | Effect |
| --- | --- |
| `seedAttestation` / `seedSchema` / `seedVerdict` | State the mock answers reads with. Also settable via the constructor's `attestations`, `schemas`, `verdicts`. |
| `setLatency(ms)` | Adds simulated round-trip latency to every call. |
| `holdNext(method?)` / `releaseHold()` | Keeps the next call pending, so the loading UI can be asserted before the promise settles. |
| `failNext(method?, error?)` | Rejects one call — the read or write that must fail without changing state. |
| `setNetworkFailure(error?)` / `clearNetworkFailure()` | Rejects every call, simulating an unreachable RPC. |
| `simulateRevocation(uid, revocationTime?)` | Marks an attestation revoked out-of-band (no call recorded), as if another party revoked it. |
| `calls` / `reset()` | The recorded call log, and a full clear back to the constructed shape. |

Two things the mock deliberately does not do: it never verifies signatures or
authorization, and it never mints a content-addressed UID on its own. For
`registerSchema` it returns the UID of a seeded schema with the same
`(schema, resolver, revocable)`, or rejects asking you to seed one — unless you
pass `deriveSchemaUid: computeSchemaUid` to get the real UID.

### Vitest walkthrough

Add Vitest, then drive the component's verification logic through the mock.
The behavior below — map the verdict to a label — is the part a unit test
should pin; it is framework-agnostic, so the same test works for React, Vue,
Svelte, or plain DOM.

```bash
npm install --save-dev vitest
```

```ts
// src/badge.ts
import type { SASClientLike, SASVerifierLike } from "@soroban-sas/sdk/testing";

export async function badgeLabel(
  provider: SASClientLike & SASVerifierLike,
  uid: string,
): Promise<string> {
  switch (await provider.verifyAttestation(uid)) {
    case "valid":
      return "Verified";
    case "revoked":
      return "Revoked";
    case "expired":
      return "Expired";
    default:
      return "Unknown";
  }
}
```

```ts
// test/badge.test.ts
import { expect, test } from "vitest";
import { MockSASProvider } from "@soroban-sas/sdk/testing";
import { badgeLabel } from "../src/badge";

const FIXED_NOW = 1_700_000_000n;
const UID = "01".repeat(32);
const ATTESTER = "G..."; // any G.../C... address your fixtures use
const RECIPIENT = "G...";

function mock(): MockSASProvider {
  return new MockSASProvider({
    now: () => FIXED_NOW, // fixed ledger clock, so expiry is deterministic
    attestations: [
      {
        uid: UID,
        schemaUid: "02".repeat(32),
        time: FIXED_NOW - 100n,
        expirationTime: 0n, // 0 = never expires
        revocationTime: 0n,
        refUid: "00".repeat(32),
        recipient: RECIPIENT,
        attester: ATTESTER,
        revocable: true,
        data: new Uint8Array(),
      },
    ],
  });
}

test("reports a valid attestation", async () => {
  await expect(badgeLabel(mock(), UID)).resolves.toBe("Verified");
});

test("reports a revocation, including one made by another party", async () => {
  const provider = mock();
  provider.simulateRevocation(UID);
  await expect(badgeLabel(provider, UID)).resolves.toBe("Revoked");
});

test("reports an expired attestation", async () => {
  const provider = mock();
  provider.seedVerdict(UID, "expired"); // stub the verdict the fixture cannot express
  await expect(badgeLabel(provider, UID)).resolves.toBe("Expired");
});

test("renders a loading state while the check is in flight", async () => {
  const provider = mock();
  provider.holdNext("verifyAttestation"); // keeps the call pending
  const pending = badgeLabel(provider, UID);

  let settled = false;
  void pending.then(() => {
    settled = true;
  });
  await Promise.resolve();
  expect(settled).toBe(false); // the component would show its spinner here

  provider.releaseHold();
  await expect(pending).resolves.toBe("Verified");
});

test("surfaces an unreachable RPC instead of throwing at the test", async () => {
  const provider = mock();
  provider.failNext("verifyAttestation", new Error("rpc unreachable"));

  await expect(badgeLabel(provider, UID)).rejects.toThrow("rpc unreachable");
  // The failure did not change state: the next read still sees the attestation.
  await expect(provider.verifyAttestation(UID)).resolves.toBe("valid");
});
```

The same three knobs cover writes: `failNext("attest")` rejects an issuance
without storing it, and `setNetworkFailure()` (cleared with
`clearNetworkFailure()`) makes every call reject for a whole test.

## Scope and limitations

### Browser and wallet integration

The default package entry is a lightweight browser core and can be imported directly from Vite or a Next.js client component. It contains the canonical-compatible hashing, StrKey, and delegated-signature APIs. Transaction submission is available from the separate `/client` entry and uses the wallet callback shape exposed by `@stellar/stellar-sdk`:

```ts
import { SASClient } from "@soroban-sas/sdk/client";

const sas = new SASClient({
  contractId: "C...",
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
  publicKey: walletAddress,
  signTransaction: (xdr, options) => wallet.signTransaction(xdr, options),
});
```

The browser entry does not accept secret seeds. Keep private keys out of browser bundles and provide a wallet signing callback instead. The callback receives the unsigned transaction XDR and returns the wallet's signed transaction XDR. This replaces the earlier `SASClientConfig.secret` path; callers that previously supplied a seed should adapt it to a signer callback or sign outside the browser.

The browser and ESM conditions for the default entry resolve to a self-contained
browser core. The full contract client is retained at
`@soroban-sas/sdk/client`, and the explicit `@soroban-sas/sdk/node` entry remains
available for Node secret-seed signing. The optional contract-client dependency
cost is measured separately from the default core.

For server-side Node applications that need the previous secret-seed signing
convenience, use the explicit Node-only entry. It is intentionally not part of
the browser graph:

```ts
import { createNodeSASClient } from "@soroban-sas/sdk/node";

const client = createNodeSASClient({
  contractId: "C...",
  rpcUrl: "http://localhost:8000",
  networkPassphrase: "Test SDF Network ; September 2015",
  secret: process.env.SAS_SECRET!,
});
```

The Node helper is the supported replacement for the removed
`SASClientConfig.secret` constructor option. Never import it in client-side
code or expose its secret value to a browser.

This release intentionally makes the default root entry browser-core-only:
`SASClient` is no longer exported from `@soroban-sas/sdk`. Migrate imports to
`@soroban-sas/sdk/client`; migrate secret-seed signing to
`@soroban-sas/sdk/node` and `createNodeSASClient`.

- `hashing.ts` and `delegation.ts` are cross-checked byte-for-byte against
  Rust golden vectors (see `test/hashing.test.ts` and
  `test/delegation.test.ts`) and can be relied on for offline UID
  computation and delegated-attestation signing without a network call.
- `client.ts`'s contract-call argument encoding — in particular, the `UID`
  newtype's one-element-array representation — was derived from reading the
  Rust XDR codegen (see `packages/soroban-sas-sdk/src/events.rs`'s
  `decode_uid` comment) and has not been exercised against a live Soroban RPC
  node in this environment. Before relying on `attest`/`attestByDelegation`/
  `revoke`/`registerSchema` for a real submission, run one end-to-end call
  against a local or test network and adjust the argument shape if the
  simulated transaction reports a type mismatch.
