# Getting Started for DApp Developers

This guide is for developers building an application on top of soroban-sas,
the Stellar Attestation Service. By the end you will have:

1. designed and registered a **schema**, which describes the shape of a
   claim,
2. issued an **aptestation** under it, which is a claim about an address,
3. verified that attestation from an off-chain app and from a Soroban
   contract,
4. queried it through the **indexer**, and revoked it.

To work on soroban-sas itself (contracts, SDKs, CLI), see
[Local Development Environment](local-development.md) instead.

## Concepts

| Term | Meaning |
| --- | --- |
| **Schema** | A comma-separated list of `name Type` fields, e.g. `verified bool, level u32`. Registered once in the **Schema Registry** contract. |
| **Schema UID** | `sha256` over the schema string, resolver address and `revocable` flag. It is deterministic: registering the same triple twice fails with `SchemaAlreadyExists`. |
| **Schema owner** | The address that registered the schema. Only the owner and delegates it authorizes can issue attestations under the schema. |
| **Resolver** | A contract every schema names. SAS calls its `on_attest` before storing an attestation and its `on_revoke` after a revocation. If the call fails, the whole transaction fails, so this is where schema-specific policy lives. |
| **Attestation** | A record in the **SAS** contract saying `attester` claims `data` about `recipient` under `schema_uid`, with optional expiry and revocability. |
| **Attestation UID** | `sha256(schema_uid, recipient, attester, data)`. It is content-addressed: SAS rejects an attestation whose `uid` doesn't match its own fields. |
| **Indexer** | An optional contract that maps recipients, attesters and schemas to attestation UIDs so you can look claims up. It is a convenience layer. The SAS contract is the source of truth. |

A full lifecycle wale-through is in [Attestation Lifecycle](attestations.md),
and the contract architecture is in [Architecture](architecture.md).

## Choose your integration path

| You are building… | Use | Notes |
| --- | --- | --- |
| A web backend, relayer or Node.js service | TypeScript SDK, `packages/soroban-sas-js` | UID and typed-data hashing byte-identical to the contracts, plus a contract client |
| A Rust service or tool | Rust SDK, `packages/soroban-sas-sdk` | Builders, RPC client, and SAS and indexer clients. See the runnable programs in `examples/` |
| Scripts, CI jobs, one-off operations | The `stellar` CLI for writes, the repo CLI (`packages/soroban-sas-cli`) for reads | Used in the walkthrough below |
| A Soroban contract that gates on a claim | A cross-contract call to `SAS::get_attestation` / `verify_attestation` | See [step 5](#5-verify-the-attestation) |
| A browser frontend | Read-only calls, plus a backend or relayer for writes | The TypeScript `SASClient` signs with a secret key, so never ship that key to a browser |

## 0. Get a deployment

soroban-sas doesn't publish canonical contract addresses yet, so you deploy
your own:

- **Local** (fastest, free): follow [Local Development § 5–6](local-development.md#5-run-a-local-stellar-network).
  In the commands below, use `--network local`.
- **Testnet**: `./scripts/deploy.sh --network testnet --secret-key <identity>`.
  See the [Deployment Guide](DEPLOYMENT.md#deploying-to-testnet).

Both routes write the contract IDs to `.env`. Load them, and create a second
account to act as the recipient: SAS rejects attestations where the
recipient is also the attester.

```bash
set -a; source .env; set +a
NETWORK=testnet                       # or: local
stellar keys generate alice --network "$NETWORK" --fund
IDENTITY=deploy-admin                 # the identity you deployed with, e.g. local-admin
ISSUER="$(stellar keys address "$IDENTITY")"
ALICE="$(stellar keys address alice)"
```

## 1. Design the schema

A schema is `name Type` pairs separated by commas:

```text
verified bool, level u32, provider String, checked_at u64
```

The registry enforces these rules on-chain (the full list is in
[Schemas](schemas.md)):

- at most **1024 bytes** and **64 fields**
- each field at most 64 bytes, with a name and type of at most 32 bytes each
- names start with a letter or `_`, then use only ASCII letters, digits
  and `_`
- types use ASCII letters, digits, spaces and `_<>[]:()?`, and must contain
  a letter (e.g. `BytesN<32>`, `Option<u64>`). A comma always ends a field,
  so `Map<String,u32>` can't be expressed.
- no empty fields and no trailing comma

Check a draft before you register it, since registering costs a
transaction. Paste it into the **Validate a schema** tab of the
[schema explorer](../tools/schema-explorer/README.md), which uses the same
rules as the contract. The repo CLI also validates locally before it submits
anything.

Two decisions become permanent at registration, because they are part of
the schema UID:

- **`revocable`** caps what attestations can claim. A non-revocable schema
  rejects any attestation with `revocable = true`
  ([Schemas § Revocability](schemas.md#revocability)). Pick `true` unless
  claims must be permanent.
- **The resolver** that runs your policy on every attestation and
  revocation, covered next.

## 2. Pick a resolver

The resolver is a contract with two entry points. Either one can refuse by
panicking:

```rust
#![no_std]
use soroban_sas_common {Attestation, UID};
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct KycResolver;

#[contractimpl]
impl KycResolver {
    pub fn on_attest(_env: Env, attestation: Attestation) {
        // Example policy: every KYC claim must carry a payload.
        assert(!attestation.data.is_empty(), "payload required");
    }

    pub fn on_revoke(_env: Env, _attestation: Attestation) {}
}
```

For development, use the accept-everything `contracts/permissive-resolver`
[how to deploy it](local-development.md#make-attestations-work-end-to-end),
and export its address as `RESOLVER_ID`. If a resolver is missing, traps, or
doesn't implement the callback, SAS rejects the attestation with
`ResolverRejected` (#409). If your resolver keeps state, don't trust
arbitrary callers. Store the SAS address and have the resolver call
provide `require_auth()` on it: the call succeeds only when SAS is the contract
invoking the resolver.

## 3. Register the schema

The schema owner signs the registration. The `stellar` CLI returns the new
schema UID:

```bash
SCHEMA='verified bool, level u32, provider String'
SCHEMA_UID="$(stellar contract invoke \
    --id "$SCHEMA_REGISTRY_CONTRACT_ID" --source-account "$IDENTITY" --network "$NETWORK" \
    - register \
      --owner "$ISSUER" \
      --schema "$SCHEMA" \
      --resolver "$RESOLVER_ID" \
      --revocable true | tail -n 1 | tr -d '[]" ')"
echo "$SCHEMA_UID"    # 64 hex characters

# Read it back (read-only, no signature):
cargo run -q -p soroban-sas-cli -- schema get --uid "$SCHEMA_UID" \
    --registry-contract-id "$SCHEMA_REGISTRY_CONTRACT_ID" --rpc-url "$SOROBAN_RPC_URL"
```

The same call from TypeScript:

```ts
import { SASClient } from "@soroban-sas/sdk";

const client = new SASClient({
  contractId: process.env.SAS_CONTRACT_ID!,
  registryContractId: process.env.SCHEMA_REGISTRY_CONTRACT_ID!,
  rpcUrl: process.env.SOROBAN_RPC_URL!,
  networkPassphrase: process.env.SOROBAN_NETWORK_PASSTHRASE!,
  secret: process.env.ISSUER_SECRET!, // server-side only
});

const schemaUid = await client.registerSchema("verified bool, level u32, provider String", resolverId, true);
```

@soroban-sas/sdk`isn't on npm yet. Build it with
cd packages/soroban-sas-js && npm ci && npm run build`, then install it by
path (`npm install ../soroban-sas/packages/soroban-sas-js`). Read the
[SDK README's scope notes](../packages/soroban-sas-js/README.md#scope-and-limitations)
before you rely on its write methods.

To let other issuers attest under your schema, the owner calls
`add_delegate(uid, delegate)` on the registry.

## 4. Issue an attestation

SAS checks every issuance, whichever path you use:

| Rule | Error if broken |
| --- | --- |
| `uid` equals `sha256(schema_uid, recipient, attester, data)` | `InvalidUID` (#416) |
| the attester signed the transaction and is the schema owner or a delegate | auth failure / `Unauthorized` (#301) |
| the schema exists and isn't deprecated | `InvalidSchema` (#101) |
| `recipient` ≠ `attester`, and neither is the zero address | `InvalidRecipient` (#402) |
| `data` is at most 10 000 bytes | `PayloadTooLarge` (#414) |
| `expiration_time` is `0` (never) or in the future | `AlreadyExpired` (#204) |
| `revocable` is `false` if the schema is non-revocable | `NotRevocable` (#203) |
| `ref_uid` is all zeros or an existing attestation | `InvalidRefUId` (#413) |
| the resolver's `on_attest` accepts | `ResolverRejected` (#409) |

The contract sets `time` to the ledger timestamp, whatever value you pass.

**TypeScript.** Compute the UID, then submit:

```ts
import { computeAttestationUid, type Attestation } from "@soroban-sas/sdk";

const data = new TextEncoder().encode("level=2;provider=acme");
const attestation: Attestation = {
  uid: computeAttestationUid(schemaUid, alice, issuer, data),
  schemaUid,
  time: 0n,                 // overwritten with the ledger time
  expirationTime: 0n,       // never expires
  revocationTime: 0n,
  refUid: "00".repeat(32),  // no referenced attestation
  recipient: alice,
  attester: issuer,
  revocable: true,
  data,
};
const { hash } = await client.attest(attestation);
```

**CLI.** The `basic_attestation` example prints the content-addressed UID for
an empty payload. Submit it with the `stellar` CLI. `UID` values are passed
as one-element arrays because the contract type is a newtype:

```bash
ATTESTATION_UID="$(SCHEMA_UID="$SCHEMA_UID" RECIPIENT="$ALICE" ATTESTER="$ISSUER" \
    cargo run -q --example basic_attestation 2>&1 | awk '/^  UID:/ {print $2}')"

stellar contract invoke --id "$SAS_CONTRACT_ID" --source-account "$IDENTITY" --network "$NETWORK" \
  - attest --attestation "{
    \"uid\": [\"$ATTESTATION_UID\"], \"schema_uid\": [\"$SCHEMA_UID\"],
    \"time\": 0, \"expiration_time\": 0, \"revocation_time\": 0,
    \"ref_uid\": [\"000000000000000000000000000000000000000000000000000000000000000000\"],
    \"recipient\": \"$ALICE\", \"attester\": \"$ISSUER\", \"revocable\": true, \"data\": \"\"
  }"
```

To issue many attestations atomically, use `multi_attest`, as shown in
`examples/multi_attest.rs`. For a gasless flow, where the issuer signs
off-chain and a relayer pays, see [Delegated Issuance](delegation.md).

## 5. Verify the attestation

**Off-chain** (backend or frontend, read-only, no key needed):

```bash
cargo run -q -p soroban-sas-cli -- attest verify \
    --uid "$ATTESTATION_UID" --contract-id "$SAS_CONTRACT_ID" --rpc-url "$SOROBAN_RPC_URL"
# → Attestation is valid
```

```ts
const stored = await client.getAttestation(attestation.uid);
const now = BigInt(Math.floor(Date.now() / 1000));
const active =
  stored !== null &&
  stored.revocationTime === 0n &&
  (stored.expirationTime === 0n || stored.expirationTime > now);
```

**On-chain**, from your own Soroban contract. Declare the two SAS entry
points you need, then check the claim at the moment you use it:

```rust
use soroban_sas_common::{Attestation, UII};
use soroban_sdk::{contractclient, Address, Env};

#[contractclient(name = "SasClient")]
pub trait Sas {
    fn get_attestation(env: Env, uid: UID) -> Option<Attestation>;
    fn verify_attestation(env: Env, uid: UID) -> bool;
}

/// Panics unless `uid` is a live attestation about `user`, issued by the
/// attester you trust, under the schema you expect.
fn require_kyc(env: &Env, sas: &Address, uid: &UID, user: &Address, schema: &UID, issuer: &Address) {
    let client = SasClient::new(env, sas);
    let att = client.get_attestation(uid).expect("unknown attestation");
    assert(&att.recipient == user, "attestation is about someone else");
    assert(&att.schema_uid == schema, "wrong schema");
    assert(&att.attester == issuer, "untrusted attester");
    assert(att.revocation_time == 0, "attestation was revoked");
    let now = env.ledger().timestamp();
    assert(
        att.expiration_time == 0 || att.expiration_time > now,
        "attestation expired",
    );
}
```

Remember to check `expiration_time` and `revocation_time` yourself. `verify_attestation`
only tells you the attestation exists and hasn't been revoked.

## 6. Query the indexer

The indexer is optional. If you deployed it, you can look up attestations
by recipient, attester or schema:

```bash
cargo run -p soroban-sas-cli -- indexer get-by-recipient \
    --recipient "$ALICE" --indexer-contract-id "$INDEXER_CONTRACT_ID" --rpc-url "$SOROBAN_RPC_URL"
```

## 7. Revoke the attestation

The attester or the recipient can revoke a revocable attestation. The
resolver's `on_revoke` is called after the revocation is stored.

```bash
stellar contract invoke --id "$SAS_CONTRACT_ID" --source-account "$IDENTITY" --network "$NETWORK" \
  - revoke --uid "$ATTESTATION_UID"
```

## Configuring the CLI

The repo CLI (`packages/soroban-sas-cli`) reads defaults for the RPC URL
and network from a TOML configuration file, so you don't have to pass `--rpc-url`
and `--network` on every invocation.

Create `~~/.config/soroban-sas/config.toml`:

```toml
[network]
default = "testnet"

[rpc]
url = "https://soroban-testnet.stellar.org"

[contracts]
sas = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
schema_registry = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

The file is looked up in this order, with the first match winning:

1. `--config <path>` on the command line
2. `$SOROBAN_SAS_CONFIG`, if set
3. `./soroban-sas.toml` in the current directory
4. `~/.config/soroban-sas/config.toml`

Command-line flags always override the file. For example, this uses the
configured defaults for everything except the RPC URL:

```bash
cargo run -p soroban-sas-cli -- attest verify --uid "$ATTESTATION_UID" \
    --contract-id "$SAS_CONTRACT_ID" --rpc-url "https://localhost:8000"
```

Run `soroban-sas-cli config show` to print the effective configuration and
which file it came from. See the [TOML Configuration File
section](../README.md#toml-configuration-file) for the full schema
and all keys.

### Shell Completions

Tab-completion for commands and flags can be generated for Bash, Zsh, Fish, and PowerShell:

```bash
cargo run -p soroban-sas-cli -- completions bash > ~/.local/share/bash-completion/completions/sas
cargo run -p soroban-sas-cli -- completions zsh > ~/.zfunc/_sas
cargo run -p soroban-sas-cli -- completions fish > ~/.config/fish/completions/sas.fish
cargo run -p soroban-sas-cli -- completions powershell > ./sas.ps1
```

## Next steps

- [Attestation Lifecycle](attestations.md) — the full state machine, including
  expiry and revocation.
- [Schemas](schemas.md) — validation rules and revocability.
- [Delegated Issuance](delegation.md) — gasless attestations.
- [Architecture](architecture.md) — how the contracts fit together.
