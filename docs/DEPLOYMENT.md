# Deployment Guide

This guide walks you through taking the three soroban-sas contracts —
`schema-registry`, `sas` and `soroban-sas-indexer` — from a clean checkout of
this repository to a live deployment on **Stellar Testnet**, and then verifying
that the deployment works. It finishes with an operational checklist for
**Mainnet**.

It picks up where the [README](../README.md) leaves off: installation and
running the local test suite are covered there, so they are only summarized
here.

> **Network safety note:** Testnet XLM has no value and Friendbot hands out
> unlimited test coins, so feel free to experiment. Every command in this guide
> is safe to run repeatedly on Testnet. Do **not** point any command at Mainnet
> until you have read the [Mainnet checklist](#mainnet-checklist).

## Prerequisites

| Tool | Version | Check | Install |
| --- | --- | --- | --- |
| Rust toolchain | `1.79.0` (pinned by [`rust-toolchain.toml`](../rust-toolchain.toml)) | `rustc --version` | [rustup.rs](https://rustup.rs) |
| WASM target | matches toolchain | `rustup target list --installed \| grep wasm32` | `rustup target add wasm32-unknown-unknown` |
| Stellar CLI | v23+ (`stellar`); pre-v23 installs use the old `soroban` binary name | `stellar --version` | `cargo install --locked stellar-cli` |

Running `./scripts/bootstrap.sh --install` (see the README) performs the Rust,
target and CLI steps for you.

You also need a **funded account** to sign and pay for deployments:

```bash
# Generate a keypair locally. On Testnet, --fund tops it up via Friendbot.
stellar keys generate deploy-admin --fund
# (CLI versions before v23 also needed --global; newer CLIs store identities
# globally by default.)

# Confirm the address and balance
stellar keys address deploy-admin
# Top up again any time on Testnet:
stellar keys fund deploy-admin \
    --rpc-url https://soroban-testnet.stellar.org:443 \
    --network-passphrase "Test SDF Network ; September 2015"
```

`stellar keys generate` stores the secret key under
`~/.config/stellar/identity/`. On Testnet this is fine. For anything real, see
[key management](#key-management) in the Mainnet checklist first.

## Building optimized WASM

The workspace release profile (`[profile.release]` in
[`Cargo.toml`](../Cargo.toml)) already applies Soroban's recommended size
optimizations: `opt-level = "z"`, `lto = true`, `panic = "abort"`,
`codegen-units = 1` and symbol stripping. Build all three contracts with:

```bash
cargo build -p schema-registry -p sas -p soroban-sas-indexer \
    --release --target wasm32-unknown-unknown
```

(Equivalently, `make build` runs `cargo build --release --target
wasm32-unknown-unknown` for the whole workspace.)

When it finishes you should have exactly these artifacts:

| Crate | Artifact |
| --- | --- |
| `schema-registry` | `target/wasm32-unknown-unknown/release/schema_registry.wasm` |
| `sas` | `target/wasm32-unknown-unknown/release/sas.wasm` |
| `soroban-sas-indexer` | `target/wasm32-unknown-unknown/release/soroban_sas_indexer.wasm` |

Note that dashes in crate names become underscores in the `.wasm` filenames.

### Optional: extra shrinking with `wasm-opt`

The release profile gets contracts well within Soroban's limits, and nothing in
this repository currently post-processes its WASM. If you want to squeeze out
additional bytes, let the Stellar CLI do it — it ships a compatible Binaryen
build:

```bash
stellar contract optimize \
    --wasm target/wasm32-unknown-unknown/release/schema_registry.wasm
# → Reading: .../schema_registry.wasm (7553 bytes)
#   Optimized: .../schema_registry.optimized.wasm (6705 bytes)
```

The optimized module lands next to the original as
`<artifact>.optimized.wasm`; pass that path to `contract deploy` instead if
you use this step.

Avoid running a hand-installed `wasm-opt` with default flags against Soroban
contracts — depending on version it can enable features the Soroban VM rejects
(e.g. mutable globals) and produce a module that deploys but fails to invoke.
If you must use raw Binaryen, pin the same version the CLI bundles and test the
output on Testnet before trusting it.

## Deploying to Testnet

The three contracts must be deployed **and initialized in dependency order**:

1. `schema-registry` — no dependencies → `init(admin)`
2. `sas` — needs the registry address → `init(admin, registry)`
3. `indexer` — needs the sas address → `init(admin, sas)`

Each `init` can only succeed once (`AlreadyInitialized` error afterwards), so
get the addresses right the first time.

### One-shot deploy with `scripts/deploy.sh` (recommended)

[`scripts/deploy.sh`](../scripts/deploy.sh) performs every step in this section
for you:

```bash
./scripts/deploy.sh --network testnet --secret-key SABC...
```

To keep the key out of your shell history, export it instead:

```bash
SOROBAN_SECRET_KEY="$(stellar keys show deploy-admin)" \
    ./scripts/deploy.sh --network testnet
```

Concretely, the script:

1. Checks that a Stellar CLI (`stellar`, or `soroban` on pre-v23 installs) and
   `cargo` are available.
2. Registers your key under a well-known local identity
   (`soroban-sas-deploy-<network>` in `~/.config/stellar/identity/`) and derives
   the admin `G...` address from it.
3. On Testnet, tops the account up via Friendbot (best-effort; skipped on
   Mainnet).
4. Builds the three optimized WASM artifacts (same command as the previous
   section; `--skip-build` reuses existing ones and fails fast if any are
   missing).
5. Deploys each contract and calls its `init` in dependency order, aborting at
   the first failure.
6. Upserts the results into `.env` (backing up any existing file to `.env.bak`,
   then `chmod 600`) using exactly the key names from
   [`.env.example`](../.env.example): `SOROBAN_RPC_URL`,
   `SOROBAN_NETWORK_PASSPHRASE`, `SAS_CONTRACT_ID`,
   `SCHEMA_REGISTRY_CONTRACT_ID`, `INDEXER_CONTRACT_ID`, `ADMIN_PUBLIC_ADDRESS`.
7. Prints a summary of the three contract IDs, the admin address and network.

| Flag | Meaning |
| --- | --- |
| `--network testnet\|mainnet` | Target network (default `testnet`; sets RPC URL + passphrase defaults) |
| `--secret-key S...` | Funded source account secret (falls back to `$SOROBAN_SECRET_KEY`, then `$ADMIN_SECRET_KEY`) |
| `--rpc-url URL` | Override the network's default RPC endpoint |
| `--env-file FILE` | Where to write results (default `.env`) |
| `--skip-build` | Reuse previously built WASM artifacts |
| `--export-secret` | Opt-in: write `ADMIN_SECRET_KEY` to `.env` (default: only stores `ADMIN_PUBLIC_ADDRESS`) |

When it finishes, load the environment for the verification section:

```bash
set -a; source .env; set +a
```

> If you re-run the script later (e.g. after code changes), remember that
> already-sourced shells keep the **old** contract IDs — re-source `.env`
> afterwards, or you'll end up invoking stale addresses.

### Under the hood: manual sequence

Prefer doing it by hand (or need custom RPC settings)? The script performs
exactly this — follow it top to bottom with your own values:

```bash
IDENTITY="deploy-admin"
ADMIN_ADDRESS="$(stellar keys address "$IDENTITY")"   # G...
export RPC_URL="https://soroban-testnet.stellar.org:443"
export PASSPHRASE="Test SDF Network ; September 2015"
```

> If your CLI predates the `soroban` → `stellar` rename (v23), substitute
> `soroban` for `stellar` everywhere.

**1/3 — Deploy and initialize `schema-registry`:**

```bash
stellar contract deploy \
    --wasm target/wasm32-unknown-unknown/release/schema_registry.wasm \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE"
# → prints C... — save as SCHEMA_REGISTRY_CONTRACT_ID

stellar contract invoke \
    --id "$SCHEMA_REGISTRY_CONTRACT_ID" \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" \
    -- init --admin "$ADMIN_ADDRESS"
```

**2/3 — Deploy and initialize `sas` (with `--registry`):**

```bash
stellar contract deploy \
    --wasm target/wasm32-unknown-unknown/release/sas.wasm \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE"
# → prints C... — save as SAS_CONTRACT_ID

stellar contract invoke \
    --id "$SAS_CONTRACT_ID" \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" \
    -- init --admin "$ADMIN_ADDRESS" --registry "$SCHEMA_REGISTRY_CONTRACT_ID"
```

**3/3 — Deploy and initialize `indexer` (with `--sas`):**

```bash
stellar contract deploy \
    --wasm target/wasm32-unknown-unknown/release/soroban_sas_indexer.wasm \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE"
# → prints C... — save as INDEXER_CONTRACT_ID

stellar contract invoke \
    --id "$INDEXER_CONTRACT_ID" \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" \
    -- init --admin "$ADMIN_ADDRESS" --sas "$SAS_CONTRACT_ID"
```

**Record the results** in a `.env` file using the same key names as
[`.env.example`](../.env.example) — the rest of this guide and the SDK/CLI
tools read from these:

```bash
cat >> .env <<EOF
SOROBAN_RPC_URL="$RPC_URL"
SOROBAN_NETWORK_PASSPHRASE="$PASSPHRASE"
SAS_CONTRACT_ID=$SAS_CONTRACT_ID
SCHEMA_REGISTRY_CONTRACT_ID=$SCHEMA_REGISTRY_CONTRACT_ID
INDEXER_CONTRACT_ID=$INDEXER_CONTRACT_ID
ADMIN_PUBLIC_ADDRESS=$ADMIN_ADDRESS
EOF
chmod 600 .env   # no secret keys stored — signing uses the CLI identity
```

## Post-deploy verification

This section mixes the Stellar CLI (writes) with the repo's own CLI
(`packages/soroban-sas-cli`, read-only checks) against the live Testnet
deployment. Set up the environment first:

```bash
set -a; source .env; set +a

# Identity holding your funded test key: deploy-admin if you followed the
# Prerequisites section above, or soroban-sas-deploy-testnet if you arrived
# via scripts/deploy.sh.
IDENTITY="deploy-admin"

ADMIN_ADDRESS="$(stellar keys address "$IDENTITY")"    # G...
RPC_URL="$SOROBAN_RPC_URL"
PASSPHRASE="$SOROBAN_NETWORK_PASSPHRASE"
```

### 1. Register a schema

Using the Stellar CLI directly is the easiest way to see the new schema's UID —
the `register` call returns it:

```bash
SCHEMA_UID="$(stellar contract invoke \
    --id "$SCHEMA_REGISTRY_CONTRACT_ID" \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" \
    -- register \
        --owner "$ADMIN_ADDRESS" \
        --schema '{"first_name":"String","last_name":"String"}' \
        --resolver "$SAS_CONTRACT_ID" \
        --revocable true | tail -n 1 | tr -d '[]\" ')"
echo "$SCHEMA_UID"   # 64 hex characters
```

(The invoke prints progress lines, then the return value as a JSON array like
`["<64 hex chars>"]`; `tail -n 1 | tr -d '[]\" '` strips it down to the UID.)

Notes:

* The schema string follows the layout format described in
  [docs/schemas.md](schemas.md). The UID is deterministic — `sha256` of the
  XDR-encoded schema string — so registering the identical string twice fails
  with `SchemaAlreadyExists`; change something small to register variants.
* `--resolver` points at a contract invoked (best-effort, failures ignored)
  during attest/revoke. Using the SAS contract ID itself is a harmless
  placeholder; point it at a real resolver contract when you have one.
* You can also register through the repo CLI instead — but see the write-path
  known issue in the next section; today its submissions fail on live networks.
  (Also note its `--revocable` is a bare flag, not `--revocable true`.)

### 2. Read the schema back with `schema get`

```bash
cargo run -p soroban-sas-cli -- schema get \
    --uid "$SCHEMA_UID" \
    --registry-contract-id "$SCHEMA_REGISTRY_CONTRACT_ID" \
    --rpc-url "$RPC_URL"
```

Expected output (human-readable form):

```text
uid:       <same 64 hex chars as $SCHEMA_UID>
resolver:  <your SAS contract ID>
revocable: true
schema:    {"first_name":"String","last_name":"String"}
```

Add `--output json` to get the same record as pretty-printed JSON. A missing UID
prints `Schema not found`.

### 3. Issue an attestation

Write the attestation payload to a JSON file, then submit it with the Stellar
CLI. The `UID`-typed fields (`uid`, `schema_uid`, `ref_uid`) are passed as
single-element arrays of hex — that is how the contract's `Attestation` struct
serializes its newtype wrapper:

```bash
ATTESTATION_UID=$(openssl rand -hex 32)

cat > /tmp/attestation.json <<EOF
{
  "uid": ["$ATTESTATION_UID"],
  "schema_uid": ["$SCHEMA_UID"],
  "time": $(date +%s),
  "expiration_time": 0,
  "revocation_time": 0,
  "ref_uid": ["0000000000000000000000000000000000000000000000000000000000000000"],
  "recipient": "$ADMIN_ADDRESS",
  "attester": "$ADMIN_ADDRESS",
  "revocable": true,
  "data": ""
}
EOF

stellar contract invoke \
    --id "$SAS_CONTRACT_ID" \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" \
    -- attest --attestation "$(cat /tmp/attestation.json)"
```

A successful issuance prints an explorer link, then the contract event:

```text
📅 <SAS_CONTRACT_ID> - Success - Event: [{"symbol":"ATTESTED"}, ...]
["<same 64 hex chars as $ATTESTATION_UID>"]
```

Field notes: `expiration_time: 0` means "never expires"; `data` is hex-encoded
payload bytes (empty is valid); `ref_uid` links to a previous attestation when
chaining claims; `attester` must equal the address derived from
`--source-account`, because `attest` requires the attester's authorization.

> **Known issue:** the repo's own `attest create` /
> `schema register` subcommands currently return `"status": "FAILED"` on live
> networks — the SDK's transaction builder applies the simulated resource
> footprint and fee but drops the simulated Soroban authorization entries, so
> any call that hits `require_auth()` traps on-chain. Until that is fixed, use
> the raw Stellar CLI for all *write* operations as shown here; the repo CLI's
> read-only commands (`schema get`, `attest verify`, `query ...`) are unaffected
> because they only simulate.

### 4. Optional: bind the indexer to SAS

New deployments can mirror every issued (and replaced) attestation into the
indexer automatically. Binding is admin-gated and takes the indexer's `C...`
address — do this **before** issuing attestations you want discoverable:

```bash
stellar contract invoke \
    --id "$SAS_CONTRACT_ID" \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" \
    -- set_indexer --indexer "$INDEXER_CONTRACT_ID"
```

With no indexer bound, attestation issuance still works — claims are simply not
mirrored into the reverse-lookup contract unless indexed manually (step 6).

### 5. Verify with `attest verify`

```bash
cargo run -p soroban-sas-cli -- attest verify \
    --uid "$ATTESTATION_UID" \
    --contract-id "$SAS_CONTRACT_ID" \
    --rpc-url "$RPC_URL"
```

Expected output:

```text
Attestation is valid
```

(`--output json` prints `{"valid": true}` instead. An unknown, revoked or expired
UID prints `Attestation is invalid or not found` / `{"valid": false}`.)

### 6. Cross-check the indexer

How you check depends on step 4:

**If you bound the indexer with `set_indexer`** — the attestation from step 3
was mirrored automatically at issuance time; just query:

```bash
cargo run -p soroban-sas-cli -- query by-recipient \
    --address "$ADMIN_ADDRESS" \
    --contract-id "$INDEXER_CONTRACT_ID" \
    --rpc-url "$RPC_URL"
```

Expected output: one line per indexed attestation containing
`$ATTESTATION_UID` (`--output json` prints a JSON array instead). If this works, your
end-to-end deployment is healthy.

**If you did not bind an indexer** — `index_attestation` is permissionless, so
anyone can mirror an issued attestation manually (again note the `["hex"]`
shape for `UID` arguments):

```bash
stellar contract invoke \
    --id "$INDEXER_CONTRACT_ID" \
    --source-account "$IDENTITY" \
    --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" \
    -- index_attestation \
        --uid "[\"$ATTESTATION_UID\"]" \
        --recipient "$ADMIN_ADDRESS" \
        --schema-uid "[\"$SCHEMA_UID\"]" \
        --attester "$ADMIN_ADDRESS"
```

then run the same `query by-recipient` as above.

> **Caveat:** manual `index_attestation` calls are **not idempotent** — calling
> them twice appends duplicate UIDs to the on-chain vector, so check before
> re-submitting. The auto-mirroring path only indexes once per issuance.

## Mainnet checklist

Nothing in this repository is Mainnet-specific at the contract level — the same
WASM and sequence apply — but operations change. Work through every item below
before pointing at `--network-passphrase "Public Global Stellar Network ;
September 2015"`.

### Key management

* Generate the admin keypair **offline** and never store the seed on a machine
  that touches the internet (`stellar keys generate` on an air-gapped machine,
  hardware-wallet/HSM signing where available). The Testnet convenience of
  `~/.config/stellar/identity/` plaintext seeds is *not* acceptable for
  Mainnet.
* Understand what the admin key controls **before** choosing who holds it:
  * The `SchemaRegistry` admin may call `upgrade` (swap the registry's WASM),
    `set_fee`, `set_treasury` and `deprecate` any schema.
  * The `sas` admin may call `set_indexer` (re-point attestation mirroring at a
    new indexer contract).
  * The `indexer` admin currently has no privileged entry points — but see the
    upgrade-policy caveat below.
* Use separate keys per role: a cold admin key, and ordinary funded accounts
  for day-to-day schema registration and attestation issuance. Issuers only
  ever authorize their own `attest` calls, so issuer keys can be hotter than
  the admin key.
* If the registry will hold fees (`set_treasury`), custody of the treasury
  key needs the same care as the admin key.

### TTL and ledger-footprint bumping

Soroban contract storage entries expire unless their time-to-live (TTL) is
extended. The contracts handle part of this for you as of #15–#20:

* Every `persistent` write (schemas, attestations, index chunks) now calls
  `extend_ttl` out to roughly one year of ledgers
  (`LEDGERS_IN_ONE_YEAR`, defined in `soroban-sas-common`), and reading an
  attestation refreshes its TTL — so *active* data keeps itself alive.
* What this does **not** cover:
  * Data nobody touches again: an attestation issued once and never read or
    re-written still goes dormant after its last extension (~1 year).
  * The contract **instance** entries and instance-held state (admin, bound
    registry/indexer) — long-idle deployments can still age out.
* Dormant ≠ destroyed: expired entries are restored automatically when next
  accessed, but the accessing transaction pays archival/re-creation fees, and
  verifiers see missing data until then.
* For attestations that must outlive a year without traffic, schedule periodic
  bumps with `stellar contract extend` (see `--help`; `--instance-only`
  covers just the instance):

  ```bash
  stellar contract extend \
      --id "$SAS_CONTRACT_ID" \
      --ttl-to-ledger <target-ledger> \
      --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE"
  ```

* Budget for it: extensions pre-pay rent, so a keeper that refreshes thousands
  of dormant attestations has real XLM costs. Size the strategy (cron job,
  keeper service, or off-chain archival) before launch.

### Fee estimation

* Every invocation pays a **resource fee** (instructions, memory, footprint)
  plus an **inclusion fee** bid. Simulate first and inspect costs instead of
  guessing: `stellar tx simulate` (or `--cost` on invocations, where your CLI
  supports it), and watch Soroban RPC `getFeeStats` for prevailing inclusion
  fee levels rather than hard-coding bids.
* Deployments and first-time writes of large payloads (schemas, big attestation
  data) are the expensive cases; steady-state verification is cheap because
  `attest verify` and `schema get` are read-only simulations.
* Keep an XLM buffer on every operational account; transactions that exhaust
  their resource budget fail after consuming fees.

### Upgrade policy

Be aware of the current reality in the code:

* Only `SchemaRegistry::upgrade(new_wasm_hash)` exists (admin-gated, via
  `env.deployer().update_current_contract_wasm`). `sas` and
  `soroban-sas-indexer` expose **no** upgrade entry point — once deployed they
  are immutable. Bug fixes or features in those two contracts mean deploying
  fresh instances and migrating state, which is why the key-management and TTL
  decisions above matter before launch.
* Recommended policy until unified upgrade paths exist: treat each Mainnet
  deploy as final; stage contract changes behind review/audit; publish the
  exact WASM hashes you deploy so integrators can pin them; announce any
  redeployment of `sas`/`indexer` well in advance, since consumers hold those
  `C...` addresses.
* Registry upgrades deserve equal rigor — an admin-compromise scenario
  includes swapping registry logic — so consider multisig or shared custody of
  the registry admin key before enabling fees or deprecating schemas at scale.

## Troubleshooting

* **`account not found` during deploy** — the source account isn't funded. On
  Testnet: `stellar keys fund <identity>` (or hit
  `https://friendbot.stellar.org?addr=<G...>`). On Mainnet, fund the account
  from an exchange or another wallet first.
* **`Contract already initialized`** — you ran `init` twice, or you're pointing
  at someone else's deployment. Double-check every `C...` ID against `.env`.
* **`UnknownContract` / invoke fails right after deploy** — the `--id` doesn't
  exist on that network. Make sure `--rpc-url` and `--network-passphrase`
  belong to the same network the deploy targeted.
* **`SchemaAlreadyExists`** — schema UIDs are derived from the schema string;
  you registered this exact definition before. Tweak the string or reuse the
  existing UID.
* **`Error(Contract, #101)` (`InvalidSchema`) during `attest`** — the SAS
  contract looked the `schema_uid` up in *its* bound registry and found
  nothing. Almost always stale shell state: if you re-ran `scripts/deploy.sh`,
  your shell still exports the **old** contract IDs. Re-run
  `set -a; source .env; set +a` (or open a fresh shell).
* **Repo CLI write commands return `"status": "FAILED"`** — see the known issue
  in [Post-deploy verification](#3-issue-an-attestation): the SDK's transaction
  builder drops simulated auth entries. Use the raw Stellar CLI for writes;
  read-only repo CLI commands are unaffected.
* **`attest` fails with an attester mismatch** — the JSON's `attester` field
  must equal the G... address derived from `--source-account`, because `attest`
  requires the attester's authorization.
* **CLI flag errors mentioning `--network`** — older CLIs lack built-in network
  aliases; always passing explicit `--rpc-url` and `--network-passphrase` (as
  this guide does) works on every version.

