# Local Development Environment

This guide takes you from a fresh machine to a working soroban-sas setup:
toolchain installed, workspace building and passing tests, git hooks on, and
the contracts deployed to a local Stellar node you can call. It is written
for contributors to the contracts, SDKs, CLI and tools. If you want to build
an application *on top of* soroban-sas, start with
[Getting Started for DApp Developers](getting-started.md).

## Quick start

On a machine that already has Rust, Docker and the Stellar CLI:

```bash
git clone https://github.com/Soroban-Eas/soroban-sas.git
cd soroban-sas
./scripts/bootstrap.sh --install     # wasm target + pinned Stellar CLI
./scripts/install_hooks.sh           # fmt/clippy git hooks
cargo test --workspace               # everything should pass

docker compose up -d stellar-quickstart
./scripts/wait_for_localnet.sh       # blocks until RPC is healthy
stellar network add local \
  --rpc-url http://localhost:8000/soroban/rpc \
  --network-passphrase "Standalone Network ; February 2017"
stellar keys generate local-admin --network local --fund
./scripts/deploy.sh --network local --secret-key local-admin
```

The rest of this guide explains each step and what to do when one fails.

## 1. Prerequisites

| Tool | Version | Needed for | Install |
| --- | --- | --- | --- |
| Git | any recent | everything | <https://git-scm.com> |
| Rust (rustup) | `1.79.0`, pinned by `rust-toolchain.toml` | building and testing | <https://rustup.rs> |
| `wasm32-unknown-unknown` target | matches the toolchain | building contract WASM | `./scripts/bootstrap.sh --install` |
| Stellar CLI (`stellar`) | `28.0.0` (what `scripts/bootstrap.sh` installs) | deploying and invoking contracts | `./scripts/bootstrap.sh --install` |
| Docker (with Compose v2) | any recent | the local network | <https://docs.docker.com/get-docker/> |
| Node.js | 18+ (CI uses 20) | `packages/soroban-sas-js`, `tools/schema-explorer` only | <https://nodejs.org> |
| Python 3 | 3.8+ | `scripts/check_docs.sh` only | <https://www.python.org> |

You don't need to install toolchain `1.79.0` yourself. The first `cargo`
command in the repository reads `rust-toolchain.toml` and has rustup fetch
it.

**Windows.** Every script in `scripts/` is a bash script. Use
[WSL 2](https://learn.microsoft.com/windows/wsl/) (recommended), or the Git
Bash shell that ships with Git for Windows. The repository's
`.gitattributes` keeps `*.sh`, `.githooks/*` and `*.rs` on LF line endings.
The scripts therefore run, and `cargo fmt --check` passes
(`rustfmt.toml` requires Unix newlines), even when `core.autocrlf` is on.
Expect the first workspace build to take 10–20 minutes.

## 2. Bootstrap the toolchain

```bash
./scripts/bootstrap.sh --install
```

The script checks that `rustup` and `cargo` exist, adds the
`wasm32-unknown-unknown` target if it's missing, and installs `stellar-cli`
with `cargo install --locked` if neither `stellar` nor `soroban` is on
`PATH`. Running it again is safe. It doesn't upgrade a CLI you already have,
so check yours with `stellar --version`. To install a different version, set
`STELLAR_CLI_VERSION=<x.y.z>`.

## 3. Build and test

```bash
cargo build --workspace          # native build of every crate (same as: make build-native)
make build-contracts             # optimized WASM for schema-registry, sas and indexer
cargo test --workspace           # all unit, snapshot and doc tests (same as: make test)
```

`make build-contracts` finishes by listing the WASM artifacts it expects
under `target/wasm32-unknown-unknown/release/`, and fails if one is missing.

While you iterate, run one crate's tests or filter by test name:

```bash
cargo test -p soroban-sas                    # the SAS contract
cargo test -p schema-registry register       # registry tests whose name contains "register"
cargo test -p soroban-sas-common --lib       # shared validation, hashing and types
```

The runnable SDK examples need no network when run with `--dry-run`:

```bash
cargo run --example basic_attestation
cargo run --example multi_attest -- --dry-run
```

The repository's own CLI is a normal workspace binary:

```bash
cargo run -p soroban-sas-cli -- --help
```

On macOS, if the sandbox stops rustc from writing temporary files, prefix
cargo commands with `TMPDIR=/tmp`.

Snapshot tests pin the exact XDR encoding of events and storage types. If
you change a `#[contracttype]` on purpose, follow the snapshot update steps
in [CONTRIBUTING.md](../CONTRIBUTING.md#snapshot-testing-for-xdr-event-payloads-256).

## 4. Formatting, linting and git hooks

CI rejects any pull request that fails `cargo fmt --all -- --check` or
`cargo clippy --workspace --all-targets -- -D warnings`. Run both locally
with:

```bash
make lint      # the exact fmt and clippy commands CI runs
make fmt       # apply formatting
```

### Git hooks

The repository ships two git hooks in `.githooks/`. Turn them on once per
clone:

```bash
./scripts/install_hooks.sh            # sets core.hooksPath=.githooks for this clone only
./scripts/install_hooks.sh --check    # is it installed?
./scripts/install_hooks.sh --uninstall
```

| Hook | Runs | When |
| --- | --- | --- |
| `pre-commit` | `cargo fmt --all -- --check` | a staged `*.rs`, `Cargo.toml`, `Cargo.lock`, `rustfmt.toml`, `clippy.toml` or `rust-toolchain.toml` |
| `pre-commit` | `bash -n` on each staged script | a staged `*.sh` or `.githooks/*` file |
| `pre-push` | `cargo fmt --all -- --check`, then `cargo clippy --workspace --all-targets -- -D warnings` | every push that sends commits (a branch deletion skips it) |

Commits stay fast because clippy runs on push, not on commit. Environment
variables change what the hooks do:

| Variable | Effect |
| --- | --- |
| `SAS_HOOK_CLIPPY=1` | pre-commit also runs clippy |
| `SAS_HOOK_TEST=1` | pre-push also runs `cargo test --workspace` |
| `SAS_SKIP_HOOKS=1` | skip every check (for clients without `--no-verify`) |

To skip the hooks for one command, use `git commit --no-verify` or
`git push --no-verify`. CI runs the same checks either way.

A few details:

- `pre-commit` checks the working tree, not the index. If you fix a staged
  file but don't re-stage the fix, the commit still goes through.
- The installer never overwrites an existing `core.hooksPath` (for example,
  one set by another hook manager), and leaves `.git/hooks` alone.
- If a GUI client or Git for Windows starts hooks without cargo on `PATH`,
  the hooks fall back to `$CARGO_HOME/bin` (default `~/.cargo/bin`).
- `./scripts/test_git_hooks.sh` tests the hooks against a stub `cargo`, and
  CI runs it in the *Developer Tooling* workflow. Run it after you change
  anything in `.githooks/`.

## 5. Run a local Stellar network

`docker-compose.yml` runs a pinned `stellar/quickstart` image as a standalone
network with Soroban RPC:

```bash
docker compose up -d stellar-quickstart     # or: make localnet (also waits)
./scripts/wait_for_localnet.sh
```

`wait_for_localnet.sh` returns once RPC reports healthy and the ledger is
advancing. If that doesn't happen before the timeout, it prints diagnostics
and exits non-zero.

| Setting | Value |
| --- | --- |
| RPC URL | `http://localhost:8000/soroban/rpc` |
| Network passphrase | `Standalone Network ; February 2017` |
| Friendbot | `http://localhost:8000/friendbot?addr=G...` |

Register the network with the Stellar CLI once, so you can pass
`--network local` instead of typing the URL and passphrase each time:

```bash
stellar network add local \
  --rpc-url http://localhost:8000/soroban/rpc \
  --network-passphrase "Standalone Network ; February 2017"
```

Stop the node with `docker compose down` (or `make localnet-down`). Ledger
state is kept in the `quickstart_data` volume. Use `docker compose down -v`
to wipe it and start from an empty ledger.

The pinned image, protocol version and the procedure for updating them are
covered in [Deployment Guide § Local Development](DEPLOYMENT.md#local-development-localnet--docker-quickstart).

## 6. Deploy the contracts locally

Create a funded identity on the local network, then run the one-shot
deploy script with `--network local`:

```bash
stellar keys generate local-admin --network local --fund
./scripts/deploy.sh --network local --secret-key local-admin    # or: make deploy-local
```

`--secret-key` accepts either an `S...` seed or the name of a Stellar CLI
identity. A named identity keeps the seed out of your shell history.
`deploy.sh` builds the WASM, deploys `schema-registry`, `sas` and `indexer`
in dependency order, initializes each one, and merges the contract IDs into
`.env`. On `local` and `testnet` it first tops up the admin account from
Friendbot, as a best effort. Load the results into your shell:

```bash
set -a; source .env; set +a
echo "$SAS_CONTRACT_ID $SCHEMA_REGISTRY_CONTRACT_ID $INDEXER_CONTRACT_ID"
```

If a deploy fails partway, the IDs deployed so far are saved in
`.deploy-manifest.env`. Rerun with `--resume` to continue from there. Run
`./scripts/deploy.sh --help` to see every flag.

### Make attestations work end to end

Every schema names a resolver contract, and `SAS::attest`/`revoke` call that
resolver's `on_attest`/`on_revoke`. If the call fails, the attestation fails.
For local experiments, deploy the accept-everything
`contracts/permissive-resolver`. It is a test fixture, so never use it on a
real network.

```bash
cargo build --release --target wasm32-unknown-unknown -p permissive-resolver
RESOLVER_ID="$(stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/permissive_resolver.wasm \
  --source-account local-admin --network local)"

# Optional: mirror every new attestation into the indexer.
stellar contract invoke --id "$SAS_CONTRACT_ID" --source-account local-admin --network local \
  -- set_indexer --indexer "$INDEXER_CONTRACT_ID"
```

To register a schema and issue your first attestation, continue with
[Getting Started for DApp Developers](getting-started.md#3-register-the-schema).
Use `--network local` wherever it shows `--network testnet`.

## 7. Integration tests against the local node

Workspace tests run against Soroban's in-process mock host. The live-node
suite in `tests/integration/` deploys a fresh stack to a real RPC node and
drives it through the Rust SDK. It is `#[ignore]`d by default:

```bash
export SOROBAN_RPC_URL=http://localhost:8000/soroban/rpc
export NETWORK_PASSPHRASE="Standalone Network ; February 2017"
export STELLAR_SECRET_KEY="$(stellar keys show local-admin)"
cargo test --test integration -- --ignored --test-threads=1
```

[DEVELOPER_RUNBOOK.md](../DEVELOPER_RUNBOOK.md) describes what each test
covers.

## 8. JavaScript packages

The TypeScript SDK and the schema explorer are standalone npm projects. The
Cargo workspace doesn't depend on either.

```bash
cd packages/soroban-sas-js && npm ci && npm test && npm run typecheck

cd tools/schema-explorer && npm ci && npm test
npm run dev    # http://localhost:5173, choose the "Local" preset
```

The [schema explorer](../tools/schema-explorer/README.md) lists the schemas
in your local registry. Paste `SCHEMA_REGISTRY_CONTRACT_ID` from `.env`. Its
validator applies the same rules as `SchemaRegistry::register`, so you can
check a schema string before you register it.

## 9. Other checks

| Check | Command | Details |
| --- | --- | --- |
| Documentation links and snippets | `./scripts/check_docs.sh` | needs `python3`; runs in CI as `check-docs` |
| Git hook behaviour | `./scripts/test_git_hooks.sh` | runs in CI as *Developer Tooling* |
| Dependency advisories and licenses | `cargo deny` / `cargo audit` | [CONTRIBUTING.md § Dependency security](../CONTRIBUTING.md#dependency-security) |
| Mutation testing | `cargo mutants` | [CONTRIBUTING.md § Mutation testing](../CONTRIBUTING.md#mutation-testing) |
| Fuzzing | `cargo +nightly-2024-06-13 fuzz run ...` | [CONTRIBUTING.md § Indexer fuzzing](../CONTRIBUTING.md#indexer-fuzzing) |

## 10. Make targets

| Target | Does |
| --- | --- |
| `make build-contracts` | Release WASM for the three contracts |
| `make build-native` | `cargo build --workspace` |
| `make test` | `cargo test --workspace` |
| `make fmt` / `make lint` | Apply formatting / run CI's fmt and clippy gates |
| `make install-hooks` | `./scripts/install_hooks.sh` |
| `make localnet` / `make localnet-down` | Start the local node and wait for it / stop it |
| `make deploy-local` | `./scripts/deploy.sh --network local` (reads the key from `$SOROBAN_SECRET_KEY`) |

## 11. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `error[E0463]: can't find crate for 'core'` when building WASM | The wasm target is missing: `./scripts/bootstrap.sh --install` |
| `$'\r': command not found` from a script | The file was checked out with CRLF endings. Run `git add --renormalize . && git checkout -- .` so `.gitattributes` restores LF. |
| Hook says `cargo not found` | Put `~/.cargo/bin` on `PATH`, or set `CARGO_HOME`. To commit anyway, use `--no-verify`. |
| `wait_for_localnet.sh` times out | Run `docker compose ps` and `docker compose logs stellar-quickstart`. The first start downloads history and can take a minute or two. Make sure nothing else is listening on port 8000. |
| `deploy.sh`: `neither 'soroban' nor 'stellar' CLI found` | `./scripts/bootstrap.sh --install`, then open a new shell |
| `deploy.sh`: account not found / `txNoAccount` | The account isn't funded. Rerun `stellar keys generate ... --fund`, or `curl "http://localhost:8000/friendbot?addr=$(stellar keys address local-admin)"`. |
| Contract calls fail with a version or XDR mismatch | Your CLI and the node disagree on the protocol. Compare `stellar --version` with the compatibility matrix in [DEPLOYMENT.md](DEPLOYMENT.md#protocol-and-toolchain-compatibility-matrix). |
| `attest` fails with `Error(Contract, #409)` (`ResolverRejected`) | The schema's resolver is not a deployed contract implementing `on_attest`. Use the permissive resolver [above](#make-attestations-work-end-to-end) for local testing. |
