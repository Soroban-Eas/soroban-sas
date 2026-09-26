# Contributing to Soroban SAS

First off, thank you for considering contributing to Soroban SAS!

## Development Setup
1. Ensure you have Rust installed via rustup.
2. Install the `wasm32-unknown-unknown` target.
3. Install the Soroban CLI.
4. Run `make test` to ensure your environment is working.

## Pull Request Process
1. Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2. Update the README.md with details of changes to the interface.
3. Your PR must pass all CI checks (Formatting, Clippy, Tests) before it can be merged.

## Dependency security

New and updated dependencies must pass both security checks before merge:

```sh
rustup update stable
cargo +stable install cargo-deny --version 0.20.2 --locked
cargo +stable install cargo-audit --version 0.22.2 --locked
cargo +stable deny --workspace --all-features --locked check
cargo +stable audit --file Cargo.lock
```

`deny.toml` rejects vulnerable/yanked dependencies and licenses outside the
explicit allowlist. Duplicate versions are warnings. The configuration uses
[current cargo-deny syntax](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html):
vulnerabilities are errors by default and the old `vulnerability`, `notice`,
`copyleft`, and license `deny` keys are no longer supported. `cargo-audit`
continues to report unmaintained-package warnings.

Advisory exceptions require a specific RustSec ID and a justification comment
in **both** `deny.toml` and `.cargo/audit.toml`. Review existing accepted risks whenever
Soroban is upgraded; do not suppress new findings merely to make CI green.

Workspace packages declare `publish = false` because the repository has no
project license yet. Cargo-deny's private-package policy excludes these
unpublished packages' own license metadata; all external dependencies remain
subject to the license allowlist and security checks, including development
dependencies. This does not grant a license or change dependency exceptions.
Before publishing a package, maintainers must select and record the project
license and remove its `publish = false` setting; its license metadata will
then be checked as well.

Repository administrators must enable **cargo-deny** and **cargo-audit** as
required status checks in the `main` branch protection rule or ruleset after
the workflow has run. Workflow YAML cannot enable branch protection. Replace
the former **Cargo Audit** required check if it was enabled.

## Mutation testing

Line/branch coverage only proves a test *executed* a piece of code, not that
the test would actually notice if that code were wrong. `cargo-mutants`
injects small artificial bugs (flipping `<` to `<=`, negating a condition,
dropping an authorization check, changing a return value, ...) and re-runs
the test suite once per mutant; a mutant that still passes tests ("survives")
marks a gap in coverage.

Run it locally against the contract/library crates:

```sh
cargo install cargo-mutants --version 24.7.0 --locked
cargo mutants --workspace \
    --package schema-registry \
    --package sas \
    --package soroban-sas-indexer \
    --package soroban-sas-common \
    --package soroban-sas-sdk
```

Config lives in `.cargo/mutants.toml` (per-mutant timeout, excluded test
paths). A full workspace run can take a while; scope it to one crate or one
file while iterating, e.g. `cargo mutants -f contracts/sas/src/lib.rs`, or use
`--jobs` to parallelize.

CI runs the `Mutation Tests` workflow (`.github/workflows/mutation-tests.yml`)
on every PR, on `main`, and nightly; it uploads a `mutants-report` artifact
but does not block merges yet. The goal is >=80% mutant kill rate on contract
crates before Mainnet deployment — treat surviving mutants reported there as
a signal to add or strengthen a test, not as noise to ignore.

## Indexer fuzzing

```sh
rustup toolchain install nightly-2024-06-13 --profile minimal
cargo +stable install cargo-fuzz --version 0.13.2 --locked
cargo +nightly-2024-06-13 fuzz build indexer_chunking_fuzz
cargo +nightly-2024-06-13 fuzz run indexer_chunking_fuzz -- -runs=1000 -max_len=14400
```

Fuzz compilation uses a pinned nightly compatible with Soroban 20's exact
`ethnum = 1.5.0` dependency (the latest nightly changes the layout of a standard
library error type assumed by that crate). The cargo-fuzz executable itself is
installed with current stable Rust.

Inputs contain 36-byte records: a four-byte key and a 32-byte UID seed. The
harness salts each UID with its insertion position, limiting inputs to 400
insertions, and checks both address and schema chunk writers against an
independent per-key sequence. The current indexer has no public count getter;
the oracle reads the same stored counters used by its queries. Assertions
cover complete reads, counts, physical chunk lengths, and transitions at
99/100/101, 200/201, and 300/301. Committed seeds include 0, 1, 100, 101, 200,
201, 300, and 301 insertions. The zero seed is one incomplete record.

Every PR runs a 1,000-execution smoke test. Scheduled/manual CI runs 100
100,000-execution shards (ten million total), with at most ten running at once, and uploads crash artifacts
on failure. Campaign completion must be confirmed in Actions; configuration
alone is not evidence that ten million executions passed.

On Apple Silicon, AddressSanitizer can fail during linking due to a
[known Soroban SDK limitation](https://github.com/stellar/stellar-docs/issues/2238).
Use the thread sanitizer locally; Linux CI retains AddressSanitizer:

```sh
cargo +nightly-2024-06-13 fuzz run --sanitizer thread --codegen-units 16 indexer_chunking_fuzz -- -runs=1000 -max_len=14400
```
