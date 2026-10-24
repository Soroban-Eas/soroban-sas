# Contributing to Soroban SAS

First off, thank you for considering contributing to Soroban SAS!

## Development Setup
1. Ensure you have Rust installed via rustup.
2. Install the `wasm32-unknown-unknown` target and the Stellar CLI:
   `./scripts/bootstrap.sh --install`.
3. Enable the git hooks, which run CI's `cargo fmt` and `cargo clippy` gates
   before you push: `./scripts/install_hooks.sh`.
4. Run `make test` to ensure your environment is working.

The full walkthrough, including a local Stellar node, local deployment and
troubleshooting, is in
[docs/local-development.md](docs/local-development.md).

## Pull Request Process
1. Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2. Update the README.md with details of changes to the interface.
3. Your PR must pass all CI checks (Formatting, Clippy, Tests, Build contracts, and `check-docs`) before it can be merged.

## Feature requests

Propose new capabilities with the **Feature request** issue form
(`.github/ISSUE_TEMPLATE/feature_request.yml`). It asks for the problem, the
proposed solution, compatibility and security/privacy impact, and acceptance
criteria, so a maintainer can triage without a round of questions. Report
security vulnerabilities privately as described in `SECURITY.md`, never
through an issue. `scripts/test_issue_templates.sh` validates the templates
and runs in the `Developer Tooling` workflow.

## Documentation checks

`scripts/check_docs.sh` runs as the `check-docs` job in
[`.github/workflows/docs.yml`](.github/workflows/docs.yml) on every push to
`main` and every pull request targeting `main`. It verifies that paths and
links referenced from `README.md`/`docs/*.md` still exist, that no obsolete
paths or commands are documented, that the CI workflow definitions match what
the README claims, and that bash snippets embedded in the README parse
correctly. `check-docs` must be added to `main`'s required branch protection
status checks alongside the existing `fmt`, `clippy`, `test`, and
`build-contracts` jobs; adding a workflow file does not enable branch
protection on its own — a repository administrator must do this from the
repository settings.

## Translations and Internationalization (i18n)

Contributors adding translations or localizing documentation, CLI error messages, and developer resources must follow the [Internationalization (i18n) and Translation Guidelines](docs/i18n-translation-guidelines.md). All translations must maintain code block integrity and pass relative link validation.

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

## Coverage reporting

Line/branch coverage is measured with
[`cargo-tarpaulin`](https://github.com/xd009642/tarpaulin) and enforced in CI
on every push and pull request against `main`. The CI job fails if total line
coverage falls below **60 %**; keep new code tested to prevent regressions.

### Running coverage locally

```sh
cargo install cargo-tarpaulin --locked
make coverage
```

This runs the workspace test suite under tarpaulin (config in
`.cargo/tarpaulin.toml`) and writes three report formats to `coverage-report/`:

| File | Purpose |
|------|---------|
| `tarpaulin-report.html` | Human-readable HTML, open in any browser |
| `cobertura.xml` | Cobertura XML, consumed by Codecov and IDE plugins |
| `tarpaulin-report.json` | JSON summary (used by the CI step summary) |

The `coverage-report/` directory is gitignored; do not commit it.

### Threshold and CI enforcement

The Coverage workflow (`.github/workflows/coverage.yml`) runs
`cargo tarpaulin --fail-under 60`, which exits non-zero when coverage is below
the threshold. The job also:

1. Writes a coverage percentage table to the GitHub Actions job summary
   (visible on the workflow run page).
2. Uploads the full HTML report as a downloadable artifact
   (`coverage-html-<run-id>`, retained for 30 days).
3. Uploads `cobertura.xml` to Codecov when the `CODECOV_TOKEN` repository
   secret is configured (the step is a no-op in forks without the secret).

The **Coverage** job must be added to `main`'s required branch protection
status checks by a repository administrator (adding the workflow file alone
does not enforce it).

### Exclusions

The following are excluded from measurement (see `.cargo/tarpaulin.toml`):

- `fuzz/` crate — compiled with a pinned nightly, incompatible with tarpaulin.
- `benches/` and `examples/` — harness code, not production logic.
- `tests/integration/` — end-to-end tests that require a live Stellar node.

### Increasing coverage

When the CI job fails on your PR, look at the HTML report or the Codecov diff
to find uncovered lines. Prefer writing unit tests for the specific logic
rather than adding broad smoke tests just to hit the threshold. Surviving
mutants (from `cargo-mutants`) are a stronger signal than raw line coverage;
use both tools together.

## Fuzzing

Fuzz targets live in the `fuzz/` workspace-excluded crate and are built with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz). All targets require a
pinned nightly toolchain; `cargo-fuzz` itself is installed with stable.

### Prerequisites

```sh
rustup toolchain install nightly-2024-06-13 --profile minimal
cargo +stable install cargo-fuzz --version 0.13.2 --locked
```

Fuzz compilation uses a pinned nightly because Soroban's `ethnum = 1.5.0`
dependency relies on a stable-library layout that the latest nightly can change.
The `cargo-fuzz` executable itself is installed with current stable Rust.

### Running a fuzz target

```sh
# Build one target
cargo +nightly-2024-06-13 fuzz build <target>

# Run it (Ctrl-C to stop; add -runs=N for a finite run)
cargo +nightly-2024-06-13 fuzz run <target>

# Short smoke-test (useful before pushing)
cargo +nightly-2024-06-13 fuzz run <target> -- -runs=1000 -max_len=4096
```

### Available targets

| Target | What it fuzzes |
|---|---|
| `schema_fuzz` | `validate_schema_syntax` — schema string parser |
| `typed_data_fuzz` | `hash_attestation_struct`, `hash_domain`, `hash_delegated_revocation` |
| `eip712_encode_fuzz` | EIP-712 `encode_data`, `hash_struct`, `hash_typed_data` determinism |
| `xdr_decode_fuzz` | Soroban XDR `ScVal::from_xdr_base64` |
| `cli_json_fuzz` | `serde_json` Value parsing |
| `indexer_chunking_fuzz` | Indexer chunk writer/reader round-trips and boundary transitions |
| `indexer_idempotency_fuzz` | `index_attestation` idempotency and duplicate-rejection invariants |
| `cross_contract_registry_sas_fuzz` | Schema-registry → SAS cross-contract boundary |
| `validation_fuzz` | `validate_attestation_parties`, `validate_ttl`, `validate_recipient` |
| `merkle_fuzz` | `merkle_root` + `verify_proof` round-trip and non-membership |
| `csv_bulk_fuzz` | `parse_bulk_csv` — `attest bulk` CSV parser |
| `strkey_fuzz` | `validate_strkey` — off-host Stellar address validator |
| `schema_builder_fuzz` | `SchemaBuilder::build` — SDK schema builder |
| `attestation_builder_fuzz` | `AttestationRequestBuilder::build` — SDK attestation builder |

### Indexer chunking target — corpus and seed details

Inputs contain 36-byte records: a four-byte key and a 32-byte UID seed. The
harness salts each UID with its insertion position, limiting inputs to 400
insertions, and checks both address and schema chunk writers against an
independent per-key sequence. Committed seeds cover 0, 1, 100, 101, 200, 201,
300, and 301 insertions. The zero seed is one incomplete record.

```sh
cargo +nightly-2024-06-13 fuzz run indexer_chunking_fuzz -- -runs=1000 -max_len=14400
```

### CI and campaigns

Every PR runs a smoke test (1,000–5,000 executions) of **all 14 fuzz targets**
via `.github/workflows/fuzz.yml`. Each smoke job builds the target and replays
the committed seed corpus before the PR is merged.

Long campaigns run on the weekly schedule (Sunday 02:00 UTC) and on
`workflow_dispatch`. Nine targets have a sharded campaign job:

| Target | Campaign shards | Total executions |
|---|---|---|
| `indexer_chunking_fuzz` | 100 (10 groups × 10 shards) | 10,000,000 |
| `validation_fuzz` | 5 | 2,500,000 |
| `strkey_fuzz` | 5 | 2,500,000 |
| `cross_contract_registry_sas_fuzz` | 5 | 1,000,000 |
| `schema_fuzz` | 5 | 1,500,000 |
| `merkle_fuzz` | 5 | 1,000,000 |
| `attestation_builder_fuzz` | 5 | 1,000,000 |
| `csv_bulk_fuzz` | 5 | 500,000 |

Crash artifacts are uploaded as GitHub Actions artifacts on failure; each
shard is named `<target>-crashes-<shard>` for easy retrieval.

### Apple Silicon note

AddressSanitizer can fail during linking on Apple Silicon due to a
[known Soroban SDK limitation](https://github.com/stellar/stellar-docs/issues/2238).
Use the thread sanitizer locally; Linux CI retains AddressSanitizer:

```sh
cargo +nightly-2024-06-13 fuzz run --sanitizer thread --codegen-units 16 \
    indexer_chunking_fuzz -- -runs=1000 -max_len=14400
```

### Adding a new fuzz target

1. Create `fuzz/fuzz_targets/<name>.rs` with `#![no_main]` and a
   `fuzz_target!(|data: &[u8]| { … })` body.
2. Add a `[[bin]]` entry to `fuzz/Cargo.toml`.
3. Add a smoke-test step to `.github/workflows/fuzz.yml`.
4. Add seed inputs under `fuzz/corpus/<name>/` if known-interesting inputs exist.

**Important safety rules for fuzz targets:**
- Never call `Address::from_string` (or `SorobanString::from_str` for an
  address) on a fuzz-derived string without first validating it with
  `soroban_sas_sdk::strkey::validate_strkey`. A malformed strkey traps the
  Soroban host and panics the fuzzer process rather than returning an error.
- Use `Env::default()` for pure-function targets and
  `env.mock_all_auths(); env.budget().reset_unlimited();` for contract targets.
- Every property assertion must come after confirming the input is well-formed
  enough to reach that branch; guard early with `if data.len() < N { return; }`.

### OSS-Fuzz continuous fuzzing

The `oss-fuzz/` directory contains the three files needed to register this
project with [OSS-Fuzz](https://github.com/google/oss-fuzz) for continuous,
infrastructure-backed fuzzing:

| File | Purpose |
|---|---|
| `oss-fuzz/project.yaml` | Project metadata, language (`rust`), sanitizer (`address`), engine (`libfuzzer`) |
| `oss-fuzz/Dockerfile` | Builder image (extends `base-builder-rust`); installs the pinned nightly toolchain |
| `oss-fuzz/build.sh` | Compiles all 14 targets with `cargo fuzz build -O --debug-assertions` and packages seed corpora |

**Constraints from the OSS-Fuzz Rust integration guide
([reference](https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/)):**
- Only `libfuzzer` and `address` sanitizer are supported for Rust projects.
- The `base-builder-rust` image ships with `cargo-fuzz` and the latest nightly; `build.sh` installs our pinned version (`0.13.2`) to ensure reproducibility.

To integrate with OSS-Fuzz:
1. Fork the [oss-fuzz repository](https://github.com/google/oss-fuzz).
2. Copy `oss-fuzz/` contents into `projects/soroban-sas/` in your fork.
3. Open a pull request against the OSS-Fuzz repository.
4. After merge, OSS-Fuzz builds and runs targets continuously and reports
   crashes to the security contact in `project.yaml`.

To test the OSS-Fuzz build locally (requires Docker):

```sh
git clone https://github.com/google/oss-fuzz
cd oss-fuzz
python3 infra/helper.py build_image soroban-sas
python3 infra/helper.py build_fuzzers --sanitizer address soroban-sas
# Run one target interactively
python3 infra/helper.py run_fuzzer soroban-sas validation_fuzz
# Reproduce a crash from a crash artifact
python3 infra/helper.py reproduce soroban-sas validation_fuzz /path/to/crash-input
```

## Snapshot Testing for XDR Event Payloads (#256)

Snapshot tests capture the exact XDR binary encoding of events and storage structures
to detect breaking changes that would silently corrupt off-chain indexers and dApp backends.
Snapshots are stored in `test_snapshots/` directories within each contract crate.

### Running snapshot tests

```sh
# Run all tests (includes snapshot tests)
make test

# Update snapshots after intentional breaking changes
UPDATE_SNAPSHOTS=1 cargo test -p soroban-sas --lib snapshot_tests
UPDATE_SNAPSHOTS=1 cargo test -p schema-registry --lib snapshot_tests
UPDATE_SNAPSHOTS=1 cargo test -p soroban-sas-indexer --lib snapshot_tests
```

### What snapshots capture

- **Events**: Exact XDR encoding of emitted event payloads (AttestationIssued, AttestationRevoked,
  SchemaRegistered, FeeConfigUpdated, ContractPaused, etc.)
- **Storage structures**: XDR layout of on-chain data structures (Attestation, SchemaRecord,
  AttesterKeyRecord, IndexerChunk, etc.)
- **Field ordering**: Ensures struct field order in XDR remains stable

### When snapshots change

If a test fails with "snapshot mismatch", the XDR encoding has changed. Possible causes:

1. **Intentional breaking change**: struct field reordering, type changes, new fields
   - Review the change in `git diff` carefully
   - Update snapshots: `UPDATE_SNAPSHOTS=1 cargo test ...`
   - Document as a breaking change in CHANGELOG.md
   - **Note**: Breaking XDR changes require a protocol version bump and off-chain migration

2. **Unintended change**: accidental field reordering or type mutation
   - Revert the change and run the test again
   - Verify the snapshot matches expected encodings

3. **New tests**: first run of a new snapshot test
   - Review the struct definition to ensure correctness
   - Run `UPDATE_SNAPSHOTS=1 cargo test ...` to create the initial snapshot
   - Commit the snapshot file to version control

### Snapshot file locations

```
contracts/sas/test_snapshots/
  - AttestationIssued.xdr
  - AttestationRevoked.xdr
  - Attestation.xdr
  - BatchAttested.xdr
  - FeeConfigUpdated.xdr
  - ContractPaused.xdr
  - ContractUnpaused.xdr

contracts/schema-registry/test_snapshots/
  - SchemaRegistered.xdr
  - SchemaRecord.xdr
  - SchemaFeeUpdated.xdr
  - SchemaDeprecated.xdr
  - SchemaDelegateAdded.xdr
  - AttesterKeyRecord.xdr

contracts/indexer/test_snapshots/
  - AttestationChunk.xdr
  - IndexerChunk.xdr
```
