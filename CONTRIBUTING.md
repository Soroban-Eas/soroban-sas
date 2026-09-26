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
