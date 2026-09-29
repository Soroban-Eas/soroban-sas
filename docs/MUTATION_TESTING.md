# Mutation Testing Baseline

This document records the first mutation testing baseline for the workspace,
measured with [`cargo-mutants`](https://mutants.rs). A mutant is a small
change to the source (for example `<` to `<=`). If the test suite still
passes, the mutant "survived" and points at behaviour the tests do not check.

## Results

| Package | Mutants | Caught | Missed | Timeouts | Unviable | Score |
|---|---|---|---|---|---|---|
| soroban-sas-common | 246 | 169 | 43 | 6 | 28 | 77.5% |
| schema-registry | 179 | 127 | 23 | 0 | 29 | 84.7% |
| sas | 253 | 187 | 34 | 0 | 32 | 84.6% |
| soroban-sas-indexer | 164 | 96 | 32 | 3 | 33 | 73.3% |
| soroban-sas-sdk | 466 | 202 | 86 | 19 | 159 | 65.8% |
| soroban-sas-cli | 219 | 145 | 63 | 6 | 5 | 67.8% |
| permissive-resolver | 0 | 0 | 0 | 0 | 0 | n/a |
| **Total** | **1527** | **926** | **281** | **34** | **286** | **74.6%** |

Score = caught / (caught + missed + timeouts). Unviable mutants do not
compile and are not counted.

Notes:
- `permissive-resolver` has 0 mutants: both functions have empty bodies
  returning `()`, so there is nothing to mutate. It is a test-harness contract.
- The `soroban-sas-indexer` run was made before `chunking_test_support.rs`
  was excluded. 6 of its 32 missed mutants are in that file and are no longer
  generated.
- Most `soroban-sas-sdk` timeouts are in `rpc.rs` (`RpcClient::post`,
  `read_body_bounded`, `parse_response`), where a mutant makes the tests wait
  on the network. A timeout counts as detected but is slow.

## Exclusions

Configured in `.cargo/mutants.toml`:
- `**/chunking_test_support.rs`, `tests/**`, `benches/**`, `fuzz/**`:
  test-support code, not production logic.

## Reproducing

Locally:

```
cargo install cargo-mutants
cargo mutants -p <package> --timeout-multiplier 3
```

Package names: `soroban-sas-common`, `schema-registry`, `sas`,
`soroban-sas-indexer`, `soroban-sas-sdk`, `soroban-sas-cli`,
`permissive-resolver`.

In GitHub Actions: run the "Mutation Testing" workflow manually
(`workflow_dispatch`) and enter the package name. Results are uploaded as the
`mutants-<package>` artifact. The workflow is manual only, so it does not
affect the existing CI, coverage or fuzz pipelines.

`cargo-mutants` exits with code 2 when mutants survive and 3 when some time
out. The workflow treats both as a successful baseline run.

## Highest-priority surviving mutants

- `schema-registry`: ownership and authorization (`transfer_ownership`,
  `is_schema_owner`, `is_owner_address`, `validate_owner_set`,
  `require_transferable_schema`).
- `sas`: `pause`, `unpause`, `is_paused`, `upgrade`, `set_treasury`, and the
  events `publish_withdrawal` and `publish_contract_paused`.
- `soroban-sas-cli`: `io_safety.rs` (`write_atomic_private`, `read_bounded`)
  and `perform_online_verification`.
- `soroban-sas-common`: `merkle.rs` (`verify_proof`, `merkle_root`).
- `soroban-sas-indexer`: pagination arithmetic and `upgrade`.
