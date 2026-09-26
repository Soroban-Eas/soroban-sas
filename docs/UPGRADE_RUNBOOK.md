# Contract Upgrade and Recovery Runbook

## Shared versioning and safety model

`schema-registry`, `sas`, and `soroban-sas-indexer` support in-place,
admin-authorized upgrades. Each contract stores an instance `VERSION` key,
treats a missing key on a legacy initialized instance as genesis version `1`,
and accepts only the exact next version. A skip, current version, or downgrade
returns `SASError::InvalidValue`; a version above that contract's audited
`MAX_KNOWN_VERSION` returns `SASError::IncompatibleDependency`. The current
maximum is `2`, so the audited activation supported by this code is `1 -> 2`.

The candidate hash must be non-zero and must already identify uploaded contract
WASM. Validation and the existing-layout sanity reads happen before version or
hash storage is changed and before the swap is requested. These reads validate
the state the currently executing code can deterministically inspect. They do
not run the candidate WASM or prove its post-installation behavior; simulation,
state comparison, and review of the candidate remain mandatory.

Every successful SAS or Indexer upgrade emits `ContractUpgraded` immediately
before `update_current_contract_wasm`. Soroban does not expose the current
contract's installed WASM hash to its own code. Consequently, the first SAS or
Indexer upgrade on an existing deployment emits an all-zero `old_wasm_hash` as
an explicit unknown sentinel, never as an asserted genesis hash. The candidate
hash is then tracked in instance storage, so later upgrade events can report the
previously targeted hash. Record the deployed genesis hash off-chain as part of
the release manifest.

If activation fails, the invocation is rolled back: version/hash writes and
contract events are not committed to ledger transaction metadata. The SDK 20
native test host may still expose an event published by a failed call through
its in-memory `Env::events()` collector; do not treat that collector as proof of
ledger commitment.

## Common preparation

For the selected contract:

1. Build, optimize, hash, and independently audit the candidate.

   ```bash
   # Set these to schema-registry/schema_registry, sas/sas, or
   # soroban-sas-indexer/soroban_sas_indexer.
   PACKAGE=sas
   WASM_BASENAME=sas
   stellar contract build --locked --package "$PACKAGE" --optimize --out-dir .upgrade
   CANDIDATE_WASM=".upgrade/$WASM_BASENAME.optimized.wasm"
   sha256sum "$CANDIDATE_WASM"
   stellar contract upload --wasm "$CANDIDATE_WASM" --optimize=false --source-account "$ADMIN_ADDRESS" --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE"
   ```

2. Query `get_version` on the target contract and set `NEXT_VERSION` to exactly
   the returned value plus one. Confirm it does not exceed that build's
   `MAX_KNOWN_VERSION`.
3. Save pre-upgrade query results and the contract IDs, bindings, administrator,
   release commit, optimized WASM hash, ledger sequence, and transaction hash.
4. Exercise the same version and state on a Testnet or localnet copy. Simulate
   the exact invocation before submitting it and inspect authorization, events,
   resource cost, and result.

   ```bash
   stellar contract invoke --id "$CONTRACT_ID" --source-account "$ADMIN_ADDRESS" --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" --send=no --cost -- upgrade --new-wasm-hash "$WASM_HASH" --new-version "$NEXT_VERSION"
   ```

## SchemaRegistry

### Pre-upgrade and activation

- Confirm the registry administrator and query `get_version`, `get_schemas`,
  representative `get_schema` results, fee configuration, and treasury.
- The current pre-activation sanity read touches `SCHEMA_COUNT`. This is a
  compatibility signal for the existing layout, not execution of the candidate
  and not a complete schema migration proof.
- Simulate and then submit:

  ```bash
  stellar contract invoke --id "$SCHEMA_REGISTRY_CONTRACT_ID" --source-account "$ADMIN_ADDRESS" --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" --send=yes -- upgrade --new-wasm-hash "$WASM_HASH" --new-version "$NEXT_VERSION"
  ```

### Post-upgrade verification

- Confirm `get_version == NEXT_VERSION`.
- Compare `get_schemas`, representative records, fee configuration, treasury,
  creator/delegate behavior, and validation results with the pre-upgrade
  capture.
- Confirm the same registry contract ID is still configured in SAS. An in-place
  upgrade preserves that ID; SAS does not need reinitialization.

## SAS

### Pre-upgrade and activation

- Confirm the SAS administrator and `get_version`; inspect the contract's
  `SCHEMA_REGISTRY` instance entry via RPC/ledger state (there is no public
  registry getter), and query `get_indexer`. Exercise representative
  attestation reads and record fee, treasury, strict-indexing, and
  admin-transfer state when configured.
- The on-chain sanity gate requires readable `SAS_ADMIN` and `SCHEMA_REGISTRY`
  addresses and, when `INDEXER` exists, a readable Indexer address. Missing or
  type-incompatible required layout returns `IncompatibleDependency`.
- Simulate and then submit:

  ```bash
  stellar contract invoke --id "$SAS_CONTRACT_ID" --source-account "$ADMIN_ADDRESS" --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" --send=yes -- upgrade --new-wasm-hash "$WASM_HASH" --new-version "$NEXT_VERSION"
  ```

### Post-upgrade verification and binding

- Confirm `get_version == NEXT_VERSION`, `admin` is unchanged, the
  `SCHEMA_REGISTRY` instance entry is unchanged, `get_indexer` is unchanged,
  and representative attestations remain readable and verifiable.
- Confirm the Indexer's `get_sas` still equals `SAS_CONTRACT_ID` and perform a
  controlled attestation/index lookup test.
- An in-place SAS upgrade preserves `SAS_CONTRACT_ID`; do not call
  `Indexer::init` again. It is one-time-only and will reject a second call.
- Call `SAS::set_indexer` only when intentionally changing to a different
  Indexer contract ID, repairing a previously absent/incorrect SAS-side
  binding, or executing an explicitly reviewed migration. It is not required
  after a successful in-place upgrade.

## Indexer

### Pre-upgrade and activation

- Confirm the Indexer administrator, `get_version`, and `get_sas`. Capture
  representative recipient, schema, attester, status, and pagination queries.
- The on-chain sanity gate requires readable `INDEXER_ADMIN` and `SAS_CONTRACT`
  addresses. Missing or type-incompatible required layout returns
  `IncompatibleDependency`.
- Simulate and then submit:

  ```bash
  stellar contract invoke --id "$INDEXER_CONTRACT_ID" --source-account "$ADMIN_ADDRESS" --rpc-url "$RPC_URL" --network-passphrase "$PASSPHRASE" --send=yes -- upgrade --new-wasm-hash "$WASM_HASH" --new-version "$NEXT_VERSION"
  ```

### Post-upgrade verification and binding

- Confirm `get_version == NEXT_VERSION`, `get_admin` and `get_sas` are
  unchanged, and the captured index queries return the same historical data.
- Confirm SAS `get_indexer` still equals `INDEXER_CONTRACT_ID`, then issue a
  controlled attestation and verify that it appears in each expected index.
- An in-place Indexer upgrade preserves `INDEXER_CONTRACT_ID` and its stored SAS
  binding. Do not call `Indexer::init` again. Call `SAS::set_indexer` only if a
  different Indexer ID is deliberately deployed or the SAS-side binding was
  already absent/incorrect.

## Forward recovery (all contracts)

There is no version downgrade. Recovery is a new, audited release with the next
monotonic version number, even when its WASM restores previously known-good
logic. Before recovery can activate version `3`, the recovery build must raise
its explicit `MAX_KNOWN_VERSION` to `3`; the current v2 code intentionally
rejects unknown future versions.

1. Halt affected writes operationally and preserve ledger/event evidence.
2. Identify or build the corrective WASM, audit it, pin its hash, and verify its
   storage compatibility against a state copy.
3. Add the next version to the reviewed contract build, upload its WASM,
   simulate the exact forward upgrade, then activate it.
4. Repeat every contract-specific post-upgrade and binding check above.
5. If faulty code wrote bad data, restoring code alone is insufficient. Reconcile
   affected records from the pre-upgrade capture and committed event history.

Re-wiring is needed only when recovery deploys a new contract ID or a binding
was already wrong. For a new Indexer ID, call `SAS::set_indexer(new_id)` and
initialize that new Indexer once with the existing SAS ID. For a new SAS ID,
deploy or explicitly migrate to an Indexer whose one-time SAS binding targets
that new ID; an already initialized Indexer cannot be rebound by calling
`init` again.

## Required release checks

Run the contract-specific upgrade tests plus the complete repository gates:

```bash
cargo fmt --all -- --check
cargo test -p sas
cargo test -p soroban-sas-indexer
cargo test -p schema-registry
TMPDIR=/tmp cargo test --workspace
./scripts/check_docs.sh
cargo clippy --workspace --all-targets -- -D warnings
```

Keep the resulting logs with the release manifest and candidate hashes.

## State-breaking changes and storage migrations

The per-attester SAS delegation nonce watermark key was migrated from the raw
tuple `(DELEGATION_NONCE, attester)` to the typed `DelegationNonceKey` structure.
Existing deployments with historical delegation nonces require a separately
reviewed migration that enumerates known attesters and copies each watermark.
New deployments use the typed key directly. This migration is not performed by
the generic upgrade entrypoint.


## Verification
Ensure you verify hashes using `scripts/verify_wasm_hashes.sh` against `CHANGELOG.md`.