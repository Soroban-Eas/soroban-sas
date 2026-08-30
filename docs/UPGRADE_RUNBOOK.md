# SchemaRegistry Upgrade & Recovery Runbook

> **Scope**: `schema-registry` is the only contract that exposes an
> in-place upgrade entry point. `sas` and `soroban-sas-indexer` are
> **immutable** once deployed — bug fixes there require deploying fresh
> instances and re-wiring their dependencies (`SAS::set_indexer`,
> `Indexer::init` binding). Treat every Mainnet `schema-registry` upgrade
> as a staged, audited deployment.

## 1. Versioning Model

- Genesis version is `1` (set by `init`). `get_version()` reports it.
- Every upgrade **must** increment by exactly `1`: `new_version == old_version + 1`.
  Skips or downgrades are rejected with `SASError::InvalidValue` before any WASM
  is written.
- Only **known** versions are accepted. The contract stores `MAX_KNOWN_VERSION`
  (currently `2`) — any `new_version > MAX_KNOWN_VERSION` is rejected with
  `SASError::IncompatibleDependency` even if the hash looks valid. Add a new
  audited release to the allow-list before deploying it.
- The hash must be **non-zero** (`[0;32]` is rejected). Pin the exact `sha256`
  of the audited `schema_registry.wasm` for each release in git (`CHANGELOG.md`)
  and verify with `sha256sum target/wasm32-unknown-unknown/release/schema_registry.wasm`.

## 2. Pre-Upgrade Validation (Off-Chain, Required)

1. **Build & audit** the candidate WASM:
   ```bash
   cargo build -p schema-registry --release --target wasm32-unknown-unknown
   stellar contract optimize --wasm target/wasm32-unknown-unknown/release/schema_registry.wasm
   # → schema_registry.optimized.wasm
   sha256sum schema_registry.optimized.wasm | tee WASM_HASH
   ```
2. **Dry-run on Testnet** via `stellar contract deploy` + `stellar contract invoke --id <test_registry> -- upgrade --new-wasm-hash <hash> --new-version <next>` and run:
   - `cargo test -p schema-registry` (includes `test_upgrade_preserves_schemas`)
   - Manual `get_schema` / `get_schemas` / `validate_schema` against every live
     schema UID before and after the call.
   - `get_version` increments by one, `UPGRADE` event is emitted (see §4).
3. **Storage-migration gate** — the on-chain `upgrade` itself reads
   `SCHEMA_COUNT` to confirm the persistent layout is still readable. If the
   new WASM would orphan `SCHEMA_COUNT` or `CREATOR` keys, the gate fails and
   the upgrade reverts with `IncompatibleDependency`. For larger migrations,
   deploy a migration contract, simulate it with `stellar tx simulate`, and only
   then stage the upgrade.

## 3. Staged Activation

1. **Announce** the upcoming `old_version → new_version` and its hash at least
   one week before Mainnet activation (governance forum + on-chain event
   feed).
2. **Propose** the upgrade from a cold admin key (hardware wallet). Do not reuse
   the hot deploy key used for Testnet.
3. **Simulate** first:
   ```bash
   stellar contract invoke --id $SCHEMA_REGISTRY_CONTRACT_ID \
     --source-account $ADMIN_ADDRESS --rpc-url $RPC_URL --network-passphrase "$PASSPHRASE" \
     -- upgrade --new-wasm-hash <64_hex> --new-version 2 --simulate --cost
   ```
   Inspect `--cost` and the returned `UPGRADE` event; abort if the resource
   fee exceeds the keeper's buffer.
4. **Execute** the same invocation without `--simulate`:
   ```bash
   stellar contract invoke --id $SCHEMA_REGISTRY_CONTRACT_ID \
     --source-account $ADMIN_ADDRESS --rpc-url $RPC_URL --network-passphrase "$PASSPHRASE" \
     -- upgrade --new-wasm-hash <64_hex> --new-version 2
   ```
5. **Verify** within the same ledger:
   - `stellar contract invoke --id $SCHEMA_REGISTRY_CONTRACT_ID -- get_version` → `2`
   - `stellar contract invoke --id $SCHEMA_REGISTRY_CONTRACT_ID -- get_schemas --start 0 --limit 100` returns every pre-upgrade schema unchanged (checked via `sha256` of their XDR).
   - `validate_schema` on a known UID still returns `true`; deprecated UIDs remain `false`.

## 4. Events & Auditing

`upgrade(old_version, new_version, wasm_hash)` publishes:

```
topics: (symbol!("UPGRADE"), old_version: u32, new_version: u32)
data:   (old_version, new_version, wasm_hash: BytesN<32>)
```

Indexers (Zephyr, The Graph) should subscribe to `UPGRADE` to build a tamper-evident
upgrade history. Store `(old_version, new_version, hash, ledger_seq, tx_hash)`
off-chain for incident response.

## 5. Rollback / Forward Recovery

> There is no implicit `downgrade` entry point. A downgrade is a **forward
> upgrade** to a previously audited version's hash with the next monotonic
> version number.

### Scenario A: Faulty Activation Detected Within ~10 Ledgers

1. **Halt** new `register` / `deprecate` calls by rotating the admin key's
   signing authority off (revoke the compromised session; the contract remains
   readable).
2. **Re-build** the last known good WASM (e.g. `v1` hash `abc...` or `v2` hash
   `def...`). Verify its `sha256` matches the `CHANGELOG.md` pin.
3. **Forward-upgrade** to the good hash as the next version:
   ```bash
   # Suppose v2 was faulty; v3 will be a re-upload of v1's hash.
   stellar contract invoke --id $SCHEMA_REGISTRY_CONTRACT_ID \
     --source-account $ADMIN_ADDRESS --rpc-url $RPC_URL --network-passphrase "$PASSPHRASE" \
     -- upgrade --new-wasm-hash <GOOD_HASH> --new-version 3
   ```
   The `UPGRADE` event will show `2 → 3 (GOOD_HASH)`.
4. **Re-verify** every `get_schema` and `get_schemas` — the persistent
   `SCHEMA_COUNT` / `CREATOR` maps survive upgrades because the storage-migration
   gate rejects layouts that would orphan them (tested in
   `test_upgrade_preserves_schemas_and_config`). If any schema is missing,
   restore from the off-chain backup of `get_schemas` taken before activation.

### Scenario B: Faulty Activation After Extended Use

If bad data was written through the faulty logic, a hash rollback alone is
insufficient. Follow the same forward-upgrade step, then:

- Replay the off-chain `SchemaRegistered` event log to re-issue any schemas
  registered under the bad logic (their UIDs are deterministic `sha256(schema_xdr)`).
- Keep the bad version's `UPGRADE` event in the on-chain history — do not delete
  it — and document the incident in `CHANGELOG.md` with the ledger range and
  remediated UIDs.

### Tested Recovery Procedure

`test_upgrade_preserves_schemas_and_config` deploys a genesis registry, registers
two schemas and sets `fee`/`treasury`, upgrades `1→2`, and asserts:

- `get_version() == 2` and the `UPGRADE` event `(1,2,hash)` was emitted,
- both pre-upgrade `get_schema(uid)` still return the exact `SchemaRecord`,
- `get_schemas(0,10)` returns both,
- `fee`/`treasury` instance values survive,
- an upgrade with `new_version == 1` (downgrade) or `new_version == 3`
  (unknown) or `hash == 0` is rejected with `InvalidValue` / `IncompatibleDependency`
  **before** `update_current_contract_wasm` is called.

Run it with:

```bash
cargo test -p schema-registry -- test_upgrade_preserves_schemas_and_config
cargo test -p schema-registry -- test_upgrade_rejects_incompatible_version
cargo test -p schema-registry -- test_upgrade_rejects_zero_hash
```

Keep these green before every Mainnet upgrade.
