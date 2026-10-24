# Bulk CSV / JSON-L import (issue #470)

`soroban-sas attest import --file attestations.csv --contract-id C...`
processes datasets as atomic `multi_attest` transaction chunks. Each CSV
row must have `schema_uid` and `recipient`; optional columns are `data`,
`expiration` and `revocable`, as documented in
[CSV bulk attestations](bulk-csv-attestations.md).

JSON Lines files (`.jsonl` / `.ndjson`) use those same keys as JSON
objects, one object per line. Invalid rows are reported in
`<file>.errors.jsonl` without stopping valid rows. Input is capped at
5,000 records per invocation; use `--chunk-size 1..100` (default 10)
to tune per-transaction resource usage. Use `--dry-run` to preview row
validation without making any network submission.

A Soroban contract's explicit `FAILED` result indicates an atomic rollback.
Only in that case will the importer retry rows individually to isolate
on-chain failures. A transport failure is **not** retried since the
transaction might have already landed; reconcile transaction hashes and UIDs
before rerunning imports. Generated UIDs and transaction hashes are in the
output. The SDK does not yet expose the fee charged by transaction results,
so gas is reported as unavailable (never as a fabricated zero).
