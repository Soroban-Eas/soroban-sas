# Bulk Attestation Creation from CSV

`attest bulk` issues many on-chain attestations in a single run, reading them
from a CSV file. It exists for the case `attest attest` is awkward for: a
cohort, an airdrop allowlist, or a migration batch where the same schema is
applied to a list of recipients.

Each row is one on-chain transaction, in its own right. This is **not** the
Merkle batching described in [Batch Attestations](batch-attestations.md), and
it is not the on-chain `multi_attest` call: every row here produces a full,
individually readable, independently revocable on-chain attestation that shows
up in indexer queries.

## CSV format

The file needs a **header row**. Columns are matched **by name**, so their
order is free.

| Column | Required | Default | Meaning |
|---|---|---|---|
| `schema_uid` | yes | — | 32-byte schema UID, hex encoded |
| `recipient` | yes | — | Recipient address (`G...` or `C...`) |
| `data` | no | empty | Attestation payload, hex (`0x`-prefixed or not) or base64 |
| `expiration` | no | `0` | Unix expiry timestamp; `0` means no expiry |
| `revocable` | no | `false` | Whether the attestation can be revoked |

Minimal example:

```csv
schema_uid,recipient
1a2b3c...,GABC...
```

Full example:

```csv
schema_uid,recipient,data,expiration,revocable
1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b,GDVEU3DD4KOFECV66VIHWEZOYX4ZKR3WV27L464SIIPOU2IUI3JCZA57,0xdeadbeef,0,true
1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b,GD6ROJBYLKQMOW3E7N4M2YBPUHMZD7PL65VRHRMO24BOVSBV5H3BQRSL,,1800000000,false
```

The parser implements an RFC 4180 subset: comma separators, optional
double-quoted fields, `""` as an escaped quote inside a quoted field, and both
`\n` and `\r\n` line endings. Blank lines are skipped, and a quoted field may
span lines. A column that is present but unrecognised is an error rather than
a silent no-op, so a typo like `recievable` is reported instead of quietly
issuing an attestation with the wrong payload.

## Always dry-run first

`--dry-run` validates every row and prints the UID each one will get, without
building or submitting a single transaction:

```bash
cargo run -p soroban-sas-cli -- --output json attest bulk \
  --csv-file attestations.csv --identity my-attester --dry-run
```

It needs a signing key, because each UID is the content-addressed UID *for
that attester* — a preview with the wrong attester would be a preview of the
wrong thing. It needs no network configuration and makes no RPC call at all,
so it works fully offline.

## Everything is validated before anything is submitted

The command parses and fully validates **every** row — schema UID hex, payload
encoding, recipient strkey, and the contract's own recipient rules — before it
submits the first transaction. A typo in the last line of a large file
therefore aborts the run with nothing issued, rather than leaving you to
reconcile a half-issued batch by hand. Errors name the 1-based source line:

```text
error: line 3: schema_uid is invalid: invalid hex in uid: Odd number of digits
```

The same recipient checks the single-row commands apply are enforced here, so
attesting to the zero-address "no recipient" sentinel or to the attester
itself is refused locally with the contract's own `InvalidRecipient` (402)
error, before any fee is spent.

## Running the batch

```bash
cargo run -p soroban-sas-cli -- --output json attest bulk \
  --csv-file attestations.csv --secret-key S... \
  --network-passphrase "Test SDF Network ; September 2015" \
  --contract-id C... --rpc-url URL
```

All rows in one run are signed against a single ledger close time, so a batch
cannot straddle a ledger boundary with mixed `time` values. The time comes
from the network ledger, as with `attest attest`; `--allow-local-time` and
`--max-ledger-skew` behave the same way.

By default the run **stops at the first row that fails** so you can inspect
and fix the cause. Pass `--continue-on-error` to submit the remaining rows and
report each failure individually:

```json
{
  "status": "error",
  "message": "1 of 3 attestation(s) failed; first error: attest failed with status FAILED",
  "data": {
    "total": 3,
    "succeeded": 2,
    "failed": 1,
    "results": [
      { "line": 2, "status": "ok", "recipient": "G...", "uid": "…", "hash": "…" },
      { "line": 3, "status": "ok", "recipient": "G...", "uid": "…", "hash": "…" },
      { "line": 4, "status": "error", "recipient": "G...", "uid": "…", "error": "attest failed with status FAILED" }
    ]
  }
}
```

The command exits non-zero if any row failed, so it is safe to chain in a
script. Because already-issued rows cannot be undone, pair `--dry-run` with a
small first batch rather than a full production file.

## Limits

A file may contain at most **5,000 rows**, and is read through the same
bounded-read helper as every other CLI file input, so an oversized or
mistyped path is rejected before allocation rather than becoming an unbounded
sequence of fee-spending writes.

## Cost

One transaction, and one attestation's storage fee, per row. Issuing N
attestations therefore costs N transactions — this is the right tool for
hundreds of rows, not for thousands. If you are publishing a large, mostly
static dataset and only need "is this one entry in the set" to be provable,
use a [Merkle commitment](batch-attestations.md) instead: constant on-chain
storage and no per-item indexing cost.
