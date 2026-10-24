# Video Tutorials: Schema Generation

This page is the production plan and the written companion for the schema
generation video series. Each episode has a fixed running time, a script
outline and the exact commands shown on screen, so a viewer can follow along
with the video or skip it and read this page instead. Every command below is
real: it is the same CLI surface documented by `soroban-sas schema --help`.

Episodes are meant to be recorded against **Testnet** with throwaway keys.
Never show a secret key, a funded mainnet account or a `.env` file on screen.

## Series overview

| # | Episode | Length | You will learn |
|---|---------|--------|----------------|
| 1 | What is a schema? | 4 min | Schema structure, UIDs, why they are content addressed |
| 2 | Writing a schema definition | 6 min | Field syntax, supported types, common mistakes |
| 3 | Registering with the CLI | 7 min | `schema register`, `--dry-run`, resolver and revocability choices |
| 4 | Interactive mode | 5 min | `schema interactive` field-by-field builder |
| 5 | Registering from Rust | 6 min | `SchemaBuilder` and the `schema!` macro in the SDK |
| 6 | Verifying and looking up | 5 min | `schema get`, `schema get-by-content`, duplicate detection |

## Recording conventions

- Terminal font at least 18 pt, dark theme, 1920x1080 at 30 fps.
- Export the secret key through `SAS_SECRET_KEY` before recording starts and
  clear the terminal, so it never appears in shell history on screen.
- Use `--dry-run` for the first run of every command, then run it for real.
- Add captions for every episode and publish the transcript beside the video.
- Re-record an episode when a flag it shows is renamed. Keep the episode
  numbers stable and note the CLI version in the video description.

## Episode 1: What is a schema?

Talking points:

1. A schema is the canonical definition of an attestation format, for example
   `bool is_verified, string provider`.
2. The registry derives a content-addressed UID from the definition, the
   resolver and the revocability flag, so identical inputs always give the
   same UID and a schema cannot be registered twice.
3. Show the lifecycle diagram from [Architecture](architecture.md) and point to
   [Schema Definitions and Payloads](schemas.md) for the reference.

## Episode 2: Writing a schema definition

On-screen steps:

1. Write a definition such as `string name, uint32 score, bool passed`.
2. Show an empty definition and a malformed field being rejected, and explain
   that the registry validates the string before it stores anything.
3. Explain payload limits using the "Payload Size" section of
   [schemas.md](schemas.md).

## Episode 3: Registering with the CLI

```sh
export SAS_SECRET_KEY=S...   # off camera
export SCHEMA_REGISTRY_CONTRACT_ID=C...
export SOROBAN_RPC_URL=https://soroban-testnet.stellar.org
export SOROBAN_NETWORK_PASSPHRASE="Test SDF Network ; September 2015"

# Preview the resource fee. No state changes and no fee is spent.
soroban-sas schema register \
  --schema "bool is_verified, string provider" \
  --resolver C... \
  --revocable \
  --dry-run

# Submit for real. The signer becomes the schema owner.
soroban-sas schema register \
  --schema "bool is_verified, string provider" \
  --resolver C... \
  --revocable
```

Talking points: the resolver runs on every attest and revoke, `--revocable`
cannot be changed afterwards, and the signing account owns the schema.

## Episode 4: Interactive mode

```sh
soroban-sas schema interactive
```

Enter one `name Type` pair per line, finish with a blank line, then answer the
resolver and revocability prompts. Show an invalid answer being re-prompted.

## Episode 5: Registering from Rust

Show `SchemaBuilder` from `soroban-sas-sdk`, building a `SchemaRecord`, and
the failure for an empty definition. Point viewers at
`packages/soroban-sas-sdk/src/schema_builder.rs` and `schema_macro.rs`.

## Episode 6: Verifying and looking up

```sh
soroban-sas schema get --uid <64 hex characters>

soroban-sas schema get-by-content \
  --schema "bool is_verified, string provider" \
  --resolver C... \
  --revocable
```

Explain that `get-by-content` lets a caller check for an existing schema
without reproducing the host hashing rules.

## Publishing checklist

- [ ] Episode recorded against Testnet only, no secrets visible.
- [ ] Captions and transcript published.
- [ ] Description lists the CLI version and links to this page.
- [ ] Link added to the README Documentation section.
