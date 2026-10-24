# `sas-docgen`: Soroban SAS Schema Documentation Generator

`sas-docgen` is an automated documentation generator that queries the on-chain Soroban SAS `SchemaRegistry` and produces structured, static Markdown documentation sites compatible with [VitePress](https://vitepress.dev/), [Docusaurus](https://docusaurus.io/), and [mdBook](https://rust-lang.github.io/mdBook/).

## Features

- **On-Chain Discovery**: Connects directly to Soroban RPC to fetch registered schemas via `SchemaRegistry::get_schemas` and `get_creator`.
- **Field Extraction & Type Inspection**: Parses raw schema syntax into typed field definitions, detects off-chain metadata URIs (IPFS, HTTPS, Arweave), and annotates field roles.
- **Multi-Engine Compatible Markdown**: Emits documentation with universal YAML frontmatter (`title`, `id`, `description`, `sidebar_label`), markdown tables, and a structured `index.md` catalog and `SUMMARY.md`.
- **Code Examples**: Automatically generates usable integration examples for:
  - **Rust** using `soroban-sas-sdk`
  - **TypeScript** using `@soroban-eas/sas-sdk`
  - **cURL** targeting Soroban JSON-RPC (`simulateTransaction` and `getEvents`)
- **Offline / CI Fixtures**: Supports loading input schema definitions from offline JSON fixtures (`--from-file`) and exporting sample templates (`--sample-config`).

## Usage

### Build

```bash
cargo build -p sas-docgen
```

### Generating Documentation from an On-Chain Registry

```bash
# Generate docs from Stellar Testnet
cargo run -p sas-docgen -- \
  --network testnet \
  --registry-contract-id "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4" \
  --output-dir docs/schemas-generated
```

### Generating Documentation from an Offline Fixture

```bash
cargo run -p sas-docgen -- \
  --from-file tools/sas-docgen/fixtures/sample-schemas.json \
  --output-dir docs/schemas-generated
```

### Generating a Sample Configuration Template

```bash
cargo run -p sas-docgen -- --sample-config sample-schemas.json
```

## Options & Arguments

| Flag | Env Variable | Default | Description |
|---|---|---|---|
| `-n, --network <NET>` | `STELLAR_NETWORK` | `testnet` | Target network: `testnet`, `mainnet`, or `localnet` |
| `--rpc-url <URL>` | `SOROBAN_RPC_URL` | *(network default)* | Override Soroban RPC endpoint URL |
| `-r, --registry-contract-id <ID>` | `SCHEMA_REGISTRY_CONTRACT_ID` | — | SchemaRegistry contract address (`C...`) |
| `-o, --output-dir <DIR>` | — | `docs/schemas-generated` | Destination directory for markdown documentation |
| `--from-file <PATH>` | — | — | Path to JSON schema fixture file for offline generation |
| `--sample-config <PATH>` | — | — | Write a sample schema JSON fixture and exit |
| `--start-index <N>` | — | `0` | Starting index for on-chain schema pagination |
| `--limit <N>` | — | `100` | Maximum number of schemas to retrieve |

## Output Site Structure

The output directory contains:
- `index.md` — Catalog table summarizing all registered schemas, network details, and registry IDs.
- `<schema_uid>.md` — Dedicated documentation page for each schema, complete with field tables, metadata, and copy-pasteable Rust, TypeScript, and cURL snippets.
- `SUMMARY.md` — Navigation table of contents for `mdBook`.
