# soroban-sas

`soroban-sas` is a Rust workspace for a Stellar Attestation Service where users can create, verify and revoke on-chain and off-chain attestations. It provides a foundational layer for decentralized identity, reputation and verifiable claims on the Stellar network

This repository is structured as a multi-crate environment. It enables developers to locally test the fundamental attestation logic prior to integrating it with Soroban's specific mechanisms for storage, authorization and deployment

## Project Vision

The primary goal is to offer a seamless and intuitive user experience:

- Individuals and organizations can define new attestation formats, known as schemas (e.g., verifying human identity or confirming KYC completion).
- Any user or application can issue attestations conforming to these schemas, associating the claims with a particular Stellar account or external identifier.
- The issuer, or an authorized delegate, has the ability to update or completely revoke these claims.
- These verifiable claims can then be utilized across the ecosystem by decentralized applications, smart contracts, and off-chain services to manage access controls or establish trust and reputation.

## Example Use Cases

- **Decentralized Identity (DID)**: Issue proofs of personhood or identity verification.
- `DeFi Compliance`**: Attach KYC/AML attestations to accounts for permissioned liquidity pools.
- **DAO Governance**: Issue reputation scores or contribution attestations to weight voting power.
- **Social Networks**: Create a web of trust with user-issued endorsements and social graphs.

## System Architecture

For an in-depth look at how state is managed, the interactions between various smart contracts, and data synchronization processes, please consult the [Architecture Documentation](docs/architecture.md).

## Security and Threat Mitigation

Details about our security perimeter, administrative capabilities, and known vulnerabilities can be found in the [Security Assumptions and Threat Model](docs/security.md) guide.

Dependency security checks and indexer fuzzing commands are described in [Contributing](CONTRIBUTING.md).

## Project Status

The workspace has evolved beyond initial mocks and now includes comprehensive domain logic for the smart contracts:

- Common validation logic ensuring the integrity of schemas, attestations, expiry times, and issuer identities.
- Robust attestation records that track the full lifecycle of a claim, including its creation, expiration, and potential revocation.
- Fully stateful smart contracts handling the registry, schemas, attestations, and indexing capabilities.
- Extensive unit testing across all contract crates to validate standard operational flows.

## Repository Organization

### Smart Contracts

- `contracts/schema-registry`
  **Role**: Manages the canonical repository of schemas.
  **Duties**:
  - Persists schema structures and associated metadata.
  - Guarantees schema uniqueness and applies validation criteria.
  - Implements ownership-based access controls for modifications.

- `contracts/sas`
  **Role**: Handles the generation and administration of attestations.
  **Duties**:
  - Associates individual attestations with their defining schemas.
  - Records the core attestation payload along with issuer and recipient details.
  - Applies rules surrounding revocation, expiration, and any associated fees.
  - Facilitates off-chain verification processes, kin to EIP-712 standards.

- `contracts/indexer`
  **Role**: Provides efficient lookup and query functionalities.
  **Duties**:
  - Maintains mappings from recipient addresses to their respective attestations.
  - Maintains mappings from schemas to all associated attestations.
  - Supports newest-first cursor pages for recipient, schema, and attester history.

- `contracts/cross-chain-verifier`
  **Role**: Verifies remote attestation status updates authenticated by an Axelar GMP gateway.
  **Duties**:
  - Binds one remote chain and source contract at deployment.
  - Rejects unapproved, stale or expired updates and exposes short-lived remote verdicts.
  - Accepts versioned proof payloads carrying EVM schema, recipient, mapped Stellar address, and data.
  - Documents its [wire format and trust limits](docs/cross-chain-verification.md).

### Rust Packages

- `packages/soroban-sas-common`
  Contains shared definitions, error types, constants, and validation utilities utilized across the smart contract suite.

- `packages/soroban-sas-sdk`
  A streamlined Rust Software Development Kit designed to facilitate future integrations with wallets and decentralized applications.
  It includes builders such as `SchemaBuilder` and client helpers such as
  `SASClient::multi_attest` for batch attestation submission and
  `SASClient::fetch_admin` for deployment and governance verification.
  API documentation is published to GitHub Pages at
  https://soroban-sas.github.io/soroban-sas/soroban-sas_sdk/. To build it locally:
  ```bash
  cargo doc -p soroban-sas-sdk --no-deps
  ```
  The generated HTML lands in `target/doc/soroban-sas_sdk/index.html`.

### CLI and Operations

- `packages/soroban-sas-cli`
  A straightforward command-line interface for tasks such as registering new schemas, issuing claims, and revoking existing ones.

- `scripts/`
  A collection of shell scripts to assist with local environment setup, contract deployment, and invocation.

- `tools/schema-explorer`
  A prototype read-only web dashboard for browsing a Schema Registry and validating draft schemas.
  See the [Schema Explorer README](tools/schema-explorer/README.md).

- `tools/prometheus-exporter`
  A Prometheus metrics exporter that monitors SAS contract events and exposes metrics for observability.
  See the [Prometheus Exporter README](tools/prometheus-exporter/README.md).
- `.github_workflows/docs.yml`
  Builds the `soroban-sas-sdk` rustdoc and deploys it to GitHub Pages on every push to `main`.

- `.githooks/`
  Opt-in `pre-commit` and `pre-push` hooks that run CI's formatting and lint checks locally.
  Enable them with `./scripts/install_hooks.sh`.

## Command-Line Interface

All commands support `--output human` (default) or `--output json` for machine-readable output.

Usage examples:

```bash
cargo run -p soroban-sas-cli -- --output json schema get --uid UID... --registry-contract-id C... --rpc-url URL
cargo run -p soroban-sas-cli -- --output json schema withdraw-fees --amount 1000000 \
  --secret-key S... --network-passphrase "Test DF Network ;; September 2015" \
  --registry-contract-id C... --rpc-url URL
cargo run -p soroban-sas-cli -- --output json attest verify --uid UID... --contract-id C... --rpc-url URL
cargo run -p soroban-sas-cli -- --output json attest attest \
  --schema-uid UID... --recipient G... --data 0xdeadbeef \
  --secret-key S... --network-passphrase "Test DF Network ;; September 2015" \
  --contract-id C... --rpc-url URL