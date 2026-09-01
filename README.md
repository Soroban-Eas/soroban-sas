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
- **DeFi Compliance**: Attach KYC/AML attestations to accounts for permissioned liquidity pools.
- **DAO Governance**: Issue reputation scores or contribution attestations to weight voting power.
- **Social Networks**: Create a web of trust with user-issued endorsements and social graphs.

## System Architecture

For an in-depth look at how state is managed, the interactions between various smart contracts, and data synchronization processes, please consult the [Architecture Documentation](docs/architecture.md).

## Security and Threat Mitigation

Details about our security perimeter, administrative capabilities, and known vulnerabilities can be found in the [Security Assumptions and Threat Model](docs/security.md) guide.

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
  - Facilitates off-chain verification processes, akin to EIP-712 standards.

- `contracts/indexer`
  **Role**: Provides efficient lookup and query functionalities.
  **Duties**:
  - Maintains mappings from recipient addresses to their respective attestations.
  - Maintains mappings from schemas to all associated attestations.

### Rust Packages

- `packages/soroban-sas-common`
  Contains shared definitions, error types, constants, and validation utilities utilized across the smart contract suite.

- `packages/soroban-sas-sdk`
  A streamlined Rust Software Development Kit designed to facilitate future integrations with wallets and decentralized applications.
  It includes builders such as `SchemaBuilder` and client helpers such as
  `SASClient::multi_attest` for batch attestation submission.

### CLI and Operations

- `packages/soroban-sas-cli`
  A straightforward command-line interface for tasks such as registering new schemas, issuing claims, and revoking existing ones.

- `scripts/`
  A collection of shell scripts to assist with local environment setup, contract deployment, and invocation.

## Command-Line Interface

All commands support `--output human` (default) or `--output json` for machine-readable output.

Usage examples:

```bash
cargo run -p soroban-sas-cli -- --output json schema get --uid UID... --registry-contract-id C... --rpc-url URL
cargo run -p soroban-sas-cli -- --output json attest verify --uid UID... --contract-id C... --rpc-url URL
cargo run -p soroban-sas-cli -- --output json attest attest \
  --schema-uid UID... --recipient G... --data 0xdeadbeef \
  --secret-key S... --network-passphrase "Test SDF Network ; September 2015" \
  --contract-id C... --rpc-url URL
cargo run -p soroban-sas-cli -- --output json query by-recipient --address G... --contract-id C... --rpc-url URL
```

Detailed usage and flags for every subcommand are available via:

```bash
cargo run -p soroban-sas-cli -- --help
```

## Local Development Network

A local standalone Stellar node with Soroban RPC is available via Docker Compose using a pinned Stellar Quickstart image (`stellar/quickstart:testing@sha256:2182a7558123ff6420ea5516283616634673956530a8edf89796ebe4b58bd784`):

```bash
docker compose up -d
./scripts/wait_for_localnet.sh
```

The health check ensures JSON-RPC is healthy and the local ledger is advancing before tests or deployment scripts run.

## Continuous Integration

Our CI pipeline automatically validates formatting (`cargo fmt`), executes linter checks (`cargo clippy`), runs workspace tests (`cargo test`), compiles optimized WASM artifacts (`wasm32-unknown-unknown`), and checks documentation consistency.

## Core Data Structures

The `Attestation` type within `packages/soroban-sas-common` serves as the foundational data model for the primary contract workflows. It captures the following attributes:

- `uid`: Unique identifier for the attestation.
- `schema_uid`: The identifier of the governing schema.
- `time`: Timestamp of creation.
- `expiration_time`: When the attestation is no longer valid.
- `revocation_time`: Timestamp of revocation, if applicable.
- `ref_uid`: Optional reference to a related attestation.
- `recipient`: The subject of the attestation.
- `attester`: The issuer of the attestation.
- `revocable`: Boolean indicating if the claim can be revoked.
- `data`: The encoded payload of the attestation.

The system evaluates the status of an attestation based on these fields:

- **Valid**: The current time is before the `expiration_time` (if defined), and `revocation_time` is zero.
- **Expired**: The current time has surpassed the `expiration_time`.
- **Revoked**: The `revocation_time` has been set to a non-zero value.

## Administrative and Recovery Policies

We have adopted a strict and conservative approach regarding administrative controls:

- There is no mechanism for an administrator to recover or alter existing attestations.
- Forced transfers or emergency reassignments of active attestations are not permitted.
- Only the original `attester` has the authority to revoke a claim, and only if it was marked as `revocable` upon creation.

This philosophy ensures that the system behaves predictably. Should governance or admin recovery features be introduced in the future, they will require rigorous Soroban authorization, transparent event logging, and clear documentation detailing the governance protocols.

## The Lifecycle of an Attestation

Issuing an attestation involves a streamlined on-chain process:

1. The issuer constructs a transaction detailing the `schema_uid`, the `recipient`, and the relevant `data`.
2. The smart contract queries the schema registry to confirm the schema's existence and validity.
3. Upon validation, the attestation is persisted on-chain and assigned a distinct `uid`.
4. As an optional step, the new record can be indexed or cryptographically linked to previous claims using the `ref_uid`.

## Data Consistency

To maintain integrity between the schema definitions and the issued claims, the core SAS contract strictly validates all operations against the canonical state held in the schema registry. The SAS contract maintains a reference to the registry's address to perform these checks during any state-modifying actions.

This architectural choice guarantees a single, authoritative source of truth for all schemas.

## Core Validation Checks

The shared validation libraries enforce several key constraints:

- Schemas must contain defined fields and cannot be empty.
- The submitted attestation data must conform strictly to the Soroban types outlined in the schema's signature.
- Expiration timestamps must be explicitly provided for temporary claims.
- Both the issuer and the recipient fields must contain valid identifiers.

## Getting Started

### System Requirements

- A recent stable version of the Rust toolchain (pinned to `1.79.0` via `rust-toolchain.toml`).
- WebAssembly compilation target: `rustup target add wasm32-unknown-unknown`
- The Stellar CLI suite: `cargo install --locked stellar-cli`

### Automated Setup (Recommended)

To automatically install or verify your toolchain environment, use the provided script:

```bash
./scripts/bootstrap.sh --install
```

### Manual Installation

Clone the repository and format the source code:

```bash
git clone https://github.com/Soroban-Eas/soroban-sas.git
cd soroban-sas
cargo fmt --all
```

Execute the test suite:

```bash
TMPDIR=/tmp cargo test --workspace
```

*Note: `TMPDIR=/tmp` is required because the default macOS temporary directories may restrict the Rust compiler from creating build artifacts during sandboxed test execution.*

## Documentation

- Documentation on Schema Syntax and Payloads: `docs/schemas.md`
- [Deployment Guide](docs/DEPLOYMENT.md): build optimized WASM, deploy
  `schema-registry`, `sas` and `indexer` to Testnet (via `scripts/deploy.sh` or
  `scripts/deploy_testnet.sh`), verify the deployment, and a Mainnet operational checklist.
- [Upgrade Runbook](docs/UPGRADE_RUNBOOK.md): staged upgrade and recovery procedures for `schema-registry`.
## Project Roadmap

`soroban-sas` is under active development. Our roadmap to a production-ready release is structured as follows:

### Phase 1: MVP Foundation (In Progress)
- Implement foundational contract logic (Schema Registry, core SAS contract).
- Develop initial SDK wrappers and CLI tools.
- Establish comprehensive shared validation protocols.

### Phase 2: Beta on Testnet
- **Integration**: Fully connect the CLI tools with the complete schema and attestation workflows.
- **Testing**: Broaden the scope of unit tests to cover off-chain capabilities and edge cases.
- **CI/CD**: Automate code formatting checks and workspace testing pipelines.
- **SDK**: Deliver a robust client implementation complete with Soroban RPC bindings.

### Phase 3: Mainnet Launch
- **Security**: Conduct third-party audits focusing on smart contract state management and authorization schemas.
- **Governance**: Introduce an optional fee mechanism for registering new schemas.
- **Ecosystem**: Integrate with indexing services and subgraphs for complex querying.
- **Documentation**: Launch a comprehensive developer portal with integration guides.

## Contributing

We welcome contributions! Please feel free to submit a Pull Request or open an issue for discussion.
