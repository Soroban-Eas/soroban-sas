# Security Policy and Vulnerability Disclosure

## Supported Versions

| Version / Branch | Supported          | Status             |
| ---------------- | ------------------ | ------------------ |
| `main`           | :white_check_mark: | Active Development |
| `< 0.1.0`        | :x:                | Unsupported        |

The project is under active development. Security updates and bug fixes are applied directly to the `main` branch and tagged in release candidates.

---

## Vulnerability Disclosure Policy

Soroban Attestation Service (SAS) welcomes responsible security research from the community. If you identify a security vulnerability or suspect a security flaw in any component of this repository (smart contracts, SDK, CLI, indexer, or verifiers), we urge you to report it privately and give our team reasonable time to remediate the vulnerability before public disclosure.

### Scope

The following components within this repository are in scope for security vulnerability reports:
- **Core Smart Contracts**: `contracts/sas`, `contracts/schema-registry`, `contracts/indexer`, `contracts/cross-chain-verifier`, `contracts/zk-verifier`
- **Core Protocol Packages**: `packages/soroban-sas-common`, `packages/soroban-sas-sdk`, `packages/soroban-sas-cli`
- **Cryptographic & Verification Logic**: Off-chain typed data EIP-712-style hashing, Ed25519 signature checks, zero-knowledge attestation commitment proofs, replay defense nonces, and timestamp anchoring.

Out of Scope:
- Attacks requiring physical access to a user's machine or compromised local developer environment.
- Phishing or social engineering targeting community members or contributors.
- Denial of Service against third-party public Stellar RPC endpoints or Horizon nodes.

---

## Reporting a Vulnerability

**DO NOT** file a public GitHub issue or submit a public pull request for security vulnerabilities.

Please report security issues privately via:
1. **GitHub Private Vulnerability Reporting**:
   Navigate to the [Security Advisories tab](../../security/advisories/new) of this repository and click "Report a vulnerability". This encrypts and restricts access to repository maintainers only.
2. **Security Contact**:
   If GitHub Security Advisories are unavailable or you prefer PGP encryption, email `security@soroban-sas.org` (or reach out to repository maintainers via GitHub security contacts) with details.

### What to Include in Your Report
To help us assess and resolve the issue quickly, please provide:
- A clear description of the vulnerability, including its category (e.g. authorization bypass, reentrancy, signature replay, state confusion, economic flaw).
- Step-by-step instructions or an end-to-end reproducible test case (preferably using `soroban-sdk` test harness).
- Affected contract(s), functions, or files with line numbers.
- Assessment of potential impact and exploitability under realistic network conditions.
- Any suggested remediation or patch.

---

## Response Process and SLAs

We take security issues seriously and adhere to the following service level objectives:
- **Initial Acknowledgment**: Within 48 hours of submission.
- **Triage and Assessment**: Within 5 business days, confirming severity rating (Critical, High, Medium, Low according to CVSS v3.1 / smart contract impact matrix).
- **Remediation & Patch Development**: A private patch will be prepared and tested within GitHub Security Advisories.
- **Release and Coordinated Disclosure**: A security advisory and patched release will be coordinated with the reporter. Standard embargo periods are typically 30 to 90 days from report confirmation unless active exploitation necessitates an immediate emergency release.

---

## Severity Classification

We classify vulnerabilities according to protocol impact:
- **Critical**: Direct theft of protocol fee tokens, arbitrary minting/altering of on-chain attestations without authorization, bypass of cryptographic verification, or catastrophic contract lockout.
- **High**: Bypassing resolver revocation gates, unexpected state desynchronization between SAS and Indexer under normal traffic, or unauthenticated manipulation of schema delegate allowlists.
- **Medium**: High-gas consumption attacks / un-metered state bloat, griefing attacks that prevent honest attesters from indexing, or minor logic discrepancies in expiration calculations.
- **Low / Informational**: Minor deviations from specification that do not impact funds or attestation integrity, documentation omissions, or non-exploitable edge cases.

---

## Safe Harbor & Research Conduct

We consider security research conducted under this policy to be authorized. We commit not to pursue legal action against researchers who:
- Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of services.
- Test only against local mock environments, testnets, or isolated Soroban sandbox instances, and never against live production users or contracts.
- Give maintainers reasonable time to resolve the issue before sharing any technical details publicly.
- Do not exploit a vulnerability beyond what is strictly necessary to prove its existence.

---

## Additional Resources

- [Security Assumptions and Threat Model](docs/security.md)
- [Zero-Knowledge Private Attestations](docs/zk-private-attestations.md)
- [Contributing Guidelines](CONTRIBUTING.md)
