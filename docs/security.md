# Security Assumptions and Threat Model

This document describes the trust model of the SAS (Schema Attestation Service)
contract suite — `schema-registry`, `sas`, and the off-chain `soroban-sas-indexer`
— for auditors, security researchers, and protocol integrators evaluating the
system ahead of a Mainnet deployment.

## Trust Hierarchy

Trust in the system is layered, from most to least privileged:

1. **SAS / registry admin** — the address recorded by `SAS::init` /
   `SchemaRegistry::init`. Can reconfigure protocol parameters and move funds
   the contracts hold, but cannot forge, alter, or backdate an attestation.
2. **Schema creators** — the `owner` of a registered schema. Can manage that
   schema's delegate list and ownership, and (depending on the schema's
   `resolver`) gate who may attest under it.
3. **Resolvers** — contracts named by a schema's `resolver` field. Run
   arbitrary code on `on_attest`/`on_revoke` but only within the sandbox of a
   cross-contract call (see [Resolver Trust Boundary](#resolver-trust-boundary)).
4. **Attesters / recipients / anyone** — subject to whatever the schema and
   its resolver require; cannot bypass `attest_internal`'s validation.

No party above can forge an attestation's cryptographic identity: a UID is
derived deterministically from its contents (`schema_uid`, `attester`,
`recipient`, `data`, etc.), and issuance always requires either the
attester's `require_auth()` (`attest`) or a verified ed25519 signature bound
to that attester (`attest_by_delegation`).

## Admin Power

The SAS admin (set at `init`, rotatable via the two-step
`propose_admin`/`accept_admin` flow) can, with its own `require_auth()`:

- **Rotate the indexer** — `set_indexer` — the indexer only *records* what
  SAS reports; it does not decide who may attest, so rotating it cannot
  retroactively alter or forge indexed history in the SAS contract itself.
- **Change the fee policy** — `set_fee` / `clear_fee` — pins or clears the
  `(token, amount)` required by `attest_with_value`.
- **Withdraw collected fee tokens** — `withdraw_tokens` — see
  [Token Custody](#token-custody).
- **Toggle indexer-call strictness** — `set_indexer_strict`.

The schema-registry admin additionally controls the registry's own
fee/treasury configuration (`set_fee`, `clear_fee`, `set_treasury`,
`withdraw_fees`) and can **upgrade the registry's WASM** (`upgrade`).

The admin **cannot**: forge an attestation's UID or signature, bypass a
schema's `revocable` policy, alter an attestation already written to
storage, or read/modify a resolver's own contract state. There is currently
**no pause/circuit-breaker function** in either contract — a compromised
admin key cannot halt or freeze the protocol, but it can redirect fees and
rotate the indexer pointer as described above.

Risk profile of a compromised admin key: an attacker gains the ability to
redirect protocol fee revenue (via `set_fee` + `withdraw_tokens`, or their
registry equivalents) and to rewire the SAS↔Indexer link. They cannot mint,
alter, or revoke attestations they are not otherwise authorized to touch,
and they cannot drain funds held outside the contracts. Because there is no
mainnet-deployed instance yet, no compromised-admin incident has occurred.

## Resolver Trust Boundary

A schema may optionally name a `resolver` contract address. When present,
the SAS contract invokes `on_attest` before writing a new attestation, and
`on_revoke` before revoking one (see
[docs/schemas.md](schemas.md#resolver-callbacks) for the exact ordering).

- A resolver runs in its own contract's storage and instance sandbox; the
  cross-contract call gives it **no read or write access to the SAS
  contract's own storage**. It can only see the arguments passed to
  `on_attest`/`on_revoke` (the attestation, in `Val` form).
- A resolver's only two levers are (a) **reject** — return `false`, revert,
  or fail to implement the callback, all of which abort the attest/revoke
  call — or (b) accept, letting the operation proceed. It cannot modify the
  attestation's contents, redirect it to a different recipient, or force an
  attestation to be issued that the caller didn't request.
- Because `attest_internal` bounds `attestation.data` to
  `MAX_ATTESTATION_DATA_BYTES` (10 000 bytes) before invoking the resolver,
  a resolver can safely budget its own instruction estimate assuming that
  ceiling and skip redundant size re-validation (see
  [docs/schemas.md](schemas.md#payload-size)).
- A malicious or buggy resolver is a schema-level risk, not a protocol-level
  one: it can only affect attestations issued under schemas that explicitly
  named it.

## Token Custody

The SAS contract (and, separately, the schema-registry contract) can hold
SEP-41 token balances collected via `attest_with_value`'s fee mechanism.

- `withdraw_tokens` moves SAS-held fee tokens to `destination`. It may be
  authorized by the current admin, **or** by whichever address is currently
  configured as `TREASURY` (if any) — both cases still require
  `authorizer.require_auth()`.
- The admin therefore controls both the fee rate (`set_fee`) and the
  destination of withdrawn funds (`withdraw_tokens`'s `destination`
  argument); nothing else constrains where fee revenue can go. **This is
  intentional and expected** — the admin key is the protocol's designated
  fee-revenue controller, not a neutral escrow.
- The schema-registry's analogous `withdraw_fees` is admin-only and pays out
  to the registry's own `TREASURY` address, set via `set_treasury`.
- Attestation/schema fee tokens are the only value the contracts custody;
  neither contract escrows collateral, stakes, or bonds tied to attestation
  content.

## Known Limitations

- **No admin key recovery.** `init` sets the admin once; ownership can only
  move forward via `propose_admin`/`accept_admin`, both of which require the
  respective key's signature. If the current admin's key is lost (and no
  `propose_admin` was pending and accepted beforehand), the contract's admin
  role is **permanently and irrecoverably locked** — fee configuration and
  indexer rotation become frozen at their last-set values, though issuance,
  verification, and revocation of attestations continue to function
  normally since they do not require admin auth.
- **Irrevocable attestations are permanent.** An attestation issued with
  `revocable: false` (or under a schema with `revocable: false`) can never
  be revoked by anyone, including the admin — see
  [docs/schemas.md](schemas.md#revocability).
- **Indexer integrity depends on Indexer admin honesty.** The Indexer
  contract is a read-optimized index of attestation history, populated only
  by calls that require the configured SAS contract's `require_auth()`
  (`index_attestation`). The SAS contract, not the Indexer, is the
  authoritative source of truth for whether an attestation exists, is
  revoked, or is valid. An attacker who compromises the Indexer's own admin
  key can rotate which `sas` address the Indexer trusts or corrupt the
  Indexer's query results, degrading the *convenience* of querying
  attestation history — but cannot forge, alter, or revoke an attestation
  in the SAS contract itself, since the Indexer has no authority over SAS
  storage.
- **No pause/circuit-breaker.** Neither the SAS nor the schema-registry
  contract has an emergency-stop function; there is no way to halt
  attestation issuance or fee collection short of a WASM upgrade (registry
  only) or admin key rotation.

## Delegation Replay Protection

`attest_by_delegation` accepts an off-chain ed25519 signature instead of an
on-chain `require_auth()`, so it needs its own replay defense. The signed
payload commits to an `AttestationDomain`:

```
AttestationDomain {
    network_id: env.ledger().network_id(),
    contract:   env.current_contract_address(),
    nonce,
}
```

- **`network_id`** binds the signature to one Stellar network (e.g.
  Testnet vs. Mainnet vs. a Futurenet fork), so a signature captured on one
  network cannot be replayed on another.
- **`contract`** binds the signature to this specific SAS contract instance,
  so the same attester's signature cannot be replayed against a different
  deployment (e.g. a fork or a future upgraded instance at a new address).
- **`nonce`** is attester-scoped and consumed exactly once
  (`consume_delegation_nonce`) before `attest_internal` runs, so the same
  signed payload cannot be replayed twice against the same contract on the
  same network.
- The ed25519 public key presented alongside a delegated attestation must
  match the declared attester `Address`'s own key (enforced by comparing the
  key against the attester address's XDR encoding), so a caller cannot
  submit an attestation "from" an attester using a key that address doesn't
  actually correspond to.

### Domain separator byte layout

The domain separator and the full signed digest are computed in
`soroban_sas_common::typed_data` with the following exact preimage layout
(all multi-byte integers big-endian; addresses encoded as ScVal XDR):

```text
payload_hash = sha256(
    PAYLOAD_PREFIX                # b"\x19SorobanSAS\x01" (13 bytes)
    || domain_hash                # 32 bytes
    || struct_hash                # 32 bytes (attestation) or action-specific body
)

domain_hash = sha256(
    DOMAIN_TYPE_TAG               # b"SorobanSAS Domain v1(network_id,contract,nonce)"
    || network_id                 # sha256(network passphrase), 32 bytes
    || contract                   # ScVal XDR of the verifying contract's
                                  # ScAddress (SCV_ADDRESS discriminant, then
                                  # the 32-byte contract id)
    || nonce                      # u64, big-endian (8 bytes)
)
```

- `network_id` is `env.ledger().network_id()` on-chain — i.e. the SHA-256
  hash of the network passphrase (e.g.
  `"Test SDF Network ; September 2015"` for Testnet,
  `"Public Global Stellar Network ; September 2015"` for Mainnet).
- `contract` is `env.current_contract_address()` on-chain, XDR-encoded via
  `ToXdr`, so the separator commits to the exact verifying instance.
- Every delegated entry point (`attest_by_delegation`,
  `multi_attest_by_delegation`, `revoke_by_delegation`,
  `multi_revoke_by_delegation`, `invalidate_nonces_by_delegation`, and the
  read-only `verify_offchain_attestation`) constructs this domain from the
  live ledger values — callers cannot supply their own network id or
  contract binding.

The digest for an attestation additionally commits to every attestation
field (`ATTESTATION_TYPE_TAG || uid || schema_uid || time || expiration_time
|| ref_uid || recipient || attester || revocable || sha256(data)`); see
[offchain-attestations.md](offchain-attestations.md#typed-data-hashing) for
the struct layout and the golden vectors that pin it. Regression tests in
`contracts/sas/src/test_issue_492.rs` exercise cross-network and
cross-contract replay at the entry-point level and pin the exact rejection
error surfaces.

### Ed25519 signature malleability

An ed25519 signature is the 64-byte encoding `R || S`, where `S` is a scalar
that must satisfy `S < L` with
`L = 2^252 + 27742317777372353535851937790883648493` (the prime order of the
ed25519 group). Unless this bound is enforced, signatures are *malleable*:
for any valid `(R, S)`, the pair `(R, S + L)` (when it fits in 256 bits)
satisfies the ed25519 verification equation under a naive implementation,
so one logical signature would have two valid byte encodings.

SAS enforces canonicity at two independent layers:

1. **Contract-level guard** — `verify_offchain_signature` (the single
   verification entry point used by every delegated path) checks `S < L`
   against the embedded little-endian encoding of `L` *before* invoking the
   host, and rejects non-canonical inputs with the typed
   `SASError::InvalidSignature` (error code 302). This makes malleability
   rejection a deterministic contract-level guarantee, independent of host
   behaviour.
2. **Host verification** — the Soroban host's `ed25519_verify` uses
   ed25519-dalek's `verify_strict`, which additionally rejects non-canonical
   scalars, small-order components, and weak keys. A canonical but
   cryptographically invalid signature (e.g. `S = L - 1`) fails here with a
   host trap; through a `try_` client this surfaces as the non-contract host
   error `Context/InvalidAction` in the test environment.

Both layers fail closed: a rejected signature aborts the whole invocation
before `consume_delegation_nonce` runs, so no nonce is consumed and no
state is written. Regression tests cover `S + L`, `S = L`, `S = 2^256 - 1`,
and the canonical boundary `S = L - 1` for both the attestation and
revocation paths (`contracts/sas/src/test_issue_492.rs`, with unit-level
coverage in `packages/soroban-sas-common/src/test.rs`).

## Security Audit Checklist

- [x] **Signature malleability and cross-network replay audit (#492)** —
  domain separator confirmed to bind `env.current_contract_address()` and
  `env.ledger().network_id()` at every delegated entry point; cross-network
  (Testnet↔Mainnet) and cross-contract replay attempts verified to fail
  closed; non-canonical Ed25519 scalars (`S >= L`) rejected deterministically
  with `SASError::InvalidSignature` by the contract-level guard and by the
  host's `verify_strict`. Regression tests:
  `contracts/sas/src/test_issue_492.rs` (11 tests) and
  `packages/soroban-sas-common/src/test.rs` (malleability unit tests).

See [offchain-attestations.md](offchain-attestations.md) for the full
signing/hashing scheme.

## Vulnerability Disclosure and Reporting

For instructions on reporting security vulnerabilities, response SLAs, disclosure guidelines, and safe harbor terms, refer to our comprehensive [Security Policy and Vulnerability Disclosure Policy](../SECURITY.md).

