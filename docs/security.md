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

See [offchain-attestations.md](offchain-attestations.md) for the full
signing/hashing scheme.
