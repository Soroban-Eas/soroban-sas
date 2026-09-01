# Off-Chain Attestations

## Version 1 Protocol Specification

**Version:** v1  
**Status:** Stable  
**Breaking Changes:** Any change to the byte layout, hash order, type tags, or XDR encoding is a major version bump.

Off-chain attestations let an issuer sign an `Attestation` payload without
submitting a transaction. Holders can store the signed payload locally (for
example in a mobile wallet) and selectively reveal it; any verifier — a
Soroban contract or an off-chain service — can check it against the issuer's
ed25519 public key.

## Versioning and Compatibility

The v1 protocol is locked by golden test vectors in
`packages/soroban-sas-common/src/typed_data.rs` (`golden_vectors` module).
These tests pin the exact digest values for canonical inputs covering:

- Testnet vs. Mainnet network ID separation
- Different contract addresses
- Different nonce values
- End-to-end signature verification

Any implementation change that alters the computed digest for these inputs
**must** be treated as a breaking change and released as v2 with a new type tag.

Cross-language implementations (JavaScript, Python, Go, etc.) should verify
their hash outputs against the golden vectors to ensure interoperability.

## Typed-data hashing

Hashing lives in `soroban_sas_common::typed_data` and follows an EIP-712
style two-level scheme over SHA-256:

```text
payload_hash = sha256(
    "\x19SorobanSAS\x01"
    || domain_hash
    || struct_hash
)

domain_hash = sha256(
    DOMAIN_TYPE_TAG
    || network_id            # sha256(network passphrase), 32 bytes
    || contract              # ScVal XDR of the verifying contract address
    || nonce                 # u64, big-endian
)

struct_hash = sha256(
    ATTESTATION_TYPE_TAG
    || uid                   # 32 bytes
    || schema_uid            # 32 bytes
    || time                  # u64, big-endian
    || expiration_time       # u64, big-endian
    || ref_uid               # 32 bytes
    || recipient             # ScVal XDR of the address
    || attester              # ScVal XDR of the address
    || revocable             # 1 byte (0 or 1)
    || sha256(data)          # 32 bytes
)
```

`revocation_time` is deliberately excluded: it is mutated by on-chain
revocation, and including it would let a stale signed copy diverge from the
canonical record.

The issuer signs `payload_hash` with the ed25519 key backing its Stellar
account (`ed25519(payload_hash)`), producing a 64-byte signature.

## Replay protection

A signature commits to:

- **network_id** — a payload signed for testnet is invalid on mainnet;
- **contract** — the signature is bound to one SAS contract instance;
- **nonce** — an issuer-chosen `u64`; verifiers decide which nonces they
  accept, so the same attestation content can be re-issued only under a new
  nonce;
- **expiration_time** — the on-chain verifier rejects expired attestations
  against the ledger timestamp.

The on-chain verifier additionally checks that the provided public key is
exactly the ed25519 key of the declared `attester` account (by comparing
against the address's XDR encoding), and that the attestation's UID has not
been revoked on-chain.

## On-chain verification

```rust
// SAS contract
pub fn verify_offchain_attestation(
    env: Env,
    attestation: Attestation,
    nonce: u64,
    public_key: BytesN<32>,
    signature: BytesN<64>,
) -> bool
```

Returns `true` when the attestation verifies; panics when the public key does
not match the attester, the attestation is expired or revoked, or the
signature is invalid (`ed25519_verify` host semantics).

## CLI

Sign an attestation off-chain:

```sh
soroban-sas offchain sign \
  --data-file attestation.json \
  --secret-key SB... \
  --nonce 7 \
  --network-passphrase "Test SDF Network ; September 2015" \
  --contract-id C... \
  --output signed.json
```

`attestation.json`:

```json
{
  "uid": "0101...01",
  "schema_uid": "0202...02",
  "time": 1000,
  "expiration_time": 0,
  "ref_uid": "0000...00",
  "recipient": "G...",
  "attester": "G...",
  "revocable": true,
  "data": "deadbeef"
}
```

Verify a signed attestation off-chain:

```sh
soroban-sas offchain verify --file signed.json
```

The CLI computes the digest with the same `soroban_sas_common` code the
contract uses, so the two can never drift.
