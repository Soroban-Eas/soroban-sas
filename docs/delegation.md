# Delegated Issuance

Delegated issuance lets an issuer authorize an attestation or revocation with
an off-chain ed25519 signature, then let another account submit and pay for the
transaction. This keeps the issuer's signing key out of an online relayer. For
example, an issuer can sign with a hardware-backed or offline key and hand the
resulting JSON to an online service for submission.

The relayer does not become the attester and does not need to control the
attester account. Its secret seed only authorizes and funds the transaction.
The SAS contract authenticates the requested action from the issuer's signed
payload.

This guide describes delegated on-chain issuance and revocation. For the
underlying off-chain attestation format and its stable byte layout, see
[Off-Chain Attestations](offchain-attestations.md).

## Delegated attestation flow

`attest_by_delegation` receives an `Attestation`, a `u64` nonce, a 64-byte
signature, and a 32-byte public key. The contract:

1. Requires `revocation_time` to be zero.
2. Binds the supplied public key to `attestation.attester`. For a classic
   ed25519 account, the key must match the account address structurally. The
   contract also accepts the current non-revoked key stored by
   `register_attester_key` or `rotate_attester_key`.
3. Constructs the signed `AttestationDomain` from the current network ID, the
   current SAS contract address, and the supplied nonce.
4. Hashes the domain together with the signed attestation fields and verifies
   the ed25519 signature.
5. Consumes the nonce for the attester.
6. Runs the normal attestation validation and storage path.

The signed attestation fields are `uid`, `schema_uid`, `time`,
`expiration_time`, `ref_uid`, `recipient`, `attester`, `revocable`, and the
SHA-256 hash of `data`. `revocation_time` is deliberately excluded because the
contract mutates it when an attestation is revoked. A signature is therefore
bound to the attestation content, network, SAS contract, and nonce.

The entrypoint does not call `require_auth` on the attester or require the
transaction source to equal the attester. Any funded relayer can submit a valid
signed payload.

## Delegated revocation flow

`revoke_by_delegation` receives an attestation UID, nonce, signature, and
public key. It first loads the recorded attestation. The contract uses that
record's `attester` for both the public-key binding and the signed revocation
body, so a caller cannot substitute a different issuer.

Revocation uses the same `AttestationDomain` model—current network ID, current
SAS contract address, and nonce—but hashes a body containing the UID and
recorded attester under `DELEGATED_REVOCATION_TYPE_TAG`. That tag is distinct
from `ATTESTATION_TYPE_TAG`, and the two actions use different hash layouts.
Consequently, a signature created for an attestation cannot authorize a
revocation, or vice versa.

After signature verification, the contract consumes the nonce for the recorded
attester and runs the normal revocation checks. The attestation must exist, be
revocable, and not already be revoked.

## Nonce model and limitations

Delegated attestations and delegated revocations share one per-attester `u64`
high-watermark. The highest consumed value is stored in contract instance
storage under the typed `DelegationNonceKey { attester }` representation. The
same watermark is shared by delegated attestation and delegated revocation
flows. A delegated operation is accepted only when `nonce > last_nonce`;
otherwise it fails with
`SASError::DelegationReplay` (code `303`). On the first operation for an
attester, no watermark exists; issuers should start their increasing sequence
at `1`.

For example, after nonce `5` succeeds, nonce `5` and every value below `5`
fail. Nonce `6`, or any value greater than `5`, can succeed. If nonce `8` is
submitted before an already-signed operation using nonce `7`, the watermark
becomes `8` and the nonce-`7` operation can no longer succeed. Concurrent
signers and relayers therefore need a coordinated allocator and submission
policy; merely choosing distinct values is not sufficient when they can arrive
out of order.

Delegation activity renews the SAS contract's instance TTL, so the watermark's
lifetime tracks contract liveness rather than a separate per-signature
tombstone. This is not permanent storage: if the contract's instance storage
truly expires and its prior state is not restored, the watermark can be lost or
reset. Operators must keep the contract live and maintain its TTL. Restoring
archived instance state should preserve that state; redeploying or
reinitializing a contract is not a nonce-recovery mechanism and creates a
different signing domain when the contract address changes.

The contract exposes `get_delegation_nonce(attester) -> Option<u64>` for
inspecting this state. `None` means that no delegation nonce has been consumed
for the attester. `Some(n)` means that `n` is the current consumed
high-watermark, so the next valid nonce must be strictly greater than `n`.
Calling the getter also renews the contract's instance TTL.

The SDK wraps the contract getter as
`SASClient::fetch_delegation_nonce(&env, &rpc, &attester)`. Integrators should
read the current watermark before allocating and signing a new nonce. The read
is only a snapshot: two concurrent callers can observe the same value, and a
higher submission can land before a lower one. Offline and concurrent signers
must therefore still coordinate through a durable allocator rather than
treating the getter as an atomic nonce reservation.

## Issuer guidance

- Use a monotonically increasing counter. Allocate each value centrally,
  persist it before handing work to a signer or relayer, and retain the last
  allocated and last confirmed-consumed values.
- When several signers or relayers act for one attester, use a shared durable
  allocator and control submission order. Remember that attestations and
  revocations consume the same sequence.
- Unix timestamps can be nonces only when the issuer guarantees strict
  monotonicity. Equal timestamps, clock rollback, and a lower timestamp after a
  higher one was submitted all cause failures.
- Random nonces are unsafe unless the issuer knows the selected value is above
  the current high-watermark. Uniqueness alone does not satisfy the contract's
  ordering rule.
- If the watermark is uncertain, first reconcile durable allocator records,
  signed-payload inventories, and relayer receipts, and query
  `get_delegation_nonce` (or the SDK's `fetch_delegation_nonce` wrapper). Choose
  a value above both the on-chain high-watermark and every locally allocated
  nonce that might still be submitted. A `DelegationReplay` response means a
  competing operation advanced the watermark; query it again and allocate a
  newly signed higher nonce. Avoid jumping unnecessarily close to `u64::MAX`,
  because no greater nonce remains after that value is consumed.

Nonce state is keyed by `attester`, not by public key. Registering, rotating,
revoking, or re-registering a delegated-verification key does not reset the
attester's watermark. A rotated or revoked registered fallback key no longer
matches the current registered record, so signatures that depend on that
record stop authorizing new delegated operations. However, the implementation
accepts a key when it either structurally matches a classic ed25519 attester
address **or** matches the current registered record. Registered-key revocation
therefore does not act as a denylist for a key that independently passes the
classic-account structural check.

## CLI workflow

Use obvious environment placeholders or a configured `--identity`; do not put
production secret seeds in shell history. The attestation input format is the
one documented in [Off-Chain Attestations](offchain-attestations.md#cli).

Sign an attestation with the offline issuer key. The nonce is shared with the
issuer's delegated revocations and must be above its current watermark:

```sh
cargo run -p soroban-sas-cli -- offchain sign \
  --data-file attestation.json \
  --secret-key "$ISSUER_SECRET_SEED" \
  --nonce 6 \
  --network-passphrase "$NETWORK_PASSPHRASE" \
  --contract-id "$SAS_CONTRACT_ID" \
  --output signed-attestation.json
```

Move only the signed JSON to the online environment, then submit it with a
funded relayer account:

```sh
cargo run -p soroban-sas-cli -- delegate submit-attest \
  --file signed-attestation.json \
  --secret-key "$RELAYER_SECRET_SEED" \
  --rpc-url "$SOROBAN_RPC_URL"
```

To revoke, sign an action-specific payload with a new nonce. `--attester` must
be the recorded attester and must match the issuer signing key:

```sh
cargo run -p soroban-sas-cli -- delegate sign-revoke \
  --uid "$ATTESTATION_UID_HEX" \
  --attester "$ATTESTER_ADDRESS" \
  --nonce 7 \
  --network-passphrase "$NETWORK_PASSPHRASE" \
  --contract-id "$SAS_CONTRACT_ID" \
  --secret-key "$ISSUER_SECRET_SEED" \
  --output signed-revocation.json
```

Submit the signed revocation through the relayer:

```sh
cargo run -p soroban-sas-cli -- delegate submit-revoke \
  --file signed-revocation.json \
  --secret-key "$RELAYER_SECRET_SEED" \
  --rpc-url "$SOROBAN_RPC_URL"
```

`submit-attest` and `submit-revoke` use the network passphrase and contract ID
embedded in the signed file. The offline signer should verify those values
before signing, and the relayer should treat signed files as security-sensitive
input.

## Rust SDK submission

The SDK exposes `AttestationRequestBuilder` through its
`attestation_builder` module; it is not re-exported at the crate root. The
builder derives the content-addressed UID and initializes `time` and
`revocation_time` consistently with the current contract. This example also
reads the current nonce high-watermark through the SDK before submitting:

```rust,no_run
use soroban_sas_sdk::attestation_builder::AttestationRequestBuilder;
use soroban_sas_sdk::{client::SASClient, rpc::RpcClient};
use soroban_sdk::{Bytes, Env};

let env = Env::default();
let rpc = RpcClient::new("https://example.invalid");
let client = SASClient::new("C...SAS_CONTRACT".to_string());

// Load real strkey addresses from trusted configuration.
let recipient = std::env::var("RECIPIENT").expect("RECIPIENT is required");
let attester = std::env::var("ATTESTER").expect("ATTESTER is required");
let attestation = AttestationRequestBuilder::new()
    .with_schema_uid([2_u8; 32])
    .with_recipient(&recipient)
    .with_attester(&attester)
    .with_data(Bytes::from_slice(&env, b"example payload"))
    .with_expiration(0)
    .with_revocable(true)
    .with_ref_uid([0_u8; 32])
    .build(&env)?;

// This simple next-value calculation assumes one coordinated allocator.
// Persist the allocation before sending the nonce to an offline signer.
let watermark = client.fetch_delegation_nonce(&env, &rpc, &attestation.attester)?;
let nonce = watermark
    .unwrap_or(0)
    .checked_add(1)
    .expect("delegation nonce space exhausted");

// These values must be loaded securely and must contain the issuer's
// signature over this exact attestation and nonce.
let signature: [u8; 64] = /* decoded issuer signature */ [0_u8; 64];
let public_key: [u8; 32] = /* issuer ed25519 public key */ [0_u8; 32];
let relayer_secret_seed: [u8; 32] = /* loaded securely */ [0_u8; 32];

let result = client.attest_by_delegation(
    &env,
    &rpc,
    "Test SDF Network ; September 2015",
    &relayer_secret_seed,
    attestation,
    nonce,
    &signature,
    &public_key,
)?;
# Ok::<(), soroban_sas_sdk::errors::SdkError>(())
```

The fixed schema UID and zero-filled key/signature arrays above are explicit
placeholders, not valid production values. The built attestation, allocated
nonce, signature, public key, network passphrase, and contract ID must all
correspond to the same signed payload. Reading the watermark and submitting an
operation are separate calls, so production allocators must handle concurrent
advances between them.

For revocation, supply the UID bytes and an action-specific revocation
signature created with a new nonce:

```rust,no_run
# use soroban_sas_sdk::{client::SASClient, rpc::RpcClient};
# use soroban_sdk::Env;
# let env = Env::default();
# let rpc = RpcClient::new("https://example.invalid");
# let client = SASClient::new("C...SAS_CONTRACT".to_string());
# let relayer_secret_seed = [0_u8; 32];
# let public_key = [0_u8; 32];
let uid: [u8; 32] = [1_u8; 32];
let nonce: u64 = 7;
let revocation_signature: [u8; 64] = [0_u8; 64];

let result = client.revoke_by_delegation(
    &env,
    &rpc,
    "Test SDF Network ; September 2015",
    &relayer_secret_seed,
    &uid,
    nonce,
    &revocation_signature,
    &public_key,
)?;
# Ok::<(), soroban_sas_sdk::errors::SdkError>(())
```

These SDK methods submit already-signed operations; they do not allocate a
nonce or create the issuer signature.
