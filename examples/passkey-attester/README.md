# Passkey Attester for Stellar Smart Wallets

Browser demo that builds and signs SAS (Stellar Attestation Service) delegated attestation payloads using Passkeys (WebAuthn / Secp256r1) and submits them to a Stellar smart wallet contract on Soroban.

This example demonstrates the end-to-end flow required by the issue:

- Register a passkey and derive the Secp256r1 public key from the WebAuthn attestation.
- Construct a delegated attestation payload for a smart wallet account.
- Sign the payload with the browser WebAuthn API (`navigator.credentials.get`).
- Format `clientDataJSON` and `authenticatorData` into a Soroban-compatible signature structure.
- Verify the signature against the smart wallet account on-chain.

## Prerequisites

- Node.js 20+ and npm 9.+.
- A modern browser with WebAuthn support (Chrome, Safari, Firefox).
- A Stellar smart wallet contract deployed on Soroban that implements the SAS attestation verification interface.
- A Soroban RPC endpoint (e.g. `Test Soroban S3) and a funded account for submitting transactions.

## Installation

```bash
cd examples/passkey-attester
npm install
```

## Configuration

Copy the environment template and fill in the values for your deployment:

```bash
cp .env.local .env.local
```

Variables used by the demo:

| Variable | Description |
| --- | --- |
| `SoROBAN_RPC_URL` | Soroban RPC endpoint (e.g. `https://soroban-testnet.stellar.org`) |
| `SoROBAN_NETWORK_PASSPHRASE` | Network passphrase (e.g. `Test Soroban S3 Passphrase ; September 2023`) |
| `SWALLET_CONTRACT_ID` | Contract ID (C-address) of the smart wallet that verifies SAS attestations |
| `SOURCE_ACCOUNT_SECRET` | Secret key of the account that submits the transaction | 

The demo runs entirely in the browser for the WebAuthn portion and uses a small local dev server to submit transactions to Soroban.

## Running the demo

```bash
npm run dev
```

Open the printed URL in a browser. The demo exposes three steps:

1. **Register Passkey** — creates a new WebAuthn credential and derives the Secp256r1 public key from the attestation object.
2. **Sign Attestation** — builds the SAS delegated attestation payload and signs it with `navigator.credentials.get`.
3. **Verify On-Chain** — submits the formatted signature to the smart wallet contract and reads the verification result.

## Signature Format

Soroban verifies Secp256r1 signatures using the following structure, which the demo assembles from the WebAuthn response:

```ts
interface PasskeySignature {
  /** Raw authenticator data bytes (authenticatorData). */
  authenticatorData: Uint8Array;
  /** UTF-8 encoded clientDataJSON bytes. */
  clientDataJSON: Uint8Array;
  /** Derived Secp256r1 public key (X||), uncompressed. */
  publicKey: Uint8Array;
  /** ASN.1 DER encoded ECDSA signature. */
  signature: Uint8Array;
}
```

The demo produces this object and passes it to the contract as a `Scval` argument. The contract is responsible for:

- Parsing `clientDataJSON` and verifying the `challenge` field matches the expected attestation digest.
- Verifying the `rpIdHash` in `authenticatorData` matches the wallet's configured relying party ID.
- Verifying the ECDSA signature over `authenticatorData || SHA256(clientDataJSON)` using the Secp256r1 public key.

## Smart Wallet Integration Workflow

1. **Registration.** The wallet calls `navigator.credentials.create` with `publicKey.algorithm = -7` (ES256) and `publicKey.authenticatorSelection.authenticatorAttachment = "platform"`. The attestation object is parsed to extract the Secp256r1 public key, which is stored in the smart wallet contract.
2. **Challenge construction.** For each attestation, the wallet builds a deterministic challenge from the attestation payload (e.g. `SHA256(payload_bytes)`). The challenge is passed to WebAuthn as a base6url encoded string.
3. **Signing.** The wallet calls `navigator.credentials.get` with the challenge and the credential ID. The resulting `authenticatorData` and `clientDataJSON` are encoded as byte arrays.
4. **Signature formatting.** The demo assembles the `PasskeySignature` structure described above. The ECDSA signature returned by WebAuthn is DER-encoded and is passed through unchanged.
5. **Verification.** The signature structure is passed to the smart wallet contract, which verifies it against the stored public key and the expected challenge.

## Error Handling

WebAuthn operations can fail for many reasons. The demo handles the following cases and surfaces them to the user:

| Error | Handling |
| --- | --- |
| `NotAllowedError` (user cancelled) | Displays a retry prompt; no signature is submitted. |
| `SecurityError` | Displays an explanation that the origin is not trusted for the credential. |
| `InvalidStateError` | Resets the credential state and prompts for re-registration. |
| `NotSupportedError` | Shows a fallback message and suggests a supported browser. |
| Hardware failure (e.g. authenticator unresponsive) | Times out after 60 s and suggests retrying or using a different authenticator. |

## Browser Compatibility

The demo is tested on Chrome, Safari, and Firefox on desktop and mobile. Notes:

- Safari on iOS requires a user gesture (a click) to invoke WebAuthn. The demo always calls WebAuthn from a click handler.
- Firefox on Android supports platform authenticators via Google Play Services.
- Chrome on desktop requires a platform authenticator or a connected security key.

## Scripts

```bash
npm run dev      # Start the dev server

```