# Ledger hardware signing (issue #471)

The SAS CLI can sign **on-chain transaction calls** using a Ledger Nano S/X
or Stax without accepting or storing a software secret key. The official
[Stellar CLI](https://developers.stellar.org/docs/tools/cli/stellar-cli)
performs the Ledger Stellar app's USB/APDU communication and on-device
approval. SAS verifies that the returned transaction is unchanged, was signed
by the selected account, and has a valid ed25519 signature.

## Device preparation

1. Install the official Stellar CLI and verify the commands
   `stellar keys public-key --ledger --hd-path 0` and
   `stellar tx sign --help` (look for `--sign-with-ledger`).
2. Plug in the Ledger, unlock it, and open the Stellar app. Enable any
   transaction-signing options required by your Stellar app firmware.
3. Confirm the address on device. Make sure the Ledger account is funded for
   the network you use.
4. Execute any on-chain SAS signing command with the **global** `--ledger`
   flag and hardened Stellar BIP-44 path:

```sh
cargo run -p soroban-sas-cli -- \
  --ledger --bip44-path "m/44'/148'/0'" --network testnet \
  attest attest --contract-id C... \
  --schema-uid <64-hex-digits> --recipient G...
```

The flags apply to on-chain schema registrations, admin operations,
attestations, revocations, and other SDK signing flows. The CLI discovers the
device's G-address before building the transaction; simulation and resource
estimation happen before the device is asked to sign. Review all available
transaction details on the Ledger screen before approval. The CLI prints the
source, sequence, fee and operation count plus the resulting transaction hash.

For compatibility, the earlier global `--hardware-wallet ledger --hd-account 0`
form also routes through the same backend. Do not combine either device option
with `--secret-key`, `SAS_SECRET_KEY`, or `--identity`. Unplugging the device,
closing the Stellar app, or rejecting approval returns an error and causes
exit code 1. There is **no private-key fallback**.

## Sign externally prepared XDR

```sh
cargo run -p soroban-sas-cli -- \
  --ledger --bip44-path "m/44'/148'/0'" \
  ledger-sign --xdr-file unsigned.xdr \
  --network-passphrase "Test SDF Network ; September 2015" \
  --output-file signed.xdr
```

The prepared envelope must be fully simulated, have the resource footprint
and fee included, and use the Ledger G-address as source. The signed output
file is created without overwriting an existing file. It is **not**
automatically sent by `ledger-sign`: submit it only after reviewing it.

**Limits:** Ledger Stellar app signs Stellar envelopes, not the arbitrary
off-chain SAS delegation payloads handled by `delegate sign-*` and
`offchain sign-*`. These commands fail closed when hardware is selected.
A real hardware-in-the-loop validation (Nano S/X/Stax, firmware and USB)
is still required before claiming device compatibility: no physical device
is present in the automated test environment.
