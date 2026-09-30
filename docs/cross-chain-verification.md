# Cross-chain attestation verification through Axelar GMP

The `soroban-sas-cross-chain-verifier` contract receives attestation status updates from one remote source contract through the [Axelar Stellar GMP gateway](https://docs.axelar.dev/dev/general-message-passing/stellar-gmp/intro). It is a separate contract, so the existing SAS v1 storage and `verify_attestation` semantics do not change.

## Trust and deployment

Deploy the verifier and call `init(admin, gateway, source_chain, source_address)`. Use the gateway contract ID for the target Stellar network and Axelar's exact registered source chain name. `source_address` must identify the remote program that computes status from its authoritative attestation registry. The init values cannot change; deploy another verifier to change the gateway or remote source. The admin authorizes initialization but cannot submit status updates.

Any relayer may call `execute(source_chain, message_id, source_address, payload)`. Before storing a verdict, the contract checks the configured source and calls the configured gateway's `validate_message(destination, source_chain, message_id, source_address, keccak256(payload))`, where `destination` is the verifier's own address. The gateway must return `true`; this consumes the approved message. A relayer's signature or a raw payload alone is never evidence of remote attestation status.

This is an Axelar trust model. The contract does not run an IBC light client or independently read remote chain state. A compromised gateway or configured source can supply false verdicts. Integrators must verify the gateway deployment and source program before `init`.

## Status payload v1

The remote source sends exactly 50 bytes, with no XDR or ABI wrapper:

| Offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 1 | Version `0x01` |
| 1 | 32 | Attestation UID bytes |
| 33 | 8 | Per-UID revision, unsigned big endian, greater than zero |
| 41 | 8 | `valid_until` Unix timestamp, unsigned big endian |
| 49 | 1 | `0x01` valid or `0x00` invalid |

For a valid update, `valid_until` must be later than the receiving ledger's timestamp and no more than 24 hours ahead. For an invalid update, `valid_until` must be zero. Revisions must strictly increase for each UID. The source should increase the revision when validity changes or when it refreshes a positive verdict. The source must send an invalid update after revocation; a positive update remains usable until its `valid_until` if that message is delayed.

The verifier rejects malformed, expired, overlong, unapproved and out-of-order messages. A failed call does not record a verdict. Successful calls publish `rem_att` with the UID and a `RemoteAttestationUpdated` payload containing the message ID and status.

## Reading a verdict

`verify_remote(uid)` returns `true` only for a stored positive update whose `valid_until` is still in the future. It returns `false` for unknown, negative or expired status. `get_status(uid)` returns the latest approved status and revision for diagnostics. The record's persistent storage TTL is renewed on reads. If archived, restore its footprint before querying, as with local SAS attestation records.

This verdict reflects the latest **delivered** update, not a synchronous remote query. Consumers requiring a shorter revocation window should have the source issue a shorter `valid_until` and refresh positive messages more often. Once the stored status expires, verification fails closed until a newer approved update arrives.
