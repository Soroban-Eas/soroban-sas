# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- `Indexer::index_attestation` is now idempotent: a repeated call with the
  same `(recipient, schema_uid, attester)` triple for a UID is a no-op, and a
  repeated call with a different triple is rejected with
  `SASError::DuplicateAttestation`. Adds `Indexer::get_attestation_status` and
  the `IndexStatus` type. (#129)
- `soroban-sas-sdk`: `RpcClient` now bounds RPC response bodies
  (`with_max_response_bytes`, default 4 MiB) and decodes every RPC-supplied
  XDR payload with finite depth/size limits (`soroban_sas_sdk::limits`),
  returning `SdkError::ResponseTooLarge` instead of allocating without
  bound. (#136)
- `soroban-sas-sdk`: `SequenceManager` hands out collision-free account
  sequence numbers to concurrent writers
  (`SASClient::with_sequence_manager`), resynchronising and retrying once on
  a `txBadSeq` rejection. (#132)
- `soroban-sas-sdk`: `SubmissionPolicy` makes write settlement configurable —
  poll interval, wall-clock deadline, poll cap, fixed/exponential backoff,
  and blocking vs. asynchronous mode (`SASClient::with_submission_policy`).
  `GetTransactionResult` gains a `hash` field. (#133)
- Initial workspace structure and foundational crates.
- Schema Registry contract implementation.
- SAS core contract implementation for issuing and revoking attestations.
- Indexer contract for reverse lookups.
- CLI tool (`soroban-sas-cli`) for interacting with contracts.
- SDK wrapper (`soroban-sas-sdk`) for dApp integration.
- EIP-712 style off-chain attestations: deterministic typed-data hashing and
  ed25519 verification utilities in `soroban-sas-common`, a
  `verify_offchain_attestation` entrypoint in the SAS contract, and
  `offchain sign` / `offchain verify` CLI commands.
- `SASError::AlreadyInitialized` (code 1) and `SASError::InvalidValue` (code 403).
- `Indexer::init` now binds the indexer to an admin and a SAS contract
  address, with `Indexer::get_admin` / `Indexer::get_sas` accessors.
- `SchemaBuilder` for constructing SDK `SchemaRecord` values and
  `SASClient::multi_attest` for submitting batch attestations.
- `LEDGERS_IN_ONE_YEAR` common constant for persistent storage TTL bumps.

### Changed
- `soroban-sas-sdk`: a blocking write that never settles now returns
  `SdkError::SettlementTimeout { hash, last_status, polls }` instead of a
  generic `SdkError::RpcError`, and a `sendTransaction` rejection returns
  `SdkError::SubmissionRejected` — so timeout, RPC failure, and terminal
  on-chain failure are distinguishable. (#133)
- All contract failure paths now panic with typed `SASError` variants instead
  of bare `panic!` strings, so callers can distinguish failures by error code.
- `SAS::attest_with_value` now performs the SEP-41 token transfer from the
  attester to the contract before issuing the attestation, instead of
  silently ignoring the `token` and `value` arguments. Negative values are
  rejected with `SASError::InvalidValue`.
- Persistent contract storage writes now extend TTL, and attestation reads
  refresh TTL for active state.
- `SAS` can bind an `Indexer` and mirror newly issued attestations so
  replacements are discoverable through indexer lookups.

### Fixed
- `SAS::set_indexer` and `SAS::attest` no longer trap when the contract has
  not been initialized. Both now report `SASError::NotInitialized` through a
  shared `require_admin` / `require_registry` guard, so SDK and CLI callers
  get one stable error code for a missing `init` instead of an unclassified
  host trap. `set_indexer` classifies the pre-init case before requiring
  authorization; `attest` resolves the registry before payload validation so
  a configuration failure is never masked by a payload complaint.
  (#76, #77)
- `Indexer::get_attestations_by_recipient` / `_by_schema` / `_by_attester`
  now walk every chunk backing a lookup key instead of returning chunk 0
  only, so a key with more than 100 UIDs is no longer silently truncated.
  All three dimensions share the same cursor model as the paginated and
  filtered reads. (#78)
- Indexer chunk reads now extend the TTL of the entries they touch, so a
  frequently queried but rarely updated index is not archived out from under
  its callers. Reads of a missing chunk return empty without creating storage
  or trapping. (#79)

### Known Issues
- `SchemaRegistry::deprecate` currently lacks an authorization check.
- Delegated attest/revoke signatures do not bind the full attestation payload or a nonce, permitting potential replay.
