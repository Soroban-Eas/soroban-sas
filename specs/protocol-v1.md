# Protocol Specification

## Recipient invariants

Soroban `Address` values are already structurally validated by the host. SAS therefore applies semantic rules rather than duplicating address-format checks: the recipient must not be the protocol's zero account or zero contract sentinel, and it must differ from the attester. Self-targeting is rejected because an attestation is a claim made by an issuer about a distinct subject; accepting it would make issuer/subject separation ambiguous for consumers. These rules are applied by `attest`, `attest_with_value`, and `multi_attest` before an attestation is stored.

## Batch issuance

`multi_attest` accepts at most 100 attestations (`SASError::BatchTooLarge`). The limit bounds authorization, registry callbacks, storage, and indexing work within the measured Soroban budget envelope and is checked before processing begins, so an oversized batch cannot partially issue records. Distinct attesters are authorization-deduplicated with a Soroban `Map`, avoiding a linear scan of all earlier attesters.

## Dependency compatibility

SAS initialization performs the `sasreg` compatibility probe on the configured schema registry and rejects any dependency that does not return `true` with `SASError::IncompatibleDependency`; an arbitrary account or unrelated contract is never persisted. The schema-registry contract implements this probe as part of its v1 interface.

Indexer initialization uses the analogous `sasv1` probe on the configured SAS contract. A bad binding is rejected before state is written, and the admin/trust assumption is explicit: the initializer chooses the dependency, while the dependency proves it implements the expected interface. No contract-address-only check is treated as compatibility.
