# Blacklist Resolver

The `blacklist-resolver` Soroban contract (issue #460) can be registered
as a schema resolver. It has two constant-time blacklist lookups during
`on_attest` (one for the attester and one for the recipient).

Initialize it once using `initialize(admin)`. The address supplied as admin
**must authorize** the call. To add or remove blocked addresses invoke
`set_blacklist(admin, addresses, true|false)` with no more than 64
addresses per transaction. Query `is_blacklisted(address)` to inspect state.

**Revocation semantics:** `on_revoke` always permits SAS's already-authorized
revocation, including when the parties are blacklisted. Changing the resolver
list alone cannot force an existing credential's `revocation_time` to
change. Applications that need immediate sanctions enforcement for already
issued credentials must check this resolver at verification time; they can
also submit authorized SAS revocations separately. The contract refuses
attestations if its configuration expires instead of defaulting to allow.

This implementation uses the resolver's *instance* storage for the admin
and blacklist, so a possible TTL expiry of the instance cannot leave
individual blacklist entries invisibly expired while initialization remains
valid. Operators must maintain instance TTL for long-lived deployments.
