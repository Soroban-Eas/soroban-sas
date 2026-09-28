#![no_std]

//! A permissive schema resolver used only by the integration test harness
//! (`tests/integration/e2e_node_test.rs`, issue #247).
//!
//! `SAS::attest`/`revoke` always invoke the schema's named resolver's
//! `on_attest`/`on_revoke` and abort the call if that invocation fails —
//! rejection, a trap, or a missing method are all treated the same way (see
//! docs/schemas.md's "Resolver Failure Semantics"). A schema therefore needs
//! *some* deployed contract implementing both methods before `attest`/
//! `revoke` can succeed against it, even when the test has no interest in
//! resolver-side enforcement. This contract exists to be that address: it
//! unconditionally accepts every attestation and revocation. Production
//! schemas should use a resolver that actually enforces policy.

use soroban_sas_common::Attestation;
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct PermissiveResolver;

#[contractimpl]
impl PermissiveResolver {
    /// Always accepts. Called by `SAS::attest`/`attest_by_delegation`/
    /// `multi_attest`/`attest_with_value`/`replace_attestation` before the
    /// attestation is stored.
    pub fn on_attest(_env: Env, _attestation: Attestation) {}

    /// Always accepts. Called by `SAS::revoke`/`revoke_by_delegation`/
    /// `multi_revoke` after the revocation is stored.
    pub fn on_revoke(_env: Env, _attestation: Attestation) {}
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sas_common::UID;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Bytes, BytesN};

    fn sample_attestation(env: &Env) -> Attestation {
        Attestation {
            uid: UID(BytesN::from_array(env, &[1u8; 32])),
            schema_uid: UID(BytesN::from_array(env, &[2u8; 32])),
            time: 1000,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
            recipient: Address::generate(env),
            attester: Address::generate(env),
            revocable: true,
            data: Bytes::new(env),
        }
    }

    #[test]
    fn on_attest_and_on_revoke_accept_any_attestation() {
        let env = Env::default();
        let contract_id = env.register_contract(None, PermissiveResolver);
        let client = PermissiveResolverClient::new(&env, &contract_id);
        let attestation = sample_attestation(&env);

        // Neither call should panic, regardless of attestation contents.
        client.on_attest(&attestation);
        client.on_revoke(&attestation);
    }
}
