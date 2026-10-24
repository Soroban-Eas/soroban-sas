#![no_std]

//! Fail-closed attestation policy for an administrator-maintained address blacklist.
//!
//! Install this contract as a schema resolver. SAS invokes `on_attest` before
//! storing new credentials and `on_revoke` after a successful revocation.
//! Updating the list does NOT autonomously revoke already-issued credentials:
//! consumers requiring historical invalidation must query `is_blacklisted`
//! when verifying them, or execute SAS revocations explicitly.

use soroban_sas_common::Attestation;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, Address, Env, Vec,
};

/// Keep the batch small enough for predictable Soroban transaction budgets.
pub const MAX_UPDATE_BATCH: u32 = 64;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BlacklistError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    BlockedParty = 3,
    BatchTooLarge = 4,
    Unauthorized = 5,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Admin,
    Blocked(Address),
}

#[contract]
pub struct BlacklistResolver;

fn require_initialized(env: &Env) -> Address {
    match env.storage().instance().get(&Key::Admin) {
        Some(admin) => admin,
        None => panic_with_error!(env, BlacklistError::NotInitialized),
    }
}

fn blocked(env: &Env, who: &Address) -> bool {
    env.storage().instance().has(&Key::Blocked(who.clone()))
}

#[contractimpl]
impl BlacklistResolver {
    /// Initialize once. `admin` must authorize the initialization.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&Key::Admin) {
            panic_with_error!(&env, BlacklistError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&Key::Admin, &admin);
    }

    /// Bulk-add or bulk-remove addresses, with an explicit per-call limit.
    /// The admin must sign; an arbitrary caller cannot manipulate the list.
    pub fn set_blacklist(env: Env, admin: Address, addresses: Vec<Address>, blocked: bool) {
        let owner = require_initialized(&env);
        if admin != owner {
            // Requiring the actual owner (rather than the passed address)
            // prevents privileged writes from relying on caller-controlled keys.
            panic_with_error!(&env, BlacklistError::Unauthorized);
        }
        owner.require_auth();
        if addresses.len() > MAX_UPDATE_BATCH {
            panic_with_error!(&env, BlacklistError::BatchTooLarge);
        }
        for address in addresses {
            let key = Key::Blocked(address);
            if blocked {
                env.storage().instance().set(&key, &true);
            } else {
                env.storage().instance().remove(&key);
            }
        }
    }

    /// Read-only check used both by the resolver and off-chain verifiers.
    /// A missing initialization fails closed rather than silently clearing a
    /// blacklist if the contract's instance TTL ever expires.
    pub fn is_blacklisted(env: Env, address: Address) -> bool {
        require_initialized(&env);
        blocked(&env, &address)
    }

    /// Disallow *either* party from creating credentials when blacklisted.
    /// O(1) storage checks, no iteration across blacklist entries.
    pub fn on_attest(env: Env, attestation: Attestation) {
        require_initialized(&env);
        if blocked(&env, &attestation.attester) || blocked(&env, &attestation.recipient) {
            panic_with_error!(&env, BlacklistError::BlockedParty);
        }
    }

    /// Never block revocation: already-issued attestations must remain
    /// revocable after a recipient or issuer is blacklisted.
    /// SAS performs its own authorization before invoking this callback.
    pub fn on_revoke(env: Env, _attestation: Attestation) {
        require_initialized(&env);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sas_common::UID;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Bytes, BytesN};

    fn attestation(env: &Env, attester: Address, recipient: Address) -> Attestation {
        Attestation {
            uid: UID(BytesN::from_array(env, &[1; 32])),
            schema_uid: UID(BytesN::from_array(env, &[2; 32])),
            time: 1000,
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0; 32])),
            recipient,
            attester,
            revocable: true,
            data: Bytes::new(env),
        }
    }

    #[test]
    fn rejects_either_blacklisted_party_and_allows_removal() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let attester = Address::generate(&env);
        let recipient = Address::generate(&env);
        let resolver = env.register_contract(None, BlacklistResolver);
        let client = BlacklistResolverClient::new(&env, &resolver);
        client.initialize(&admin);
        let a = attestation(&env, attester.clone(), recipient.clone());
        client.on_attest(&a);
        let recipients = Vec::from_array(&env, [recipient.clone()]);
        client.set_blacklist(&admin, &recipients, &true);
        assert!(client.is_blacklisted(&recipient));
        assert!(client.try_on_attest(&a).is_err());
        client.on_revoke(&a);
        client.set_blacklist(&admin, &recipients, &false);
        client.on_attest(&a);

        let issuers = Vec::from_array(&env, [attester.clone()]);
        client.set_blacklist(&admin, &issuers, &true);
        assert!(client.try_on_attest(&a).is_err());
        client.on_revoke(&a);
        client.set_blacklist(&admin, &issuers, &false);
        client.on_attest(&a);
    }

    #[test]
    fn initialization_and_batch_limit_are_enforced() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register_contract(None, BlacklistResolver);
        let client = BlacklistResolverClient::new(&env, &id);
        let recipient = Address::generate(&env);
        assert!(client.try_is_blacklisted(&recipient).is_err());
        client.initialize(&admin);
        assert!(client.try_initialize(&admin).is_err());
        let mut many = Vec::new(&env);
        for _ in 0..=MAX_UPDATE_BATCH {
            many.push_back(Address::generate(&env));
        }
        assert!(client.try_set_blacklist(&admin, &many, &true).is_err());
        assert!(!client.is_blacklisted(&many.get(0).unwrap()));
    }

    #[test]
    fn unauthenticated_updates_are_rejected() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let id = env.register_contract(None, BlacklistResolver);
        let client = BlacklistResolverClient::new(&env, &id);
        // First initialization requires an actual signature.
        assert!(client.try_initialize(&admin).is_err());
    }
}
