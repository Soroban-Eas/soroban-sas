#![allow(unexpected_cfgs)]
#![no_std]

use soroban_sas_common::{Attestation, SASError, UID};
use soroban_sdk::{
    contract, contractimpl, panic_with_error, symbol_short, token, Address, Env, IntoVal, Symbol,
};

mod events;

// v1.0.0 State Schema Frozen

#[contract]
pub struct SAS;

pub const SAS_ADMIN: Symbol = symbol_short!("ADMIN");
pub const SCHEMA_REGISTRY: Symbol = symbol_short!("REGISTRY");
pub const ATTESTER_KEY: Symbol = symbol_short!("ATTKEY");
pub const DELEGATION_NONCE: Symbol = symbol_short!("DELNONCE");

#[contractimpl]
impl SAS {
    pub fn init(env: Env, admin: Address, registry: Address) {
        if env.storage().instance().has(&SAS_ADMIN) {
            panic_with_error!(&env, SASError::AlreadyInitialized);
        }
        env.storage().instance().set(&SAS_ADMIN, &admin);
        env.storage().instance().set(&SCHEMA_REGISTRY, &registry);
    }

    pub fn attest(env: Env, attestation: Attestation) -> UID {
        attestation.attester.require_auth();
        Self::attest_internal(env, attestation)
    }

    pub fn attest_by_delegation(
        env: Env,
        attestation: Attestation,
        nonce: u64,
        signature: soroban_sdk::BytesN<64>,
        public_key: soroban_sdk::BytesN<32>,
    ) -> UID {
        if attestation.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        Self::require_attester_key(&env, &attestation.attester, &public_key);
        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        let payload_hash =
            soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain);
        soroban_sas_common::verify_offchain_signature(&env, &payload_hash, &public_key, &signature);
        Self::consume_delegation_nonce(&env, &attestation.attester, nonce);

        Self::attest_internal(env, attestation)
    }

    fn attest_internal(env: Env, attestation: Attestation) -> UID {
        if attestation.expiration_time != 0
            && attestation.expiration_time <= env.ledger().timestamp()
        {
            panic_with_error!(&env, SASError::AlreadyExpired);
        }

        let registry: Address = env.storage().instance().get(&SCHEMA_REGISTRY).unwrap();
        let schema_opt: Option<soroban_sas_common::SchemaRecord> = env.invoke_contract(
            &registry,
            &Symbol::new(&env, "get_schema"),
            soroban_sdk::vec![&env, attestation.schema_uid.clone().into_val(&env)],
        );
        let Some(schema) = schema_opt else {
            panic_with_error!(&env, SASError::InvalidSchema);
        };

        // Optional resolver callback support
        let _ = env.try_invoke_contract::<(), soroban_sdk::Error>(
            &schema.resolver,
            &Symbol::new(&env, "on_attest"),
            soroban_sdk::vec![&env, attestation.clone().into_val(&env)],
        );

        // Store the attestation
        env.storage()
            .persistent()
            .set(&attestation.uid, &attestation);

        events::publish_attested(&env, &attestation);

        attestation.uid.clone()
    }

    pub fn revoke(env: Env, uid: UID) {
        let Some(attestation) = env.storage().persistent().get::<_, Attestation>(&uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        attestation.attester.require_auth();
        Self::revoke_internal(env, uid)
    }

    pub fn revoke_by_delegation(
        env: Env,
        uid: UID,
        nonce: u64,
        signature: soroban_sdk::BytesN<64>,
        public_key: soroban_sdk::BytesN<32>,
    ) {
        let Some(attestation) = env.storage().persistent().get::<_, Attestation>(&uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };
        Self::require_attester_key(&env, &attestation.attester, &public_key);
        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        let payload_hash = soroban_sas_common::hash_delegated_revocation(
            &env,
            &uid,
            &attestation.attester,
            &domain,
        );
        soroban_sas_common::verify_offchain_signature(&env, &payload_hash, &public_key, &signature);
        Self::consume_delegation_nonce(&env, &attestation.attester, nonce);

        Self::revoke_internal(env, uid)
    }

    fn revoke_internal(env: Env, uid: UID) {
        let Some(mut attestation) = env.storage().persistent().get::<_, Attestation>(&uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };

        if !attestation.revocable {
            panic_with_error!(&env, SASError::NotRevocable);
        }

        let timestamp = env.ledger().timestamp();
        attestation.revocation_time = timestamp;
        env.storage().persistent().set(&uid, &attestation);

        events::publish_revoked(&env, &uid, timestamp);
    }

    /// Atomically replaces `old_uid` with `new_data`: revokes the old
    /// attestation and issues a new one linked to it via `ref_uid`, in a
    /// single contract execution — so consumers checking `old_uid`'s
    /// recipient never observe a window where neither attestation is valid.
    ///
    /// `new_data.ref_uid` is set to `old_uid` by this function regardless of
    /// what the caller passed, so the linkage can't be spoofed. Requires
    /// `old_uid`'s attester to authorize the call, the old attestation to be
    /// revocable and not already revoked, and `new_data.attester`/`recipient`
    /// to match the old attestation's — a replacement changes what is being
    /// claimed, not who is claiming it or about whom.
    pub fn replace_attestation(env: Env, old_uid: UID, new_data: Attestation) -> UID {
        let Some(old) = env.storage().persistent().get::<_, Attestation>(&old_uid) else {
            panic_with_error!(&env, SASError::AttestationNotFound);
        };

        old.attester.require_auth();

        if !old.revocable {
            panic_with_error!(&env, SASError::NotRevocable);
        }
        if old.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        if new_data.attester != old.attester || new_data.recipient != old.recipient {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let new_data = Attestation {
            ref_uid: old_uid.clone(),
            ..new_data
        };
        Self::revoke_internal(env.clone(), old_uid);
        Self::attest_internal(env, new_data)
    }

    pub fn multi_attest(
        env: Env,
        attestations: soroban_sdk::Vec<Attestation>,
    ) -> soroban_sdk::Vec<UID> {
        let mut uids = soroban_sdk::Vec::new(&env);
        // Gas optimization: process attestations in a single batch layout
        for attestation in attestations.into_iter() {
            let uid = Self::attest(env.clone(), attestation);
            uids.push_back(uid);
        }
        uids
    }

    /// Issues an attestation and collects `value` units of the SEP-41
    /// `token` from the attester into this contract's balance.
    ///
    /// The transfer happens before the attestation is recorded, so a failed
    /// payment aborts the whole invocation and no attestation is issued.
    /// `value` must be non-negative (`SASError::InvalidValue`); a `value` of
    /// zero performs no transfer, which keeps the entrypoint usable for
    /// fee-free schemas without paying for a no-op token call.
    pub fn attest_with_value(
        env: Env,
        attestation: Attestation,
        token: Address,
        value: i128,
    ) -> UID {
        if value < 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        attestation.attester.require_auth();

        if value > 0 {
            token::Client::new(&env, &token).transfer(
                &attestation.attester,
                &env.current_contract_address(),
                &value,
            );
        }

        Self::attest_internal(env, attestation)
    }

    pub fn multi_revoke(env: Env, uids: soroban_sdk::Vec<UID>) {
        for uid in uids.iter() {
            Self::revoke(env.clone(), uid);
        }
    }

    /// Registers the ed25519 public key that backs `attester`'s Stellar
    /// account, so `verify_offchain_attestation` can bind signatures to it.
    ///
    /// This is only needed as a fallback for attester addresses that
    /// `soroban_sas_common::attester_matches_key`'s structural XDR check
    /// cannot resolve on its own — e.g. any future `Address` kind beyond a
    /// classic Ed25519 account (this SDK's `ScAddress` only has `Account`
    /// and `Contract` today, but newer Stellar protocol versions add
    /// multiplexed accounts and other address kinds). Standard account
    /// attesters do not need to call this at all.
    ///
    /// Requires `attester.require_auth()`, so only the address owner can
    /// bind a key to it.
    pub fn register_attester_key(env: Env, attester: Address, public_key: soroban_sdk::BytesN<32>) {
        attester.require_auth();
        env.storage()
            .persistent()
            .set(&(ATTESTER_KEY, attester), &public_key);
    }

    /// Returns true if `public_key` was explicitly registered for `attester`
    /// via `register_attester_key`.
    fn registered_key_matches(
        env: &Env,
        attester: &Address,
        public_key: &soroban_sdk::BytesN<32>,
    ) -> bool {
        env.storage()
            .persistent()
            .get::<_, soroban_sdk::BytesN<32>>(&(ATTESTER_KEY, attester.clone()))
            .is_some_and(|registered| registered == *public_key)
    }

    fn require_attester_key(env: &Env, attester: &Address, public_key: &soroban_sdk::BytesN<32>) {
        if !soroban_sas_common::attester_matches_key(env, attester, public_key)
            && !Self::registered_key_matches(env, attester, public_key)
        {
            panic_with_error!(env, SASError::Unauthorized);
        }
    }

    fn consume_delegation_nonce(env: &Env, attester: &Address, nonce: u64) {
        let key = (DELEGATION_NONCE, attester.clone(), nonce);
        if env.storage().persistent().has(&key) {
            panic_with_error!(env, SASError::DelegationReplay);
        }
        env.storage().persistent().set(&key, &true);
    }

    /// Verifies an off-chain attestation signed by the attester's ed25519 key.
    ///
    /// The signed digest commits to the current network id, this contract's
    /// address, and `nonce` (see `soroban_sas_common::typed_data`), so a
    /// signature cannot be replayed on another network, against another
    /// contract, or under a different nonce. Panics if the public key does
    /// not belong to the declared attester (`SASError::Unauthorized`), if the
    /// attestation is revoked locally or by an on-chain revocation of the
    /// same UID (`SASError::AlreadyRevoked`), if it is expired
    /// (`SASError::AlreadyExpired`), or if the signature is invalid
    /// (`ed25519_verify` host error).
    ///
    /// Key binding is accepted either structurally (the public key derives
    /// the attester's classic Ed25519 account address) or via an explicit
    /// `register_attester_key` registration, so attester addresses the
    /// structural check cannot resolve are not permanently locked out.
    pub fn verify_offchain_attestation(
        env: Env,
        attestation: Attestation,
        nonce: u64,
        public_key: soroban_sdk::BytesN<32>,
        signature: soroban_sdk::BytesN<64>,
    ) -> bool {
        Self::require_attester_key(&env, &attestation.attester, &public_key);

        if attestation.revocation_time != 0 {
            panic_with_error!(&env, SASError::AlreadyRevoked);
        }
        if attestation.expiration_time != 0
            && env.ledger().timestamp() >= attestation.expiration_time
        {
            panic_with_error!(&env, SASError::AlreadyExpired);
        }

        // An on-chain revocation of the same UID also invalidates the
        // off-chain copy.
        if let Some(stored) = env
            .storage()
            .persistent()
            .get::<_, Attestation>(&attestation.uid)
        {
            if stored.revocation_time != 0 {
                panic_with_error!(&env, SASError::AlreadyRevoked);
            }
        }

        let domain = soroban_sas_common::AttestationDomain {
            network_id: env.ledger().network_id(),
            contract: env.current_contract_address(),
            nonce,
        };
        let payload_hash =
            soroban_sas_common::hash_offchain_attestation(&env, &attestation, &domain);
        soroban_sas_common::verify_offchain_signature(&env, &payload_hash, &public_key, &signature);

        true
    }

    pub fn verify_attestation(env: Env, uid: UID) -> bool {
        if let Some(attestation) = env.storage().persistent().get::<_, Attestation>(&uid) {
            if attestation.revocation_time != 0 {
                return false;
            }
            if attestation.expiration_time != 0
                && env.ledger().timestamp() >= attestation.expiration_time
            {
                return false;
            }
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test;
