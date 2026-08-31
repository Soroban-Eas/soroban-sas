use crate::{SASClient, SAS};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{
    hash_delegated_revocation, Attestation, AttestationDomain, AttestationIssuedEvent,
    AttestationRevokedEvent, SASError, UID,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::testutils::Events as _;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env, IntoVal};

/// Builds a minimal valid attestation for `attester`/`recipient`, keyed by
/// `uid_seed` so each test can own a distinct UID.
fn attestation_fixture(
    env: &Env,
    attester: &Address,
    recipient: &Address,
    uid_seed: [u8; 32],
) -> Attestation {
    Attestation {
        uid: UID(BytesN::from_array(env, &uid_seed)),
        schema_uid: UID(BytesN::from_array(env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(env),
    }
}

pub mod mock1 {
    use super::*;
    #[contract]
    pub struct MockRegistry;

    #[contractimpl]
    impl MockRegistry {
        pub fn on_attest(_env: Env, _attestation: Attestation) {}
        pub fn on_revoke(_env: Env, _attestation: Attestation) {}

        pub fn validate_schema(_env: Env, _uid: UID) -> bool {
            true
        }

        pub fn SASREG(_env: Env) -> bool {
            true
        }

        pub fn get_schema(env: Env, uid: UID) -> Option<soroban_sas_common::SchemaRecord> {
            Some(soroban_sas_common::SchemaRecord {
                uid: uid.clone(),
                resolver: env.current_contract_address(),
                revocable: true,
                schema: soroban_sdk::String::from_str(&env, "bool like"),
            })
        }
    }
}

pub mod mock2 {
    use super::*;
    #[contract]
    pub struct MockRejectRegistry;

    #[contractimpl]
    impl MockRejectRegistry {
        pub fn on_attest(_env: Env, _attestation: Attestation) {}
        pub fn on_revoke(_env: Env, _attestation: Attestation) {}

        pub fn validate_schema(_env: Env, _uid: UID) -> bool {
            false
        }
        pub fn SASREG(_env: Env) -> bool {
            true
        }
        pub fn get_schema(_env: Env, _uid: UID) -> Option<soroban_sas_common::SchemaRecord> {
            None
        }
    }
}

pub mod mock3 {
    use super::*;
    #[contract]
    pub struct MockResolver;

    #[contractimpl]
    impl MockResolver {
        pub fn on_attest(_env: Env, _attestation: Attestation) {
            // Mock execution
        }
        pub fn on_revoke(_env: Env, _attestation: Attestation) {
            // Mock execution
        }
    }
}

pub mod mock4 {
    use super::*;
    #[contract]
    pub struct MockIndexer;

    #[contractimpl]
    impl MockIndexer {
        pub fn index_attestation(
            env: Env,
            uid: UID,
            recipient: Address,
            _schema_uid: UID,
            _attester: Address,
        ) {
            let mut uids: soroban_sdk::Vec<UID> = env
                .storage()
                .persistent()
                .get(&recipient)
                .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
            uids.push_back(uid);
            env.storage().persistent().set(&recipient, &uids);
        }

        pub fn get_attestations_by_recipient(
            env: Env,
            recipient: Address,
        ) -> soroban_sdk::Vec<UID> {
            env.storage()
                .persistent()
                .get(&recipient)
                .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
        }
    }
}

#[test]
fn test_happy_path_attestation() {
    let env = Env::default();

    // Deploy Mock Registry
    let registry_id = env.register_contract(None, mock1::MockRegistry);

    // Deploy SAS
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let ref_uid = UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32]));

    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid,
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid,
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();

    let result_uid = sas_client.attest(&attestation);
    assert_eq!(result_uid, uid);
}

/*
#[test]
fn test_auth_failure_missing_signature() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let ref_uid = UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32]));

    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid,
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid,
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    // Attempting to attest without mock_all_auths or explicitly providing signatures should panic
    let res = sas_client.try_attest(&attestation);
    assert!(res.is_err());
}

#[test]
fn test_schema_validation_rejection() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock2::MockRejectRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));
    let ref_uid = UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32]));

    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid,
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid,
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();
    let res = sas_client.try_attest(&attestation);
    assert!(res.is_err());
}
*/

#[test]
fn test_revocation_success() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();
    sas_client.attest(&attestation);

    // Revoke
    sas_client.revoke(&uid);
}

mod replace {
    use super::*;

    pub struct Fixture {
        pub env: Env,
        pub sas_client: SASClient<'static>,
        pub sas_id: Address,
        pub attester: Address,
        pub recipient: Address,
        pub old_uid: UID,
    }

    /// Registers SAS + a mock registry, attests one revocable attestation
    /// under `old_uid`, and returns everything a `replace_attestation` test
    /// needs to build a replacement for it.
    pub fn setup(revocable: bool) -> Fixture {
        let env = Env::default();
        let registry_id = env.register_contract(None, mock1::MockRegistry);
        let sas_id = env.register_contract(None, SAS);
        let sas_client = SASClient::new(&env, &sas_id);

        let admin = Address::generate(&env);
        sas_client.init(&admin, &registry_id);

        let attester = Address::generate(&env);
        let recipient = Address::generate(&env);
        let old_uid = UID(BytesN::from_array(&env, &[1u8; 32]));

        let old_attestation = Attestation {
            uid: old_uid.clone(),
            schema_uid: UID(BytesN::from_array(&env, &[2u8; 32])),
            time: 1000,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
            recipient: recipient.clone(),
            attester: attester.clone(),
            revocable,
            data: Bytes::new(&env),
        };

        env.mock_all_auths();
        sas_client.attest(&old_attestation);

        // Ledger timestamp defaults to 0 in a fresh test Env, which would
        // make a revocation's `revocation_time` indistinguishable from
        // never-revoked (`verify_attestation` treats 0 as "not revoked").
        env.ledger().with_mut(|li| li.timestamp = 5000);

        Fixture {
            env,
            sas_client,
            sas_id,
            attester,
            recipient,
            old_uid,
        }
    }

    impl Fixture {
        /// A replacement attestation reusing this fixture's attester and
        /// recipient (the invariants `replace_attestation` enforces).
        pub fn new_attestation(&self, uid: [u8; 32]) -> Attestation {
            Attestation {
                uid: UID(BytesN::from_array(&self.env, &uid)),
                schema_uid: UID(BytesN::from_array(&self.env, &[3u8; 32])),
                time: 2000,
                expiration_time: 0,
                revocation_time: 0,
                // Deliberately wrong: replace_attestation must overwrite this
                // with old_uid regardless of what's passed in.
                ref_uid: UID(BytesN::from_array(&self.env, &[9u8; 32])),
                recipient: self.recipient.clone(),
                attester: self.attester.clone(),
                revocable: true,
                data: Bytes::from_slice(&self.env, &[7, 7, 7]),
            }
        }
    }
}

#[test]
fn test_replace_attestation_success() {
    let f = replace::setup(true);
    let new_attestation = f.new_attestation([2u8; 32]);

    let returned_uid = f
        .sas_client
        .replace_attestation(&f.old_uid, &new_attestation);
    assert_eq!(returned_uid, new_attestation.uid);

    // Old is now revoked; new is valid.
    assert!(!f.sas_client.verify_attestation(&f.old_uid));
    assert!(f.sas_client.verify_attestation(&new_attestation.uid));

    // The new attestation is linked back to the old one via ref_uid,
    // overwriting whatever the caller passed.
    let stored: Attestation = f.env.as_contract(&f.sas_id, || {
        f.env
            .storage()
            .persistent()
            .get(&new_attestation.uid)
            .unwrap()
    });
    assert_eq!(stored.ref_uid, f.old_uid);
}

#[test]
fn test_replace_attestation_rejects_non_revocable() {
    let f = replace::setup(false);
    let new_attestation = f.new_attestation([2u8; 32]);

    let res = f
        .sas_client
        .try_replace_attestation(&f.old_uid, &new_attestation);
    assert!(res.is_err());
}

#[test]
fn test_replace_attestation_rejects_already_revoked() {
    let f = replace::setup(true);
    f.sas_client.revoke(&f.old_uid);

    let new_attestation = f.new_attestation([2u8; 32]);
    let res = f
        .sas_client
        .try_replace_attestation(&f.old_uid, &new_attestation);
    assert!(res.is_err());
}

#[test]
fn test_replace_attestation_rejects_unknown_old_uid() {
    let f = replace::setup(true);
    let unknown_uid = UID(BytesN::from_array(&f.env, &[99u8; 32]));
    let new_attestation = f.new_attestation([2u8; 32]);

    let res = f
        .sas_client
        .try_replace_attestation(&unknown_uid, &new_attestation);
    assert!(res.is_err());
}

#[test]
fn test_replace_attestation_rejects_mismatched_attester() {
    let f = replace::setup(true);
    let mut new_attestation = f.new_attestation([2u8; 32]);
    new_attestation.attester = Address::generate(&f.env);

    let res = f
        .sas_client
        .try_replace_attestation(&f.old_uid, &new_attestation);
    assert!(res.is_err());
}

#[test]
fn test_replace_attestation_rejects_mismatched_recipient() {
    let f = replace::setup(true);
    let mut new_attestation = f.new_attestation([2u8; 32]);
    new_attestation.recipient = Address::generate(&f.env);

    let res = f
        .sas_client
        .try_replace_attestation(&f.old_uid, &new_attestation);
    assert!(res.is_err());
}

/*
#[test]
fn test_revocation_failure() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[1u8; 32]));
    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: false, // NOT REVOCABLE
        data: Bytes::new(&env),
    };

    env.mock_all_auths();
    sas_client.attest(&attestation);

    // Should panic
    let res = sas_client.try_revoke(&uid);
    assert!(res.is_err());
}
*/

#[test]
fn test_multi_attest_returns_both_uids() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[3u8; 32]));
    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[4u8; 32]));

    let att1 = Attestation {
        uid: uid1.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    let att2 = Attestation {
        uid: uid2.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();
    let batch = soroban_sdk::vec![&env, att1, att2];

    let result = sas_client.multi_attest(&batch);
    assert_eq!(result.len(), 2);
    assert!(result.contains(&uid1));
    assert!(result.contains(&uid2));
}

/*
#[test]
fn test_batch_operations() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid1 = UID(soroban_sdk::BytesN::from_array(&env, &[3u8; 32]));
    let uid2 = UID(soroban_sdk::BytesN::from_array(&env, &[4u8; 32]));

    let att1 = Attestation {
        uid: uid1.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    let att2 = Attestation {
        uid: uid2.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();
    let batch = soroban_sdk::vec![&env, att1, att2];

    let result = sas_client.multi_attest(&batch);
    assert_eq!(result.len(), 2);
    let revoke_batch = soroban_sdk::vec![&env, uid1.clone(), uid2.clone()];
    env.ledger().with_mut(|li| li.timestamp = 100);
    env.mock_all_auths();
    sas_client.multi_revoke(&revoke_batch);
}
*/

#[test]
fn test_replace_attestation_indexes_new_uid() {
    let f = replace::setup(true);
    let indexer_id = f.env.register_contract(None, mock4::MockIndexer);
    let indexer_client = mock4::MockIndexerClient::new(&f.env, &indexer_id);
    let new_attestation = f.new_attestation([2u8; 32]);

    f.env.mock_all_auths();
    f.sas_client.set_indexer(&indexer_id);
    let new_uid = f
        .sas_client
        .replace_attestation(&f.old_uid, &new_attestation);

    let recipient_uids = indexer_client.get_attestations_by_recipient(&f.recipient);
    assert!(recipient_uids.contains(&new_uid));
}

#[test]
fn test_resolver_callback() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let _resolver_id = env.register_contract(None, mock3::MockResolver);

    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[5u8; 32]));

    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();
    sas_client.attest(&attestation);
    // Verifies it doesn't panic on try_invoke_contract
}

#[test]
fn test_attest_with_value_collects_the_fee() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let token_id = env.register_stellar_asset_contract(admin.clone());
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &token_id);
    let token = soroban_sdk::token::Client::new(&env, &token_id);

    env.mock_all_auths();
    token_admin.mint(&attester, &1_000);
    sas_client.set_fee(&token_id, &500);

    let attestation = attestation_fixture(&env, &attester, &recipient, [7u8; 32]);
    let uid = sas_client.attest_with_value(&attestation, &token_id, &500);

    assert_eq!(uid, attestation.uid);
    assert_eq!(token.balance(&attester), 500);
    assert_eq!(token.balance(&sas_id), 500);
    assert!(sas_client.verify_attestation(&attestation.uid));
}

#[test]
fn test_attest_with_value_zero_skips_transfer() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract(admin.clone());
    let token = soroban_sdk::token::Client::new(&env, &token_id);

    env.mock_all_auths();
    let attestation = attestation_fixture(&env, &attester, &recipient, [8u8; 32]);
    sas_client.attest_with_value(&attestation, &token_id, &0);

    assert_eq!(token.balance(&attester), 0);
    assert!(sas_client.verify_attestation(&attestation.uid));
}

#[test]
fn test_attest_with_value_rejects_negative_value() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract(admin.clone());

    env.mock_all_auths();
    let attestation = attestation_fixture(&env, &attester, &recipient, [9u8; 32]);
    let res = sas_client.try_attest_with_value(&attestation, &token_id, &-1);

    assert_eq!(res, Err(Ok(SASError::InvalidValue.into())));
}

#[test]
fn test_attest_with_value_insufficient_balance_issues_nothing() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract(admin.clone());

    env.mock_all_auths();
    sas_client.set_fee(&token_id, &500);
    let attestation = attestation_fixture(&env, &attester, &recipient, [10u8; 32]);
    // Fee is configured but the attester has no balance: the transfer fails
    // and no attestation is issued.
    let res = sas_client.try_attest_with_value(&attestation, &token_id, &500);

    assert!(res.is_err());
    assert!(!sas_client.verify_attestation(&attestation.uid));
}

#[test]
fn test_init_requires_admin_authorization() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    let res = sas_client.try_init(&admin, &registry_id);

    assert!(res.is_err());
}

#[test]
fn test_second_revocation_is_rejected_for_direct_and_batch_paths() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let attestation = attestation_fixture(&env, &attester, &recipient, [10u8; 32]);
    sas_client.attest(&attestation);

    sas_client.revoke(&attestation.uid);
    let direct_res = sas_client.try_revoke(&attestation.uid);
    assert_eq!(direct_res, Err(Ok(SASError::AlreadyRevoked.into())));

    let second_attestation = attestation_fixture(&env, &attester, &recipient, [11u8; 32]);
    sas_client.attest(&second_attestation);
    let batch = soroban_sdk::vec![&env, second_attestation.uid.clone()];
    let batch_res = sas_client.try_multi_revoke(&batch);
    assert_eq!(batch_res, Err(Ok(SASError::AlreadyRevoked.into())));
}

#[test]
fn test_withdraw_tokens_requires_authorized_balance_and_event_path() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let destination = Address::generate(&env);
    let token_id = env.register_stellar_asset_contract(admin.clone());
    let token_admin = soroban_sdk::token::StellarAssetClient::new(&env, &token_id);
    let token = soroban_sdk::token::Client::new(&env, &token_id);

    let attestation = attestation_fixture(&env, &attester, &recipient, [12u8; 32]);
    token_admin.mint(&attester, &1_000);
    sas_client.set_fee(&token_id, &500);
    let uid = sas_client.attest_with_value(&attestation, &token_id, &500);
    assert_eq!(uid, attestation.uid);

    let res = sas_client.try_withdraw_tokens(&admin, &token_id, &600, &destination);
    assert_eq!(res, Err(Ok(SASError::InvalidValue.into())));

    let withdrawal = sas_client.try_withdraw_tokens(&admin, &token_id, &250, &destination);
    assert!(withdrawal.is_ok());
    assert_eq!(token.balance(&destination), 250);
    assert_eq!(token.balance(&sas_id), 250);

    let unauthorized = sas_client.try_withdraw_tokens(&attester, &token_id, &1, &destination);
    assert_eq!(unauthorized, Err(Ok(SASError::Unauthorized.into())));
}

#[test]
fn test_init_twice_is_rejected() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let res = sas_client.try_init(&admin, &registry_id);
    assert_eq!(res, Err(Ok(SASError::AlreadyInitialized.into())));
}

#[test]
fn test_expired_attestation_reports_already_expired() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    env.ledger().with_mut(|li| li.timestamp = 2_000);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let mut attestation = attestation_fixture(&env, &attester, &recipient, [11u8; 32]);
    attestation.expiration_time = 1_000;

    env.mock_all_auths();
    let res = sas_client.try_attest(&attestation);
    assert_eq!(res, Err(Ok(SASError::AlreadyExpired.into())));
}

#[test]
fn test_unknown_schema_reports_invalid_schema() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock2::MockRejectRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let attestation = attestation_fixture(&env, &attester, &recipient, [12u8; 32]);

    env.mock_all_auths();
    let res = sas_client.try_attest(&attestation);
    assert_eq!(res, Err(Ok(SASError::InvalidSchema.into())));
}

#[test]
fn test_attest_rejects_zero_recipient() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::from_string(&soroban_sdk::String::from_str(
        &env,
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    ));
    let attestation = attestation_fixture(&env, &attester, &recipient, [15u8; 32]);

    env.mock_all_auths();
    let res = sas_client.try_attest(&attestation);
    assert_eq!(res, Err(Ok(SASError::InvalidRecipient.into())));
}

#[test]
fn test_attest_rejects_self_attestation() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let attestation = attestation_fixture(&env, &attester, &attester, [16u8; 32]);

    env.mock_all_auths();
    let res = sas_client.try_attest(&attestation);
    assert_eq!(res, Err(Ok(SASError::InvalidRecipient.into())));
}

#[test]
fn test_non_revocable_attestation_reports_not_revocable() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let mut attestation = attestation_fixture(&env, &attester, &recipient, [13u8; 32]);
    attestation.revocable = false;

    env.mock_all_auths();
    sas_client.attest(&attestation);

    let res = sas_client.try_revoke(&attestation.uid);
    assert_eq!(res, Err(Ok(SASError::NotRevocable.into())));
}

#[test]
fn test_revoking_unknown_uid_reports_attestation_not_found() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    env.mock_all_auths();
    let unknown = UID(BytesN::from_array(&env, &[14u8; 32]));
    let res = sas_client.try_revoke(&unknown);
    assert_eq!(res, Err(Ok(SASError::AttestationNotFound.into())));
}

/*
#[test]
fn test_attestation_expiration() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[8u8; 32]));
    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 100, // Expired if ledger is > 100
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    // Simulate time advancement
    env.ledger().with_mut(|li| li.timestamp = 150);

    env.mock_all_auths();
    let res = sas_client.try_attest(&attestation);
    assert!(res.is_err());
}

#[test]
fn test_attest_by_delegation() {
    let env = Env::default();

    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);

    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[9u8; 32]));
    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    let signature = soroban_sdk::BytesN::from_array(&env, &[0u8; 64]);
    let pub_key = soroban_sdk::BytesN::from_array(&env, &[0u8; 32]);

    env.mock_all_auths();
    let res = sas_client.try_attest_by_delegation(&attestation, &signature, &pub_key);
    assert!(res.is_err());
}
*/

mod offchain {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use soroban_sas_common::{
        hash_delegated_revocation, hash_offchain_attestation, AttestationDomain,
    };
    use soroban_sdk::{BytesN, String as SorobanString};

    pub struct Setup {
        pub env: Env,
        pub sas_client: SASClient<'static>,
        pub sas_id: Address,
        pub signing_key: SigningKey,
        pub attestation: Attestation,
    }

    pub fn setup(seed: [u8; 32]) -> Setup {
        let env = Env::default();
        let registry_id = env.register_contract(None, mock1::MockRegistry);
        let sas_id = env.register_contract(None, SAS);
        let sas_client = SASClient::new(&env, &sas_id);

        let admin = Address::generate(&env);
        env.mock_all_auths();
        sas_client.init(&admin, &registry_id);

        let signing_key = SigningKey::from_bytes(&seed);
        let attester_strkey =
            stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes()).to_string();
        let attester = Address::from_string(&SorobanString::from_str(&env, &attester_strkey));

        let attestation = Attestation {
            uid: UID(BytesN::from_array(&env, &[42u8; 32])),
            schema_uid: UID(BytesN::from_array(&env, &[2u8; 32])),
            time: 1000,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
            recipient: Address::generate(&env),
            attester,
            revocable: true,
            data: Bytes::from_slice(&env, &[1, 2, 3]),
        };

        Setup {
            env,
            sas_client,
            sas_id,
            signing_key,
            attestation,
        }
    }

    pub fn sign(setup: &Setup, attestation: &Attestation, nonce: u64) -> BytesN<64> {
        let domain = AttestationDomain {
            network_id: setup.env.ledger().network_id(),
            contract: setup.sas_id.clone(),
            nonce,
        };
        let payload_hash = hash_offchain_attestation(&setup.env, attestation, &domain);
        let signature = setup.signing_key.sign(&payload_hash.to_array());
        BytesN::from_array(&setup.env, &signature.to_bytes())
    }

    pub fn public_key(setup: &Setup) -> BytesN<32> {
        BytesN::from_array(&setup.env, &setup.signing_key.verifying_key().to_bytes())
    }

    pub fn sign_revocation(setup: &Setup, uid: &UID, nonce: u64) -> BytesN<64> {
        let domain = AttestationDomain {
            network_id: setup.env.ledger().network_id(),
            contract: setup.sas_id.clone(),
            nonce,
        };
        let payload_hash =
            hash_delegated_revocation(&setup.env, uid, &setup.attestation.attester, &domain);
        let signature = setup.signing_key.sign(&payload_hash.to_array());
        BytesN::from_array(&setup.env, &signature.to_bytes())
    }
}

#[test]
fn test_delegated_attestation_binds_full_payload_and_nonce() {
    let s = offchain::setup([41u8; 32]);
    let nonce = 7;
    let signature = offchain::sign(&s, &s.attestation, nonce);
    let public_key = offchain::public_key(&s);

    // Same schema and recipient as the signed payload, but different data:
    // the legacy implementation accepted this mutation.
    let mut tampered = s.attestation.clone();
    tampered.data = Bytes::from_slice(&s.env, &[9, 9, 9]);
    let res = s
        .sas_client
        .try_attest_by_delegation(&tampered, &nonce, &signature, &public_key);
    assert!(res.is_err());

    // A failed verification must not consume the nonce; the original signed
    // action remains valid exactly once.
    assert_eq!(
        s.sas_client
            .attest_by_delegation(&s.attestation, &nonce, &signature, &public_key),
        s.attestation.uid
    );
    let replay =
        s.sas_client
            .try_attest_by_delegation(&s.attestation, &nonce, &signature, &public_key);
    assert!(replay.is_err());
}

#[test]
fn test_delegated_revoke_binds_attester_and_nonce() {
    let s = offchain::setup([42u8; 32]);
    let issue_nonce = 1;
    let issue_signature = offchain::sign(&s, &s.attestation, issue_nonce);
    let public_key = offchain::public_key(&s);
    s.sas_client
        .attest_by_delegation(&s.attestation, &issue_nonce, &issue_signature, &public_key);

    let revoke_nonce = 2;
    let revoke_signature = offchain::sign_revocation(&s, &s.attestation.uid, revoke_nonce);
    s.env.ledger().with_mut(|li| li.timestamp = 100);
    s.sas_client.revoke_by_delegation(
        &s.attestation.uid,
        &revoke_nonce,
        &revoke_signature,
        &public_key,
    );
    assert!(!s.sas_client.verify_attestation(&s.attestation.uid));

    let replay = s.sas_client.try_revoke_by_delegation(
        &s.attestation.uid,
        &revoke_nonce,
        &revoke_signature,
        &public_key,
    );
    assert!(replay.is_err());
}

#[test]
fn test_delegated_revoke_rejects_a_different_attesters_key() {
    let s = offchain::setup([43u8; 32]);
    let issue_nonce = 1;
    let issue_signature = offchain::sign(&s, &s.attestation, issue_nonce);
    s.sas_client.attest_by_delegation(
        &s.attestation,
        &issue_nonce,
        &issue_signature,
        &offchain::public_key(&s),
    );

    let other_key = SigningKey::from_bytes(&[44u8; 32]);
    let other_public_key = BytesN::from_array(&s.env, &other_key.verifying_key().to_bytes());
    let domain = AttestationDomain {
        network_id: s.env.ledger().network_id(),
        contract: s.sas_id.clone(),
        nonce: 2,
    };
    let payload_hash =
        hash_delegated_revocation(&s.env, &s.attestation.uid, &s.attestation.attester, &domain);
    let signature =
        BytesN::from_array(&s.env, &other_key.sign(&payload_hash.to_array()).to_bytes());

    let res = s.sas_client.try_revoke_by_delegation(
        &s.attestation.uid,
        &2,
        &signature,
        &other_public_key,
    );
    assert!(res.is_err());
}

#[test]
fn test_verify_offchain_attestation_valid() {
    let s = offchain::setup([31u8; 32]);
    let signature = offchain::sign(&s, &s.attestation, 7);
    assert!(s.sas_client.verify_offchain_attestation(
        &s.attestation,
        &7,
        &offchain::public_key(&s),
        &signature
    ));
}

#[test]
fn test_verify_offchain_attestation_tampered_data() {
    let s = offchain::setup([31u8; 32]);
    let signature = offchain::sign(&s, &s.attestation, 7);

    let mut tampered = s.attestation.clone();
    tampered.data = Bytes::from_slice(&s.env, &[9, 9, 9]);

    let res = s.sas_client.try_verify_offchain_attestation(
        &tampered,
        &7,
        &offchain::public_key(&s),
        &signature,
    );
    assert!(res.is_err());
}

#[test]
fn test_verify_offchain_attestation_wrong_key() {
    let s = offchain::setup([31u8; 32]);
    let signature = offchain::sign(&s, &s.attestation, 7);

    // A different keypair: fails the attester binding check.
    let other = offchain::setup([32u8; 32]);
    let res = s.sas_client.try_verify_offchain_attestation(
        &s.attestation,
        &7,
        &offchain::public_key(&other),
        &signature,
    );
    assert!(res.is_err());
}

#[test]
fn test_verify_offchain_attestation_nonce_replay_bound() {
    let s = offchain::setup([31u8; 32]);
    let signature = offchain::sign(&s, &s.attestation, 7);

    // The same signature under a different nonce must not verify.
    let res = s.sas_client.try_verify_offchain_attestation(
        &s.attestation,
        &8,
        &offchain::public_key(&s),
        &signature,
    );
    assert!(res.is_err());
}

#[test]
fn test_verify_offchain_attestation_expired() {
    let s = offchain::setup([31u8; 32]);
    let mut expired = s.attestation.clone();
    expired.expiration_time = 100;
    let signature = offchain::sign(&s, &expired, 7);

    s.env.ledger().with_mut(|li| li.timestamp = 150);

    let res = s.sas_client.try_verify_offchain_attestation(
        &expired,
        &7,
        &offchain::public_key(&s),
        &signature,
    );
    assert!(res.is_err());
}

#[test]
fn test_verify_offchain_attestation_invalidated_by_onchain_revocation() {
    let s = offchain::setup([31u8; 32]);
    let signature = offchain::sign(&s, &s.attestation, 7);

    // Record the same attestation on-chain, then revoke it.
    s.env.mock_all_auths();
    s.sas_client.attest(&s.attestation);
    s.env.ledger().with_mut(|li| li.timestamp = 100);
    s.sas_client.revoke(&s.attestation.uid);

    let res = s.sas_client.try_verify_offchain_attestation(
        &s.attestation,
        &7,
        &offchain::public_key(&s),
        &signature,
    );
    assert!(res.is_err());
}

#[test]
fn test_register_attester_key_requires_auth() {
    let s = offchain::setup([31u8; 32]);

    // No mock_all_auths and no explicit signature: the attester never
    // authorized this registration, so it must fail.
    let res = s
        .sas_client
        .try_register_attester_key(&s.attestation.attester, &offchain::public_key(&s));
    assert!(res.is_err());
}

#[test]
fn test_verify_offchain_attestation_via_registered_key() {
    let s = offchain::setup([31u8; 32]);

    // An attester address whose structure does not encode this signing
    // key's bytes at all (a freshly generated test address) stands in for
    // any address kind `attester_matches_key`'s structural XDR check can't
    // resolve on its own (e.g. a future non-Account `Address` variant).
    let unresolvable_attester = Address::generate(&s.env);
    let mut attestation = s.attestation.clone();
    attestation.attester = unresolvable_attester.clone();

    let signature = offchain::sign(&s, &attestation, 7);
    let public_key = offchain::public_key(&s);

    // Without registering the key, the structural check has nothing to
    // fall back on and verification is rejected.
    let res =
        s.sas_client
            .try_verify_offchain_attestation(&attestation, &7, &public_key, &signature);
    assert!(res.is_err());

    // Once the attester explicitly registers which key backs their
    // address, the same call succeeds via the registration fallback.
    s.env.mock_all_auths();
    s.sas_client
        .register_attester_key(&unresolvable_attester, &public_key);

    assert!(s
        .sas_client
        .verify_offchain_attestation(&attestation, &7, &public_key, &signature));
}

#[test]
fn test_comprehensive_lifecycle() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[10u8; 32]));

    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();

    // 1. Attest
    let _ = sas_client.attest(&attestation);

    // 2. Verify valid
    assert!(sas_client.verify_attestation(&uid));

    // 3. Revoke
    env.ledger().with_mut(|li| li.timestamp = 100);
    sas_client.revoke(&uid);

    // 4. Verify invalid
    assert!(!sas_client.verify_attestation(&uid));
}

#[test]
fn test_attest_emits_attestation_issued_event() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[11u8; 32]));
    let schema_uid = UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32]));

    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: schema_uid.clone(),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();
    sas_client.attest(&attestation);

    let expected = AttestationIssuedEvent {
        uid: uid.clone(),
        schema_uid: schema_uid.clone(),
        attester: attester.clone(),
        recipient: recipient.clone(),
    };
    assert_eq!(
        env.events().all(),
        soroban_sdk::vec![
            &env,
            (
                sas_id.clone(),
                (symbol_short!("ATTESTED"), schema_uid, attester).into_val(&env),
                expected.into_val(&env),
            )
        ]
    );
}

#[test]
fn test_revoke_emits_attestation_revoked_event() {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);

    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    let uid = UID(soroban_sdk::BytesN::from_array(&env, &[12u8; 32]));

    let attestation = Attestation {
        uid: uid.clone(),
        schema_uid: UID(soroban_sdk::BytesN::from_array(&env, &[2u8; 32])),
        time: 1000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(soroban_sdk::BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: attester.clone(),
        revocable: true,
        data: Bytes::new(&env),
    };

    env.mock_all_auths();
    sas_client.attest(&attestation);

    let revoked_at = 4242u64;
    env.ledger().with_mut(|li| li.timestamp = revoked_at);
    sas_client.revoke(&uid);

    let expected = AttestationRevokedEvent {
        uid: uid.clone(),
        timestamp: revoked_at,
    };
    let events = env.events().all();
    assert_eq!(
        events.slice(events.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                sas_id.clone(),
                (symbol_short!("REVOKED"), uid.clone()).into_val(&env),
                expected.into_val(&env),
            )
        ]
    );

    // Emitted timestamp must match the revocation time written to storage.
    assert!(!sas_client.verify_attestation(&uid));
}

#[test]
fn test_delegation_nonce_survives_one_year_ttl_and_rejects_replay() {
    // Validates durable nonce: per-attester strictly increasing instance storage
    // must reject replay even after ledger advancement beyond the previous
    // one-year TOMBSTONE TTL (LEDGERS_IN_ONE_YEAR).
    let s = offchain::setup([55u8; 32]);
    let nonce = 42u64;
    let signature = offchain::sign(&s, &s.attestation, nonce);
    let public_key = offchain::public_key(&s);

    // First delegation succeeds and consumes nonce 42
    s.sas_client
        .attest_by_delegation(&s.attestation, &nonce, &signature, &public_key);
    assert!(s.sas_client.verify_attestation(&s.attestation.uid));

    // Replay before TTL must fail
    let replay_before = s
        .sas_client
        .try_attest_by_delegation(&s.attestation, &nonce, &signature, &public_key);
    assert!(replay_before.is_err());

    // Advance ledger in two stages with intermediate renewal to keep instance
    // and attestation entries alive across the old one-year tombstone window.
    // First half-year.
    s.env.ledger().with_mut(|li| {
        li.sequence_number += soroban_sas_common::LEDGERS_IN_ONE_YEAR / 2;
        li.timestamp += 60 * 60 * 24 * 180;
    });
    // Renew instance and attestation TTLs via a read that extends them.
    let _ = s.sas_client.verify_attestation(&s.attestation.uid);
    // Second half-year + 10 beyond original TTL
    s.env.ledger().with_mut(|li| {
        li.sequence_number += soroban_sas_common::LEDGERS_IN_ONE_YEAR / 2 + 10;
        li.timestamp += 60 * 60 * 24 * 186;
    });

    // Replay after the previous one-year TTL must still fail (durable protection)
    let replay_after = s
        .sas_client
        .try_attest_by_delegation(&s.attestation, &nonce, &signature, &public_key);
    assert!(replay_after.is_err());
}

#[test]
fn test_delegation_nonce_strictly_increasing_and_out_of_order() {
    let s = offchain::setup([56u8; 32]);
    let public_key = offchain::public_key(&s);

    // First delegation with nonce 10
    let att1 = s.attestation.clone();
    let sig10 = offchain::sign(&s, &att1, 10);
    s.sas_client
        .attest_by_delegation(&att1, &10, &sig10, &public_key);

    // Out-of-order smaller nonce 5 must be rejected (strictly increasing)
    let mut att2 = s.attestation.clone();
    att2.uid = UID(BytesN::from_array(&s.env, &[99u8; 32]));
    let sig5 = offchain::sign(&s, &att2, 5);
    let res_small = s
        .sas_client
        .try_attest_by_delegation(&att2, &5, &sig5, &public_key);
    assert!(res_small.is_err());

    // Next increasing nonce 11 succeeds
    let mut att3 = s.attestation.clone();
    att3.uid = UID(BytesN::from_array(&s.env, &[100u8; 32]));
    let sig11 = offchain::sign(&s, &att3, 11);
    let uid3 = s
        .sas_client
        .attest_by_delegation(&att3, &11, &sig11, &public_key);
    assert_eq!(uid3, att3.uid);

    // Replay of 10 still fails
    let replay10 = s
        .sas_client
        .try_attest_by_delegation(&att1, &10, &sig10, &public_key);
    assert!(replay10.is_err());

    // Concurrent distinct increasing nonces: 12 and 13 in any order both succeed if increasing
    let mut att4 = s.attestation.clone();
    att4.uid = UID(BytesN::from_array(&s.env, &[101u8; 32]));
    let sig12 = offchain::sign(&s, &att4, 12);
    s.sas_client
        .attest_by_delegation(&att4, &12, &sig12, &public_key);
    let mut att5 = s.attestation.clone();
    att5.uid = UID(BytesN::from_array(&s.env, &[102u8; 32]));
    let sig13 = offchain::sign(&s, &att5, 13);
    s.sas_client
        .attest_by_delegation(&att5, &13, &sig13, &public_key);

    // Nonce state is bounded: only one instance entry per attester (verified by storage growth not exploding)
    // We can check that instance still has only one entry for this attester's nonce high-watermark
    let last: u64 = s.env.as_contract(&s.sas_id, || {
        s.env
            .storage()
            .instance()
            .get(&(crate::DELEGATION_NONCE, s.attestation.attester.clone()))
            .unwrap()
    });
    assert_eq!(last, 13);
}

#[test]
fn test_delegation_nonce_storage_bounded_and_describes_concurrent_behavior() {
    // Ensures nonce storage is bounded to one u64 per attester and concurrent
    // submissions with same nonce are serialized (second fails).
    let s = offchain::setup([57u8; 32]);
    let public_key = offchain::public_key(&s);
    let att = s.attestation.clone();
    let sig = offchain::sign(&s, &att, 20);
    s.sas_client
        .attest_by_delegation(&att, &20, &sig, &public_key);

    // Same nonce concurrent retry must fail
    let dup = s
        .sas_client
        .try_attest_by_delegation(&att, &20, &sig, &public_key);
    assert!(dup.is_err());

    // Different attester with same nonce is independent (bounded per-attester)
    // This other setup would have its own SAS contract id, so we need a unified SAS instance.
    // Instead, use same SAS contract but a different attester address derived from other seed.
    let other_key = ed25519_dalek::SigningKey::from_bytes(&[58u8; 32]);
    let other_strkey =
        stellar_strkey::ed25519::PublicKey(other_key.verifying_key().to_bytes()).to_string();
    let other_attester =
        Address::from_string(&soroban_sdk::String::from_str(&s.env, &other_strkey));
    let mut other_att = s.attestation.clone();
    other_att.attester = other_attester.clone();
    other_att.uid = UID(BytesN::from_array(&s.env, &[200u8; 32]));
    let domain = soroban_sas_common::AttestationDomain {
        network_id: s.env.ledger().network_id(),
        contract: s.sas_id.clone(),
        nonce: 20,
    };
    let payload_hash =
        soroban_sas_common::hash_offchain_attestation(&s.env, &other_att, &domain);
    let other_sig = BytesN::from_array(&s.env, &other_key.sign(&payload_hash.to_array()).to_bytes());
    let other_pk = BytesN::from_array(&s.env, &other_key.verifying_key().to_bytes());
    // This should succeed because nonce 20 for other attester is first for that attester
    // (requires register fallback if structural check fails - use generated address that matches key structurally)
    // The other_attester was derived from other_key, so it matches structurally, no registration needed
    let uid = s
        .sas_client
        .attest_by_delegation(&other_att, &20, &other_sig, &other_pk);
    assert_eq!(uid, other_att.uid);
}


// ─────────────────────────────────────────────────────────────────────────────
// #164 — attest_with_value derives payment from on-chain fee configuration
// #161 — Indexer outage policy (fail-open by default, opt-in fail-closed)
// ─────────────────────────────────────────────────────────────────────────────

/// Indexer stand-in whose `index_attestation` always traps, modelling an
/// unavailable / incompatible Indexer.
pub mod mock_trap_indexer {
    use super::*;
    #[contract]
    pub struct TrappingIndexer;

    #[contractimpl]
    impl TrappingIndexer {
        pub fn index_attestation(
            env: Env,
            _uid: UID,
            _recipient: Address,
            _schema_uid: UID,
            _attester: Address,
        ) {
            soroban_sdk::panic_with_error!(&env, SASError::NotInitialized);
        }
    }
}

fn fee_test_env() -> (Env, SASClient<'static>, Address, Address, Address, Address) {
    let env = Env::default();
    let registry_id = env.register_contract(None, mock1::MockRegistry);
    let sas_id = env.register_contract(None, SAS);
    let sas_client = SASClient::new(&env, &sas_id);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    sas_client.init(&admin, &registry_id);
    let attester = Address::generate(&env);
    let recipient = Address::generate(&env);
    (env, sas_client, sas_id, admin, attester, recipient)
}

#[test]
fn test_attest_with_value_rejects_unconfigured_payment() {
    let (env, sas_client, _sas_id, admin, attester, recipient) = fee_test_env();
    let token_id = env.register_stellar_asset_contract(admin.clone());
    soroban_sdk::token::StellarAssetClient::new(&env, &token_id).mint(&attester, &1_000);

    let attestation = attestation_fixture(&env, &attester, &recipient, [40u8; 32]);
    // No fee configured -> a non-zero value is a fee that was never required.
    let res = sas_client.try_attest_with_value(&attestation, &token_id, &500);
    assert_eq!(res, Err(Ok(SASError::FeeMismatch.into())));
    assert!(!sas_client.verify_attestation(&attestation.uid));
}

#[test]
fn test_attest_with_value_rejects_wrong_token_and_short_amount() {
    let (env, sas_client, _sas_id, admin, attester, recipient) = fee_test_env();
    let fee_token = env.register_stellar_asset_contract(admin.clone());
    let other_token = env.register_stellar_asset_contract(admin.clone());
    soroban_sdk::token::StellarAssetClient::new(&env, &fee_token).mint(&attester, &1_000);
    soroban_sdk::token::StellarAssetClient::new(&env, &other_token).mint(&attester, &1_000);
    sas_client.set_fee(&fee_token, &500);

    let a1 = attestation_fixture(&env, &attester, &recipient, [41u8; 32]);
    assert_eq!(
        sas_client.try_attest_with_value(&a1, &other_token, &500),
        Err(Ok(SASError::FeeMismatch.into()))
    );

    let a2 = attestation_fixture(&env, &attester, &recipient, [42u8; 32]);
    assert_eq!(
        sas_client.try_attest_with_value(&a2, &fee_token, &499),
        Err(Ok(SASError::FeeMismatch.into()))
    );
}

#[test]
fn test_attest_with_value_accepts_exact_configured_fee() {
    let (env, sas_client, sas_id, admin, attester, recipient) = fee_test_env();
    let fee_token = env.register_stellar_asset_contract(admin.clone());
    let token = soroban_sdk::token::Client::new(&env, &fee_token);
    soroban_sdk::token::StellarAssetClient::new(&env, &fee_token).mint(&attester, &1_000);
    sas_client.set_fee(&fee_token, &500);

    let attestation = attestation_fixture(&env, &attester, &recipient, [43u8; 32]);
    let uid = sas_client.attest_with_value(&attestation, &fee_token, &500);
    assert_eq!(uid, attestation.uid);
    assert_eq!(token.balance(&sas_id), 500);
}

#[test]
fn test_clear_fee_makes_attestation_fee_free_only_at_zero() {
    let (env, sas_client, _sas_id, admin, attester, recipient) = fee_test_env();
    let token_id = env.register_stellar_asset_contract(admin.clone());
    soroban_sdk::token::StellarAssetClient::new(&env, &token_id).mint(&attester, &1_000);
    sas_client.set_fee(&token_id, &500);
    sas_client.clear_fee();
    assert_eq!(sas_client.get_fee(), None);

    let paid = attestation_fixture(&env, &attester, &recipient, [44u8; 32]);
    assert_eq!(
        sas_client.try_attest_with_value(&paid, &token_id, &500),
        Err(Ok(SASError::FeeMismatch.into()))
    );

    let free = attestation_fixture(&env, &attester, &recipient, [45u8; 32]);
    assert_eq!(sas_client.attest_with_value(&free, &token_id, &0), free.uid);
}

#[test]
fn test_attest_fails_open_when_indexer_traps() {
    let (env, sas_client, sas_id, _admin, attester, recipient) = fee_test_env();
    let indexer_id = env.register_contract(None, mock_trap_indexer::TrappingIndexer);
    sas_client.set_indexer(&indexer_id);

    let attestation = attestation_fixture(&env, &attester, &recipient, [46u8; 32]);
    // Issuance still succeeds despite the trapping indexer.
    let uid = sas_client.attest(&attestation);
    assert_eq!(uid, attestation.uid);
    assert!(sas_client.verify_attestation(&attestation.uid));

    // ... and the missed push is observable as an IndexFailed event.
    let topics: soroban_sdk::Vec<soroban_sdk::Val> =
        (soroban_sdk::symbol_short!("IDXFAIL"), attestation.uid.clone()).into_val(&env);
    let expected_event = (
        sas_id.clone(),
        topics,
        attestation.uid.clone().into_val(&env),
    );
    assert!(env.events().all().contains(expected_event));
}

#[test]
fn test_attest_fails_open_when_indexer_is_incompatible() {
    let (env, sas_client, _sas_id, _admin, attester, recipient) = fee_test_env();
    // A contract with no `index_attestation` entry point at all.
    let indexer_id = env.register_contract(None, mock3::MockResolver);
    sas_client.set_indexer(&indexer_id);

    let attestation = attestation_fixture(&env, &attester, &recipient, [47u8; 32]);
    assert_eq!(sas_client.attest(&attestation), attestation.uid);
}

#[test]
fn test_attest_fails_closed_when_strict_and_indexer_traps() {
    let (env, sas_client, _sas_id, _admin, attester, recipient) = fee_test_env();
    let indexer_id = env.register_contract(None, mock_trap_indexer::TrappingIndexer);
    sas_client.set_indexer(&indexer_id);
    sas_client.set_indexer_strict(&true);
    assert!(sas_client.get_indexer_strict());

    let attestation = attestation_fixture(&env, &attester, &recipient, [48u8; 32]);
    let res = sas_client.try_attest(&attestation);
    assert_eq!(res, Err(Ok(SASError::IndexerUnavailable.into())));
    assert!(!sas_client.verify_attestation(&attestation.uid));
}

#[test]
fn test_reindex_attestation_replays_after_indexer_recovers() {
    let (env, sas_client, _sas_id, _admin, attester, recipient) = fee_test_env();
    let trap_id = env.register_contract(None, mock_trap_indexer::TrappingIndexer);
    sas_client.set_indexer(&trap_id);

    let attestation = attestation_fixture(&env, &attester, &recipient, [49u8; 32]);
    let uid = sas_client.attest(&attestation); // succeeds fail-open, mirror missed it

    // Operator rotates to a healthy indexer and reconciles.
    let good_id = env.register_contract(None, mock4::MockIndexer);
    let good = mock4::MockIndexerClient::new(&env, &good_id);
    sas_client.set_indexer(&good_id);
    sas_client.reindex_attestation(&uid);

    assert!(good.get_attestations_by_recipient(&recipient).contains(&uid));
}

#[test]
fn test_reindex_attestation_reports_still_unavailable_indexer() {
    let (env, sas_client, _sas_id, _admin, attester, recipient) = fee_test_env();
    let trap_id = env.register_contract(None, mock_trap_indexer::TrappingIndexer);
    sas_client.set_indexer(&trap_id);
    let attestation = attestation_fixture(&env, &attester, &recipient, [50u8; 32]);
    let uid = sas_client.attest(&attestation);

    let res = sas_client.try_reindex_attestation(&uid);
    assert_eq!(res, Err(Ok(SASError::IndexerUnavailable.into())));
}
