//! Tests for schema attester access control lists (#443).
//!
//! The registry half of the feature: owners grant and revoke attester
//! permissions with `add_authorized_attester` / `remove_authorized_attester`,
//! and expose them through `is_attester_authorized`, `is_schema_restricted`
//! and `get_authorized_attester_count`. SAS enforcement is covered in
//! `contracts/sas/src/test_issue_443.rs`.
//!
//! Authorization is bound to the stored creator, so the negative tests use
//! `mock_auths` for an unrelated address instead of `mock_all_auths`, which
//! would approve every caller and prove nothing.

use crate::{SchemaRegistry, SchemaRegistryClient, UID};
use soroban_sas_common::{SASError, SchemaAttesterAddedEvent, SchemaAttesterRemovedEvent};
use soroban_sdk::testutils::{Address as _, Events as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{symbol_short, Address, Env, IntoVal, String};

struct Fixture {
    env: Env,
    contract_id: Address,
    owner: Address,
    uid: UID,
}

fn fixture() -> Fixture {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.init(&admin);

    let owner = Address::generate(&env);
    let resolver = Address::generate(&env);
    let uid = client.register(
        &owner,
        &String::from_str(&env, "bool in_private_group"),
        &resolver,
        &true,
    );
    Fixture {
        env,
        contract_id,
        owner,
        uid,
    }
}

impl Fixture {
    fn client(&self) -> SchemaRegistryClient<'_> {
        SchemaRegistryClient::new(&self.env, &self.contract_id)
    }
}

#[test]
fn schema_is_unrestricted_by_default() {
    let f = fixture();
    let client = f.client();
    let anyone = Address::generate(&f.env);

    assert!(!client.is_schema_restricted(&f.uid));
    assert_eq!(client.get_authorized_attester_count(&f.uid), 0);
    assert!(!client.is_attester_authorized(&f.uid, &anyone));
    // The owner keeps issuing rights regardless of the list.
    assert!(client.is_authorized(&f.uid, &f.owner));
}

#[test]
fn owner_can_add_an_authorized_attester() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);
    let outsider = Address::generate(&f.env);

    client.add_authorized_attester(&f.uid, &attester);

    assert!(client.is_attester_authorized(&f.uid, &attester));
    assert!(!client.is_attester_authorized(&f.uid, &outsider));
    assert!(client.is_schema_restricted(&f.uid));
    assert_eq!(client.get_authorized_attester_count(&f.uid), 1);
}

#[test]
fn listed_attester_is_not_a_delegate() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);

    client.add_authorized_attester(&f.uid, &attester);

    // `is_authorized` is what gates revoking other attesters' attestations,
    // so an ACL entry must not widen it.
    assert!(!client.is_delegate(&f.uid, &attester));
    assert!(!client.is_authorized(&f.uid, &attester));
}

#[test]
fn adding_an_attester_emits_an_event() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);

    client.add_authorized_attester(&f.uid, &attester);

    let events = f.env.events().all();
    let expected = SchemaAttesterAddedEvent {
        schema_uid: f.uid.clone(),
        attester: attester.clone(),
        authorizer: f.owner.clone(),
    };
    assert_eq!(
        soroban_sdk::vec![&f.env, events.last().unwrap()],
        soroban_sdk::vec![
            &f.env,
            (
                f.contract_id.clone(),
                (symbol_short!("ATTADD"), f.uid.clone()).into_val(&f.env),
                expected.into_val(&f.env),
            )
        ]
    );
}

#[test]
fn adding_the_same_attester_twice_is_idempotent() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);

    client.add_authorized_attester(&f.uid, &attester);
    client.add_authorized_attester(&f.uid, &attester);

    assert_eq!(client.get_authorized_attester_count(&f.uid), 1);
    client.remove_authorized_attester(&f.uid, &attester);
    assert!(!client.is_attester_authorized(&f.uid, &attester));
    assert!(!client.is_schema_restricted(&f.uid));
}

#[test]
fn owner_can_remove_an_authorized_attester() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);
    client.add_authorized_attester(&f.uid, &attester);

    client.remove_authorized_attester(&f.uid, &attester);

    assert!(!client.is_attester_authorized(&f.uid, &attester));
    assert_eq!(client.get_authorized_attester_count(&f.uid), 0);
    assert!(
        !client.is_schema_restricted(&f.uid),
        "removing the last attester returns the schema to its default"
    );
}

#[test]
fn removing_an_attester_emits_an_event() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);
    client.add_authorized_attester(&f.uid, &attester);

    client.remove_authorized_attester(&f.uid, &attester);

    let events = f.env.events().all();
    let expected = SchemaAttesterRemovedEvent {
        schema_uid: f.uid.clone(),
        attester: attester.clone(),
        authorizer: f.owner.clone(),
    };
    assert_eq!(
        soroban_sdk::vec![&f.env, events.last().unwrap()],
        soroban_sdk::vec![
            &f.env,
            (
                f.contract_id.clone(),
                (symbol_short!("ATTREM"), f.uid.clone()).into_val(&f.env),
                expected.into_val(&f.env),
            )
        ]
    );
}

#[test]
fn removing_one_attester_keeps_the_others_and_the_restriction() {
    let f = fixture();
    let client = f.client();
    let first = Address::generate(&f.env);
    let second = Address::generate(&f.env);
    client.add_authorized_attester(&f.uid, &first);
    client.add_authorized_attester(&f.uid, &second);
    assert_eq!(client.get_authorized_attester_count(&f.uid), 2);

    client.remove_authorized_attester(&f.uid, &first);

    assert!(!client.is_attester_authorized(&f.uid, &first));
    assert!(client.is_attester_authorized(&f.uid, &second));
    assert!(client.is_schema_restricted(&f.uid));
    assert_eq!(client.get_authorized_attester_count(&f.uid), 1);
}

#[test]
fn removing_an_unlisted_attester_changes_nothing() {
    let f = fixture();
    let client = f.client();
    let listed = Address::generate(&f.env);
    let unlisted = Address::generate(&f.env);
    client.add_authorized_attester(&f.uid, &listed);

    client.remove_authorized_attester(&f.uid, &unlisted);

    assert!(client.is_attester_authorized(&f.uid, &listed));
    assert_eq!(client.get_authorized_attester_count(&f.uid), 1);
}

#[test]
fn a_non_owner_cannot_add_an_attester() {
    let f = fixture();
    let client = f.client();
    let stranger = Address::generate(&f.env);
    let attester = Address::generate(&f.env);

    f.env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "add_authorized_attester",
            args: (f.uid.clone(), attester.clone()).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);

    let result = client.try_add_authorized_attester(&f.uid, &attester);
    assert!(
        result.is_err(),
        "only the schema owner may grant attester permissions"
    );
    assert!(!client.is_attester_authorized(&f.uid, &attester));
    assert!(!client.is_schema_restricted(&f.uid));
}

#[test]
fn a_non_owner_cannot_remove_an_attester() {
    let f = fixture();
    let client = f.client();
    let stranger = Address::generate(&f.env);
    let attester = Address::generate(&f.env);
    client.add_authorized_attester(&f.uid, &attester);

    f.env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "remove_authorized_attester",
            args: (f.uid.clone(), attester.clone()).into_val(&f.env),
            sub_invokes: &[],
        },
    }]);

    let result = client.try_remove_authorized_attester(&f.uid, &attester);
    assert!(
        result.is_err(),
        "only the schema owner may revoke attester permissions"
    );
    assert!(client.is_attester_authorized(&f.uid, &attester));
}

#[test]
fn acl_management_rejects_an_unknown_schema() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);
    let unknown = UID(soroban_sdk::BytesN::from_array(&f.env, &[9u8; 32]));

    assert_eq!(
        client.try_add_authorized_attester(&unknown, &attester),
        Err(Ok(SASError::SchemaNotFound.into()))
    );
    assert_eq!(
        client.try_remove_authorized_attester(&unknown, &attester),
        Err(Ok(SASError::SchemaNotFound.into()))
    );
    assert!(!client.is_schema_restricted(&unknown));
}

#[test]
fn acl_is_scoped_to_one_schema() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);
    let resolver = Address::generate(&f.env);
    let other_uid = client.register(
        &f.owner,
        &String::from_str(&f.env, "bool other_schema"),
        &resolver,
        &true,
    );

    client.add_authorized_attester(&f.uid, &attester);

    assert!(client.is_attester_authorized(&f.uid, &attester));
    assert!(!client.is_attester_authorized(&other_uid, &attester));
    assert!(!client.is_schema_restricted(&other_uid));
}

#[test]
fn deprecated_schema_authorizes_no_acl_attesters() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);
    client.add_authorized_attester(&f.uid, &attester);

    client.deprecate(&f.uid, &f.owner);

    assert!(!client.is_attester_authorized(&f.uid, &attester));
}

#[test]
fn acl_survives_a_schema_ownership_transfer() {
    let f = fixture();
    let client = f.client();
    let attester = Address::generate(&f.env);
    let new_owner = Address::generate(&f.env);
    client.add_authorized_attester(&f.uid, &attester);

    client.transfer_schema_ownership(&f.uid, &new_owner);
    assert_eq!(client.get_creator(&f.uid), Some(new_owner.clone()));
    assert!(client.is_attester_authorized(&f.uid, &attester));

    // The new owner now manages the list.
    client.remove_authorized_attester(&f.uid, &attester);
    let events = f.env.events().all();
    let expected = SchemaAttesterRemovedEvent {
        schema_uid: f.uid.clone(),
        attester,
        authorizer: new_owner,
    };
    assert_eq!(
        soroban_sdk::vec![&f.env, events.last().unwrap()],
        soroban_sdk::vec![
            &f.env,
            (
                f.contract_id.clone(),
                (symbol_short!("ATTREM"), f.uid.clone()).into_val(&f.env),
                expected.into_val(&f.env),
            )
        ]
    );
}
