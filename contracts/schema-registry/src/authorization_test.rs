//! Regression tests for issue #325 ("review all unauthorized state
//! mutators"): every state-mutating entry point must bind its authorization
//! check to an address the contract itself looked up (the stored schema
//! creator, the registry admin, ...), never to a value the caller supplies
//! unchecked or to "anyone who can produce any valid signature."
//!
//! `add_delegate`/`remove_delegate` take no caller-supplied "authorizer"
//! parameter at all — they call `owner.require_auth()` where `owner` is the
//! schema's stored creator, so there is no address argument to spoof. That
//! makes `env.mock_all_auths()` the wrong tool to test them: it authorizes
//! every address unconditionally and would pass even if the contract checked
//! nothing. These tests instead use `mock_auths`/`MockAuth` to authorize only
//! an unrelated address and confirm the call still fails, proving the
//! authorization is bound to the actual owner and not to whichever address
//! happens to hold a signature.
//!
//! The legacy `transfer_ownership(sender, uid, new_owner)` entry point
//! (kept alongside `transfer_schema_ownership` for backwards compatibility)
//! had no test coverage at all before this file — not even a happy path —
//! despite being a live, reachable ownership-mutating function. It is
//! covered here for the same reason.

use crate::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::SASError;
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, Env, IntoVal, String, Vec};

fn deploy(env: &Env) -> SchemaRegistryClient {
    let contract_id = env.register_contract(None, SchemaRegistry);
    SchemaRegistryClient::new(env, &contract_id)
}

fn register_schema(env: &Env, client: &SchemaRegistryClient, owner: &Address) -> crate::UID {
    let schema = String::from_str(env, "bool like_soroban");
    let resolver = Address::generate(env);
    client.register(owner, &schema, &resolver, &true)
}

#[test]
fn add_delegate_cannot_be_authorized_by_a_non_owner() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let owner = Address::generate(&env);
    let uid = register_schema(&env, &client, &owner);
    let stranger = Address::generate(&env);
    let delegate = Address::generate(&env);

    // Only `stranger` authorizes this call. `add_delegate` internally calls
    // `owner.require_auth()` (the actual creator, looked up from storage),
    // which has no matching mocked auth entry — the host must reject the
    // call, not silently accept `stranger`'s signature as sufficient.
    env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "add_delegate",
            args: (uid.clone(), delegate.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    let result = client.try_add_delegate(&uid, &delegate);
    assert!(
        result.is_err(),
        "add_delegate must reject a call authorized by anyone other than the schema owner"
    );
    assert!(
        !client.is_delegate(&uid, &delegate),
        "a rejected add_delegate call must not have taken effect"
    );
}

#[test]
fn remove_delegate_cannot_be_authorized_by_a_non_owner() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let owner = Address::generate(&env);
    let uid = register_schema(&env, &client, &owner);
    let delegate = Address::generate(&env);
    client.add_delegate(&uid, &delegate);
    assert!(client.is_delegate(&uid, &delegate));

    let stranger = Address::generate(&env);
    env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &client.address,
            fn_name: "remove_delegate",
            args: (uid.clone(), delegate.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    let result = client.try_remove_delegate(&uid, &delegate);
    assert!(
        result.is_err(),
        "remove_delegate must reject a call authorized by anyone other than the schema owner"
    );
    assert!(
        client.is_delegate(&uid, &delegate),
        "a rejected remove_delegate call must not have taken effect"
    );
}

#[test]
fn legacy_transfer_ownership_moves_the_creator_when_called_by_the_owner() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let owner = Address::generate(&env);
    let uid = register_schema(&env, &client, &owner);
    let new_owner = Address::generate(&env);

    client.transfer_ownership(&owner, &uid, &new_owner);

    assert_eq!(client.get_creator(&uid), Some(new_owner));
}

#[test]
fn legacy_transfer_ownership_allows_the_registry_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let admin = Address::generate(&env);
    client.init(&admin);
    let owner = Address::generate(&env);
    let uid = register_schema(&env, &client, &owner);
    let new_owner = Address::generate(&env);

    client.transfer_ownership(&admin, &uid, &new_owner);

    assert_eq!(client.get_creator(&uid), Some(new_owner));
}

#[test]
fn legacy_transfer_ownership_rejects_an_unrelated_caller() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let admin = Address::generate(&env);
    client.init(&admin);
    let owner = Address::generate(&env);
    let uid = register_schema(&env, &client, &owner);
    let stranger = Address::generate(&env);
    let new_owner = Address::generate(&env);

    let result = client.try_transfer_ownership(&stranger, &uid, &new_owner);
    assert_eq!(result, Err(Ok(SASError::Unauthorized.into())));
    assert_eq!(
        client.get_creator(&uid),
        Some(owner),
        "a rejected transfer must leave the creator unchanged"
    );
}

#[test]
fn legacy_transfer_ownership_cannot_bypass_a_multisig_owner_set() {
    let env = Env::default();
    env.mock_all_auths();
    let client = deploy(&env);

    let owner = Address::generate(&env);
    let uid = register_schema(&env, &client, &owner);
    let co_owner = Address::generate(&env);
    let mut owners = Vec::new(&env);
    owners.push_back(owner.clone());
    owners.push_back(co_owner.clone());
    client.configure_owner_set(&uid, &owner, &owners, &2);

    let new_owner = Address::generate(&env);
    let result = client.try_transfer_ownership(&owner, &uid, &new_owner);
    assert_eq!(
        result,
        Err(Ok(SASError::Unauthorized.into())),
        "a multisig schema must go through propose/approve, not the legacy single-signature path"
    );
    assert_eq!(client.get_creator(&uid), Some(owner));
}
