use crate::{SchemaRegistry, SchemaRegistryClient};
use soroban_sas_common::SASError;
use soroban_sdk::{testutils::Address as _, Address, Env, String};
extern crate alloc;
use alloc::format;

fn setup(env: &Env) -> (SchemaRegistryClient<'_>, Address, Address) {
    let id = env.register_contract(None, SchemaRegistry);
    env.mock_all_auths();
    let client = SchemaRegistryClient::new(env, &id);
    let admin = Address::generate(env);
    client.init(&admin);
    (client, Address::generate(env), Address::generate(env))
}

#[test]
fn category_registration_and_legacy_registration_are_compatible() {
    let env = Env::default();
    let (client, owner, resolver) = setup(&env);
    let category = String::from_str(&env, "defi");
    let tagged = client.register_with_category(
        &owner,
        &String::from_str(&env, "bool authorized"),
        &resolver,
        &true,
        &Some(category.clone()),
    );
    let legacy = client.register(
        &owner,
        &String::from_str(&env, "bool legacy"),
        &resolver,
        &true,
    );
    assert_eq!(client.get_schema_category(&tagged), Some(category.clone()));
    assert_eq!(client.get_schema_category(&legacy), None);
    let (page, next) = client.get_schemas_by_category(&category, &0, &10);
    assert_eq!(page.len(), 1);
    assert_eq!(page.first().unwrap().uid, tagged);
    assert_eq!(next, 1);
    // Uncategorized registration is supported without modifying the record.
    let uncategorized = client.register_with_category(
        &owner,
        &String::from_str(&env, "bool empty"),
        &resolver,
        &true,
        &None,
    );
    assert_eq!(client.get_schema_category(&uncategorized), None);
}

#[test]
fn rejects_invalid_categories_without_registering() {
    let env = Env::default();
    let (client, owner, resolver) = setup(&env);
    let schema = String::from_str(&env, "bool valid");
    for invalid in [
        "hello_world",
        "some space",
        "emoji😀",
        "kyc/",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567",
    ] {
        let category = String::from_str(&env, invalid);
        assert_eq!(
            client.try_register_with_category(&owner, &schema, &resolver, &true, &Some(category)),
            Err(Ok(SASError::InvalidValue.into()))
        );
    }
    let (all, _) = client.get_schemas_paginated(&0, &10);
    assert!(all.is_empty());
}

#[test]
fn category_pagination_skips_deprecated_and_honors_cursor() {
    let env = Env::default();
    let (client, owner, resolver) = setup(&env);
    let category = String::from_str(&env, "education");
    let mut registered = alloc::vec::Vec::new();
    for i in 0..9 {
        let schema = String::from_str(&env, &format!("bool verified{i}"));
        registered.push(client.register_with_category(
            &owner,
            &schema,
            &resolver,
            &true,
            &Some(category.clone()),
        ));
    }
    client.deprecate(&registered[3], &owner);
    let mut cursor = 0;
    let mut seen = alloc::vec::Vec::new();
    while cursor < registered.len() as u32 {
        let (page, next) = client.get_schemas_by_category(&category, &cursor, &2);
        assert!(next > cursor);
        for record in page.iter() {
            seen.push(record.uid);
        }
        cursor = next;
    }
    assert_eq!(seen.len(), 8);
    assert!(!seen.contains(&registered[3]));
    assert_eq!(
        client
            .get_schemas_by_category(&category, &cursor, &2)
            .0
            .len(),
        0
    );
    assert_eq!(
        client
            .get_schemas_by_category(&String::from_str(&env, "gaming"), &0, &3)
            .0
            .len(),
        0
    );
}

#[test]
fn category_pages_across_scan_budget() {
    let env = Env::default();
    env.budget().reset_unlimited();
    let (client, owner, resolver) = setup(&env);
    let category = String::from_str(&env, "analytics-1");
    for index in 0..105u32 {
        let schema = String::from_str(&env, &format!("bool batch{index}"));
        client.register_with_category(&owner, &schema, &resolver, &true, &Some(category.clone()));
    }
    let (first, cursor) = client.get_schemas_by_category(&category, &0, &105);
    assert_eq!(first.len(), 100);
    assert_eq!(cursor, 100);
    let (second, end) = client.get_schemas_by_category(&category, &cursor, &105);
    assert_eq!(second.len(), 5);
    assert_eq!(end, 105);
    let (empty, end_again) = client.get_schemas_by_category(&category, &end, &2);
    assert!(empty.is_empty());
    assert_eq!(end_again, end);
}
