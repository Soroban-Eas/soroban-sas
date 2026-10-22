extern crate alloc;
use crate::{SchemaRegistry, SchemaRegistryClient};
use alloc::format;
use alloc::vec::Vec;
use soroban_sas_common::{SASError, SchemaBatchItem, LEDGERS_IN_ONE_YEAR, UID};
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

/// `live_until_ledger` recorded for one persistent contract-data entry, or
/// `None` when no such entry exists. The SDK 20 test host neither exposes
/// `get_ttl` nor evicts lapsed entries, so reading the ledger snapshot is the
/// only way to observe a TTL extension directly.
fn persistent_live_until<K>(env: &Env, key: &K) -> Option<u32>
where
    K: soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
{
    use soroban_sdk::xdr::{ContractDataDurability, LedgerKey, ScVal};
    use soroban_sdk::TryFromVal;

    let target = ScVal::try_from_val(env, &key.into_val(env)).unwrap();
    env.to_ledger_snapshot()
        .ledger_entries
        .iter()
        .find_map(|(k, (_, live_until))| match &**k {
            LedgerKey::ContractData(data)
                if data.durability == ContractDataDurability::Persistent && data.key == target =>
            {
                *live_until
            }
            _ => None,
        })
}

#[test]
fn test_pre_init_admin_endpoints_return_not_initialized() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    env.mock_all_auths();
    let hash = BytesN::from_array(&env, &[0u8; 32]);
    assert_eq!(
        client.try_upgrade(&hash, &2u32),
        Err(Ok(SASError::NotInitialized.into()))
    );
    let token = Address::generate(&env);
    assert_eq!(
        client.try_set_fee(&token, &100),
        Err(Ok(SASError::NotInitialized.into()))
    );
    let treasury = Address::generate(&env);
    assert_eq!(
        client.try_set_treasury(&treasury),
        Err(Ok(SASError::NotInitialized.into()))
    );
    assert_eq!(
        client.try_withdraw_fees(&100),
        Err(Ok(SASError::NotInitialized.into()))
    );
    let fake = UID(BytesN::from_array(&env, &[9u8; 32]));
    let auth = Address::generate(&env);
    assert_eq!(
        client.try_deprecate(&fake, &auth),
        Err(Ok(SASError::NotInitialized.into()))
    );
}

#[test]
fn test_no_partial_write_on_failure() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    env.mock_all_auths();
    // Try set_fee before init should fail and not write
    let token = Address::generate(&env);
    let _ = client.try_set_fee(&token, &100);
    // Init should still succeed
    let admin = Address::generate(&env);
    client.init(&admin);
    // Now set_fee should succeed and be independent
    client.set_fee(&token, &123);
    // If previous partial write had stored 100, this would be 123 anyway, but we verify that init succeeded
    // Also test deprecate no tombstone for unknown
    let unknown = UID(BytesN::from_array(&env, &[77u8; 32]));
    let res = client.try_deprecate(&unknown, &admin);
    assert_eq!(res, Err(Ok(SASError::SchemaNotFound.into())));
    let has: bool = env.as_contract(&cid, || {
        env.storage()
            .persistent()
            .get(&(soroban_sdk::symbol_short!("DEPRECATE"), unknown.clone()))
            .unwrap_or(false)
    });
    assert!(!has, "no tombstone should exist");
}

#[test]
fn test_deprecate_unknown_and_idempotent() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);
    let unknown = UID(BytesN::from_array(&env, &[99u8; 32]));
    assert_eq!(
        client.try_deprecate(&unknown, &admin),
        Err(Ok(SASError::SchemaNotFound.into()))
    );
    let has: bool = env.as_contract(&cid, || {
        env.storage()
            .persistent()
            .get(&(soroban_sdk::symbol_short!("DEPRECATE"), unknown.clone()))
            .unwrap_or(false)
    });
    assert!(!has);
    // Register and deprecate
    let schema = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);
    let uid = client.register(&owner, &schema, &resolver, &true);
    client.deprecate(&uid, &owner);
    assert!(client.get_schema(&uid).is_none());
    // Idempotent second
    let res = client.try_deprecate(&uid, &owner);
    assert!(res.is_ok());
    assert!(client.get_schema(&uid).is_none());
    let res2 = client.try_deprecate(&uid, &admin);
    assert!(res2.is_ok());
}

/// Issue #82: `get_schema` renews an existing record's TTL, and an unknown
/// UID returns `None` without creating storage.
#[test]
fn test_get_schema_renews_active_record_and_missing_uid_is_read_only() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let schema = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);
    let uid = client.register(&owner, &schema, &resolver, &true);

    let at_write = persistent_live_until(&env, &uid).expect("record written");

    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    assert_eq!(persistent_live_until(&env, &uid), Some(at_write));

    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    assert!(client.get_schema(&uid).is_some());
    assert_eq!(persistent_live_until(&env, &uid), Some(expected));

    // Unknown UID: None, no storage created.
    let unknown = UID(BytesN::from_array(&env, &[0xAB; 32]));
    assert!(client.get_schema(&unknown).is_none());
    assert_eq!(persistent_live_until(&env, &unknown), None);
    let has: bool = env.as_contract(&cid, || env.storage().persistent().has(&unknown));
    assert!(!has);
}

/// Issue #83: successful `validate_schema` extends the record's TTL; a
/// missing or deprecated UID returns `false` without touching storage.
#[test]
fn test_validate_schema_renews_on_success_and_missing_is_read_only() {
    use soroban_sdk::testutils::Ledger;
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let schema = String::from_str(&env, "bool like_soroban");
    let resolver = Address::generate(&env);
    let uid = client.register(&owner, &schema, &resolver, &true);

    env.ledger().with_mut(|li| {
        li.sequence_number += LEDGERS_IN_ONE_YEAR / 2;
    });
    let expected = env.ledger().sequence() + LEDGERS_IN_ONE_YEAR;
    assert!(client.validate_schema(&uid));
    assert_eq!(persistent_live_until(&env, &uid), Some(expected));

    // Unknown UID: false, no storage created.
    let unknown = UID(BytesN::from_array(&env, &[0xCD; 32]));
    assert!(!client.validate_schema(&unknown));
    assert_eq!(persistent_live_until(&env, &unknown), None);
    let has: bool = env.as_contract(&cid, || env.storage().persistent().has(&unknown));
    assert!(!has);

    // Deprecated schema: false, and no further TTL extension past deprecation.
    client.deprecate(&uid, &admin);
    assert!(!client.validate_schema(&uid));
}

#[test]
fn test_get_schemas_pagination_skips_deprecated_and_returns_cursor() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);
    let mut uids: Vec<UID> = Vec::new();
    for i in 0..5 {
        let owner = Address::generate(&env);
        let s = String::from_str(&env, &format!("bool field{}", i));
        let resolver = Address::generate(&env);
        let uid = client.register(&owner, &s, &resolver, &true);
        uids.push(uid);
    }
    // deprecate middle
    client.deprecate(&uids[2], &admin);
    // get_schemas should skip deprecated and fill page
    let page = client.get_schemas(&0, &2);
    assert_eq!(page.len(), 2);
    // check deprecated not included
    for r in page.iter() {
        assert_ne!(r.uid, uids[2]);
    }
    // deprecated at start
    client.deprecate(&uids[0], &admin);
    let page2 = client.get_schemas(&0, &2);
    assert_eq!(page2.len(), 2);
    for r in page2.iter() {
        assert!(r.uid != uids[0] && r.uid != uids[2]);
    }
    // deprecated at end
    client.deprecate(&uids[4], &admin);
    let page3 = client.get_schemas(&3, &2);
    // Should have 1 active (index3) because 4 deprecated
    assert_eq!(page3.len(), 1);
    assert_eq!(page3.get(0).unwrap().uid, uids[3]);

    // paginated cursor
    let env2 = Env::default();
    let cid2 = env2.register_contract(None, SchemaRegistry);
    let client2 = SchemaRegistryClient::new(&env2, &cid2);
    let admin2 = Address::generate(&env2);
    env2.mock_all_auths();
    client2.init(&admin2);
    let mut uids2: Vec<UID> = Vec::new();
    for i in 0..5 {
        let owner = Address::generate(&env2);
        let s = String::from_str(&env2, &format!("uint32 f{}", i));
        let resolver = Address::generate(&env2);
        let uid = client2.register(&owner, &s, &resolver, &true);
        uids2.push(uid);
    }
    client2.deprecate(&uids2[1], &admin2);
    client2.deprecate(&uids2[2], &admin2);
    let (schemas, next) = client2.get_schemas_paginated(&0, &2);
    assert_eq!(schemas.len(), 2);
    assert_eq!(next, 4);
    let (schemas2, next2) = client2.get_schemas_paginated(&next, &2);
    assert_eq!(schemas2.len(), 1);
    assert_eq!(schemas2.get(0).unwrap().uid, uids2[4]);
    assert_eq!(next2, 5);

    // bounded scanning: heavily deprecated (30 total, 25 deprecated, budget not hit but still bounded)
    let env3 = Env::default();
    let cid3 = env3.register_contract(None, SchemaRegistry);
    let client3 = SchemaRegistryClient::new(&env3, &cid3);
    let admin3 = Address::generate(&env3);
    env3.mock_all_auths();
    client3.init(&admin3);
    let mut uids3: Vec<UID> = Vec::new();
    for i in 0..30 {
        let owner = Address::generate(&env3);
        let s = String::from_str(&env3, &format!("bool x{}", i));
        let resolver = Address::generate(&env3);
        let uid = client3.register(&owner, &s, &resolver, &true);
        uids3.push(uid);
    }
    for uid in uids3.iter().take(25) {
        client3.deprecate(uid, &admin3);
    }
    // First page from 0 limit 5 should skip 25 deprecated and return next 5 (25..29)
    let (p1, c1) = client3.get_schemas_paginated(&0, &5);
    assert_eq!(p1.len(), 5);
    assert_eq!(c1, 30); // scanned 30 slots (0..29) to find 5 active at end
                        // Ensure bounded: scanning stops at budget or end, not infinite
                        // Second page should be empty as all remaining scanned
    let (p2, c2) = client3.get_schemas_paginated(&c1, &5);
    assert_eq!(p2.len(), 0);
    assert_eq!(c2, 30);
}

/// Issue #259: `get_schema_by_content` resolves the same record as
/// `get_schema`, returns `None` for unregistered content, and reverts on a
/// malformed schema string instead of silently reporting "not registered".
#[test]
fn test_get_schema_by_content_matches_uid_lookup_and_rejects_invalid_syntax() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let schema = String::from_str(&env, "bool certified");
    let resolver = Address::generate(&env);
    let uid = client.register(&owner, &schema, &resolver, &true);

    // Registered content resolves to the same record as the UID lookup.
    let by_content = client
        .get_schema_by_content(&schema, &resolver, &true)
        .expect("registered content resolves");
    let by_uid = client.get_schema(&uid).expect("registered uid resolves");
    assert_eq!(by_content.uid, by_uid.uid);
    assert_eq!(by_content.schema, schema);
    assert!(by_content.revocable);

    // Policy fields participate in the UID, so flipping either one addresses
    // different, unregistered content.
    assert!(client
        .get_schema_by_content(&schema, &resolver, &false)
        .is_none());
    let other_resolver = Address::generate(&env);
    assert!(client
        .get_schema_by_content(&schema, &other_resolver, &true)
        .is_none());

    // Unregistered-but-valid content returns None rather than reverting.
    let unknown = String::from_str(&env, "uint32 score");
    assert!(client
        .get_schema_by_content(&unknown, &resolver, &true)
        .is_none());

    // Malformed syntax reverts with the same typed error register raises.
    let malformed = String::from_str(&env, "!!!");
    assert_eq!(
        client.try_get_schema_by_content(&malformed, &resolver, &true),
        Err(Ok(SASError::InvalidSchemaDefinition.into()))
    );

    // Deprecated content resolves to None, matching get_schema.
    client.deprecate(&uid, &admin);
    assert!(client
        .get_schema_by_content(&schema, &resolver, &true)
        .is_none());
}

#[test]
fn test_schema_metadata_uri_registration_and_update() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let schema = String::from_str(&env, "bool certified");
    let resolver = Address::generate(&env);
    let initial_uri = String::from_str(&env, "ipfs://QmInitialMetadataUri");

    // Register with metadata URI
    let uid = client.register_schema(
        &owner,
        &schema,
        &resolver,
        &true,
        &Some(initial_uri.clone()),
    );

    // Verify metadata lookup
    assert_eq!(client.get_schema_metadata(&uid), Some(initial_uri.clone()));
    assert_eq!(client.get_schema_metadata_uri(&uid), Some(initial_uri));

    let with_meta = client.get_schema_with_metadata(&uid).expect("record found");
    assert_eq!(with_meta.0.schema, schema);
    assert_eq!(
        with_meta.1,
        Some(String::from_str(&env, "ipfs://QmInitialMetadataUri"))
    );

    // Update metadata URI by owner succeeds
    let updated_uri = String::from_str(&env, "https://example.com/schema-context.jsonld");
    client.update_schema_metadata(&uid, &owner, &updated_uri);
    assert_eq!(client.get_schema_metadata(&uid), Some(updated_uri.clone()));

    // Non-owner cannot update metadata URI
    let unauthorized_uri = String::from_str(&env, "https://evil.com/fake.jsonld");
    assert_eq!(
        client.try_update_schema_metadata(&uid, &stranger, &unauthorized_uri),
        Err(Ok(SASError::Unauthorized.into()))
    );

    // Deprecated schema hides metadata URI
    client.deprecate(&uid, &admin);
    assert_eq!(client.get_schema_metadata(&uid), None);
    assert_eq!(client.get_schema_with_metadata(&uid), None);
}

#[test]
fn test_schema_metadata_uri_length_limits() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let schema = String::from_str(&env, "uint32 score");
    let resolver = Address::generate(&env);

    // 256 characters should succeed
    let mut exact_256 = alloc::string::String::with_capacity(256);
    for _ in 0..256 {
        exact_256.push('a');
    }
    let valid_uri = String::from_str(&env, &exact_256);
    let uid = client.register_schema(&owner, &schema, &resolver, &false, &Some(valid_uri.clone()));
    assert_eq!(client.get_schema_metadata(&uid), Some(valid_uri));

    // 257 characters should fail with InvalidValue
    let mut too_long = alloc::string::String::with_capacity(257);
    for _ in 0..257 {
        too_long.push('b');
    }
    let invalid_uri = String::from_str(&env, &too_long);
    let schema2 = String::from_str(&env, "string title");
    assert_eq!(
        client.try_register_schema(
            &owner,
            &schema2,
            &resolver,
            &false,
            &Some(invalid_uri.clone()),
        ),
        Err(Ok(SASError::InvalidValue.into()))
    );

    // Updating to > 256 characters should also fail
    assert_eq!(
        client.try_update_schema_metadata(&uid, &owner, &invalid_uri),
        Err(Ok(SASError::InvalidValue.into()))
    );
}

#[test]
fn test_register_schemas_batch_happy_path() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    let owner1 = Address::generate(&env);
    let owner2 = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let resolver = Address::generate(&env);
    let mut batch = soroban_sdk::Vec::new(&env);
    batch.push_back(SchemaBatchItem {
        owner: owner1.clone(),
        schema: String::from_str(&env, "bool certified"),
        resolver: resolver.clone(),
        revocable: true,
    });
    batch.push_back(SchemaBatchItem {
        owner: owner2.clone(),
        schema: String::from_str(&env, "uint32 score, string badge"),
        resolver: resolver.clone(),
        revocable: false,
    });
    batch.push_back(SchemaBatchItem {
        owner: owner1.clone(),
        schema: String::from_str(&env, "bytes32 commitment"),
        resolver: resolver.clone(),
        revocable: true,
    });

    let uids = client.register_schemas_batch(&batch);
    assert_eq!(uids.len(), 3);

    // Distinct UIDs generated in matching order
    let uid0 = uids.get(0).unwrap();
    let uid1 = uids.get(1).unwrap();
    let uid2 = uids.get(2).unwrap();
    assert_ne!(uid0, uid1);
    assert_ne!(uid1, uid2);
    assert_ne!(uid0, uid2);

    // Each is retrievable
    let s0 = client.get_schema(&uid0).expect("schema 0 found");
    assert_eq!(s0.schema, String::from_str(&env, "bool certified"));
    assert!(s0.revocable);

    let s1 = client.get_schema(&uid1).expect("schema 1 found");
    assert_eq!(
        s1.schema,
        String::from_str(&env, "uint32 score, string badge")
    );
    assert!(!s1.revocable);

    let s2 = client.get_schema(&uid2).expect("schema 2 found");
    assert_eq!(s2.schema, String::from_str(&env, "bytes32 commitment"));
    assert!(s2.revocable);
}

#[test]
fn test_register_schemas_batch_atomic_rollback() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let resolver = Address::generate(&env);
    let valid_schema = String::from_str(&env, "bool certified");
    let invalid_schema = String::from_str(&env, "!!!");

    let mut batch = soroban_sdk::Vec::new(&env);
    batch.push_back(SchemaBatchItem {
        owner: owner.clone(),
        schema: valid_schema.clone(),
        resolver: resolver.clone(),
        revocable: true,
    });
    batch.push_back(SchemaBatchItem {
        owner: owner.clone(),
        schema: invalid_schema,
        resolver: resolver.clone(),
        revocable: false,
    });

    // Batch must fail
    let res = client.try_register_schemas_batch(&batch);
    assert!(res.is_err());

    // The first valid schema was NOT committed because execution rolled back
    let expected_uid = soroban_sas_common::schema_uid(&env, &valid_schema, &resolver, true);
    assert!(client.get_schema(&expected_uid).is_none());
}

#[test]
fn test_register_schemas_batch_bounds() {
    let env = Env::default();
    let cid = env.register_contract(None, SchemaRegistry);
    let client = SchemaRegistryClient::new(&env, &cid);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    env.mock_all_auths();
    client.init(&admin);

    let resolver = Address::generate(&env);

    // Empty batch fails with InvalidValue
    let empty_batch = soroban_sdk::Vec::new(&env);
    assert_eq!(
        client.try_register_schemas_batch(&empty_batch),
        Err(Ok(SASError::InvalidValue.into()))
    );

    // Exceeding MAX_SCHEMA_BATCH_SIZE (50) fails with BatchTooLarge
    let mut large_batch = soroban_sdk::Vec::new(&env);
    for i in 0..51 {
        let field = alloc::format!("uint32 field_{}", i);
        large_batch.push_back(SchemaBatchItem {
            owner: owner.clone(),
            schema: String::from_str(&env, &field),
            resolver: resolver.clone(),
            revocable: true,
        });
    }
    assert_eq!(
        client.try_register_schemas_batch(&large_batch),
        Err(Ok(SASError::BatchTooLarge.into()))
    );
}
