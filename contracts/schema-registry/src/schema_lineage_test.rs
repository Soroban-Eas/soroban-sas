//! Tests for hierarchical schema versioning (#442): `register_with_parent`,
//! the `parent_schema_uid` field of `SchemaRecord`, and `get_schema_lineage`.
//!
//! Every schema here uses the same definition and a fresh resolver address.
//! The resolver is part of the schema UID, so that is the cheapest way to get
//! many distinct schemas without hand-writing unique definitions.

use crate::{SchemaRegistry, SchemaRegistryClient, MAX_SCHEMA_LINEAGE_DEPTH, UID};
use soroban_sas_common::SASError;
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, BytesN, Env, IntoVal, String, Vec};

struct Fixture {
    env: Env,
    contract_id: Address,
    admin: Address,
}

fn fixture() -> Fixture {
    let env = Env::default();
    env.mock_all_auths();
    env.budget().reset_unlimited();
    let contract_id = env.register_contract(None, SchemaRegistry);
    let admin = Address::generate(&env);
    SchemaRegistryClient::new(&env, &contract_id).init(&admin);
    Fixture {
        env,
        contract_id,
        admin,
    }
}

impl Fixture {
    fn client(&self) -> SchemaRegistryClient<'_> {
        SchemaRegistryClient::new(&self.env, &self.contract_id)
    }

    /// Registers a schema owned by `owner`, optionally under `parent`.
    fn register(&self, owner: &Address, parent: Option<&UID>) -> UID {
        let resolver = Address::generate(&self.env);
        self.client().register_with_parent(
            owner,
            &String::from_str(&self.env, "bool credential_v"),
            &resolver,
            &true,
            &parent.cloned(),
        )
    }

    fn try_register(
        &self,
        owner: &Address,
        parent: Option<&UID>,
    ) -> Result<UID, Result<soroban_sdk::Error, soroban_sdk::InvokeError>> {
        let resolver = Address::generate(&self.env);
        match self.client().try_register_with_parent(
            owner,
            &String::from_str(&self.env, "bool credential_v"),
            &resolver,
            &true,
            &parent.cloned(),
        ) {
            Ok(Ok(uid)) => Ok(uid),
            Ok(Err(_)) => panic!("registry returned an undecodable UID"),
            Err(err) => Err(err),
        }
    }
}

fn unknown_uid(env: &Env) -> UID {
    UID(BytesN::from_array(env, &[7u8; 32]))
}

#[test]
fn root_schema_has_no_parent_and_is_its_own_root() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let uid = f.register(&owner, None);

    let record = f.client().get_schema(&uid).unwrap();
    assert_eq!(record.parent_schema_uid, None);

    let lineage = f.client().get_schema_lineage(&uid);
    assert_eq!(lineage.schema_uid, uid);
    assert_eq!(lineage.parent, None);
    assert_eq!(lineage.root, uid);
    assert_eq!(lineage.depth, 0);
    assert_eq!(lineage.ancestors.len(), 0);
}

#[test]
fn plain_register_creates_a_root_schema() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let resolver = Address::generate(&f.env);

    let uid = f.client().register(
        &owner,
        &String::from_str(&f.env, "bool plain_root"),
        &resolver,
        &true,
    );

    assert_eq!(f.client().get_schema(&uid).unwrap().parent_schema_uid, None);
    assert_eq!(f.client().get_schema_lineage(&uid).root, uid);
}

#[test]
fn registration_accepts_an_existing_parent() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let parent = f.register(&owner, None);

    let child = f.register(&owner, Some(&parent));

    assert_ne!(child, parent);
    let record = f.client().get_schema(&child).unwrap();
    assert_eq!(record.parent_schema_uid, Some(parent.clone()));

    let lineage = f.client().get_schema_lineage(&child);
    assert_eq!(lineage.parent, Some(parent.clone()));
    assert_eq!(lineage.root, parent);
    assert_eq!(lineage.depth, 1);
    assert_eq!(lineage.ancestors.len(), 1);
    assert_eq!(lineage.ancestors.get(0), Some(parent));
}

#[test]
fn registration_rejects_a_parent_that_does_not_exist() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    f.register(&owner, None);
    let missing = unknown_uid(&f.env);

    let result = f.try_register(&owner, Some(&missing));

    assert_eq!(result, Err(Ok(SASError::InvalidSchema.into())));
    assert_eq!(
        f.client().get_schemas(&0, &10).len(),
        1,
        "a rejected registration must not leave a schema behind"
    );
}

#[test]
fn multi_generation_lineage_reports_every_ancestor_in_order() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let v1 = f.register(&owner, None);
    let v2 = f.register(&owner, Some(&v1));
    let v3 = f.register(&owner, Some(&v2));
    let v4 = f.register(&owner, Some(&v3));

    let lineage = f.client().get_schema_lineage(&v4);
    assert_eq!(lineage.schema_uid, v4);
    assert_eq!(lineage.parent, Some(v3.clone()));
    assert_eq!(lineage.root, v1);
    assert_eq!(lineage.depth, 3);
    let mut expected: Vec<UID> = Vec::new(&f.env);
    expected.push_back(v3.clone());
    expected.push_back(v2.clone());
    expected.push_back(v1.clone());
    assert_eq!(lineage.ancestors, expected);

    // Intermediate generations see only their own ancestry.
    let mid = f.client().get_schema_lineage(&v2);
    assert_eq!(mid.parent, Some(v1.clone()));
    assert_eq!(mid.root, v1);
    assert_eq!(mid.depth, 1);

    // The root is unaffected by descendants.
    let root = f.client().get_schema_lineage(&v1);
    assert_eq!(root.parent, None);
    assert_eq!(root.root, v1);
    assert_eq!(root.depth, 0);
}

#[test]
fn sibling_branches_share_a_root() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let root = f.register(&owner, None);
    let left = f.register(&owner, Some(&root));
    let right = f.register(&owner, Some(&root));
    let left_child = f.register(&owner, Some(&left));

    assert_eq!(f.client().get_schema_lineage(&left).root, root);
    assert_eq!(f.client().get_schema_lineage(&right).root, root);
    let lineage = f.client().get_schema_lineage(&left_child);
    assert_eq!(lineage.root, root);
    assert_eq!(lineage.parent, Some(left));
    assert_eq!(lineage.depth, 2);
}

#[test]
fn only_the_parent_owner_or_admin_may_register_a_child() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let stranger = Address::generate(&f.env);
    let parent = f.register(&owner, None);

    assert_eq!(
        f.try_register(&stranger, Some(&parent)),
        Err(Ok(SASError::Unauthorized.into()))
    );

    // The registry admin may derive a child from someone else's schema.
    let child = f.register(&f.admin, Some(&parent));
    assert_eq!(
        f.client().get_schema_lineage(&child).parent,
        Some(parent.clone())
    );

    // So may the parent's owner.
    let owner_child = f.register(&owner, Some(&parent));
    assert_eq!(f.client().get_schema_lineage(&owner_child).root, parent);
}

#[test]
fn new_owner_may_derive_children_after_an_ownership_transfer() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let new_owner = Address::generate(&f.env);
    let parent = f.register(&owner, None);

    f.client().transfer_schema_ownership(&parent, &new_owner);

    assert_eq!(
        f.try_register(&owner, Some(&parent)),
        Err(Ok(SASError::Unauthorized.into()))
    );
    let child = f.register(&new_owner, Some(&parent));
    assert_eq!(f.client().get_schema_lineage(&child).parent, Some(parent));
}

#[test]
fn registering_a_child_requires_the_owner_signature() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let stranger = Address::generate(&f.env);
    let parent = f.register(&owner, None);
    let resolver = Address::generate(&f.env);
    let schema = String::from_str(&f.env, "bool signed_child");
    let parent_arg = Some(parent.clone());

    // Only `stranger` signs, but `owner` is the registering account.
    f.env.mock_auths(&[MockAuth {
        address: &stranger,
        invoke: &MockAuthInvoke {
            contract: &f.contract_id,
            fn_name: "register_with_parent",
            args: (
                owner.clone(),
                schema.clone(),
                resolver.clone(),
                true,
                parent_arg.clone(),
            )
                .into_val(&f.env),
            sub_invokes: &[],
        },
    }]);

    let result =
        f.client()
            .try_register_with_parent(&owner, &schema, &resolver, &true, &parent_arg);
    assert!(result.is_err());
}

#[test]
fn a_deprecated_parent_can_still_be_superseded() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let v1 = f.register(&owner, None);
    f.client().deprecate(&v1, &owner);
    assert!(f.client().get_schema(&v1).is_none());

    let v2 = f.register(&owner, Some(&v1));

    // Lineage walks through the deprecated ancestor even though the public
    // lookup hides it, and works for a deprecated schema itself.
    let lineage = f.client().get_schema_lineage(&v2);
    assert_eq!(lineage.parent, Some(v1.clone()));
    assert_eq!(lineage.root, v1);
    assert_eq!(f.client().get_schema_lineage(&v1).depth, 0);
}

#[test]
fn lineage_of_an_unknown_schema_is_not_found() {
    let f = fixture();
    let unknown = unknown_uid(&f.env);

    assert_eq!(
        f.client().try_get_schema_lineage(&unknown),
        Err(Ok(SASError::SchemaNotFound.into()))
    );
}

#[test]
fn the_parent_does_not_change_schema_identity() {
    let f = fixture();
    let owner = Address::generate(&f.env);
    let resolver = Address::generate(&f.env);
    let schema = String::from_str(&f.env, "bool shared_definition");
    let parent = f.register(&owner, None);

    let original = f
        .client()
        .register_with_parent(&owner, &schema, &resolver, &true, &None);

    // Same definition, resolver and revocability: still a duplicate, even
    // when a parent is supplied this time.
    let duplicate =
        f.client()
            .try_register_with_parent(&owner, &schema, &resolver, &true, &Some(parent));
    assert_eq!(duplicate, Err(Ok(SASError::SchemaAlreadyExists.into())));
    assert_eq!(
        f.client().get_schema(&original).unwrap().parent_schema_uid,
        None
    );
}

#[test]
fn lineage_depth_is_capped() {
    let f = fixture();
    let owner = Address::generate(&f.env);

    let mut tip = f.register(&owner, None);
    for _ in 0..MAX_SCHEMA_LINEAGE_DEPTH {
        tip = f.register(&owner, Some(&tip));
    }
    let lineage = f.client().get_schema_lineage(&tip);
    assert_eq!(lineage.depth, MAX_SCHEMA_LINEAGE_DEPTH);
    assert_eq!(lineage.ancestors.len(), MAX_SCHEMA_LINEAGE_DEPTH);

    assert_eq!(
        f.try_register(&owner, Some(&tip)),
        Err(Ok(SASError::LimitExceeded.into()))
    );
}
