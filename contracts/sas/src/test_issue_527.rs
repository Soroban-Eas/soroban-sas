use crate::{DelegationPolicy, SASClient, DELEGATION_PERMISSION_ISSUE, SAS};
use ed25519_dalek::{Signer, SigningKey};
use soroban_sas_common::{
    attestation_uid, hash_offchain_attestation, hash_scoped_attestation, Attestation,
    AttestationDomain, DelegationAuthorization, DelegationSchemaScope, SASError, UID,
};
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, String as SorobanString};

fn fixture() -> (
    Env,
    SASClient<'static>,
    Address,
    Address,
    SigningKey,
    Address,
) {
    let env = Env::default();
    env.mock_all_auths();
    let registry = env.register_contract(None, crate::test::mock1::MockRegistry);
    let id = env.register_contract(None, SAS);
    let client = SASClient::new(&env, &id);
    client.init(&Address::generate(&env), &registry);
    let signing_key = SigningKey::from_bytes(&[23u8; 32]);
    let account =
        stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes()).to_string();
    let attester = Address::from_string(&SorobanString::from_str(&env, &account));
    let recipient = Address::generate(&env);
    (env, client, id, attester, signing_key, recipient)
}

fn attestation(env: &Env, attester: &Address, recipient: &Address, schema: u8) -> Attestation {
    let schema_uid = UID(BytesN::from_array(env, &[schema; 32]));
    let data = Bytes::from_array(env, &[schema; 8]);
    Attestation {
        uid: attestation_uid(env, &schema_uid, recipient, attester, &data),
        schema_uid,
        time: 0,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: attester.clone(),
        revocable: true,
        data,
    }
}

fn signature(
    env: &Env,
    id: &Address,
    key: &SigningKey,
    a: &Attestation,
    nonce: u64,
    scope: &DelegationSchemaScope,
) -> BytesN<64> {
    let domain = AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: id.clone(),
        nonce,
    };
    let digest = hash_scoped_attestation(
        env,
        a,
        &domain,
        &DelegationAuthorization {
            schema_scope: scope.clone(),
            permissions: DELEGATION_PERMISSION_ISSUE,
            valid_until: 0,
        },
    );
    BytesN::from_array(env, &key.sign(&digest.to_array()).to_bytes())
}

#[test]
fn signed_scope_restricts_schema_and_wildcard_remains_valid() {
    let (env, sas, id, attester, key, recipient) = fixture();
    let public_key = BytesN::from_array(&env, &key.verifying_key().to_bytes());
    let a = attestation(&env, &attester, &recipient, 2);
    let b = attestation(&env, &attester, &recipient, 3);
    sas.set_delegation_policy(
        &attester,
        &DelegationPolicy {
            authorized_schema_uid: DelegationSchemaScope::Only(a.schema_uid.clone()),
            permissions: DELEGATION_PERMISSION_ISSUE,
            valid_until: 0,
        },
    );
    let bad_signature = signature(
        &env,
        &id,
        &key,
        &b,
        1,
        &DelegationSchemaScope::Only(b.schema_uid.clone()),
    );
    assert_eq!(
        sas.try_attest_by_scoped_delegation(
            &b,
            &1,
            &bad_signature,
            &public_key,
            &DelegationAuthorization {
                schema_scope: DelegationSchemaScope::Only(b.schema_uid.clone()),
                permissions: DELEGATION_PERMISSION_ISSUE,
                valid_until: 0,
            },
        ),
        Err(Ok(SASError::DelegationScopeDenied.into()))
    );
    let good_signature = signature(
        &env,
        &id,
        &key,
        &a,
        1,
        &DelegationSchemaScope::Only(a.schema_uid.clone()),
    );
    sas.attest_by_scoped_delegation(
        &a,
        &1,
        &good_signature,
        &public_key,
        &DelegationAuthorization {
            schema_scope: DelegationSchemaScope::Only(a.schema_uid.clone()),
            permissions: DELEGATION_PERMISSION_ISSUE,
            valid_until: 0,
        },
    );
    assert!(sas.verify_attestation(&a.uid));

    // Root-attester policy also restricts the original v1 signature path.
    let domain = AttestationDomain {
        network_id: env.ledger().network_id(),
        contract: id.clone(),
        nonce: 2,
    };
    let old_digest = hash_offchain_attestation(&env, &b, &domain);
    let old_sig = BytesN::from_array(&env, &key.sign(&old_digest.to_array()).to_bytes());
    assert_eq!(
        sas.try_attest_by_delegation(&b, &2, &old_sig, &public_key),
        Err(Ok(SASError::DelegationScopeDenied.into()))
    );

    sas.set_delegation_policy(
        &attester,
        &DelegationPolicy {
            authorized_schema_uid: DelegationSchemaScope::Any,
            permissions: DELEGATION_PERMISSION_ISSUE,
            valid_until: 0,
        },
    );
    let wildcard_sig = signature(&env, &id, &key, &b, 2, &DelegationSchemaScope::Any);
    assert!(sas
        .try_attest_by_scoped_delegation(
            &b,
            &2,
            &good_signature,
            &public_key,
            &DelegationAuthorization {
                schema_scope: DelegationSchemaScope::Any,
                permissions: DELEGATION_PERMISSION_ISSUE,
                valid_until: 0,
            },
        )
        .is_err());
    sas.attest_by_scoped_delegation(
        &b,
        &2,
        &wildcard_sig,
        &public_key,
        &DelegationAuthorization {
            schema_scope: DelegationSchemaScope::Any,
            permissions: DELEGATION_PERMISSION_ISSUE,
            valid_until: 0,
        },
    );
    assert!(sas.verify_attestation(&b.uid));
}
