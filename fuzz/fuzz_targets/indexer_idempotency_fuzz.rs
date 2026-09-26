#![no_main]
use libfuzzer_sys::fuzz_target;
use soroban_sas_common::{SASError, UID};
use soroban_sas_indexer::{Indexer, IndexerClient};
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, Address, BytesN, Env, IntoVal,
    String as SorobanString, Symbol,
};

#[contract]
pub struct MockSas;

#[contractimpl]
impl MockSas {
    #[allow(non_snake_case)]
    pub fn SASV1(_env: Env) -> bool {
        true
    }

    pub fn relay_index(
        env: Env,
        indexer: Address,
        uid: UID,
        recipient: Address,
        schema_uid: UID,
        attester: Address,
    ) {
        env.invoke_contract::<()>(
            &indexer,
            &Symbol::new(&env, "index_attestation"),
            soroban_sdk::vec![
                &env,
                uid.into_val(&env),
                recipient.into_val(&env),
                schema_uid.into_val(&env),
                attester.into_val(&env),
            ],
        );
    }
}

fn bytes20_to_address(env: &Env, bytes: &[u8; 20]) -> Address {
    let mut pk = [0u8; 32];
    pk[..20].copy_from_slice(bytes);
    let strkey = stellar_strkey::ed25519::PublicKey(pk).to_string();
    Address::from_string(&SorobanString::from_str(env, &strkey))
}

fn mutate_bytes20(b: &[u8; 20]) -> [u8; 20] {
    let mut mutated = *b;
    mutated[0] = mutated[0].wrapping_add(1);
    if mutated == *b {
        mutated[1] = mutated[1].wrapping_add(1);
    }
    mutated
}

fn mutate_bytes32(b: &[u8; 32]) -> [u8; 32] {
    let mut mutated = *b;
    mutated[0] = mutated[0].wrapping_add(1);
    if mutated == *b {
        mutated[1] = mutated[1].wrapping_add(1);
    }
    mutated
}

fuzz_target!(|data: &[u8]| {
    const QUADRUPLE_SIZE: usize = 32 + 20 + 32 + 20; // 104 bytes
    if data.len() < QUADRUPLE_SIZE {
        return;
    }

    let env = Env::default();
    env.mock_all_auths();

    let indexer_id = env.register_contract(None, Indexer);
    let client = IndexerClient::new(&env, &indexer_id);
    let admin = Address::generate(&env);
    let sas = env.register_contract(None, MockSas);

    client.init(&admin, &sas);

    let max_quads = 8;
    let mut inserted_uids = std::collections::HashSet::new();
    let mut successful_quads = Vec::new();

    for chunk in data.chunks_exact(QUADRUPLE_SIZE).take(max_quads) {
        let uid_bytes: [u8; 32] = chunk[0..32].try_into().unwrap();
        let recip_bytes: [u8; 20] = chunk[32..52].try_into().unwrap();
        let schema_bytes: [u8; 32] = chunk[52..84].try_into().unwrap();
        let attester_bytes: [u8; 20] = chunk[84..104].try_into().unwrap();

        let uid = UID(BytesN::from_array(&env, &uid_bytes));
        let schema_uid = UID(BytesN::from_array(&env, &schema_bytes));
        let recipient = bytes20_to_address(&env, &recip_bytes);
        let attester = bytes20_to_address(&env, &attester_bytes);

        let is_first_call = !inserted_uids.contains(&uid_bytes);

        // Path 1: First call (no prior record for this UID)
        let first_res = env.as_contract(&sas, || {
            client.try_index_attestation(&uid, &recipient, &schema_uid, &attester)
        });

        if is_first_call {
            assert_eq!(first_res, Ok(Ok(())), "first call must succeed");
            inserted_uids.insert(uid_bytes);
            successful_quads.push((
                uid.clone(),
                recipient.clone(),
                schema_uid.clone(),
                attester.clone(),
            ));
        }

        // Path 2: Idempotent retry (same triple for same UID must succeed as Ok(()))
        let retry_res = env.as_contract(&sas, || {
            client.try_index_attestation(&uid, &recipient, &schema_uid, &attester)
        });
        assert_eq!(
            retry_res,
            Ok(Ok(())),
            "idempotent retry with same triple must succeed as no-op"
        );

        // Path 3: Mutated triple (different triple for existing UID must fail with DuplicateAttestation)
        // 3a: Different recipient
        let diff_recip_bytes = mutate_bytes20(&recip_bytes);
        let diff_recipient = bytes20_to_address(&env, &diff_recip_bytes);
        let diff_recip_res = env.as_contract(&sas, || {
            client.try_index_attestation(&uid, &diff_recipient, &schema_uid, &attester)
        });
        assert_eq!(
            diff_recip_res,
            Err(Ok(SASError::DuplicateAttestation.into())),
            "re-indexing same UID with different recipient must fail with DuplicateAttestation"
        );

        // 3b: Different schema_uid
        let diff_schema_bytes = mutate_bytes32(&schema_bytes);
        let diff_schema_uid = UID(BytesN::from_array(&env, &diff_schema_bytes));
        let diff_schema_res = env.as_contract(&sas, || {
            client.try_index_attestation(&uid, &recipient, &diff_schema_uid, &attester)
        });
        assert_eq!(
            diff_schema_res,
            Err(Ok(SASError::DuplicateAttestation.into())),
            "re-indexing same UID with different schema_uid must fail with DuplicateAttestation"
        );

        // 3c: Different attester
        let diff_attester_bytes = mutate_bytes20(&attester_bytes);
        let diff_attester = bytes20_to_address(&env, &diff_attester_bytes);
        let diff_attester_res = env.as_contract(&sas, || {
            client.try_index_attestation(&uid, &recipient, &schema_uid, &diff_attester)
        });
        assert_eq!(
            diff_attester_res,
            Err(Ok(SASError::DuplicateAttestation.into())),
            "re-indexing same UID with different attester must fail with DuplicateAttestation"
        );
    }

    // Invariant check: Assert that after all insertions, the UID appears at most once
    // in every chunk for every key dimension
    for (uid, recipient, schema_uid, attester) in successful_quads {
        let recipient_uids = client.get_attestations_by_recipient(&recipient);
        let recipient_count = recipient_uids.iter().filter(|u| *u == &uid).count();
        assert_eq!(
            recipient_count, 1,
            "UID must appear at most once in recipient index"
        );

        let schema_uids = client.get_attestations_by_schema(&schema_uid);
        let schema_count = schema_uids.iter().filter(|u| *u == &uid).count();
        assert_eq!(
            schema_count, 1,
            "UID must appear at most once in schema index"
        );

        let attester_uids = client.get_attestations_by_attester(&attester);
        let attester_count = attester_uids.iter().filter(|u| *u == &uid).count();
        assert_eq!(
            attester_count, 1,
            "UID must appear at most once in attester index"
        );
    }
});
