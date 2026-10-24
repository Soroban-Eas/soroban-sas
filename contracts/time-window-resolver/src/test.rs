use super::*;
use soroban_sas_common::UID;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::{Address, Bytes, BytesN, Env, IntoVal};

const COOLDOWN: u64 = 86_400;

fn deploy(env: &Env, cooldown_period_seconds: u64) -> (TimeWindowResolverClient<'static>, Address) {
    env.mock_all_auths();
    let admin = Address::generate(env);
    let contract_id = env.register_contract(None, TimeWindowResolver);
    let client = TimeWindowResolverClient::new(env, &contract_id);
    client.init(&admin, &cooldown_period_seconds);
    (client, admin)
}

fn attestation_to(env: &Env, recipient: &Address) -> Attestation {
    Attestation {
        uid: UID(BytesN::from_array(env, &[1u8; 32])),
        schema_uid: UID(BytesN::from_array(env, &[2u8; 32])),
        time: 0,
        expiration_time: 0,
        valid_from: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
        recipient: recipient.clone(),
        attester: Address::generate(env),
        revocable: true,
        data: Bytes::new(env),
    }
}

fn set_time(env: &Env, timestamp: u64) {
    env.ledger().with_mut(|li| li.timestamp = timestamp);
}

fn cooldown_active_error() -> soroban_sdk::Error {
    SASError::CooldownActive.into()
}

#[test]
fn init_stores_config_and_rejects_reinitialization() {
    let env = Env::default();
    let (client, admin) = deploy(&env, COOLDOWN);

    assert_eq!(
        client.get_config(),
        TimeWindowConfig {
            admin: admin.clone(),
            cooldown_period_seconds: COOLDOWN,
        }
    );
    assert_eq!(client.get_admin(), admin);
    assert_eq!(client.get_cooldown_period_seconds(), COOLDOWN);

    let other = Address::generate(&env);
    assert_eq!(
        client.try_init(&other, &1),
        Err(Ok(SASError::AlreadyInitialized.into()))
    );
    // The failed re-init left the original configuration untouched.
    assert_eq!(client.get_cooldown_period_seconds(), COOLDOWN);
}

#[test]
fn init_requires_admin_authorization() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, TimeWindowResolver);
    let client = TimeWindowResolverClient::new(&env, &contract_id);

    env.set_auths(&[]);
    assert!(client.try_init(&admin, &COOLDOWN).is_err());
    assert!(client.try_get_config().is_err());
}

#[test]
fn first_attestation_succeeds_and_records_timestamp() {
    let env = Env::default();
    let (client, _admin) = deploy(&env, COOLDOWN);
    let recipient = Address::generate(&env);

    set_time(&env, 1_000);
    assert_eq!(client.get_last_attested_time(&recipient), None);
    client.on_attest(&attestation_to(&env, &recipient));
    assert_eq!(client.get_last_attested_time(&recipient), Some(1_000));
}

#[test]
fn issuance_inside_cooldown_reverts_with_cooldown_active() {
    let env = Env::default();
    let (client, _admin) = deploy(&env, COOLDOWN);
    let recipient = Address::generate(&env);

    set_time(&env, 1_000);
    client.on_attest(&attestation_to(&env, &recipient));

    // One second before the window expires.
    set_time(&env, 1_000 + COOLDOWN - 1);
    assert_eq!(
        client.try_on_attest(&attestation_to(&env, &recipient)),
        Err(Ok(cooldown_active_error()))
    );
    // The rejected attempt did not move the recorded time.
    assert_eq!(client.get_last_attested_time(&recipient), Some(1_000));
}

#[test]
fn issuance_at_exact_cooldown_boundary_succeeds() {
    let env = Env::default();
    let (client, _admin) = deploy(&env, COOLDOWN);
    let recipient = Address::generate(&env);

    set_time(&env, 1_000);
    client.on_attest(&attestation_to(&env, &recipient));

    set_time(&env, 1_000 + COOLDOWN);
    client.on_attest(&attestation_to(&env, &recipient));
    assert_eq!(
        client.get_last_attested_time(&recipient),
        Some(1_000 + COOLDOWN)
    );
}

#[test]
fn issuance_after_cooldown_expires_succeeds() {
    let env = Env::default();
    let (client, _admin) = deploy(&env, COOLDOWN);
    let recipient = Address::generate(&env);

    set_time(&env, 1_000);
    client.on_attest(&attestation_to(&env, &recipient));

    set_time(&env, 1_000 + COOLDOWN + 1);
    client.on_attest(&attestation_to(&env, &recipient));
    assert_eq!(
        client.get_last_attested_time(&recipient),
        Some(1_000 + COOLDOWN + 1)
    );
}

#[test]
fn cooldown_is_tracked_independently_per_recipient() {
    let env = Env::default();
    let (client, _admin) = deploy(&env, COOLDOWN);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);

    set_time(&env, 1_000);
    client.on_attest(&attestation_to(&env, &alice));
    set_time(&env, 2_000);
    client.on_attest(&attestation_to(&env, &bob));
    assert_eq!(client.get_last_attested_time(&alice), Some(1_000));
    assert_eq!(client.get_last_attested_time(&bob), Some(2_000));

    set_time(&env, 1_001);
    assert_eq!(
        client.try_on_attest(&attestation_to(&env, &alice)),
        Err(Ok(cooldown_active_error()))
    );

    // Alice re-attests exactly at her boundary. Bob's window started later,
    // so it is untouched and still active.
    set_time(&env, 1_000 + COOLDOWN);
    client.on_attest(&attestation_to(&env, &alice));
    assert_eq!(
        client.get_last_attested_time(&alice),
        Some(1_000 + COOLDOWN)
    );
    assert_eq!(
        client.try_on_attest(&attestation_to(&env, &bob)),
        Err(Ok(cooldown_active_error()))
    );
    assert_eq!(client.get_last_attested_time(&bob), Some(2_000));

    // Bob becomes eligible on his own schedule, independent of Alice.
    set_time(&env, 2_000 + COOLDOWN);
    client.on_attest(&attestation_to(&env, &bob));
    assert_eq!(client.get_last_attested_time(&bob), Some(2_000 + COOLDOWN));
}

#[test]
fn zero_cooldown_disables_the_restriction_but_still_records_time() {
    let env = Env::default();
    let (client, _admin) = deploy(&env, 0);
    let recipient = Address::generate(&env);

    set_time(&env, 1_000);
    client.on_attest(&attestation_to(&env, &recipient));
    // Same ledger timestamp: a zero window has nothing to wait for.
    client.on_attest(&attestation_to(&env, &recipient));
    assert_eq!(client.get_last_attested_time(&recipient), Some(1_000));

    set_time(&env, 1_500);
    client.on_attest(&attestation_to(&env, &recipient));
    assert_eq!(client.get_last_attested_time(&recipient), Some(1_500));
}

#[test]
fn recorded_time_comes_from_the_ledger_not_the_attestation_payload() {
    let env = Env::default();
    let (client, _admin) = deploy(&env, COOLDOWN);
    let recipient = Address::generate(&env);

    set_time(&env, 1_000);
    let mut attestation = attestation_to(&env, &recipient);
    // SAS normalizes `Attestation::time` only after the resolver callback, so
    // a value supplied here must not be trusted as the issuance time.
    attestation.time = 500_000;
    client.on_attest(&attestation);
    assert_eq!(client.get_last_attested_time(&recipient), Some(1_000));
}

#[test]
fn set_cooldown_requires_authorization_from_the_admin() {
    let env = Env::default();
    let (client, admin) = deploy(&env, COOLDOWN);
    let stranger = Address::generate(&env);

    assert_eq!(
        client.try_set_cooldown_period_seconds(&stranger, &1),
        Err(Ok(SASError::Unauthorized.into()))
    );
    assert_eq!(client.get_cooldown_period_seconds(), COOLDOWN);

    // The admin's own call must still carry a matching authorization.
    env.set_auths(&[]);
    assert!(client.try_set_cooldown_period_seconds(&admin, &1).is_err());
    assert_eq!(client.get_cooldown_period_seconds(), COOLDOWN);
}

#[test]
fn admin_can_update_cooldown_and_event_announces_the_change() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, TimeWindowResolver);
    let client = TimeWindowResolverClient::new(&env, &contract_id);
    client.init(&admin, &COOLDOWN);

    client.set_cooldown_period_seconds(&admin, &60);
    assert_eq!(client.get_cooldown_period_seconds(), 60);

    let all = env.events().all();
    assert_eq!(
        all.slice(all.len() - 1..),
        soroban_sdk::vec![
            &env,
            (
                contract_id,
                (COOLDOWN_UPDATED, admin.clone()).into_val(&env),
                CooldownUpdatedEvent {
                    old_cooldown_period_seconds: COOLDOWN,
                    new_cooldown_period_seconds: 60,
                    authorizer: admin,
                }
                .into_val(&env),
            )
        ]
    );
}

#[test]
fn shortening_cooldown_applies_to_a_window_already_in_progress() {
    let env = Env::default();
    let (client, admin) = deploy(&env, COOLDOWN);
    let recipient = Address::generate(&env);

    set_time(&env, 1_000);
    client.on_attest(&attestation_to(&env, &recipient));

    // The old window would still be active here; the new one has elapsed.
    set_time(&env, 1_000 + 10);
    client.set_cooldown_period_seconds(&admin, &10);
    client.on_attest(&attestation_to(&env, &recipient));
    assert_eq!(client.get_last_attested_time(&recipient), Some(1_010));
}

#[test]
fn lengthening_cooldown_extends_a_window_already_in_progress() {
    let env = Env::default();
    let (client, admin) = deploy(&env, 10);
    let recipient = Address::generate(&env);

    set_time(&env, 1_000);
    client.on_attest(&attestation_to(&env, &recipient));

    // Under the old window this timestamp was eligible; the admin's change
    // retroactively keeps the same recipient in cooldown.
    set_time(&env, 1_010);
    client.set_cooldown_period_seconds(&admin, &100);
    assert_eq!(
        client.try_on_attest(&attestation_to(&env, &recipient)),
        Err(Ok(cooldown_active_error()))
    );
    assert_eq!(client.get_last_attested_time(&recipient), Some(1_000));

    set_time(&env, 1_100);
    client.on_attest(&attestation_to(&env, &recipient));
    assert_eq!(client.get_last_attested_time(&recipient), Some(1_100));
}

#[test]
fn extreme_cooldown_saturates_instead_of_wrapping() {
    let env = Env::default();
    let (client, _admin) = deploy(&env, u64::MAX);
    let recipient = Address::generate(&env);

    set_time(&env, 1);
    client.on_attest(&attestation_to(&env, &recipient));

    // `1 + u64::MAX` must not wrap to `0`, which would read as an expired
    // window and let the second attestation through.
    set_time(&env, u64::MAX - 1);
    assert_eq!(
        client.try_on_attest(&attestation_to(&env, &recipient)),
        Err(Ok(cooldown_active_error()))
    );
    assert_eq!(client.get_last_attested_time(&recipient), Some(1));
}

#[test]
fn revocation_is_accepted_and_does_not_reset_the_cooldown() {
    let env = Env::default();
    let (client, _admin) = deploy(&env, COOLDOWN);
    let recipient = Address::generate(&env);

    set_time(&env, 1_000);
    let attestation = attestation_to(&env, &recipient);
    client.on_attest(&attestation);

    // Revoking must never trap (SAS treats any resolver failure as an
    // authoritative rejection of the revocation) ...
    client.on_revoke(&attestation);
    // ... and must not hand the recipient a fresh issuance window.
    assert_eq!(client.get_last_attested_time(&recipient), Some(1_000));
    set_time(&env, 1_001);
    assert_eq!(
        client.try_on_attest(&attestation_to(&env, &recipient)),
        Err(Ok(cooldown_active_error()))
    );
}

#[test]
fn on_attest_before_init_reports_not_initialized() {
    let env = Env::default();
    let contract_id = env.register_contract(None, TimeWindowResolver);
    let client = TimeWindowResolverClient::new(&env, &contract_id);
    let recipient = Address::generate(&env);

    assert_eq!(
        client.try_on_attest(&attestation_to(&env, &recipient)),
        Err(Ok(SASError::NotInitialized.into()))
    );
    assert_eq!(client.get_last_attested_time(&recipient), None);
}
