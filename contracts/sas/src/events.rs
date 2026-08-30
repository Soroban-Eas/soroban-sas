use soroban_sas_common::{
    events::{ATTESTED, REVOKED},
    Attestation, AttestationIssuedEvent, AttestationRevokedEvent, UID,
};
use soroban_sdk::{symbol_short, Address, Env};

/// Publishes the `AttestationIssued` event.
///
/// Topics: `(ATTESTED, schema_uid, attester)`.
pub fn publish_attested(env: &Env, attestation: &Attestation) {
    let event = AttestationIssuedEvent {
        uid: attestation.uid.clone(),
        schema_uid: attestation.schema_uid.clone(),
        attester: attestation.attester.clone(),
        recipient: attestation.recipient.clone(),
    };
    env.events().publish(
        (
            ATTESTED,
            attestation.schema_uid.clone(),
            attestation.attester.clone(),
        ),
        event,
    );
}

/// Publishes the `AttestationRevoked` event.
///
/// Topics: `(REVOKED, uid)`. `timestamp` must match the revocation time
/// written to storage so off-chain indexers never diverge from state.
pub fn publish_revoked(env: &Env, uid: &UID, timestamp: u64) {
    env.events().publish(
        (REVOKED, uid.clone()),
        AttestationRevokedEvent {
            uid: uid.clone(),
            timestamp,
        },
    );
}

pub fn publish_withdrawal(env: &Env, token: &Address, amount: i128, destination: &Address, authorizer: &Address) {
    env.events().publish(
        (symbol_short!("WITHDRAW"), token.clone(), authorizer.clone()),
        (amount, destination.clone(), token.clone(), authorizer.clone()),
    );
}
