use soroban_sas_common::{
    events::{ATTESTED, INDEXER_UPDATED, REVOKED},
    Attestation, AttestationIssuedEvent, AttestationRevokedEvent, IndexerUpdatedEvent, UID,
};
use soroban_sdk::{Address, Env};
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

/// Publishes the `IndexerUpdated` event.
///
/// Topics: `(INDEXER_UPDATED, authorizer)`. Called only after
/// `set_indexer` has already written the new binding to instance storage,
/// so a failed or unauthorized call never emits this event.
pub fn publish_indexer_updated(
    env: &Env,
    old_indexer: Option<Address>,
    new_indexer: Address,
    authorizer: Address,
) {
    env.events().publish(
        (INDEXER_UPDATED, authorizer.clone()),
        IndexerUpdatedEvent {
            old_indexer,
            new_indexer,
            authorizer,
        },
/// Publishes `IndexFailed` when a bound Indexer could not be notified of a
/// newly issued attestation under the fail-open policy (#161).
///
/// Topic: `(IDXFAIL, uid)`. The data payload repeats `uid` so consumers that
/// only read data still get it.
pub fn publish_index_failed(env: &Env, uid: &UID) {
    env.events()
        .publish((symbol_short!("IDXFAIL"), uid.clone()), uid.clone());
}

/// Publishes `Reindexed` after `reindex_attestation` replays a
/// previously-missed attestation to the Indexer (#161).
///
/// Topic: `(REINDEX, uid)`.
pub fn publish_reindexed(env: &Env, uid: &UID) {
    env.events()
        .publish((symbol_short!("REINDEX"), uid.clone()), uid.clone());
}

pub fn publish_withdrawal(env: &Env, token: &Address, amount: i128, destination: &Address, authorizer: &Address) {
    env.events().publish(
        (symbol_short!("WITHDRAW"), token.clone(), authorizer.clone()),
        (amount, destination.clone(), token.clone(), authorizer.clone()),
    );
}
