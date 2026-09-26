use soroban_sas_common::{
    events::{ATTESTED, BATCH_ATTESTED, BATCH_REVOKED, INDEXER_UPDATED, REVOKED},
    Attestation, AttestationIssuedEvent, AttestationRevokedEvent, BatchAttestedEvent,
    BatchRevokedEvent, IndexerUpdatedEvent, UID,
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
            old_indexer: old_indexer.into(),
            new_indexer,
            authorizer,
        },
    );
}

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

/// Publishes the `BatchAttested` summary event marking the end of a
/// successful `multi_attest` call. Must be called only after every per-item
/// `AttestationIssued` event for the batch has already been published, and
/// only on the batch's success path — never on a reverted call (#213).
///
/// Topics: `(BATCH_ATTESTED,)`.
pub fn publish_batch_attested(env: &Env, count: u32, attester_count: u32) {
    env.events().publish(
        (BATCH_ATTESTED,),
        BatchAttestedEvent {
            count,
            attester_count,
        },
    );
}

/// Publishes the `BatchRevoked` summary event marking the end of a
/// successful `multi_revoke` call, after every per-item `AttestationRevoked`
/// event for the batch. See `publish_batch_attested` for the shared
/// ordering/failure-path guarantees.
///
/// Topics: `(BATCH_REVOKED,)`.
pub fn publish_batch_revoked(env: &Env, count: u32, attester_count: u32) {
    env.events().publish(
        (BATCH_REVOKED,),
        BatchRevokedEvent {
            count,
            attester_count,
        },
    );
}

pub fn publish_withdrawal(
    env: &Env,
    token: &Address,
    amount: i128,
    destination: &Address,
    authorizer: &Address,
) {
    env.events().publish(
        (symbol_short!("WITHDRAW"), token.clone(), authorizer.clone()),
        (
            amount,
            destination.clone(),
            token.clone(),
            authorizer.clone(),
        ),
    );
}

/// Publishes the fee change immediately after its storage mutation.
pub fn publish_fee_config_updated(
    env: &Env,
    old: Option<(Address, i128)>,
    new: Option<(Address, i128)>,
    authorizer: Address,
) {
    use soroban_sas_common::{FeeConfigUpdatedEvent, FEECFG_UPDATED};
    env.events().publish(
        (FEECFG_UPDATED, authorizer.clone()),
        FeeConfigUpdatedEvent {
            old_token: old.as_ref().map(|(token, _)| token.clone()).into(),
            old_amount: old.map(|(_, amount)| amount),
            new_token: new.as_ref().map(|(token, _)| token.clone()).into(),
            new_amount: new.map(|(_, amount)| amount),
            authorizer,
        },
    );
}
