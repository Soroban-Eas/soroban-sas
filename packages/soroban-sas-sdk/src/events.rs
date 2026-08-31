//! Utilities for parsing SAS contract events out of Soroban RPC responses.
//!
//! Soroban RPC (`getEvents`, transaction metas) returns contract events as
//! XDR: a list of `ScVal` topics plus an `ScVal` data payload. The helpers
//! here decode the standardized SAS events — `SchemaRegistered`,
//! `AttestationIssued` and `AttestationRevoked` — into plain Rust types that
//! off-chain indexers can consume directly.

use soroban_sdk::xdr::{ContractEvent, ContractEventBody, ScAddress, ScMap, ScVal};

/// A contract's 32-byte identifier, as carried on `ContractEvent::contract_id`.
pub type ContractId = [u8; 32];

/// First topic of a `SchemaRegistered` event.
pub const TOPIC_SCHEMA_REGISTERED: &[u8] = b"REGISTER";
/// First topic of an `AttestationIssued` event.
pub const TOPIC_ATTESTATION_ISSUED: &[u8] = b"ATTESTED";
/// First topic of an `AttestationRevoked` event.
pub const TOPIC_ATTESTATION_REVOKED: &[u8] = b"REVOKED";

/// Decoded `SchemaRegistered` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaRegistered {
    pub schema_uid: [u8; 32],
    pub owner: ScAddress,
}

/// Decoded `AttestationIssued` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationIssued {
    pub uid: [u8; 32],
    pub schema_uid: [u8; 32],
    pub attester: ScAddress,
    pub recipient: ScAddress,
}

/// Decoded `AttestationRevoked` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttestationRevoked {
    pub uid: [u8; 32],
    pub timestamp: u64,
}

/// Any standardized event emitted by the SAS contracts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SasEvent {
    SchemaRegistered(SchemaRegistered),
    AttestationIssued(AttestationIssued),
    AttestationRevoked(AttestationRevoked),
}

/// Why an event could not be decoded as a SAS event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventParseError {
    /// The event's first topic is not one of the SAS topics.
    NotSasEvent,
    /// The topic list is empty.
    MissingTopic,
    /// The topic matched but the payload does not have the expected shape.
    MalformedPayload(&'static str),
}

/// Parses a full `ContractEvent` (as found in transaction metas or
/// `getEvents` responses) into a [`SasEvent`].
pub fn parse_contract_event(event: &ContractEvent) -> Result<SasEvent, EventParseError> {
    let ContractEventBody::V0(body) = &event.body;
    parse_event(body.topics.as_slice(), &body.data)
}

/// Parses decoded event `topics` and `data` into a [`SasEvent`].
pub fn parse_event(topics: &[ScVal], data: &ScVal) -> Result<SasEvent, EventParseError> {
    let first = topics.first().ok_or(EventParseError::MissingTopic)?;
    let name = match first {
        ScVal::Symbol(sym) => sym.0.as_slice(),
        _ => return Err(EventParseError::NotSasEvent),
    };
    match name {
        n if n == TOPIC_SCHEMA_REGISTERED => {
            let map = expect_map(data)?;
            Ok(SasEvent::SchemaRegistered(SchemaRegistered {
                schema_uid: decode_uid(map_get(map, b"schema_uid")?)?,
                owner: decode_address(map_get(map, b"owner")?)?,
            }))
        }
        n if n == TOPIC_ATTESTATION_ISSUED => {
            let map = expect_map(data)?;
            Ok(SasEvent::AttestationIssued(AttestationIssued {
                uid: decode_uid(map_get(map, b"uid")?)?,
                schema_uid: decode_uid(map_get(map, b"schema_uid")?)?,
                attester: decode_address(map_get(map, b"attester")?)?,
                recipient: decode_address(map_get(map, b"recipient")?)?,
            }))
        }
        n if n == TOPIC_ATTESTATION_REVOKED => {
            let map = expect_map(data)?;
            let timestamp = match map_get(map, b"timestamp")? {
                ScVal::U64(ts) => *ts,
                _ => return Err(EventParseError::MalformedPayload("timestamp is not a u64")),
            };
            Ok(SasEvent::AttestationRevoked(AttestationRevoked {
                uid: decode_uid(map_get(map, b"uid")?)?,
                timestamp,
            }))
        }
        _ => Err(EventParseError::NotSasEvent),
    }
}

/// Parses every SAS event from a batch of contract events, silently skipping
/// events emitted by other contracts or with unknown topics.
///
/// This does **not** check the emitting contract ID. Downstream code that
/// treats parsed events as genuine protocol state should use
/// [`parse_events_verified`] / [`parse_trusted_events`] with a
/// [`TrustedContracts`] allowlist instead — any contract can emit
/// SAS-shaped events (#169).
pub fn parse_events(events: &[ContractEvent]) -> Vec<SasEvent> {
    events
        .iter()
        .filter_map(|event| parse_contract_event(event).ok())
        .collect()
}

/// Allowlist of the contract IDs each SAS protocol role is expected to emit
/// events from. An unset role means "no trusted source known", so every event
/// bound to that role is reported [`EventTrust::Untrusted`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustedContracts {
    /// The SAS core contract — emits `AttestationIssued` and
    /// `AttestationRevoked`.
    pub sas: Option<ContractId>,
    /// The Schema Registry contract — emits `SchemaRegistered`.
    pub schema_registry: Option<ContractId>,
    /// The Indexer contract. Reserved: the Indexer emits no standardized SAS
    /// event today, but callers can still record its ID in the allowlist.
    pub indexer: Option<ContractId>,
}

impl TrustedContracts {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_sas(mut self, id: ContractId) -> Self {
        self.sas = Some(id);
        self
    }
    pub fn with_schema_registry(mut self, id: ContractId) -> Self {
        self.schema_registry = Some(id);
        self
    }
    pub fn with_indexer(mut self, id: ContractId) -> Self {
        self.indexer = Some(id);
        self
    }

    /// The `(role_name, expected_contract_id)` an event of this kind must come
    /// from.
    fn expected_source(&self, event: &SasEvent) -> (&'static str, Option<ContractId>) {
        match event {
            SasEvent::SchemaRegistered(_) => ("schema_registry", self.schema_registry),
            SasEvent::AttestationIssued(_) | SasEvent::AttestationRevoked(_) => ("sas", self.sas),
        }
    }
}

/// Whether a decoded event actually came from the contract bound to its
/// protocol role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventTrust {
    /// The emitting contract ID matches the allowlisted ID for this event's
    /// role.
    Trusted,
    /// The topics/payload decoded as a SAS event, but the emitting contract is
    /// not the one bound to `expected_role` (or no ID was recorded for that
    /// role, or the event carried no contract ID).
    Untrusted {
        expected_role: &'static str,
        contract_id: Option<ContractId>,
    },
}

/// A decoded SAS event paired with its source-verification result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedSasEvent {
    pub event: SasEvent,
    pub trust: EventTrust,
}

/// Like [`parse_contract_event`], but also verifies the emitting contract ID
/// against `trusted`. The event is still decoded, but a mismatch is reported
/// as [`EventTrust::Untrusted`] rather than silently accepted, so a spoofed
/// event can never be mistaken for a genuine attestation or schema change
/// (#169).
pub fn parse_contract_event_verified(
    event: &ContractEvent,
    trusted: &TrustedContracts,
) -> Result<VerifiedSasEvent, EventParseError> {
    let ContractEventBody::V0(body) = &event.body;
    let parsed = parse_event(body.topics.as_slice(), &body.data)?;
    let source: Option<ContractId> = event.contract_id.as_ref().map(|h| h.0);
    let (role, expected) = trusted.expected_source(&parsed);
    let trust = match (expected, source) {
        (Some(want), Some(got)) if want == got => EventTrust::Trusted,
        _ => EventTrust::Untrusted {
            expected_role: role,
            contract_id: source,
        },
    };
    Ok(VerifiedSasEvent {
        event: parsed,
        trust,
    })
}

/// Batch variant of [`parse_contract_event_verified`]. Every returned element
/// carries its own [`EventTrust`], so trusted and spoofed events in the same
/// batch cannot be silently mixed — the caller sees the tag on each one.
pub fn parse_events_verified(
    events: &[ContractEvent],
    trusted: &TrustedContracts,
) -> Vec<VerifiedSasEvent> {
    events
        .iter()
        .filter_map(|event| parse_contract_event_verified(event, trusted).ok())
        .collect()
}

/// Convenience over [`parse_events_verified`]: only the events proven to come
/// from an allowlisted source.
pub fn parse_trusted_events(
    events: &[ContractEvent],
    trusted: &TrustedContracts,
) -> Vec<SasEvent> {
    parse_events_verified(events, trusted)
        .into_iter()
        .filter(|v| v.trust == EventTrust::Trusted)
        .map(|v| v.event)
        .collect()
}

fn expect_map(data: &ScVal) -> Result<&ScMap, EventParseError> {
    match data {
        ScVal::Map(Some(map)) => Ok(map),
        _ => Err(EventParseError::MalformedPayload("payload is not a map")),
    }
}

fn map_get<'a>(map: &'a ScMap, key: &[u8]) -> Result<&'a ScVal, EventParseError> {
    map.0
        .iter()
        .find(|entry| matches!(&entry.key, ScVal::Symbol(sym) if sym.0.as_slice() == key))
        .map(|entry| &entry.val)
        .ok_or(EventParseError::MalformedPayload("missing payload field"))
}

/// A `UID` newtype serializes as a single-element `ScVec` wrapping the
/// 32-byte value.
fn decode_uid(val: &ScVal) -> Result<[u8; 32], EventParseError> {
    let inner = match val {
        ScVal::Vec(Some(vec)) if vec.len() == 1 => &vec.as_slice()[0],
        other => other,
    };
    match inner {
        ScVal::Bytes(bytes) => bytes
            .as_slice()
            .try_into()
            .map_err(|_| EventParseError::MalformedPayload("uid is not 32 bytes")),
        _ => Err(EventParseError::MalformedPayload(
            "uid is not a bytes value",
        )),
    }
}

fn decode_address(val: &ScVal) -> Result<ScAddress, EventParseError> {
    match val {
        ScVal::Address(address) => Ok(address.clone()),
        _ => Err(EventParseError::MalformedPayload("field is not an address")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sas_common::{
        AttestationIssuedEvent, AttestationRevokedEvent, SchemaRegisteredEvent, UID,
    };
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, BytesN, Env, IntoVal, TryFromVal, Val};

    fn to_scval(env: &Env, val: Val) -> ScVal {
        ScVal::try_from_val(env, &val).unwrap()
    }

    fn to_scaddress(env: &Env, address: &Address) -> ScAddress {
        match to_scval(env, address.to_val()) {
            ScVal::Address(sc) => sc,
            other => panic!("expected address, got {:?}", other),
        }
    }

    #[test]
    fn parses_schema_registered() {
        let env = Env::default();
        let owner = Address::generate(&env);
        let schema_uid = UID(BytesN::from_array(&env, &[7u8; 32]));

        let payload = SchemaRegisteredEvent {
            schema_uid: schema_uid.clone(),
            owner: owner.clone(),
        };
        let topics = [
            to_scval(&env, soroban_sas_common::events::REGISTERED.into_val(&env)),
            to_scval(&env, schema_uid.into_val(&env)),
        ];
        let data = to_scval(&env, payload.into_val(&env));

        let parsed = parse_event(&topics, &data).unwrap();
        assert_eq!(
            parsed,
            SasEvent::SchemaRegistered(SchemaRegistered {
                schema_uid: [7u8; 32],
                owner: to_scaddress(&env, &owner),
            })
        );
    }

    #[test]
    fn parses_attestation_issued() {
        let env = Env::default();
        let attester = Address::generate(&env);
        let recipient = Address::generate(&env);
        let uid = UID(BytesN::from_array(&env, &[1u8; 32]));
        let schema_uid = UID(BytesN::from_array(&env, &[2u8; 32]));

        let payload = AttestationIssuedEvent {
            uid: uid.clone(),
            schema_uid: schema_uid.clone(),
            attester: attester.clone(),
            recipient: recipient.clone(),
        };
        let topics = [
            to_scval(&env, soroban_sas_common::events::ATTESTED.into_val(&env)),
            to_scval(&env, schema_uid.into_val(&env)),
            to_scval(&env, attester.to_val()),
        ];
        let data = to_scval(&env, payload.into_val(&env));

        let parsed = parse_event(&topics, &data).unwrap();
        assert_eq!(
            parsed,
            SasEvent::AttestationIssued(AttestationIssued {
                uid: [1u8; 32],
                schema_uid: [2u8; 32],
                attester: to_scaddress(&env, &attester),
                recipient: to_scaddress(&env, &recipient),
            })
        );
    }

    #[test]
    fn parses_attestation_revoked() {
        let env = Env::default();
        let uid = UID(BytesN::from_array(&env, &[3u8; 32]));

        let payload = AttestationRevokedEvent {
            uid: uid.clone(),
            timestamp: 4242,
        };
        let topics = [
            to_scval(&env, soroban_sas_common::events::REVOKED.into_val(&env)),
            to_scval(&env, uid.into_val(&env)),
        ];
        let data = to_scval(&env, payload.into_val(&env));

        let parsed = parse_event(&topics, &data).unwrap();
        assert_eq!(
            parsed,
            SasEvent::AttestationRevoked(AttestationRevoked {
                uid: [3u8; 32],
                timestamp: 4242,
            })
        );
    }

    fn contract_event(
        contract_id: [u8; 32],
        topics: Vec<ScVal>,
        data: ScVal,
    ) -> ContractEvent {
        use soroban_sdk::xdr::{
            ContractEventType, ContractEventV0, ExtensionPoint, Hash,
        };
        ContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: Some(Hash(contract_id)),
            type_: ContractEventType::Contract,
            body: ContractEventBody::V0(ContractEventV0 {
                topics: topics.try_into().unwrap(),
                data,
            }),
        }
    }

    fn revoked_event(env: &Env, seed: u8) -> (Vec<ScVal>, ScVal) {
        let uid = UID(BytesN::from_array(env, &[seed; 32]));
        let payload = AttestationRevokedEvent {
            uid: uid.clone(),
            timestamp: 7,
        };
        (
            vec![
                to_scval(env, soroban_sas_common::events::REVOKED.into_val(env)),
                to_scval(env, uid.into_val(env)),
            ],
            to_scval(env, payload.into_val(env)),
        )
    }

    #[test]
    fn verified_parse_accepts_events_from_the_trusted_sas_contract() {
        let env = Env::default();
        let (topics, data) = revoked_event(&env, 1);
        let sas_id = [9u8; 32];
        let trusted = TrustedContracts::new().with_sas(sas_id);

        let verified =
            parse_contract_event_verified(&contract_event(sas_id, topics, data), &trusted).unwrap();
        assert_eq!(verified.trust, EventTrust::Trusted);
        assert!(matches!(verified.event, SasEvent::AttestationRevoked(_)));
    }

    #[test]
    fn verified_parse_flags_the_same_payload_from_an_attacker_contract() {
        let env = Env::default();
        let trusted = TrustedContracts::new().with_sas([9u8; 32]);

        let (t1, d1) = revoked_event(&env, 2);
        let honest = parse_contract_event_verified(&contract_event([9u8; 32], t1, d1), &trusted)
            .unwrap();
        let (t2, d2) = revoked_event(&env, 2);
        let spoofed = parse_contract_event_verified(&contract_event([0xAAu8; 32], t2, d2), &trusted)
            .unwrap();

        assert_eq!(honest.event, spoofed.event);
        assert_eq!(honest.trust, EventTrust::Trusted);
        assert_eq!(
            spoofed.trust,
            EventTrust::Untrusted {
                expected_role: "sas",
                contract_id: Some([0xAAu8; 32]),
            }
        );
    }

    #[test]
    fn batch_parse_tags_each_event_and_trusted_filter_drops_spoofed() {
        let env = Env::default();
        let trusted = TrustedContracts::new().with_sas([9u8; 32]);
        let (t1, d1) = revoked_event(&env, 3);
        let (t2, d2) = revoked_event(&env, 4);
        let events = [
            contract_event([9u8; 32], t1, d1),
            contract_event([1u8; 32], t2, d2),
        ];

        let verified = parse_events_verified(&events, &trusted);
        assert_eq!(verified.len(), 2);
        assert_eq!(verified[0].trust, EventTrust::Trusted);
        assert!(matches!(verified[1].trust, EventTrust::Untrusted { .. }));

        let trusted_only = parse_trusted_events(&events, &trusted);
        assert_eq!(trusted_only.len(), 1);
    }

    #[test]
    fn rejects_unknown_and_malformed_events() {
        let env = Env::default();

        assert_eq!(
            parse_event(&[], &ScVal::Void),
            Err(EventParseError::MissingTopic)
        );

        let unknown_topic = [to_scval(
            &env,
            soroban_sdk::symbol_short!("TRANSFER").into_val(&env),
        )];
        assert_eq!(
            parse_event(&unknown_topic, &ScVal::Void),
            Err(EventParseError::NotSasEvent)
        );

        let sas_topic = [to_scval(
            &env,
            soroban_sas_common::events::REVOKED.into_val(&env),
        )];
        assert_eq!(
            parse_event(&sas_topic, &ScVal::Void),
            Err(EventParseError::MalformedPayload("payload is not a map"))
        );
    }
}
