//! Asynchronous, resumable polling of SAS contract events via Soroban RPC.
//!
//! The caller must acknowledge events **after processing them** to persist a
//! checkpoint. An unacknowledged event is replayed after restart (at-least-once
//! delivery). Polling a single stream from multiple tasks and acknowledging
//! out of order is unsupported.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use soroban_sdk::xdr::{Limits, ReadXdr, ScAddress, ScVal};
use tokio::sync::mpsc;

use crate::events::{parse_event, AttestationIssued, AttestationRevoked, SasEvent};
use crate::rpc::RpcBackend;

/// Result of one SAS attestation or revocation notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttestationEvent {
    Issued(AttestationIssued),
    Revoked(AttestationRevoked),
}

/// Transport and cursor metadata associated with an event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamEnvelope {
    pub ledger: u32,
    pub cursor: String,
    pub event: AttestationEvent,
}

/// Optional filtering of issued credentials (XDR-decoded, not string matched).
///
/// A revoke event does not encode its original schema or attester; when either
/// filter is active it is excluded instead of incorrectly attributed.
#[derive(Clone, Debug, Default)]
pub struct EventFilter {
    pub schema_uid: Option<[u8; 32]>,
    pub attester: Option<ScAddress>,
}

impl EventFilter {
    fn matches(&self, event: &AttestationEvent) -> bool {
        match event {
            AttestationEvent::Issued(item) => {
                self.schema_uid.map_or(true, |s| s == item.schema_uid)
                    && self.attester.as_ref().map_or(true, |a| a == &item.attester)
            }
            AttestationEvent::Revoked(_) => self.schema_uid.is_none() && self.attester.is_none(),
        }
    }
}

/// Checkpoint persists only after explicit acknowledgment, not when data is
/// merely put onto the channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Checkpoint {
    ledger: u32,
    cursor: String,
    contract_ids: Vec<String>,
}

fn read_checkpoint(path: &Path, ids: &[String]) -> Result<Option<Checkpoint>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("read event cursor {}: {err}", path.display())),
    };
    let saved: Checkpoint = serde_json::from_str(&raw)
        .map_err(|err| format!("invalid event cursor {}: {err}", path.display()))?;
    if saved.contract_ids != ids {
        return Err("checkpoint contract ids do not match this subscription".into());
    }
    Ok(Some(saved))
}

fn write_checkpoint(path: &Path, saved: &Checkpoint) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|err| format!("create checkpoint directory {}: {err}", parent.display()))?;
    let payload =
        serde_json::to_vec(saved).map_err(|err| format!("encode event checkpoint: {err}"))?;
    let temp = path.with_extension("tmp");
    std::fs::write(&temp, payload)
        .map_err(|err| format!("write event checkpoint {}: {err}", temp.display()))?;
    std::fs::rename(&temp, path)
        .map_err(|err| format!("save event checkpoint {}: {err}", path.display()))
}

/// Consumer-side handle for the stream. To avoid losing messages if a process
/// stops mid-handler, call `acknowledge` only after downstream work succeeds.
pub struct EventSubscription {
    receiver: mpsc::Receiver<Result<StreamEnvelope, String>>,
    checkpoint: Option<PathBuf>,
    contract_ids: Vec<String>,
}

impl EventSubscription {
    pub async fn recv(&mut self) -> Option<Result<StreamEnvelope, String>> {
        self.receiver.recv().await
    }

    pub fn acknowledge(&self, event: &StreamEnvelope) -> Result<(), String> {
        if let Some(path) = &self.checkpoint {
            write_checkpoint(
                path,
                &Checkpoint {
                    ledger: event.ledger,
                    cursor: event.cursor.clone(),
                    contract_ids: self.contract_ids.clone(),
                },
            )?;
        }
        Ok(())
    }
}

/// Creates a Tokio worker which polls `getEvents`, reconnects with
/// exponential backoff, and streams only strongly typed SAS events.
///
/// `RpcBackend` allows deterministic tests and custom RPC routing.
pub struct EventStream {
    backend: Arc<dyn RpcBackend + Send + Sync>,
    contract_ids: Vec<String>,
    start_ledger: u32,
    filter: EventFilter,
    checkpoint: Option<PathBuf>,
    poll_interval: Duration,
}

impl EventStream {
    pub fn new(
        backend: impl RpcBackend + Send + Sync + 'static,
        contract_ids: Vec<String>,
        start_ledger: u32,
    ) -> Self {
        Self {
            backend: Arc::new(backend),
            contract_ids,
            start_ledger,
            filter: EventFilter::default(),
            checkpoint: None,
            poll_interval: Duration::from_secs(2),
        }
    }

    pub fn with_filter(mut self, filter: EventFilter) -> Self {
        self.filter = filter;
        self
    }

    pub fn with_checkpoint_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.checkpoint = Some(path.into());
        self
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval.max(Duration::from_millis(10));
        self
    }

    /// Spawn a worker and return an async receiver.
    pub fn subscribe(self) -> Result<EventSubscription, String> {
        if self.contract_ids.is_empty() || self.contract_ids.len() > 5 {
            return Err("provide 1 to 5 SAS contract IDs".into());
        }
        let saved = match &self.checkpoint {
            Some(path) => read_checkpoint(path, &self.contract_ids)?,
            None => None,
        };
        let mut cursor = saved.as_ref().map(|s| s.cursor.clone());
        let mut start_ledger = saved.map_or(self.start_ledger, |s| s.ledger);
        let (tx, rx) = mpsc::channel(128);
        let ids = self.contract_ids.clone();
        let ids_for_handle = ids.clone();
        let checkpoint = self.checkpoint.clone();
        tokio::spawn(async move {
            let mut failures = 0_u32;
            loop {
                if tx.is_closed() {
                    break;
                }
                let body = events_request(&ids, start_ledger, cursor.as_deref());
                let backend = self.backend.clone();
                let response = tokio::task::spawn_blocking(move || backend.post_json(&body)).await;
                let result = match response {
                    Ok(Ok(raw)) => decode_rpc_page(&raw, &self.filter),
                    Ok(Err(err)) => Err(format!("getEvents RPC: {err}")),
                    Err(err) => Err(format!("getEvents worker: {err}")),
                };

                match result {
                    Ok(page) => {
                        failures = 0;
                        // Every parsed page advances the *live* RPC cursor,
                        // including pages whose events are filtered out.
                        for (token, ledger, decoded) in page {
                            cursor = Some(token.clone());
                            start_ledger = ledger;
                            if let Some(event) = decoded {
                                if tx
                                    .send(Ok(StreamEnvelope {
                                        ledger,
                                        cursor: token,
                                        event,
                                    }))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                        tokio::select! {
                            _ = tx.closed() => return,
                            _ = tokio::time::sleep(self.poll_interval) => {}
                        }
                    }
                    Err(err) => {
                        if tx.send(Err(err)).await.is_err() {
                            return;
                        }
                        let exponent = failures.min(5);
                        let delay = Duration::from_secs(1_u64 << exponent);
                        failures = failures.saturating_add(1);
                        tokio::select! {
                            _ = tx.closed() => return,
                            _ = tokio::time::sleep(delay) => {}
                        }
                    }
                }
            }
        });
        Ok(EventSubscription {
            receiver: rx,
            checkpoint,
            contract_ids: ids_for_handle,
        })
    }
}

/// Assemble an RPC request with either a starting ledger or an opaque paging
/// token. The two options are mutually exclusive in the Stellar RPC API.
fn events_request(ids: &[String], start_ledger: u32, cursor: Option<&str>) -> String {
    let mut params = json!({
        "filters": [{ "type": "contract", "contractIds": ids }],
        "pagination": {"limit": 100}
    });
    if let Some(cursor) = cursor {
        params["pagination"]["cursor"] = json!(cursor);
    } else {
        params["startLedger"] = json!(start_ledger);
    }
    json!({"jsonrpc": "2.0", "id": 1, "method": "getEvents", "params": params}).to_string()
}

/// Page records include unseen event cursor positions, even if the event is
/// not a SAS issuance/revocation notification.
type Page = Vec<(String, u32, Option<AttestationEvent>)>;

fn decode_rpc_page(raw: &str, filter: &EventFilter) -> Result<Page, String> {
    let value: Value =
        serde_json::from_str(raw).map_err(|err| format!("invalid getEvents JSON: {err}"))?;
    if let Some(error) = value.get("error") {
        return Err(format!("getEvents: {error}"));
    }
    let entries = value
        .get("result")
        .and_then(|r| r.get("events"))
        .and_then(Value::as_array)
        .ok_or_else(|| "getEvents response is missing result.events".to_owned())?;
    let mut result = Vec::with_capacity(entries.len());
    for item in entries {
        let ledger = item
            .get("ledger")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| "getEvents event missing ledger".to_owned())?;
        let token = item
            .get("pagingToken")
            .or_else(|| item.get("id"))
            .and_then(Value::as_str)
            .ok_or_else(|| "getEvents event missing pagingToken".to_owned())?
            .to_owned();
        let topics = item
            .get("topic")
            .and_then(Value::as_array)
            .ok_or_else(|| "getEvents event missing topic array".to_owned())?;
        let topics: Vec<ScVal> = topics
            .iter()
            .map(|value| {
                let base64 = value.as_str().ok_or("event topic is not an XDR string")?;
                ScVal::from_xdr_base64(base64, Limits::none())
                    .map_err(|err| format!("malformed event topic XDR: {err:?}"))
            })
            .collect::<Result<_, String>>()?;
        let data_xdr = item
            .get("value")
            .and_then(|v| v.get("xdr"))
            .and_then(Value::as_str)
            .ok_or_else(|| "getEvents event missing value.xdr".to_owned())?;
        let data = ScVal::from_xdr_base64(data_xdr, Limits::none())
            .map_err(|err| format!("malformed event data XDR: {err:?}"))?;
        let event = match parse_event(&topics, &data) {
            Ok(SasEvent::AttestationIssued(item)) => Some(AttestationEvent::Issued(item)),
            Ok(SasEvent::AttestationRevoked(item)) => Some(AttestationEvent::Revoked(item)),
            _ => None,
        };
        result.push((token, ledger, event.filter(|event| filter.matches(event))));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sas_common::{AttestationIssuedEvent, UID};
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::xdr::WriteXdr;
    use soroban_sdk::{Address, BytesN, Env, IntoVal, TryFromVal, Val};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct Stub {
        responses: Mutex<VecDeque<String>>,
    }
    impl RpcBackend for Stub {
        fn post_json(&self, _body: &str) -> Result<String, crate::errors::SdkError> {
            Ok(self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| json!({"result":{"events":[]}}).to_string()))
        }
        fn network_url(&self) -> &str {
            "stub://events"
        }
    }

    fn issued_event() -> String {
        let env = Env::default();
        let attester = Address::generate(&env);
        let recipient = Address::generate(&env);
        let uid = UID(BytesN::from_array(&env, &[1; 32]));
        let schema_uid = UID(BytesN::from_array(&env, &[2; 32]));
        let to_xdr = |v: Val| {
            ScVal::try_from_val(&env, &v)
                .unwrap()
                .to_xdr_base64(Limits::none())
                .unwrap()
        };
        json!({
            "ledger": 100,
            "pagingToken": "100-1",
            "topic": [
                to_xdr(soroban_sas_common::events::ATTESTED.into_val(&env)),
                to_xdr(schema_uid.clone().into_val(&env)),
                to_xdr(attester.clone().into_val(&env))
            ],
            "value": {
                "xdr": to_xdr(AttestationIssuedEvent { uid, schema_uid, attester, recipient }.into_val(&env))
            }
        }).to_string()
    }

    #[test]
    fn builds_cursor_and_start_ledger_requests() {
        let ids = vec!["CABC".to_string()];
        let ledger: Value = serde_json::from_str(&events_request(&ids, 90, None)).unwrap();
        assert_eq!(ledger["params"]["startLedger"], 90);
        let after: Value = serde_json::from_str(&events_request(&ids, 90, Some("100-1"))).unwrap();
        assert!(after["params"].get("startLedger").is_none());
        assert_eq!(after["params"]["pagination"]["cursor"], "100-1");
    }

    #[test]
    fn decodes_topics_and_respects_schema_filter() {
        let raw =
            json!({"result":{"events":[serde_json::from_str::<Value>(&issued_event()).unwrap()]}})
                .to_string();
        let entries = decode_rpc_page(
            &raw,
            &EventFilter {
                schema_uid: Some([2; 32]),
                attester: None,
            },
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].2, Some(AttestationEvent::Issued(_))));
        let filtered = decode_rpc_page(
            &raw,
            &EventFilter {
                schema_uid: Some([3; 32]),
                attester: None,
            },
        )
        .unwrap();
        assert!(filtered[0].2.is_none());
    }

    #[tokio::test]
    async fn receives_events_over_async_channel() {
        let raw =
            json!({"result":{"events":[serde_json::from_str::<Value>(&issued_event()).unwrap()]}})
                .to_string();
        let backend = Stub {
            responses: Mutex::new(VecDeque::from([raw])),
        };
        let mut sub = EventStream::new(backend, vec!["CABC".into()], 90)
            .with_poll_interval(Duration::from_millis(10))
            .subscribe()
            .unwrap();
        let msg = tokio::time::timeout(Duration::from_secs(1), sub.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(msg.ledger, 100);
        assert_eq!(msg.cursor, "100-1");
        assert!(matches!(msg.event, AttestationEvent::Issued(_)));
    }
}
