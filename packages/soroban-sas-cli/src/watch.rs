//! Streaming CLI watcher backed by Soroban RPC getEvents.
//! The RPC client supplies bounded HTTP timeouts; no background threads or
//! persistent subscriptions survive Ctrl-C.
use serde_json::{json, Value};
use soroban_sas_sdk::events::{parse_event, SasEvent};
use soroban_sas_sdk::rpc::{RpcBackend, RpcClient};
use soroban_sdk::xdr::{Limits, ReadXdr, ScAddress, ScVal};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum WatchKind {
    Issued,
    Revoked,
    Schema,
}

fn address_to_strkey(address: &ScAddress) -> String {
    use soroban_sdk::xdr::{PublicKey, ScAddress::*};
    match address {
        Account(id) => match &id.0 {
            PublicKey::PublicKeyTypeEd25519(key) => {
                stellar_strkey::ed25519::PublicKey(key.0).to_string()
            }
        },
        Contract(hash) => stellar_strkey::Contract(hash.0).to_string(),
    }
}

fn filter_event(
    event: &SasEvent,
    schema: Option<&str>,
    recipient: Option<&str>,
    kind: Option<WatchKind>,
) -> bool {
    let event_kind = match event {
        SasEvent::AttestationIssued(_) => WatchKind::Issued,
        SasEvent::AttestationRevoked(_) => WatchKind::Revoked,
        SasEvent::SchemaRegistered(_) => WatchKind::Schema,
        _ => return false,
    };
    if kind.is_some_and(|k| k != event_kind) {
        return false;
    }
    match event {
        SasEvent::AttestationIssued(e) => {
            schema.is_none_or(|uid| uid.eq_ignore_ascii_case(&hex::encode(e.schema_uid)))
                && recipient.is_none_or(|addr| addr == address_to_strkey(&e.recipient))
        }
        SasEvent::SchemaRegistered(e) => {
            schema.is_none_or(|uid| uid.eq_ignore_ascii_case(&hex::encode(e.schema_uid)))
                && recipient.is_none()
        }
        // A revoked UID alone does not identify its schema/recipient.
        // Reject such filters rather than silently misclassify revocations.
        SasEvent::AttestationRevoked(_) => schema.is_none() && recipient.is_none(),
        _ => false,
    }
}

fn decode_event(event: &Value) -> Result<SasEvent, String> {
    let topics = event
        .get("topic")
        .and_then(Value::as_array)
        .ok_or("missing topic array")?;
    let topics: Vec<ScVal> = topics
        .iter()
        .map(|item| {
            let base64 = item.as_str().ok_or("invalid topic")?;
            ScVal::from_xdr_base64(base64, Limits::none()).map_err(|e| e.to_string())
        })
        .collect::<Result<_, String>>()?;
    let value = event.get("value").ok_or("missing event value")?;
    let payload = value
        .as_str()
        .or_else(|| value.get("xdr").and_then(Value::as_str))
        .ok_or("invalid event value")?;
    let decoded = ScVal::from_xdr_base64(payload, Limits::none()).map_err(|e| e.to_string())?;
    parse_event(&topics, &decoded).map_err(|e| format!("{e:?}"))
}

fn print_event(event: &Value, parsed: &SasEvent) {
    let ledger = event.get("ledger").and_then(Value::as_u64).unwrap_or(0);
    let close_time = event
        .get("ledgerClosedAt")
        .and_then(Value::as_str)
        .unwrap_or("time unavailable");
    let kind = match parsed {
        SasEvent::AttestationIssued(_) => "AttestationIssued",
        SasEvent::AttestationRevoked(_) => "AttestationRevoked",
        SasEvent::SchemaRegistered(_) => "SchemaRegistered",
        _ => "other",
    };
    let detail = match parsed {
        SasEvent::AttestationIssued(e) => format!(
            "uid={} schema={} recipient={} attester={}",
            hex::encode(e.uid),
            hex::encode(e.schema_uid),
            address_to_strkey(&e.recipient),
            address_to_strkey(&e.attester)
        ),
        SasEvent::AttestationRevoked(e) => {
            format!("uid={} timestamp={}", hex::encode(e.uid), e.timestamp)
        }
        SasEvent::SchemaRegistered(e) => format!(
            "schema={} owner={}",
            hex::encode(e.schema_uid),
            address_to_strkey(&e.owner)
        ),
        _ => String::new(),
    };
    println!("ledger={ledger} closed={close_time} {kind} {detail}");
}

pub fn watch(
    rpc_url: String,
    contract_id: String,
    schema: Option<String>,
    recipient: Option<String>,
    kind: Option<WatchKind>,
    poll_seconds: u64,
) -> Result<(), String> {
    if poll_seconds == 0 || poll_seconds > 300 {
        return Err("--poll-seconds must be 1..=300".into());
    }
    stellar_strkey::Contract::from_string(&contract_id)
        .map_err(|e| format!("invalid contract ID: {e}"))?;
    if let Some(ref uid) = schema {
        if uid.len() != 64 || !uid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("--schema must be exactly 64 hex digits".into());
        }
    }
    if let Some(ref addr) = recipient {
        if stellar_strkey::ed25519::PublicKey::from_string(addr).is_err()
            && stellar_strkey::Contract::from_string(addr).is_err()
        {
            return Err("invalid --recipient address".into());
        }
    }
    let rpc = RpcClient::new(rpc_url);
    let mut next_ledger = rpc
        .get_latest_ledger()
        .map_err(|e| e.to_string())?
        .sequence
        .saturating_sub(1);
    eprintln!("Watching events from ledger {next_ledger}; Ctrl-C to stop.");
    loop {
        let mut cursor: Option<String> = None;
        let mut last_closed_ledger: u64;
        loop {
            let mut params = json!({
                "filters": [{"type": "contract", "contractIds": [contract_id]}],
                "pagination": {"limit": 200}
            });
            if let Some(ref token) = cursor {
                params["pagination"]["cursor"] = json!(token);
            } else {
                params["startLedger"] = json!(next_ledger);
            }
            let request = json!({
                "jsonrpc": "2.0", "id": 1, "method": "getEvents", "params": params
            });
            let body = rpc
                .post_json(&request.to_string())
                .map_err(|e| e.to_string())?;
            let reply: Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
            if let Some(error) = reply.get("error") {
                return Err(format!("getEvents: {error}"));
            }
            let result = reply.get("result").ok_or("RPC reply missing result")?;
            let latest = result
                .get("latestLedger")
                .and_then(Value::as_u64)
                .ok_or("RPC reply missing latestLedger; refusing to skip events")?;
            last_closed_ledger = latest;
            let events = result
                .get("events")
                .and_then(Value::as_array)
                .ok_or("RPC reply missing events")?;
            for event in events {
                if let Ok(parsed) = decode_event(event) {
                    if filter_event(&parsed, schema.as_deref(), recipient.as_deref(), kind) {
                        print_event(event, &parsed);
                    }
                }
            }
            if events.len() < 200 {
                break;
            }
            let next = result.get("cursor").or_else(|| result.pointer("/pagination/cursor"))
                .and_then(Value::as_str)
                .filter(|next| Some(*next) != cursor.as_deref())
                .ok_or("RPC returned a full events page without a usable cursor; refusing to skip events")?;
            cursor = Some(next.to_string());
        }
        next_ledger = last_closed_ledger.saturating_add(1).min(u32::MAX as u64) as u32;
        std::thread::sleep(std::time::Duration::from_secs(poll_seconds));
    }
}
