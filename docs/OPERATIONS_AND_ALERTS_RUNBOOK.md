# Operations and Alerts Runbook

This document defines standard operating procedures, incident response workflows, and alerting integration guides for operators running and monitoring the Soroban SAS (Stellar Attestation Service) protocol.

---

## 1. Monitoring & Alert Architecture

The Soroban SAS monitoring stack consists of:
- **`soroban-sas-prometheus-exporter`**: Scrapes protocol events, contract state, and transaction execution telemetry, serving metrics on `/metrics`.
- **Prometheus Server**: Scrapes the exporter and evaluates alerting rules defined in `tools/prometheus-exporter/alerts.yml`.
- **Alertmanager**: Deduplicates, groups, and routes alert notifications to on-call responders (PagerDuty, Discord, Slack, email).
- **Grafana Dashboard**: Visualizes real-time metrics (`tools/prometheus-exporter/grafana-dashboard.json`).

---

## 2. Alert Catalog & Incident Response Procedures

### ContractPausedAlert

- **Alert Name**: `ContractPausedAlert`
- **Severity**: `critical`
- **Threshold**: `sas_contract_paused > 0 or increase(sas_contract_reverts_total{error_code="501"}[5m]) > 0`
- **Tier**: `protocol-safety`
- **Summary**: Contract is paused or rejecting write operations with `SASError::ContractPaused (501)`.

#### Impact
When paused, all mutating functions (`attest`, `attest_with_value`, `multi_attest`, `revoke`, `multi_revoke`, `register_attester_key`, `rotate_attester_key`, `revoke_attester_key`, and schema registrations) revert immediately. Read-only functions (`verify_attestation`, `get_attestation`, `get_schema`, `is_paused`) remain operational.

#### Triage Steps
1. **Verify Contract State**:
   Execute read-only query on the contract:
   ```bash
   stellar contract invoke \
     --id "$SAS_CONTRACT_ID" \
     --source "$OPERATOR_ACCOUNT" \
     --network testnet \
     -- is_paused
   ```
2. **Identify Who Paused the Contract**:
   Inspect recent contract events for `ContractPaused` (`PAUSED` topic):
   ```bash
   stellar events --id "$SAS_CONTRACT_ID" --network testnet --count 20
   ```
   Check the `authorizer` address against the authorized admin list.
3. **Determine Cause**:
   - Was this an intentional administrative pause due to suspected protocol exploit or migration?
   - Was this triggered by an automated circuit breaker or administrative error?

#### Remediation & Recovery
1. If the underlying security incident or maintenance is complete, the admin may unpause the contract:
   ```bash
   stellar contract invoke \
     --id "$SAS_CONTRACT_ID" \
     --source "$ADMIN_SECRET_KEY" \
     --network testnet \
     -- unpause
   ```
2. Confirm resumption of write traffic:
   ```bash
   curl -s http://localhost:9090/metrics | grep sas_contract_paused
   ```
3. Close the incident in PagerDuty with root cause analysis.

---

### ReentrancySpikeAlert

- **Alert Name**: `ReentrancySpikeAlert`
- **Severity**: `critical`
- **Threshold**: `rate(sas_contract_reverts_total{error_code="502"}[5m]) > 0`
- **Tier**: `security`
- **Summary**: Contract reverted due to reentrancy check failure (`SASError::Reentrancy (502)`).

#### Impact
A transaction attempted to recursively re-enter `multi_attest` or related state while an invocation was still active. This indicates either an active exploit attempt against the protocol or a buggy custom resolver/indexer callback.

#### Triage Steps
1. **Identify the Emitting Transaction & Callers**:
   Search failed RPC transactions or indexer logs for error `502`:
   ```bash
   # Filter logs for Error 502 / Reentrancy
   grep "ContractError(502)" /var/log/sas-exporter.log
   ```
2. **Inspect Invoked Schema and Resolver**:
   Determine which schema was being attested against:
   ```bash
   stellar contract invoke \
     --id "$SCHEMA_REGISTRY_CONTRACT_ID" \
     --source "$OPERATOR_ACCOUNT" \
     --network testnet \
     -- get_schema --uid "$SUSPICIOUS_SCHEMA_UID"
   ```
3. Check if the resolver contract is a known, verified contract or an unknown third-party contract.

#### Remediation
1. If an exploit is identified, immediately activate the emergency pause:
   ```bash
   stellar contract invoke \
     --id "$SAS_CONTRACT_ID" \
     --source "$ADMIN_SECRET_KEY" \
     --network testnet \
     -- pause
   ```
2. Deprecate the offending schema in `schema-registry` to prevent further attestations:
   ```bash
   stellar contract invoke \
     --id "$SCHEMA_REGISTRY_CONTRACT_ID" \
     --source "$ADMIN_SECRET_KEY" \
     --network testnet \
     -- deprecate --uid "$SUSPICIOUS_SCHEMA_UID" --authorizer "$ADMIN_ADDRESS"
   ```
3. Once the hostile vector is neutralized, unpause the contract.

---

### HighRevocationRateAlert

- **Alert Name**: `HighRevocationRateAlert`
- **Severity**: `warning`
- **Threshold**: `rate(sas_attestation_revoked_total[5m]) > 10 and (rate(sas_attestation_revoked_total[5m]) / (rate(sas_attestation_issued_total[5m]) + 0.001)) > 0.5`
- **Tier**: `operational`
- **Summary**: Abnormal spike in revocation traffic (>10/s and >50% of issuance rate).

#### Impact
High volume of revocations could signify:
- An attester account's signing keys were compromised, triggering rapid mass revocation.
- A critical business error in an attester's automated issuance pipeline requiring rollback.
- A denial-of-service attempt causing state bloat and RPC congestion.

#### Triage Steps
1. **Identify Attesters Performing Revocations**:
   Query Prometheus for recent revocation activity:
   ```promql
   rate(sas_batch_revoked_total[5m])
   ```
2. Check on-chain events:
   ```bash
   stellar events --id "$SAS_CONTRACT_ID" --network testnet --count 50 | grep -E "REVOKED|BATCHREV"
   ```
3. Contact the identified attester organization to confirm whether the revocations are expected or part of an emergency key revocation.

#### Remediation
1. If an attester key is compromised, execute key revocation for the attester:
   ```bash
   stellar contract invoke \
     --id "$SAS_CONTRACT_ID" \
     --source "$OPERATOR_ACCOUNT" \
     --network testnet \
     -- revoke_attester_key --attester "$COMPROMISED_ATTESTER"
   ```
2. If the traffic is a planned bulk revocation (e.g. quarterly credential expiration), create an Alertmanager silence for the duration of the event.

---

## 3. Alertmanager Configuration Guide

Alertmanager handles notification routing, grouping, and silencing. Below is the production reference configuration for routing SAS alerts to PagerDuty and Discord webhooks.

### `alertmanager.yml` Example

```yaml
global:
  resolve_timeout: 5m
  pagerduty_url: 'https://events.pagerduty.com/v2/enqueue'

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  receiver: 'discord-notifications'
  routes:
    # Route critical protocol safety and security alerts to PagerDuty
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
      continue: true

    # Route all alerts to Discord
    - match_re:
        severity: 'critical|warning'
      receiver: 'discord-notifications'

receivers:
  # PagerDuty integration for on-call alerting
  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: '${PAGERDUTY_INTEGRATION_KEY}'
        severity: '{{ if eq .CommonLabels.severity "critical" }}critical{{ else }}warning{{ end }}'
        description: '[{{ .Status | toUpper }}] {{ .CommonAnnotations.summary }}'
        details:
          description: '{{ .CommonAnnotations.description }}'
          runbook_url: '{{ .CommonAnnotations.runbook_url }}'
          dashboard_url: '{{ .CommonAnnotations.dashboard_url }}'
          component: '{{ .CommonLabels.component }}'
        send_resolved: true

  # Discord webhook integration for team channels
  - name: 'discord-notifications'
    webhook_configs:
      # Discord provides a Slack-compatible webhook endpoint by appending /slack
      - url: 'https://discord.com/api/webhooks/${DISCORD_WEBHOOK_ID}/${DISCORD_WEBHOOK_TOKEN}/slack'
        send_resolved: true
```

---

## 4. Notification Integration Setup

### Setting Up PagerDuty
1. In PagerDuty, navigate to **Services** -> **New Service**.
2. Integration type: **Prometheus / Alertmanager**.
3. Copy the **Integration Key** (32-character hexadecimal).
4. Set the `PAGERDUTY_INTEGRATION_KEY` environment variable in your Alertmanager deployment environment.

### Setting Up Discord Webhook
1. In Discord, navigate to **Server Settings** -> **Integrations** -> **Webhooks**.
2. Click **New Webhook**, select the target channel (e.g. `#sas-protocol-alerts`), and copy the Webhook URL.
3. Append `/slack` to the end of the Discord Webhook URL. This enables Discord's Slack-compatible payload receiver.
4. Set `DISCORD_WEBHOOK_URL` in Alertmanager `webhook_configs`.
