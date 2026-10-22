import { useMemo, useState } from "react";
import { SASProvider, useSAS } from "../context.js";
import { useAttestation } from "../hooks/useAttestation.js";
import { useAttestationsByRecipient } from "../hooks/useAttestationsByRecipient.js";
import { useSASEvents } from "../hooks/useSASEvents.js";
import { useSchema } from "../hooks/useSchema.js";
import type {
  Attestation,
  NetworkName,
  SASClientLike,
  SchemaRecord,
  UID,
} from "../types.js";

export const DEMO_ACCOUNTS = {
  ALICE: "GALICE55555555555555555555555555555555555555555555555555",
  BOB: "GBOB7777777777777777777777777777777777777777777777777777",
  ISSUER: "GISSUER9999999999999999999999999999999999999999999999999",
  RESOLVER: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
} as const;

export const DEMO_SCHEMA_UID = "a1".repeat(32);
export const DEMO_ATTESTATION_UID_1 = "b1".repeat(32);
export const DEMO_ATTESTATION_UID_2 = "b2".repeat(32);
export const ZERO_UID = "00".repeat(32);

/**
 * Creates an in-memory interactive demo client with pre-populated schemas and attestations
 * so the sample demo app and Storybook stories work out of the box without a live node.
 */
export function createDemoSASClient(): SASClientLike & {
  issueDemoAttestation: (att: Attestation) => void;
  revokeDemoAttestation: (uid: UID) => void;
} {
  const schemas = new Map<UID, SchemaRecord>([
    [
      DEMO_SCHEMA_UID,
      {
        uid: DEMO_SCHEMA_UID,
        resolver: DEMO_ACCOUNTS.RESOLVER,
        revocable: true,
        schema: "verified bool, kyc_level u32, provider String",
        deprecated: false,
      },
    ],
  ]);

  const attestations = new Map<UID, Attestation>([
    [
      DEMO_ATTESTATION_UID_1,
      {
        uid: DEMO_ATTESTATION_UID_1,
        schemaUid: DEMO_SCHEMA_UID,
        time: 1_720_000_000n,
        expirationTime: 1_900_000_000n,
        revocationTime: 0n,
        refUid: ZERO_UID,
        recipient: DEMO_ACCOUNTS.ALICE,
        attester: DEMO_ACCOUNTS.ISSUER,
        revocable: true,
        data: new TextEncoder().encode("verified=true;kyc_level=3;provider=stellar-id"),
      },
    ],
    [
      DEMO_ATTESTATION_UID_2,
      {
        uid: DEMO_ATTESTATION_UID_2,
        schemaUid: DEMO_SCHEMA_UID,
        time: 1_720_050_000n,
        expirationTime: 0n,
        revocationTime: 0n,
        refUid: ZERO_UID,
        recipient: DEMO_ACCOUNTS.BOB,
        attester: DEMO_ACCOUNTS.ISSUER,
        revocable: true,
        data: new TextEncoder().encode("verified=true;kyc_level=2;provider=anchor-kyc"),
      },
    ],
  ]);

  return {
    async getAttestation(uid: UID) {
      const item = attestations.get(uid.toLowerCase()) ?? null;
      return item ? { ...item } : null;
    },
    async getSchema(schemaUid: UID) {
      const item = schemas.get(schemaUid.toLowerCase()) ?? null;
      return item ? { ...item } : null;
    },
    async getAttestationsByRecipient(recipient: string) {
      const results: Attestation[] = [];
      for (const att of attestations.values()) {
        if (att.recipient === recipient) {
          results.push({ ...att });
        }
      }
      return results;
    },
    issueDemoAttestation(att: Attestation) {
      attestations.set(att.uid.toLowerCase(), att);
    },
    revokeDemoAttestation(uid: UID) {
      const existing = attestations.get(uid.toLowerCase());
      if (existing) {
        attestations.set(uid.toLowerCase(), {
          ...existing,
          revocationTime: 1_725_000_000n,
        });
      }
    },
  };
}

function decodePayload(data: Uint8Array): string {
  try {
    return new TextDecoder().decode(data);
  } catch {
    return "";
  }
}

export interface SASDemoDashboardProps {
  onIssueSampleAttestation?: (recipient: string) => Attestation;
  onRevokeSampleAttestation?: (uid: UID) => void;
}

export function SASDemoDashboard({
  onIssueSampleAttestation,
  onRevokeSampleAttestation,
}: SASDemoDashboardProps) {
  const {
    network,
    rpcUrl,
    account,
    switchAccount,
    switchNetwork,
    emitEvent,
  } = useSAS();

  const [selectedUid, setSelectedUid] = useState<string>(DEMO_ATTESTATION_UID_1);
  const [selectedSchemaUid, setSelectedSchemaUid] = useState<string>(DEMO_SCHEMA_UID);

  const activeRecipient = account ?? DEMO_ACCOUNTS.ALICE;

  const attestationQuery = useAttestation(selectedUid);
  const schemaQuery = useSchema(selectedSchemaUid);
  const recipientQuery = useAttestationsByRecipient(activeRecipient);
  const { events, lastEvent } = useSASEvents();

  const handleIssueEvent = () => {
    if (!onIssueSampleAttestation) return;
    const created = onIssueSampleAttestation(activeRecipient);
    setSelectedUid(created.uid);
    emitEvent({
      type: "AttestationIssued",
      uid: created.uid,
      schemaUid: created.schemaUid,
      attester: created.attester,
      recipient: created.recipient,
    });
  };

  const handleRevokeEvent = () => {
    if (!onRevokeSampleAttestation) return;
    onRevokeSampleAttestation(selectedUid);
    emitEvent({
      type: "AttestationRevoked",
      uid: selectedUid,
      recipient: activeRecipient,
      timestamp: 1_725_000_000n,
    });
  };

  return (
    <div style={{ fontFamily: "system-ui, sans-serif", maxWidth: 960, margin: "0 auto", padding: 24 }}>
      <header style={{ marginBottom: 24, borderBottom: "1px solid #e2e8f0", paddingBottom: 16 }}>
        <h1 style={{ margin: "0 0 8px" }}>Soroban SAS React Hooks Demo</h1>
        <p style={{ margin: 0, color: "#475569" }}>
          Interactive demonstration of <code>SASProvider</code>, <code>useAttestation</code>,{" "}
          <code>useSchema</code>, <code>useAttestationsByRecipient</code>, and event-driven cache invalidation.
        </p>
      </header>

      <section
        aria-label="Provider Controls"
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
          gap: 16,
          marginBottom: 24,
          padding: 16,
          background: "#f8fafc",
          borderRadius: 8,
          border: "1px solid #cbd5e1",
        }}
      >
        <div>
          <strong>Active Network:</strong> <span data-testid="active-network">{network}</span>
          <div style={{ fontSize: 12, color: "#64748b", marginTop: 4 }} data-testid="active-rpc">
            {rpcUrl}
          </div>
          <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
            {(["testnet", "local", "mainnet"] as NetworkName[]).map((net) => (
              <button
                key={net}
                type="button"
                onClick={() => switchNetwork(net)}
                data-testid={`switch-network-${net}`}
              >
                {net}
              </button>
            ))}
          </div>
        </div>

        <div>
          <strong>Connected Account:</strong>{" "}
          <code data-testid="active-account">{activeRecipient.slice(0, 12)}...</code>
          <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
            <button
              type="button"
              onClick={() => switchAccount(DEMO_ACCOUNTS.ALICE)}
              data-testid="switch-account-alice"
            >
              Switch to Alice
            </button>
            <button
              type="button"
              onClick={() => switchAccount(DEMO_ACCOUNTS.BOB)}
              data-testid="switch-account-bob"
            >
              Switch to Bob
            </button>
          </div>
        </div>

        <div>
          <strong>Event Triggers:</strong>
          <div style={{ marginTop: 8, display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              type="button"
              onClick={handleIssueEvent}
              data-testid="trigger-issue-event"
            >
              Emit AttestationIssued
            </button>
            <button
              type="button"
              onClick={handleRevokeEvent}
              data-testid="trigger-revoke-event"
            >
              Emit AttestationRevoked
            </button>
          </div>
          {lastEvent && (
            <div style={{ fontSize: 12, marginTop: 6 }} data-testid="last-event-type">
              Last event: {lastEvent.type} ({events.length} total)
            </div>
          )}
        </div>
      </section>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
        <section
          aria-label="Schema Inspector"
          style={{ border: "1px solid #cbd5e1", borderRadius: 8, padding: 16 }}
        >
          <h2 style={{ marginTop: 0, fontSize: 18 }}>useSchema(schemaUid)</h2>
          <label style={{ display: "block", marginBottom: 8, fontSize: 13 }}>
            Schema UID:
            <input
              aria-label="Schema UID Input"
              value={selectedSchemaUid}
              onChange={(e) => setSelectedSchemaUid(e.target.value)}
              style={{ width: "100%", marginTop: 4 }}
            />
          </label>
          {schemaQuery.isLoading && <div data-testid="schema-loading">Loading schema...</div>}
          {schemaQuery.error && (
            <div role="alert" data-testid="schema-error">
              Error: {schemaQuery.error.message}
            </div>
          )}
          {!schemaQuery.isLoading && !schemaQuery.error && schemaQuery.data && (
            <div data-testid="schema-details">
              <div>
                <strong>Definition:</strong> <code>{schemaQuery.data.schema}</code>
              </div>
              <div>
                <strong>Revocable:</strong> {schemaQuery.data.revocable ? "Yes" : "No"}
              </div>
              <div>
                <strong>Resolver:</strong> <code>{schemaQuery.data.resolver.slice(0, 14)}...</code>
              </div>
            </div>
          )}
          {!schemaQuery.isLoading && !schemaQuery.error && schemaQuery.data === null && (
            <div data-testid="schema-empty">Schema not found.</div>
          )}
        </section>

        <section
          aria-label="Attestation Inspector"
          style={{ border: "1px solid #cbd5e1", borderRadius: 8, padding: 16 }}
        >
          <h2 style={{ marginTop: 0, fontSize: 18 }}>useAttestation(uid)</h2>
          <label style={{ display: "block", marginBottom: 8, fontSize: 13 }}>
            Attestation UID:
            <input
              aria-label="Attestation UID Input"
              value={selectedUid}
              onChange={(e) => setSelectedUid(e.target.value)}
              style={{ width: "100%", marginTop: 4 }}
            />
          </label>
          {attestationQuery.isLoading && (
            <div data-testid="attestation-loading">Loading attestation...</div>
          )}
          {attestationQuery.error && (
            <div role="alert" data-testid="attestation-error">
              Error: {attestationQuery.error.message}
            </div>
          )}
          {!attestationQuery.isLoading && !attestationQuery.error && attestationQuery.data && (
            <div data-testid="attestation-details">
              <div>
                <strong>Recipient:</strong>{" "}
                <code>{attestationQuery.data.recipient.slice(0, 14)}...</code>
              </div>
              <div>
                <strong>Status:</strong>{" "}
                <span data-testid="attestation-status">
                  {attestationQuery.data.revocationTime > 0n ? "Revoked" : "Active"}
                </span>
              </div>
              <div>
                <strong>Payload:</strong>{" "}
                <code data-testid="attestation-payload">
                  {decodePayload(attestationQuery.data.data)}
                </code>
              </div>
            </div>
          )}
          {!attestationQuery.isLoading &&
            !attestationQuery.error &&
            attestationQuery.data === null && (
              <div data-testid="attestation-empty">Attestation not found.</div>
            )}
        </section>
      </div>

      <section
        aria-label="Recipient Attestations"
        style={{ border: "1px solid #cbd5e1", borderRadius: 8, padding: 16 }}
      >
        <h2 style={{ marginTop: 0, fontSize: 18 }}>
          useAttestationsByRecipient(address)
        </h2>
        {recipientQuery.isLoading && (
          <div data-testid="recipient-loading">Loading recipient attestations...</div>
        )}
        {recipientQuery.error && (
          <div role="alert" data-testid="recipient-error">
            Error: {recipientQuery.error.message}
          </div>
        )}
        {!recipientQuery.isLoading && !recipientQuery.error && (
          <ul data-testid="recipient-attestation-list" style={{ paddingLeft: 20, margin: 0 }}>
            {recipientQuery.attestations.map((att) => (
              <li key={att.uid} style={{ marginBottom: 8 }}>
                <button
                  type="button"
                  onClick={() => setSelectedUid(att.uid)}
                  style={{ marginRight: 8 }}
                >
                  Inspect {att.uid.slice(0, 8)}...
                </button>
                <span>{decodePayload(att.data)}</span>{" "}
                <strong>({att.revocationTime > 0n ? "Revoked" : "Active"})</strong>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

export interface SASDemoAppProps {
  initialNetwork?: NetworkName;
  initialAccount?: string;
  client?: SASClientLike;
}

/**
 * Self-contained sample demo application illustrating `SASProvider`, `useAttestation`,
 * `useSchema`, `useAttestationsByRecipient`, account switching, and event-based triggers.
 */
export function SASDemoApp({
  initialNetwork = "testnet",
  initialAccount = DEMO_ACCOUNTS.ALICE,
  client: customClient,
}: SASDemoAppProps) {
  const demoClient = useMemo(() => createDemoSASClient(), []);
  const [counter, setCounter] = useState(3);

  const handleIssue = (recipient: string): Attestation => {
    const hexSuffix = counter.toString(16).padStart(2, "0");
    const uid = hexSuffix.repeat(32);
    setCounter((c) => c + 1);
    const created: Attestation = {
      uid,
      schemaUid: DEMO_SCHEMA_UID,
      time: 1_722_000_000n,
      expirationTime: 0n,
      revocationTime: 0n,
      refUid: ZERO_UID,
      recipient,
      attester: DEMO_ACCOUNTS.ISSUER,
      revocable: true,
      data: new TextEncoder().encode(
        `verified=true;kyc_level=${counter};provider=event-trigger`,
      ),
    };
    demoClient.issueDemoAttestation(created);
    return created;
  };

  const handleRevoke = (uid: UID) => {
    demoClient.revokeDemoAttestation(uid);
  };

  return (
    <SASProvider
      network={initialNetwork}
      account={initialAccount}
      client={customClient ?? demoClient}
    >
      <SASDemoDashboard
        onIssueSampleAttestation={handleIssue}
        onRevokeSampleAttestation={handleRevoke}
      />
    </SASProvider>
  );
}
