import { Buffer } from "buffer";
import { Address, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { act, renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import {
  SAS_DOM_EVENTS,
  SASProvider,
  dispatchSASEvent,
  parseRpcContractEvent,
  uidToScVal,
  useAttestation,
  useAttestationsByRecipient,
  useSAS,
  useSASEvents,
  useSchema,
} from "../src/index.js";
import type {
  Attestation,
  SASClientLike,
  SASEvent,
  SchemaRecord,
} from "../src/types.js";

const SAMPLE_UID = "33".repeat(32);
const SAMPLE_SCHEMA_UID = "44".repeat(32);
const ZERO_UID = "00".repeat(32);
const RECIPIENT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const ATTESTER = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

function makeAttestation(revocationTime = 0n): Attestation {
  return {
    uid: SAMPLE_UID,
    schemaUid: SAMPLE_SCHEMA_UID,
    time: 1_700_000_000n,
    expirationTime: 0n,
    revocationTime,
    refUid: ZERO_UID,
    recipient: RECIPIENT,
    attester: ATTESTER,
    revocable: true,
    data: new Uint8Array([9, 9]),
  };
}

function makeSchema(schemaText: string): SchemaRecord {
  return {
    uid: SAMPLE_SCHEMA_UID,
    resolver: ATTESTER,
    revocable: true,
    schema: schemaText,
    deprecated: false,
  };
}

describe("Event-based triggers & useSASEvents", () => {
  it("invalidates and re-fetches useAttestation and useAttestationsByRecipient on AttestationIssued and AttestationRevoked", async () => {
    let currentRevocation = 0n;
    const client: SASClientLike = {
      getAttestation: vi.fn(async () => makeAttestation(currentRevocation)),
      getSchema: vi.fn(async () => makeSchema("verified bool")),
      getAttestationsByRecipient: vi.fn(async () => [
        makeAttestation(currentRevocation),
      ]),
    };

    const onIssued = vi.fn();
    const onRevoked = vi.fn();

    const wrapper = ({ children }: { children: ReactNode }) => (
      <SASProvider network="testnet" account={RECIPIENT} client={client}>
        {children}
      </SASProvider>
    );

    const { result } = renderHook(
      () => ({
        att: useAttestation(SAMPLE_UID),
        recipientAtts: useAttestationsByRecipient(RECIPIENT),
        eventsHook: useSASEvents({
          onAttestationIssued: onIssued,
          onAttestationRevoked: onRevoked,
        }),
      }),
      { wrapper },
    );

    await waitFor(() => {
      expect(result.current.att.data?.revocationTime).toBe(0n);
      expect(result.current.recipientAtts.attestations).toHaveLength(1);
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(1);
    expect(client.getAttestationsByRecipient).toHaveBeenCalledTimes(1);

    // Emit AttestationRevoked event
    currentRevocation = 1_725_000_000n;
    act(() => {
      result.current.eventsHook.emitEvent({
        type: "AttestationRevoked",
        uid: SAMPLE_UID,
        recipient: RECIPIENT,
        timestamp: currentRevocation,
      });
    });

    await waitFor(() => {
      expect(result.current.att.data?.revocationTime).toBe(1_725_000_000n);
      expect(
        result.current.recipientAtts.attestations[0]?.revocationTime,
      ).toBe(1_725_000_000n);
    });
    expect(onRevoked).toHaveBeenCalledTimes(1);
    expect(result.current.eventsHook.lastEvent?.type).toBe("AttestationRevoked");

    // Dispatch AttestationIssued via DOM CustomEvent
    currentRevocation = 0n;
    act(() => {
      dispatchSASEvent({
        type: "AttestationIssued",
        uid: SAMPLE_UID,
        schemaUid: SAMPLE_SCHEMA_UID,
        attester: ATTESTER,
        recipient: RECIPIENT,
      });
    });

    await waitFor(() => {
      expect(result.current.att.data?.revocationTime).toBe(0n);
    });
    expect(onIssued).toHaveBeenCalledTimes(1);
    expect(result.current.eventsHook.events).toHaveLength(2);

    act(() => {
      result.current.eventsHook.clearEvents();
    });
    expect(result.current.eventsHook.events).toHaveLength(0);
    expect(result.current.eventsHook.lastEvent).toBeNull();
  });

  it("invalidates useSchema on SchemaRegistered and supports BatchAttested / BatchRevoked / specific DOM events", async () => {
    let schemaVersion = "v1 bool";
    const client: SASClientLike = {
      getAttestation: vi.fn(async () => makeAttestation()),
      getSchema: vi.fn(async () => makeSchema(schemaVersion)),
      getAttestationsByRecipient: vi.fn(async () => [makeAttestation()]),
    };

    const onSchemaRegistered = vi.fn();
    const onBatchAttested = vi.fn();
    const onBatchRevoked = vi.fn();
    const onAccountChanged = vi.fn();
    const onNetworkChanged = vi.fn();
    const onEvent = vi.fn();

    const wrapper = ({ children }: { children: ReactNode }) => (
      <SASProvider network="testnet" client={client}>
        {children}
      </SASProvider>
    );

    const { result } = renderHook(
      () => ({
        sas: useSAS(),
        schema: useSchema(SAMPLE_SCHEMA_UID),
        att: useAttestation(SAMPLE_UID),
        eventsHook: useSASEvents({
          onEvent,
          onSchemaRegistered,
          onBatchAttested,
          onBatchRevoked,
          onAccountChanged,
          onNetworkChanged,
        }),
      }),
      { wrapper },
    );

    await waitFor(() => {
      expect(result.current.schema.data?.schema).toBe("v1 bool");
    });

    schemaVersion = "v2 bool, level u32";
    act(() => {
      window.dispatchEvent(
        new CustomEvent(SAS_DOM_EVENTS.SCHEMA_REGISTERED, {
          detail: { schemaUid: SAMPLE_SCHEMA_UID, owner: RECIPIENT },
        }),
      );
      window.dispatchEvent(
        new CustomEvent(SAS_DOM_EVENTS.ATTESTATION_ISSUED, {
          detail: {
            uid: SAMPLE_UID,
            schemaUid: SAMPLE_SCHEMA_UID,
            attester: ATTESTER,
            recipient: RECIPIENT,
          },
        }),
      );
      window.dispatchEvent(
        new CustomEvent(SAS_DOM_EVENTS.ATTESTATION_REVOKED, {
          detail: { uid: SAMPLE_UID },
        }),
      );
    });

    await waitFor(() => {
      expect(result.current.schema.data?.schema).toBe("v2 bool, level u32");
    });
    expect(onSchemaRegistered).toHaveBeenCalledTimes(1);

    act(() => {
      result.current.sas.emitEvent({
        type: "BatchAttested",
        count: 2,
        uids: [SAMPLE_UID],
        recipients: [RECIPIENT],
      });
      result.current.sas.emitEvent({
        type: "BatchRevoked",
        count: 1,
      });
      result.current.sas.emitEvent({
        type: "AccountChanged",
        account: RECIPIENT,
      });
      result.current.sas.switchNetwork("local");
    });

    expect(onBatchAttested).toHaveBeenCalledTimes(1);
    expect(onBatchRevoked).toHaveBeenCalledTimes(1);
    expect(onAccountChanged).toHaveBeenCalledTimes(1);
    expect(onNetworkChanged).toHaveBeenCalledTimes(1);
    expect(onEvent).toHaveBeenCalled();
  });

  it("polls client.getEvents when eventPollingInterval is configured", async () => {
    let revocation = 0n;
    const client: SASClientLike = {
      getAttestation: vi.fn(async () => makeAttestation(revocation)),
      getSchema: vi.fn(),
      getEvents: vi.fn(async () => {
        revocation = 1_799_000_000n;
        const events: SASEvent[] = [
          {
            type: "AttestationRevoked",
            uid: SAMPLE_UID,
            timestamp: revocation,
            ledger: 500,
          },
        ];
        return { events, latestLedger: 500 };
      }),
    };

    const wrapper = ({ children }: { children: ReactNode }) => (
      <SASProvider
        network="testnet"
        client={client}
        eventPollingInterval={40}
      >
        {children}
      </SASProvider>
    );

    const { result } = renderHook(() => useAttestation(SAMPLE_UID), {
      wrapper,
    });

    await waitFor(() => {
      expect(result.current.data?.revocationTime).toBe(1_799_000_000n);
    });
    expect(client.getEvents).toHaveBeenCalled();
  });

  it("parses raw Soroban RPC XDR contract events (ATTESTED, REVOKED, REGISTERED, BATCHATT, BATCHREV)", () => {
    const uidScVal = uidToScVal(SAMPLE_UID);
    const schemaUidScVal = uidToScVal(SAMPLE_SCHEMA_UID);
    const recipientScVal = Address.fromString(RECIPIENT).toScVal();
    const attesterScVal = Address.fromString(ATTESTER).toScVal();

    // 1. ATTESTED
    const attestedMap = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("uid"),
        val: uidScVal,
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("schema_uid"),
        val: schemaUidScVal,
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("attester"),
        val: attesterScVal,
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("recipient"),
        val: recipientScVal,
      }),
    ]);

    const parsedAttested = parseRpcContractEvent({
      topic: [xdr.ScVal.scvSymbol("ATTESTED"), schemaUidScVal, attesterScVal],
      value: attestedMap,
      ledger: 101,
    });
    expect(parsedAttested).toEqual({
      type: "AttestationIssued",
      uid: SAMPLE_UID,
      schemaUid: SAMPLE_SCHEMA_UID,
      attester: ATTESTER,
      recipient: RECIPIENT,
      ledger: 101,
    });

    // 2. REVOKED
    const revokedMap = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("uid"),
        val: uidScVal,
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("timestamp"),
        val: nativeToScVal(4242n, { type: "u64" }),
      }),
    ]);
    const parsedRevoked = parseRpcContractEvent({
      topic: [
        xdr.ScVal.scvSymbol("REVOKED").toXDR("base64"),
        uidScVal.toXDR("base64"),
      ],
      value: { xdr: revokedMap.toXDR("base64") },
      ledger: 102,
    });
    expect(parsedRevoked).toEqual({
      type: "AttestationRevoked",
      uid: SAMPLE_UID,
      timestamp: 4242n,
      ledger: 102,
    });

    // 3. REGISTER
    const registerMap = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("schema_uid"),
        val: schemaUidScVal,
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("owner"),
        val: recipientScVal,
      }),
    ]);
    const parsedRegister = parseRpcContractEvent({
      topic: [xdr.ScVal.scvSymbol("REGISTER"), schemaUidScVal],
      value: registerMap,
      ledger: 103,
    });
    expect(parsedRegister).toEqual({
      type: "SchemaRegistered",
      schemaUid: SAMPLE_SCHEMA_UID,
      owner: RECIPIENT,
      ledger: 103,
    });

    // 4. BATCHATT & BATCHREV
    const batchMap = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("count"),
        val: nativeToScVal(5, { type: "u32" }),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("attester_count"),
        val: nativeToScVal(2, { type: "u32" }),
      }),
    ]);
    expect(
      parseRpcContractEvent({
        topic: [xdr.ScVal.scvSymbol("BATCHATT")],
        value: batchMap,
        ledger: 104,
      }),
    ).toEqual({
      type: "BatchAttested",
      count: 5,
      attesterCount: 2,
      ledger: 104,
    });

    expect(
      parseRpcContractEvent({
        topic: [xdr.ScVal.scvSymbol("BATCHREV")],
        value: batchMap,
        ledger: 105,
      }),
    ).toEqual({
      type: "BatchRevoked",
      count: 5,
      attesterCount: 2,
      ledger: 105,
    });

    // Unknown or malformed events return null safely
    expect(parseRpcContractEvent({})).toBeNull();
    expect(
      parseRpcContractEvent({
        topic: [xdr.ScVal.scvSymbol("UNKNOWN")],
        value: xdr.ScVal.scvVoid(),
      }),
    ).toBeNull();
    expect(
      parseRpcContractEvent({
        topic: [nativeToScVal(123, { type: "u32" })],
        value: Buffer.from("invalid").toString("base64"),
      }),
    ).toBeNull();
  });
});
