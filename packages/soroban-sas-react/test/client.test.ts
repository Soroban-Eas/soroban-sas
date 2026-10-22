import { Buffer } from "buffer";
import { Address, StrKey, nativeToScVal, type rpc, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it, vi } from "vitest";
import {
  SASClientError,
  SASRpcClient,
  decodeAttestationRecord,
  decodeSchemaRecord,
  decodeUid,
  isValidAddress,
  isValidUid,
  normalizeUid,
  resolveNetworkConfig,
  uidToScVal,
} from "../src/index.js";

const CONTRACT_ID = StrKey.encodeContract(Buffer.alloc(32, 1));
const REGISTRY_ID = StrKey.encodeContract(Buffer.alloc(32, 2));
const INDEXER_ID = StrKey.encodeContract(Buffer.alloc(32, 3));
const ACCOUNT_ADDR = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 4));
const SAMPLE_UID = "11".repeat(32);
const SAMPLE_SCHEMA_UID = "22".repeat(32);
const ZERO_UID = "00".repeat(32);

describe("SASRpcClient and decoding helpers", () => {
  it("validates and normalizes UIDs and Stellar addresses", () => {
    expect(isValidUid(SAMPLE_UID)).toBe(true);
    expect(isValidUid(`0x${SAMPLE_UID.toUpperCase()}`)).toBe(true);
    expect(isValidUid("not-a-uid")).toBe(false);

    expect(normalizeUid(`0x${"AA".repeat(32)}`)).toBe("aa".repeat(32));
    expect(() => normalizeUid("1234")).toThrow(SASClientError);

    expect(isValidAddress(ACCOUNT_ADDR)).toBe(true);
    expect(isValidAddress(CONTRACT_ID)).toBe(true);
    expect(isValidAddress("invalid-address")).toBe(false);

    const customNet = resolveNetworkConfig("custom-net", {
      rpcUrl: "https://custom.rpc",
      networkPassphrase: "Custom Passphrase",
    });
    expect(customNet.id).toBe("custom-net");
    expect(customNet.rpcUrl).toBe("https://custom.rpc");
  });

  it("decodes UID, Attestation, and SchemaRecord shapes and rejects malformed inputs", () => {
    expect(decodeUid(SAMPLE_UID)).toBe(SAMPLE_UID);
    expect(decodeUid(new Uint8Array(32).fill(0x11))).toBe(SAMPLE_UID);
    expect(decodeUid([new Uint8Array(32).fill(0x11)])).toBe(SAMPLE_UID);
    expect(() => decodeUid(42)).toThrow(SASClientError);

    const decodedSchema = decodeSchemaRecord({
      uid: [new Uint8Array(32).fill(0x22)],
      resolver: CONTRACT_ID,
      revocable: true,
      schema: "verified bool",
      deprecated: false,
    });
    expect(decodedSchema.uid).toBe(SAMPLE_SCHEMA_UID);
    expect(decodedSchema.schema).toBe("verified bool");
    expect(() => decodeSchemaRecord(null)).toThrow(SASClientError);

    const decodedAtt = decodeAttestationRecord({
      uid: [new Uint8Array(32).fill(0x11)],
      schema_uid: [new Uint8Array(32).fill(0x22)],
      time: 1000n,
      expiration_time: 2000,
      revocation_time: "0",
      ref_uid: [new Uint8Array(32).fill(0)],
      recipient: ACCOUNT_ADDR,
      attester: CONTRACT_ID,
      revocable: true,
      data: "payload",
      valid_from: 500n,
    });
    expect(decodedAtt.uid).toBe(SAMPLE_UID);
    expect(decodedAtt.time).toBe(1000n);
    expect(decodedAtt.expirationTime).toBe(2000n);
    expect(decodedAtt.validFrom).toBe(500n);
    expect(() => decodeAttestationRecord("bad")).toThrow(SASClientError);
  });

  it("simulates getAttestation, getSchema, getAttestationsByRecipient, and getEvents via rpc.Server", async () => {
    const attestationScVal = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("attester"),
        val: Address.fromString(CONTRACT_ID).toScVal(),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("data"),
        val: xdr.ScVal.scvBytes(Buffer.from("hello")),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("expiration_time"),
        val: nativeToScVal(0n, { type: "u64" }),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("recipient"),
        val: Address.fromString(ACCOUNT_ADDR).toScVal(),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("ref_uid"),
        val: uidToScVal(ZERO_UID),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("revocable"),
        val: xdr.ScVal.scvBool(true),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("revocation_time"),
        val: nativeToScVal(0n, { type: "u64" }),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("schema_uid"),
        val: uidToScVal(SAMPLE_SCHEMA_UID),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("time"),
        val: nativeToScVal(1_700_000_000n, { type: "u64" }),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("uid"),
        val: uidToScVal(SAMPLE_UID),
      }),
    ]);

    const schemaScVal = xdr.ScVal.scvMap([
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("deprecated"),
        val: xdr.ScVal.scvBool(false),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("resolver"),
        val: Address.fromString(CONTRACT_ID).toScVal(),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("revocable"),
        val: xdr.ScVal.scvBool(true),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("schema"),
        val: xdr.ScVal.scvString("verified bool"),
      }),
      new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol("uid"),
        val: uidToScVal(SAMPLE_SCHEMA_UID),
      }),
    ]);

    const uidsVecScVal = xdr.ScVal.scvVec([uidToScVal(SAMPLE_UID)]);

    const simulateTransaction = vi
      .fn()
      // 1. getAttestation -> returns attestationScVal
      .mockResolvedValueOnce({
        result: { retval: attestationScVal },
      })
      // 2. getAttestation -> returns scvVoid (null)
      .mockResolvedValueOnce({
        result: { retval: xdr.ScVal.scvVoid() },
      })
      // 3. getSchema -> returns schemaScVal
      .mockResolvedValueOnce({
        result: { retval: schemaScVal },
      })
      // 4. getAttestationsByRecipient (indexer get_attestations_by_recipient) -> returns [SAMPLE_UID]
      .mockResolvedValueOnce({
        result: { retval: uidsVecScVal },
      })
      // 5. getAttestation called inside getAttestationsByRecipient -> returns attestationScVal
      .mockResolvedValueOnce({
        result: { retval: attestationScVal },
      })
      // 6. getAttestationUidsByRecipient with pagination & includeRevoked: false
      .mockResolvedValueOnce({
        result: { retval: uidsVecScVal },
      });

    const getLatestLedger = vi.fn().mockResolvedValue({ sequence: 250 });
    const getEvents = vi.fn().mockResolvedValue({
      latestLedger: 251,
      events: [
        {
          topic: [xdr.ScVal.scvSymbol("REVOKED"), uidToScVal(SAMPLE_UID)],
          value: xdr.ScVal.scvMap([
            new xdr.ScMapEntry({
              key: xdr.ScVal.scvSymbol("uid"),
              val: uidToScVal(SAMPLE_UID),
            }),
            new xdr.ScMapEntry({
              key: xdr.ScVal.scvSymbol("timestamp"),
              val: nativeToScVal(999n, { type: "u64" }),
            }),
          ]),
          ledger: 251,
        },
      ],
    });

    const mockServer = {
      simulateTransaction,
      getLatestLedger,
      getEvents,
    } as unknown as rpc.Server;

    const client = new SASRpcClient({
      rpcUrl: "https://soroban-testnet.stellar.org",
      networkPassphrase: "Test SDF Network ; September 2015",
      contractId: CONTRACT_ID,
      registryContractId: REGISTRY_ID,
      indexerContractId: INDEXER_ID,
      account: ACCOUNT_ADDR,
      server: mockServer,
    });

    const att = await client.getAttestation(SAMPLE_UID);
    expect(att?.uid).toBe(SAMPLE_UID);
    expect(att?.recipient).toBe(ACCOUNT_ADDR);

    const missingAtt = await client.getAttestation(SAMPLE_UID);
    expect(missingAtt).toBeNull();

    const schema = await client.getSchema(SAMPLE_SCHEMA_UID);
    expect(schema?.uid).toBe(SAMPLE_SCHEMA_UID);
    expect(schema?.schema).toBe("verified bool");

    const recipientAtts = await client.getAttestationsByRecipient(ACCOUNT_ADDR);
    expect(recipientAtts).toHaveLength(1);
    expect(recipientAtts[0]?.uid).toBe(SAMPLE_UID);

    const paginatedUids = await client.getAttestationUidsByRecipient(ACCOUNT_ADDR, {
      cursor: 0,
      limit: 10,
      includeRevoked: false,
    });
    expect(paginatedUids).toEqual([SAMPLE_UID]);

    const polled = await client.getEvents();
    expect(polled.latestLedger).toBe(251);
    expect(polled.events).toHaveLength(1);
    expect(polled.events[0]?.type).toBe("AttestationRevoked");
  });

  it("throws descriptive SASClientError when contract IDs are missing or address is invalid", async () => {
    const unconfiguredClient = new SASRpcClient({
      rpcUrl: "https://soroban-testnet.stellar.org",
      networkPassphrase: "Test SDF Network ; September 2015",
    });

    await expect(unconfiguredClient.getAttestation(SAMPLE_UID)).rejects.toThrow(
      /SAS contractId is required/,
    );
    await expect(unconfiguredClient.getSchema(SAMPLE_SCHEMA_UID)).rejects.toThrow(
      /Schema Registry registryContractId is required/,
    );
    await expect(
      unconfiguredClient.getAttestationsByRecipient("bad-address"),
    ).rejects.toThrow(/Invalid recipient address/);
    await expect(
      unconfiguredClient.getAttestationsByRecipient(ACCOUNT_ADDR),
    ).rejects.toThrow(/Indexer indexerContractId is required/);

    const emptyEvents = await unconfiguredClient.getEvents(100);
    expect(emptyEvents).toEqual({ events: [], latestLedger: 100 });

    // Simulation failure and empty result handling
    const errorServer = {
      simulateTransaction: vi
        .fn()
        .mockRejectedValueOnce(new Error("transport failure"))
        .mockResolvedValueOnce({ error: "HostError: trapped" })
        .mockResolvedValueOnce({}),
    } as unknown as rpc.Server;

    const failingClient = new SASRpcClient({
      rpcUrl: "http://localhost:8000/soroban/rpc",
      networkPassphrase: "Standalone Network ; February 2017",
      contractId: CONTRACT_ID,
      registryContractId: REGISTRY_ID,
      indexerContractId: INDEXER_ID,
      server: errorServer,
    });

    await expect(failingClient.getAttestation(SAMPLE_UID)).rejects.toThrow(
      /RPC request failed/,
    );
    await expect(failingClient.getAttestation(SAMPLE_UID)).rejects.toThrow(
      /Contract call get_attestation failed: HostError: trapped/,
    );
    await expect(failingClient.getAttestation(SAMPLE_UID)).rejects.toThrow(
      /returned no simulation result/,
    );
    await expect(
      failingClient.simulateContractCall("invalid-contract", "foo", []),
    ).rejects.toThrow(/Invalid contract ID/);
  });
});
