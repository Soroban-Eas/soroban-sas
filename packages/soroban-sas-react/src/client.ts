import { Buffer } from "buffer";
import {
  Account,
  Address,
  BASE_FEE,
  Contract,
  StrKey,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  scValToNative,
  xdr,
} from "@stellar/stellar-sdk";
import { parseRpcContractEvent } from "./events.js";
import type {
  Attestation,
  NetworkName,
  RecipientQueryOptions,
  SASClientLike,
  SASEvent,
  SASNetworkConfig,
  SchemaRecord,
  UID,
} from "./types.js";

export const NETWORK_PRESETS: Readonly<Record<string, SASNetworkConfig>> = {
  local: {
    id: "local",
    label: "Local (Docker Quickstart)",
    rpcUrl: "http://localhost:8000/soroban/rpc",
    networkPassphrase: "Standalone Network ; February 2017",
  },
  testnet: {
    id: "testnet",
    label: "Stellar Testnet",
    rpcUrl: "https://soroban-testnet.stellar.org",
    networkPassphrase: "Test SDF Network ; September 2015",
  },
  futurenet: {
    id: "futurenet",
    label: "Stellar Futurenet",
    rpcUrl: "https://rpc-futurenet.stellar.org",
    networkPassphrase: "Test SDF Future Network ; October 2022",
  },
  mainnet: {
    id: "mainnet",
    label: "Stellar Mainnet",
    rpcUrl: "https://mainnet.sorobanrpc.com",
    networkPassphrase: "Public Global Stellar Network ; September 2015",
  },
};

export interface NetworkOverrides {
  rpcUrl?: string;
  networkPassphrase?: string;
  contractId?: string;
  registryContractId?: string;
  indexerContractId?: string;
}

/**
 * Resolves a network preset name or partial config object into a complete `SASNetworkConfig`.
 */
export function resolveNetworkConfig(
  network: NetworkName | SASNetworkConfig = "testnet",
  overrides: NetworkOverrides = {},
): SASNetworkConfig {
  const base: SASNetworkConfig =
    typeof network === "string"
      ? (NETWORK_PRESETS[network] ?? {
          id: network,
          label: network,
          rpcUrl: overrides.rpcUrl ?? NETWORK_PRESETS.testnet.rpcUrl,
          networkPassphrase:
            overrides.networkPassphrase ?? NETWORK_PRESETS.testnet.networkPassphrase,
        })
      : network;

  return {
    id: base.id,
    label: base.label ?? base.id,
    rpcUrl: overrides.rpcUrl ?? base.rpcUrl,
    networkPassphrase: overrides.networkPassphrase ?? base.networkPassphrase,
    contractId: overrides.contractId ?? base.contractId,
    registryContractId: overrides.registryContractId ?? base.registryContractId,
    indexerContractId: overrides.indexerContractId ?? base.indexerContractId,
  };
}

export class SASClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SASClientError";
  }
}

const UID_HEX_RE = /^[0-9a-fA-F]{64}$/;
const NULL_ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

/** Checks whether `uid` is a valid 32-byte (64 hex characters, optional "0x" prefix) UID. */
export function isValidUid(uid: string): boolean {
  const trimmed = uid.trim();
  const stripped =
    trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
  return UID_HEX_RE.test(stripped);
}

/** Normalizes a 32-byte hex UID into 64 lowercase hex characters without "0x" prefix. */
export function normalizeUid(uid: string): UID {
  const trimmed = uid.trim();
  const stripped =
    trimmed.startsWith("0x") || trimmed.startsWith("0X") ? trimmed.slice(2) : trimmed;
  if (!UID_HEX_RE.test(stripped)) {
    throw new SASClientError(
      `Invalid UID "${uid}": expected 64 hexadecimal characters (32 bytes).`,
    );
  }
  return stripped.toLowerCase();
}

/** Checks whether `address` is a valid Stellar Ed25519 account (`G...`) or contract (`C...`) strkey. */
export function isValidAddress(address: string): boolean {
  const trimmed = address.trim();
  return StrKey.isValidEd25519PublicKey(trimmed) || StrKey.isValidContract(trimmed);
}

/** Encodes a 64-char hex UID into the contract's `UID(BytesN<32>)` single-element ScVec. */
export function uidToScVal(uid: UID): xdr.ScVal {
  const normalized = normalizeUid(uid);
  return xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.from(normalized, "hex"))]);
}

function isByteView(value: unknown): value is Uint8Array {
  return (
    value instanceof Uint8Array ||
    Buffer.isBuffer(value) ||
    (typeof value === "object" && value !== null && ArrayBuffer.isView(value))
  );
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !isByteView(value)
  );
}

/** Decodes a contract `UID` representation (`[Uint8Array(32)]`, `Uint8Array(32)`, or 64-char hex). */
export function decodeUid(value: unknown): UID {
  if (typeof value === "string" && isValidUid(value)) {
    return normalizeUid(value);
  }
  if (isByteView(value) && value.byteLength === 32) {
    const view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return Buffer.from(view).toString("hex").toLowerCase();
  }
  if (
    Array.isArray(value) &&
    value.length === 1 &&
    isByteView(value[0]) &&
    value[0].byteLength === 32
  ) {
    const first = value[0];
    const view = new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
    return Buffer.from(view).toString("hex").toLowerCase();
  }
  throw new SASClientError("Malformed UID in contract response.");
}

function toBigInt(value: unknown, fieldName: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isInteger(value)) return BigInt(value);
  if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
  throw new SASClientError(`Malformed ${fieldName} timestamp in contract response.`);
}

function toUint8Array(value: unknown): Uint8Array {
  if (isByteView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (Array.isArray(value) && value.every((b) => typeof b === "number")) {
    return new Uint8Array(value);
  }
  if (typeof value === "string") {
    return new Uint8Array(Buffer.from(value, "utf8"));
  }
  throw new SASClientError("Malformed attestation data bytes in contract response.");
}

/** Decodes a native object returned from `SAS::get_attestation` into an `Attestation`. */
export function decodeAttestationRecord(value: unknown): Attestation {
  if (!isPlainRecord(value)) {
    throw new SASClientError("Malformed Attestation in contract response.");
  }

  const uid = decodeUid(value.uid);
  const schemaUid = decodeUid(value.schema_uid ?? value.schemaUid);
  const refUid = decodeUid(value.ref_uid ?? value.refUid);
  const time = toBigInt(value.time, "time");
  const expirationTime = toBigInt(
    value.expiration_time ?? value.expirationTime ?? 0n,
    "expirationTime",
  );
  const revocationTime = toBigInt(
    value.revocation_time ?? value.revocationTime ?? 0n,
    "revocationTime",
  );
  const recipient = value.recipient;
  const attester = value.attester;
  const revocable = value.revocable;

  if (
    typeof recipient !== "string" ||
    typeof attester !== "string" ||
    typeof revocable !== "boolean"
  ) {
    throw new SASClientError("Malformed Attestation fields in contract response.");
  }

  const data = toUint8Array(value.data ?? new Uint8Array());
  const rawValidFrom = value.valid_from ?? value.validFrom;
  const validFrom = rawValidFrom !== undefined ? toBigInt(rawValidFrom, "validFrom") : undefined;

  return {
    uid,
    schemaUid,
    time,
    expirationTime,
    revocationTime,
    refUid,
    recipient,
    attester,
    revocable,
    data,
    ...(validFrom !== undefined ? { validFrom } : {}),
  };
}

/** Decodes a native object returned from `SchemaRegistry::get_schema` into a `SchemaRecord`. */
export function decodeSchemaRecord(value: unknown): SchemaRecord {
  if (!isPlainRecord(value)) {
    throw new SASClientError("Malformed SchemaRecord in contract response.");
  }

  const { uid, resolver, revocable, schema, deprecated } = value;
  if (
    typeof resolver !== "string" ||
    typeof schema !== "string" ||
    typeof revocable !== "boolean"
  ) {
    throw new SASClientError("Malformed SchemaRecord fields in contract response.");
  }

  return {
    uid: decodeUid(uid),
    resolver,
    revocable,
    schema,
    deprecated: deprecated === true,
  };
}

export interface SASRpcClientOptions {
  rpcUrl: string;
  networkPassphrase: string;
  contractId?: string;
  registryContractId?: string;
  indexerContractId?: string;
  account?: string | null;
  timeoutMs?: number;
  server?: rpc.Server;
}

/**
 * Default Soroban RPC client for read-only SAS, Schema Registry, and Indexer queries.
 * Uses `simulateTransaction` against the configured Soroban RPC endpoint.
 */
export class SASRpcClient implements SASClientLike {
  readonly rpcUrl: string;
  readonly networkPassphrase: string;
  readonly contractId?: string;
  readonly registryContractId?: string;
  readonly indexerContractId?: string;
  readonly account?: string | null;
  private readonly server: rpc.Server;

  constructor(options: SASRpcClientOptions) {
    this.rpcUrl = options.rpcUrl;
    this.networkPassphrase = options.networkPassphrase;
    this.contractId = options.contractId;
    this.registryContractId = options.registryContractId;
    this.indexerContractId = options.indexerContractId;
    this.account = options.account;
    this.server =
      options.server ??
      new rpc.Server(options.rpcUrl, {
        allowHttp: options.rpcUrl.startsWith("http://"),
        timeout: options.timeoutMs ?? 15_000,
      });
  }

  private sourceAccountAddress(): string {
    if (this.account && StrKey.isValidEd25519PublicKey(this.account)) {
      return this.account;
    }
    return NULL_ACCOUNT;
  }

  /** Executes a read-only contract invocation via `simulateTransaction`. */
  async simulateContractCall(
    contractId: string,
    method: string,
    args: xdr.ScVal[],
  ): Promise<xdr.ScVal> {
    if (!StrKey.isValidContract(contractId)) {
      throw new SASClientError(`Invalid contract ID "${contractId}": expected a C... address.`);
    }

    const contract = new Contract(contractId);
    const tx = new TransactionBuilder(new Account(this.sourceAccountAddress(), "0"), {
      fee: BASE_FEE,
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(contract.call(method, ...args))
      .setTimeout(30)
      .build();

    let sim: rpc.Api.SimulateTransactionResponse;
    try {
      sim = await this.server.simulateTransaction(tx);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new SASClientError(`RPC request failed for ${method}: ${msg}`);
    }

    if (rpc.Api.isSimulationError(sim)) {
      throw new SASClientError(`Contract call ${method} failed: ${sim.error}`);
    }

    if (!sim.result) {
      throw new SASClientError(`Contract call ${method} returned no simulation result.`);
    }

    return sim.result.retval;
  }

  /** Fetches a single attestation by UID from `SAS::get_attestation(uid)`. */
  async getAttestation(uid: UID): Promise<Attestation | null> {
    const normalized = normalizeUid(uid);
    if (!this.contractId) {
      throw new SASClientError(
        "SAS contractId is required on SASProvider or SASRpcClient to call getAttestation.",
      );
    }

    const retval = await this.simulateContractCall(this.contractId, "get_attestation", [
      uidToScVal(normalized),
    ]);

    if (retval.switch() === xdr.ScValType.scvVoid()) {
      return null;
    }

    const native = scValToNative(retval);
    if (native === null || native === undefined) {
      return null;
    }

    return decodeAttestationRecord(native);
  }

  /** Fetches a single schema record by UID from `SchemaRegistry::get_schema(schemaUid)`. */
  async getSchema(schemaUid: UID): Promise<SchemaRecord | null> {
    const normalized = normalizeUid(schemaUid);
    if (!this.registryContractId) {
      throw new SASClientError(
        "Schema Registry registryContractId is required on SASProvider or SASRpcClient to call getSchema.",
      );
    }

    const retval = await this.simulateContractCall(this.registryContractId, "get_schema", [
      uidToScVal(normalized),
    ]);

    if (retval.switch() === xdr.ScValType.scvVoid()) {
      return null;
    }

    const native = scValToNative(retval);
    if (native === null || native === undefined) {
      return null;
    }

    return decodeSchemaRecord(native);
  }

  /**
   * Queries the Indexer contract for all attestation UIDs associated with `recipient`.
   */
  async getAttestationUidsByRecipient(
    recipient: string,
    options?: RecipientQueryOptions,
  ): Promise<UID[]> {
    const trimmed = recipient.trim();
    if (!isValidAddress(trimmed)) {
      throw new SASClientError(
        `Invalid recipient address "${recipient}": expected a valid Stellar G... or C... address.`,
      );
    }
    if (!this.indexerContractId) {
      throw new SASClientError(
        "Indexer indexerContractId is required on SASProvider or SASRpcClient to query attestations by recipient.",
      );
    }

    const recipientScVal = Address.fromString(trimmed).toScVal();
    let retval: xdr.ScVal;

    const hasPagination = options?.cursor !== undefined || options?.limit !== undefined;
    if (hasPagination) {
      const cursor = Math.max(0, Math.trunc(options?.cursor ?? 0));
      const limit = Math.max(1, Math.trunc(options?.limit ?? 50));
      if (options?.includeRevoked === false) {
        retval = await this.simulateContractCall(
          this.indexerContractId,
          "get_recipient_page_filtered",
          [
            recipientScVal,
            nativeToScVal(cursor, { type: "u32" }),
            nativeToScVal(limit, { type: "u32" }),
            nativeToScVal(false, { type: "bool" }),
          ],
        );
      } else {
        retval = await this.simulateContractCall(
          this.indexerContractId,
          "get_atts_by_recipient_paginated",
          [
            recipientScVal,
            nativeToScVal(cursor, { type: "u32" }),
            nativeToScVal(limit, { type: "u32" }),
          ],
        );
      }
    } else if (options?.includeRevoked === false) {
      retval = await this.simulateContractCall(this.indexerContractId, "get_recipient_filtered", [
        recipientScVal,
        nativeToScVal(false, { type: "bool" }),
      ]);
    } else {
      retval = await this.simulateContractCall(
        this.indexerContractId,
        "get_attestations_by_recipient",
        [recipientScVal],
      );
    }

    if (retval.switch() === xdr.ScValType.scvVoid()) {
      return [];
    }

    const native = scValToNative(retval);
    if (!Array.isArray(native)) {
      throw new SASClientError("Malformed Indexer recipient response: expected an array of UIDs.");
    }

    return native.map(decodeUid);
  }

  /**
   * Fetches full `Attestation` records for `recipient` by querying the Indexer contract
   * and resolving each returned UID via `getAttestation`.
   */
  async getAttestationsByRecipient(
    recipient: string,
    options?: RecipientQueryOptions,
  ): Promise<Attestation[]> {
    const uids = await this.getAttestationUidsByRecipient(recipient, options);
    if (uids.length === 0) return [];

    const records = await Promise.all(uids.map((uid) => this.getAttestation(uid)));
    return records.filter((item): item is Attestation => item !== null);
  }

  /**
   * Polls Soroban RPC `getEvents` for standardized SAS events starting at `startLedger`.
   */
  async getEvents(startLedger?: number): Promise<{ events: SASEvent[]; latestLedger: number }> {
    const contractIds = [this.contractId, this.registryContractId].filter(
      (id): id is string => Boolean(id && StrKey.isValidContract(id)),
    );

    let ledgerToQuery = startLedger;
    if (ledgerToQuery === undefined) {
      const latest = await this.server.getLatestLedger();
      ledgerToQuery = latest.sequence;
    }

    if (contractIds.length === 0) {
      return { events: [], latestLedger: ledgerToQuery };
    }

    const response = await this.server.getEvents({
      startLedger: ledgerToQuery,
      filters: [
        {
          type: "contract",
          contractIds,
        },
      ],
    });

    const parsedEvents: SASEvent[] = [];
    for (const raw of response.events ?? []) {
      const parsed = parseRpcContractEvent({
        topic: raw.topic,
        value: raw.value,
        ledger: raw.ledger,
      });
      if (parsed) {
        parsedEvents.push(parsed);
      }
    }

    return {
      events: parsedEvents,
      latestLedger: response.latestLedger ?? ledgerToQuery,
    };
  }
}
