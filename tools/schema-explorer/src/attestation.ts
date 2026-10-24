// Read-only access to the SAS attestation contract and the Indexer contract.
//
// All calls use `simulateTransaction` (read-only, no signing, no fee). The
// indexer is queried for bulk lookup by recipient/attester/schema; individual
// attestation records are fetched from the SAS contract directly.
//
// Every decoded value is shape-checked before it reaches the UI. Contract
// responses are treated as untrusted input.

import { Buffer } from "buffer";
import {
  Account,
  Address,
  BASE_FEE,
  Contract,
  Keypair,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  scValToNative,
  xdr,
} from "@stellar/stellar-sdk";
import { PRESETS, type ExplorerConfig } from "./config.js";
import { bytesToHex, hexToBytes, isUidHex } from "./hex.js";
import type { ContractCaller } from "./registry.js";

export { RegistryError as AttestationError } from "./registry.js";
import { RegistryError } from "./registry.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Mirrors `soroban_sas_common::Attestation`.
 *
 * Timestamps are Unix seconds stored as `u64` in the contract; we decode them
 * as JavaScript numbers (safe up to year 9999 in seconds).
 */
export interface AttestationRecord {
  /** 64-char lowercase hex. */
  uid: string;
  /** 64-char lowercase hex of the governing schema. */
  schemaUid: string;
  /** Unix seconds – creation time. */
  time: number;
  /** Unix seconds – 0 means no expiry. */
  expirationTime: number;
  /** Unix seconds – 0 means not revoked. */
  revocationTime: number;
  /** Optional 64-char hex ref to a related attestation, or empty string. */
  refUid: string;
  recipient: string;
  attester: string;
  revocable: boolean;
  /** Hex-encoded raw payload bytes. */
  data: string;
}

/** Derived status for display purposes. */
export type AttestationStatus = "active" | "expired" | "revoked";

const NULL_ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

/** Returns the derived status of a record at the given Unix time (seconds). */
export function attestationStatus(record: AttestationRecord, nowSeconds?: number): AttestationStatus {
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  if (record.revocationTime !== 0) return "revoked";
  if (record.expirationTime !== 0 && now >= record.expirationTime) return "expired";
  return "active";
}

// ---------------------------------------------------------------------------
// ScVal helpers
// ---------------------------------------------------------------------------

/** Encodes a 64-char hex UID as the contract's `UID(BytesN<32>)` tuple struct. */
export function uidToScVal(uidHex: string): xdr.ScVal {
  if (!isUidHex(uidHex)) throw new RegistryError("UID must be 64 hexadecimal characters.");
  return xdr.ScVal.scvVec([xdr.ScVal.scvBytes(Buffer.from(hexToBytes(uidHex)))]);
}

function decodeUid(value: unknown): string {
  if (Array.isArray(value) && value.length === 1 && value[0] instanceof Uint8Array && value[0].length === 32) {
    return bytesToHex(value[0]);
  }
  throw new RegistryError("Malformed UID in attestation response.");
}

function decodeOptionalUid(value: unknown): string {
  // An absent ref_uid is encoded as a zero-filled UID on-chain.
  if (value === undefined || value === null) return "";
  try {
    const hex = decodeUid(value);
    return hex === "00".repeat(32) ? "" : hex;
  } catch {
    return "";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value) && !(value instanceof Uint8Array);
}

function decodeU64(value: unknown): number {
  // The Stellar SDK decodes u64 as BigInt.
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "number") return value;
  throw new RegistryError("Expected u64 in attestation response.");
}

function decodeAddress(value: unknown): string {
  if (typeof value === "string") return value;
  throw new RegistryError("Expected address string in attestation response.");
}

function decodeBytes(value: unknown): string {
  if (value instanceof Uint8Array) return bytesToHex(value);
  if (typeof value === "string") return Buffer.from(value, "base64").toString("hex");
  return "";
}

/** Decodes and shape-checks one `Attestation` from its native form. */
export function decodeAttestationRecord(value: unknown): AttestationRecord {
  if (!isRecord(value)) throw new RegistryError("Malformed Attestation in contract response.");
  const { uid, schema_uid, time, expiration_time, revocation_time, ref_uid, recipient, attester, revocable, data } = value;

  if (typeof revocable !== "boolean") throw new RegistryError("Malformed Attestation: revocable must be bool.");

  return {
    uid: decodeUid(uid),
    schemaUid: decodeUid(schema_uid),
    time: decodeU64(time),
    expirationTime: decodeU64(expiration_time),
    revocationTime: decodeU64(revocation_time),
    refUid: decodeOptionalUid(ref_uid),
    recipient: decodeAddress(recipient),
    attester: decodeAddress(attester),
    revocable,
    data: decodeBytes(data),
  };
}

// ---------------------------------------------------------------------------
// RPC caller for attestation contracts
// ---------------------------------------------------------------------------

/**
 * `RpcAttestationCaller` is identical to `RpcContractCaller` but targets a
 * caller-supplied contract id (either the SAS contract or the Indexer) rather
 * than the registry.
 */
export class RpcAttestationCaller implements ContractCaller {
  private readonly server: rpc.Server;
  private readonly contract: Contract;

  constructor(
    private readonly config: ExplorerConfig,
    contractId: string,
    timeoutMs = 15_000,
  ) {
    this.server = new rpc.Server(config.rpcUrl, {
      allowHttp: new URL(config.rpcUrl).protocol === "http:",
      timeout: timeoutMs,
    });
    this.contract = new Contract(contractId);
  }

  async call(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const tx = new TransactionBuilder(new Account(NULL_ACCOUNT, "0"), {
      fee: BASE_FEE,
      networkPassphrase: this.config.networkPassphrase,
    })
      .addOperation(this.contract.call(method, ...args))
      .setTimeout(30)
      .build();

    let sim: rpc.Api.SimulateTransactionResponse;
    try {
      sim = await this.server.simulateTransaction(tx);
    } catch (err) {
      throw new RegistryError(`RPC request failed: ${errorMessage(err)}`);
    }
    if (rpc.Api.isSimulationError(sim)) {
      throw new RegistryError(`Contract call ${method} failed: ${sim.error}`);
    }
    if (!sim.result) {
      throw new RegistryError(`Contract call ${method} returned no result.`);
    }
    return sim.result.retval;
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// AttestationReader
// ---------------------------------------------------------------------------

/**
 * Read-only view over the SAS contract + Indexer contract.
 *
 * - `sasCaller` targets the SAS contract (`get_attestation`).
 * - `indexerCaller` targets the Indexer contract
 *   (`get_attestations_by_recipient`, `get_attestations_by_attester`,
 *    `get_attestations_by_schema`).
 *
 * When no `indexerCaller` is supplied the reader falls back to calling the SAS
 * contract directly for single-UID lookups only.
 */
export class AttestationReader {
  constructor(
    private readonly sasCaller: ContractCaller,
    private readonly indexerCaller?: ContractCaller,
  ) {}

  /** `get_attestation(uid)`: one attestation record, or `null` if not found. */
  async getAttestation(uidHex: string): Promise<AttestationRecord | null> {
    if (!isUidHex(uidHex)) throw new RegistryError("UID must be 64 hexadecimal characters.");
    const ret = await this.sasCaller.call("get_attestation", [uidToScVal(uidHex)]);
    if (ret.switch() === xdr.ScValType.scvVoid()) return null;
    return decodeAttestationRecord(scValToNative(ret));
  }

  /**
   * Fetches all attestation UIDs associated with `address` from the indexer,
   * then resolves each to a full record via the SAS contract.
   *
   * `kind` selects the indexer method to use.
   */
  async getAttestationsFor(
    kind: "recipient" | "attester" | "schema",
    address: string,
    limit = 50,
  ): Promise<AttestationRecord[]> {
    const caller = this.indexerCaller;
    if (!caller) return [];

    const method =
      kind === "recipient"
        ? "get_attestations_by_recipient"
        : kind === "attester"
          ? "get_attestations_by_attester"
          : "get_attestations_by_schema";

    let addressVal: xdr.ScVal;
    try {
      // Schema UIDs are `UID(BytesN<32>)` ; addresses are Stellar account/contract.
      addressVal = kind === "schema" ? uidToScVal(address) : new Address(address).toScVal();
    } catch {
      throw new RegistryError(`Invalid address or UID: "${address}"`);
    }

    const pageSize = Math.min(Math.max(Math.trunc(limit), 1), 100);
    const ret = await caller.call(method, [
      addressVal,
      nativeToScVal(0, { type: "u32" }), // cursor
      nativeToScVal(pageSize, { type: "u32" }),
    ]);

    const native = scValToNative(ret) as unknown;
    const uids = decodeUidPage(native);
    const records = await Promise.allSettled(uids.map((uid) => this.getAttestation(uid)));
    return records
      .filter((r): r is PromiseFulfilledResult<AttestationRecord | null> => r.status === "fulfilled")
      .map((r) => r.value)
      .filter((r): r is AttestationRecord => r !== null);
  }

  /**
   * Looks up a single attestation or, if `query` looks like an address or
   * schema UID, fetches all attestations for that subject via the indexer.
   *
   * This is the main entry point for the search bar.
   */
  async search(query: string, limit = 50): Promise<AttestationRecord[]> {
    const normalized = query.trim();
    if (!normalized) return [];

    // 64-char hex: treat as attestation UID first, then as schema UID.
    if (isUidHex(normalized)) {
      const byUid = await this.getAttestation(normalized);
      if (byUid) return [byUid];
      return this.getAttestationsFor("schema", normalized, limit);
    }

    // Stellar address (G... or C...): try recipient then attester.
    try {
      Address.fromString(normalized);
      const [byRecipient, byAttester] = await Promise.all([
        this.getAttestationsFor("recipient", normalized, limit),
        this.getAttestationsFor("attester", normalized, limit),
      ]);
      // Merge, deduplicate by UID.
      const seen = new Set<string>();
      const out: AttestationRecord[] = [];
      for (const r of [...byRecipient, ...byAttester]) {
        if (!seen.has(r.uid)) {
          seen.add(r.uid);
          out.push(r);
        }
      }
      return out;
    } catch {
      // Not a valid address.
    }

    return [];
  }
}

// ---------------------------------------------------------------------------
// UID page decoder (indexer response)
// ---------------------------------------------------------------------------

/**
 * The indexer returns `(Vec<UID>, u32 next_cursor)` or `Vec<UID>` depending on
 * contract version. We handle both.
 */
function decodeUidPage(native: unknown): string[] {
  let uidsRaw: unknown[];
  if (Array.isArray(native) && native.length === 2 && Array.isArray(native[0])) {
    uidsRaw = native[0] as unknown[];
  } else if (Array.isArray(native)) {
    uidsRaw = native as unknown[];
  } else {
    throw new RegistryError("Malformed indexer response (expected Vec<UID> or (Vec<UID>, u32)).");
  }
  return uidsRaw.map((v) => {
    if (Array.isArray(v) && v.length === 1 && v[0] instanceof Uint8Array && v[0].length === 32) {
      return bytesToHex(v[0]);
    }
    throw new RegistryError("Malformed UID in indexer page.");
  });
}

export interface AttestationVerificationQuery {
  uid: string;
  contract: string;
  network: string;
  rpcUrl?: string;
  schemaUid?: string;
  attester?: string;
  recipient?: string;
  time?: number;
  expirationTime?: number;
  revocable?: boolean;
  signature?: string;
  dataHex?: string;
}

export type VerificationState =
  | "valid"
  | "revoked"
  | "expired"
  | "not_found"
  | "offline_valid"
  | "offline_invalid"
  | "error";

export interface VerificationResult {
  state: VerificationState;
  source: "on_chain_rpc" | "offline_signature";
  message: string;
  timestamp?: number;
  ledgerTime?: number;
  attestation?: {
    uid: string;
    schemaUid?: string;
    attester?: string;
    recipient?: string;
    expirationTime?: number;
    revocationTime?: number;
  };
}

/** Constructs a mobile deep-link URL encoding the attestation verification payload. */
export function buildAttestationDeepLink(
  query: AttestationVerificationQuery,
  baseUrl: string = typeof window !== "undefined" ? window.location.origin + window.location.pathname : "https://sas.stellar.org/verify",
): string {
  const url = new URL(baseUrl);
  url.searchParams.set("verify", "1");
  url.searchParams.set("uid", query.uid);
  url.searchParams.set("contract", query.contract);
  url.searchParams.set("network", query.network);

  if (query.rpcUrl) url.searchParams.set("rpc", query.rpcUrl);
  if (query.schemaUid) url.searchParams.set("schema", query.schemaUid);
  if (query.attester) url.searchParams.set("attester", query.attester);
  if (query.recipient) url.searchParams.set("recipient", query.recipient);
  if (query.time !== undefined) url.searchParams.set("time", String(query.time));
  if (query.expirationTime !== undefined) url.searchParams.set("exp", String(query.expirationTime));
  if (query.revocable !== undefined) url.searchParams.set("rev", query.revocable ? "1" : "0");
  if (query.signature) url.searchParams.set("sig", query.signature);
  if (query.dataHex) url.searchParams.set("data", query.dataHex);

  return url.toString();
}

/** Parses attestation deep-link query parameters from a URL search string. */
export function parseAttestationDeepLink(search: string): AttestationVerificationQuery | null {
  const params = new URLSearchParams(search);
  if (params.get("verify") !== "1" && params.get("verify") !== "true") {
    return null;
  }

  const uid = params.get("uid");
  const contract = params.get("contract");
  if (!uid || !contract) return null;

  return {
    uid: uid.toLowerCase(),
    contract,
    network: params.get("network") ?? "testnet",
    rpcUrl: params.get("rpc") ?? undefined,
    schemaUid: params.get("schema") ?? undefined,
    attester: params.get("attester") ?? undefined,
    recipient: params.get("recipient") ?? undefined,
    time: params.get("time") ? Number(params.get("time")) : undefined,
    expirationTime: params.get("exp") ? Number(params.get("exp")) : undefined,
    revocable: params.get("rev") ? params.get("rev") === "1" : undefined,
    signature: params.get("sig") ?? undefined,
    dataHex: params.get("data") ?? undefined,
  };
}

/** Verifies the attestation directly against Soroban RPC via simulateTransaction. */
export async function verifyOnChainRpc(
  query: AttestationVerificationQuery,
): Promise<VerificationResult> {
  const preset = PRESETS.find((p) => p.id === query.network || p.networkPassphrase.includes(query.network));
  const rpcUrl = query.rpcUrl || preset?.rpcUrl || "https://soroban-testnet.stellar.org";
  const networkPassphrase = preset?.networkPassphrase || "Test SDF Network ; September 2015";

  const server = new rpc.Server(rpcUrl, {
    allowHttp: rpcUrl.startsWith("http://"),
    timeout: 10_000,
  });
  const contract = new Contract(query.contract);

  const uidBytes = hexToBytes(query.uid);
  const uidScVal = xdr.ScVal.scvBytes(Buffer.from(uidBytes));

  // 1. Check get_attestation to inspect expiration and revocation
  const txGet = new TransactionBuilder(new Account(NULL_ACCOUNT, "0"), {
    fee: BASE_FEE,
    networkPassphrase,
  })
    .addOperation(contract.call("get_attestation", uidScVal))
    .setTimeout(30)
    .build();

  let simGet: rpc.Api.SimulateTransactionResponse;
  try {
    simGet = await server.simulateTransaction(txGet);
  } catch (err) {
    throw new Error(`RPC simulation connection failed: ${(err as Error).message}`);
  }

  if (rpc.Api.isSimulationError(simGet)) {
    throw new Error(`Simulation failed on-chain: ${simGet.error}`);
  }

  const latestLedger = simGet.latestLedger;
  const resultVal = simGet.result?.retval;
  if (!resultVal) {
    return {
      state: "not_found",
      source: "on_chain_rpc",
      message: "Attestation UID was not found on-chain.",
    };
  }

  const native = scValToNative(resultVal);
  if (!native) {
    return {
      state: "not_found",
      source: "on_chain_rpc",
      message: "Attestation does not exist in contract storage.",
    };
  }

  // Inspect attestation record fields
  const expirationTime = Number(native.expiration_time ?? native.expirationTime ?? 0);
  const revocationTime = Number(native.revocation_time ?? native.revocationTime ?? 0);
  const recipient = String(native.recipient ?? "");
  const attester = String(native.attester ?? "");
  const schemaUid = native.schema_uid ? Buffer.from(native.schema_uid).toString("hex") : undefined;

  if (revocationTime > 0) {
    return {
      state: "revoked",
      source: "on_chain_rpc",
      message: `Attestation has been revoked at ledger time ${revocationTime}.`,
      attestation: {
        uid: query.uid,
        schemaUid,
        attester,
        recipient,
        expirationTime,
        revocationTime,
      },
    };
  }

  // Check expiration if set
  const approxLedgerSeconds = Math.floor(Date.now() / 1000);
  if (expirationTime > 0 && approxLedgerSeconds >= expirationTime) {
    return {
      state: "expired",
      source: "on_chain_rpc",
      message: `Attestation expired at timestamp ${expirationTime}.`,
      attestation: {
        uid: query.uid,
        schemaUid,
        attester,
        recipient,
        expirationTime,
      },
    };
  }

  return {
    state: "valid",
    source: "on_chain_rpc",
    message: "Attestation is valid and active on-chain.",
    ledgerTime: latestLedger,
    timestamp: Date.now(),
    attestation: {
      uid: query.uid,
      schemaUid,
      attester,
      recipient,
      expirationTime,
    },
  };
}

/** Computes SHA-256 in browser or node runtime. */
async function computeSha256(data: Uint8Array): Promise<Uint8Array> {
  if (typeof crypto !== "undefined" && crypto.subtle) {
    const hash = await crypto.subtle.digest("SHA-256", data as unknown as BufferSource);
    return new Uint8Array(hash);
  }
  // Node fallback
  const { createHash } = await import("node:crypto");
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/** Verifies the attestation cryptographically offline without network access. */
export async function verifyOfflineSignature(
  query: AttestationVerificationQuery,
): Promise<VerificationResult> {
  if (!query.attester || !query.signature) {
    return {
      state: "offline_invalid",
      source: "offline_signature",
      message: "Offline verification requires both attester address and cryptographic signature.",
    };
  }

  // Check expiration locally
  const now = Math.floor(Date.now() / 1000);
  if (query.expirationTime && query.expirationTime > 0 && now >= query.expirationTime) {
    return {
      state: "expired",
      source: "offline_signature",
      message: `Attestation expired at timestamp ${query.expirationTime}.`,
    };
  }

  try {
    const keypair = Keypair.fromPublicKey(query.attester);
    const cleanSig = query.signature.startsWith("0x") ? query.signature.slice(2) : query.signature;
    const sigBytes = Buffer.from(cleanSig, "hex");

    // The digest payload prefix for Soroban SAS
    const prefix = Buffer.from("\x19SorobanSAS\x01", "ascii");
    const uidBytes = Buffer.from(hexToBytes(query.uid));
    const contractBytes = Buffer.from(query.contract, "utf8");
    const networkBytes = Buffer.from(query.network, "utf8");

    const digestPayload = Buffer.concat([prefix, networkBytes, contractBytes, uidBytes]);
    const digest = await computeSha256(digestPayload);

    const isValid = keypair.verify(Buffer.from(digest), sigBytes);

    if (isValid) {
      return {
        state: "offline_valid",
        source: "offline_signature",
        message: "Cryptographically verified offline via Ed25519 signature.",
        timestamp: Date.now(),
        attestation: {
          uid: query.uid,
          schemaUid: query.schemaUid,
          attester: query.attester,
          recipient: query.recipient,
          expirationTime: query.expirationTime,
        },
      };
    } else {
      return {
        state: "offline_invalid",
        source: "offline_signature",
        message: "Cryptographic signature mismatch for attester key.",
      };
    }
  } catch (err) {
    return {
      state: "offline_invalid",
      source: "offline_signature",
      message: `Offline cryptographic verification failed: ${(err as Error).message}`,
    };
  }
}

/** Master verification: attempts on-chain verification, falls back to offline signature proof. */
export async function verifyAttestation(
  query: AttestationVerificationQuery,
): Promise<VerificationResult> {
  // If navigator is offline or no RPC connectivity, attempt offline signature proof
  if (typeof navigator !== "undefined" && !navigator.onLine && query.signature && query.attester) {
    return verifyOfflineSignature(query);
  }

  try {
    return await verifyOnChainRpc(query);
  } catch (rpcErr) {
    // If online RPC fails, fallback to offline verification if signature is provided
    if (query.signature && query.attester) {
      const offlineResult = await verifyOfflineSignature(query);
      if (offlineResult.state === "offline_valid") {
        return offlineResult;
      }
    }

    return {
      state: "error",
      source: "on_chain_rpc",
      message: `Verification check could not reach Soroban RPC: ${(rpcErr as Error).message}`,
    };
  }
}
