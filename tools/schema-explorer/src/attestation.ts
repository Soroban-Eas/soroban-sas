// Attestation deep-link verification, Soroban RPC query, and offline cryptographic proof.

import {
  Account,
  BASE_FEE,
  Contract,
  Keypair,
  TransactionBuilder,
  rpc,
  scValToNative,
  xdr,
} from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { PRESETS } from "./config.js";
import { hexToBytes } from "./hex.js";

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

const NULL_ACCOUNT = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

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
