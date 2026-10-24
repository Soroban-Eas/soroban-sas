import { Address, BASE_FEE, Contract, Keypair, StrKey, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { computeSchemaUidWasm, validateDraft, type SchemaDraft } from "./designer.js";
import { RegistryReader, RpcContractCaller } from "./registry.js";
import type { ExplorerConfig } from "./config.js";

export const TESTNET_PASSPHRASE = "Test SDF Network ; September 2015";

export interface WalletSigner {
  address: string;
  signTransaction(xdr: string, options: { networkPassphrase: string; address: string }): Promise<{ signedTxXdr: string; signerAddress?: string }>;
}

export interface RegistrationResult {
  uid: string;
  hash: string;
  ledger: number;
}

type TxServer = Pick<rpc.Server, "getAccount" | "prepareTransaction" | "sendTransaction">;
export interface RegisterDeps {
  createServer?: (rpcUrl: string) => TxServer;
  /** Raw RPC transaction polling supports newer protocol results than older typed SDK decoders. */
  getTransaction?: (rpcUrl: string, hash: string) => Promise<{ status: string; ledger?: number }>;
  getSchema?: (config: ExplorerConfig, uid: string) => Promise<unknown>;
  sleep?: (ms: number) => Promise<void>;
}

export async function pollTransaction(rpcUrl: string, hash: string): Promise<{ status: string; ledger?: number }> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "register", method: "getTransaction", params: { hash } }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error("Transaction status RPC request failed: HTTP " + response.status);
  const payload: unknown = await response.json();
  if (typeof payload !== "object" || payload === null || !("result" in payload)) throw new Error("Malformed RPC transaction status");
  const result = payload.result as Record<string, unknown>;
  if (!result || typeof result.status !== "string") throw new Error("Malformed RPC transaction status");
  return { status: result.status, ledger: typeof result.ledger === "number" ? result.ledger : undefined };
}

/** A submission is only made after a user-selected Testnet wallet approves the prepared XDR. */
export async function registerSchema(
  draft: SchemaDraft,
  config: ExplorerConfig,
  wallet: WalletSigner,
  deps: RegisterDeps = {},
): Promise<RegistrationResult> {
  if (config.networkPassphrase !== TESTNET_PASSPHRASE) throw new Error("Schema designer wallet registration supports Testnet only");
  if (!config.rpcUrl.startsWith("https://")) throw new Error("Registration requires an HTTPS RPC endpoint");
  if (!StrKey.isValidContract(config.registryContractId)) throw new Error("Enter a valid deployed Schema Registry contract ID");
  if (!StrKey.isValidEd25519PublicKey(wallet.address)) throw new Error("Wallet did not supply a valid G... account");
  const check = validateDraft(draft);
  if (!check.ok) throw new Error(check.errors.join(" "));
  const expectedUid = await computeSchemaUidWasm(draft);
  const server = deps.createServer?.(config.rpcUrl) ?? new rpc.Server(config.rpcUrl);
  const account = await server.getAccount(wallet.address);
  const contract = new Contract(config.registryContractId);
  const tx = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: config.networkPassphrase })
    .addOperation(contract.call(
      "register",
      Address.fromString(wallet.address).toScVal(),
      xdr.ScVal.scvString(Buffer.from(check.schema, "utf8")),
      Address.fromString(draft.resolver).toScVal(),
      xdr.ScVal.scvBool(draft.revocable),
    ))
    .setTimeout(120).build();
  // Simulation determines Soroban resource limits, auth and transaction fees.
  const prepared = await server.prepareTransaction(tx);
  const requestXdr = prepared.toXDR();
  const response = await wallet.signTransaction(requestXdr, {
    networkPassphrase: config.networkPassphrase,
    address: wallet.address,
  });
  if (!response.signedTxXdr || response.signerAddress && response.signerAddress !== wallet.address) {
    throw new Error("Wallet refused signing or signed with another account");
  }
  const signed = TransactionBuilder.fromXDR(response.signedTxXdr, config.networkPassphrase);
  if (signed.hash().toString("hex") !== prepared.hash().toString("hex")) {
    throw new Error("Wallet changed the transaction contents");
  }
  const accountKey = Keypair.fromPublicKey(wallet.address);
  if (!signed.signatures.some(signature => accountKey.verify(signed.hash(), signature.signature()))) {
    throw new Error("Wallet envelope does not contain a valid account signature");
  }
  const submitted = await server.sendTransaction(signed);
  if (submitted.status === "ERROR" || !submitted.hash) throw new Error("Stellar RPC rejected registration transaction");
  const getTx = deps.getTransaction ?? pollTransaction;
  const sleep = deps.sleep ?? (ms => new Promise<void>(resolve => setTimeout(resolve, ms)));
  for (let attempt = 0; attempt < 25; attempt++) {
    const state = await getTx(config.rpcUrl, submitted.hash);
    if (state.status === "FAILED") throw new Error("Registration failed on Testnet: " + submitted.hash);
    if (state.status === "SUCCESS") {
      const record = deps.getSchema
        ? await deps.getSchema(config, expectedUid)
        : await new RegistryReader(new RpcContractCaller(config)).getSchema(expectedUid);
      if (!record || typeof record !== "object" || !("uid" in record) || record.uid !== expectedUid) {
        throw new Error("Registration transaction succeeded but on-chain Schema UID does not match preview");
      }
      return { uid: expectedUid, hash: submitted.hash, ledger: state.ledger ?? 0 };
    }
    await sleep(1_500);
  }
  throw new Error("Registration submitted but not confirmed yet: " + submitted.hash);
}
