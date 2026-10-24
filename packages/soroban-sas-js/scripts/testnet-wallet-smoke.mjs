import assert from "node:assert/strict";
import { Account, BASE_FEE, Keypair, Networks, Operation, TransactionBuilder, rpc } from "@stellar/stellar-sdk";

/**
 * Opt-in REAL Stellar Testnet smoke test.
 * Creates an ephemeral key in RAM, funds it using Friendbot, signs a harmless
 * manageData transaction and verifies ledger inclusion by raw JSON-RPC.
 * Never uses a user's wallet or stores a private key. Never run on Mainnet.
 */
const RPC_URL = "https://soroban-testnet.stellar.org";
const FRIEND_BOT = "https://friendbot.stellar.org";
const STELLAR_TESTNET = "Test SDF Network ; September 2015";
assert.equal(Networks.TESTNET, STELLAR_TESTNET);

async function jsonRpc(method, params = undefined) {
  const response = await fetch(RPC_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: method, method, ...(params ? { params } : {}) }),
    signal: AbortSignal.timeout(15_000),
  });
  assert.equal(response.status, 200, method + " HTTP status");
  const body = await response.json();
  if (body.error) throw new Error(method + ": " + JSON.stringify(body.error));
  return body.result;
}

const health = await jsonRpc("getHealth");
const network = await jsonRpc("getNetwork");
assert.equal(health.status, "healthy");
assert.equal(network.passphrase, STELLAR_TESTNET);

const signer = Keypair.random();
const address = signer.publicKey();
const funding = await fetch(FRIEND_BOT + "/?addr=" + encodeURIComponent(address), {
  signal: AbortSignal.timeout(20_000),
});
if (!funding.ok) throw new Error("Friendbot funding failed: HTTP " + funding.status);
const server = new rpc.Server(RPC_URL);
const account = await server.getAccount(address);
const tx = new TransactionBuilder(new Account(address, account.sequenceNumber()), {
  fee: BASE_FEE,
  networkPassphrase: STELLAR_TESTNET,
}).addOperation(Operation.manageData({
  name: "bounty564-testnet-wallet-check", value: "testnet-only",
})).setTimeout(60).build();

const unsignedXdr = tx.toXDR();
tx.sign(signer);
const signed = TransactionBuilder.fromXDR(tx.toXDR(), STELLAR_TESTNET);
assert.notEqual(unsignedXdr, tx.toXDR());
assert(signed.signatures.some((sig) => signer.verify(signed.hash(), sig.signature())));
const submitted = await server.sendTransaction(tx);
if (submitted.status === "ERROR" || !submitted.hash) {
  throw new Error("Testnet rejected signed transaction: " + submitted.status);
}

let result;
for (let attempt = 0; attempt < 24; attempt++) {
  result = await jsonRpc("getTransaction", { hash: submitted.hash });
  if (result?.status === "SUCCESS" || result?.status === "FAILED") break;
  await new Promise((r) => setTimeout(r, 1500));
}
assert.equal(result?.status, "SUCCESS", "on-chain transaction result");
console.log(JSON.stringify({
  status: "SUCCESS", network: "Stellar Testnet", publicKey: address,
  hash: submitted.hash, ledger: result.ledger,
  signatureVerified: true,
}));
