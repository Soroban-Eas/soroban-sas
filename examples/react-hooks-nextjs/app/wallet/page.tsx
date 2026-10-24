"use client";

import { useState } from "react";
import { Account, BASE_FEE, Keypair, Networks, Operation, TransactionBuilder, rpc } from "@stellar/stellar-sdk";
import { connectFreighter, signFreighterEnvelope } from "../freighter-wallet";

const rpcUrl = "https://soroban-testnet.stellar.org";
const config = {
  rpcUrl, networkPassphrase: Networks.TESTNET,
  // Placeholders are never invoked: this page tests wallet signatures, not SAS contracts.
  contractId: "CPLACEHOLDER_NOT_DEPLOYED",
  registryContractId: "CPLACEHOLDER_NOT_DEPLOYED",
  indexerContractId: "CPLACEHOLDER_NOT_DEPLOYED",
};

export default function WalletDiagnostics() {
  const [address, setAddress] = useState<string | null>(null);
  const [status, setStatus] = useState("Not connected");
  const [signature, setSignature] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function connect() {
    setBusy(true);
    try {
      const wallet = await connectFreighter(config);
      setAddress(wallet.address);
      setStatus("Connected to Freighter on Testnet");
      setSignature(null);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  async function verifySignature() {
    if (!address) return;
    setBusy(true);
    setSignature(null);
    try {
      const server = new rpc.Server(rpcUrl);
      const account = await server.getAccount(address);
      const unsigned = new TransactionBuilder(
        new Account(address, account.sequenceNumber()),
        { fee: BASE_FEE, networkPassphrase: Networks.TESTNET },
      ).addOperation(Operation.manageData({
        name: "soroban-sas-wallet-diagnostic", value: "unsigned-check-only",
      })).setTimeout(120).build();
      const result = await signFreighterEnvelope(unsigned.toXDR(), Networks.TESTNET, address);
      const tx = TransactionBuilder.fromXDR(result.signedTxXdr, Networks.TESTNET);
      const pub = Keypair.fromPublicKey(address);
      if (!tx.signatures.some((item) => pub.verify(tx.hash(), item.signature()))) {
        throw new Error("Freighter signature failed cryptographic verification");
      }
      if (tx.hash().toString("hex") !== unsigned.hash().toString("hex")) {
        throw new Error("Wallet modified the requested transaction");
      }
      setSignature(tx.hash().toString("hex"));
      setStatus("Valid Freighter signature; transaction was NOT submitted");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  }

  return <main>
    <h1>Freighter signature diagnostics</h1>
    <p className="warning">Testnet only. This page signs a harmless transaction envelope but NEVER broadcasts it.</p>
    <p>1. Install Freighter and select Stellar Testnet.</p>
    <p>2. Connect your wallet; Freighter will ask you for permission.</p>
    <p>3. Sign the sample transaction; its cryptographic signature is checked locally.</p>
    <button type="button" disabled={busy} onClick={() => void connect()}>Connect Freighter (Testnet)</button>
    <button type="button" disabled={busy || !address} onClick={() => void verifySignature()}>Sign without broadcasting</button>
    <article>
      <p role="status">{status}</p>
      <p>Wallet: <code>{address ?? "not connected"}</code></p>
      <p>Verified transaction hash: <code>{signature ?? "none"}</code></p>
      <p className="muted">No transaction is sent; this verifies SEP-43 envelope signing only. To test real SAS methods, deploy the three contracts on Testnet first.</p>
    </article>
    <p><a href="/">Back to hooks demo</a></p>
  </main>;
}
