"use client";

import { useState } from "react";
import { useAttestation, useRecipientAttestations, useSchema, useAttest, useRevoke } from "@soroban-sas/react";
import { Providers } from "./providers";
import { demoAccount, demoSchemaUid, demoUid } from "./demo-client";

function AttestationDemo() {
  const [uid, setUid] = useState(demoUid);
  const attestation = useAttestation(uid);
  const recipient = useRecipientAttestations(demoAccount);
  const schema = useSchema(demoSchemaUid);
  const issue = useAttest();
  const revocation = useRevoke();
  const [message, setMessage] = useState("");

  async function submitDemo() {
    if (!attestation.data) return;
    setMessage("");
    try {
      const result = await issue.attest(attestation.data);
      setMessage(`Simulated submission: ${result.hash}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    }
  }

  async function revokeDemo() {
    setMessage("");
    try {
      const result = await revocation.revoke(uid);
      setMessage(`Simulated revocation: ${result.hash}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : String(error));
    }
  }

  return (
    <main>
      <h1>Soroban SAS React hooks</h1>
      <p className="warning">Demo mode: in-memory mock client. No wallet prompts, network requests or on-chain transactions.</p>
      <article>
        <h2>useAttestation(uid)</h2>
        <label htmlFor="uid">Attestation UID</label>
        <p><input id="uid" value={uid} onChange={(event) => setUid(event.target.value)} /></p>
        <p>Loading: {String(attestation.isLoading)} — {attestation.error?.message ?? "No error"}</p>
        <p>Status: {attestation.data ? (attestation.data.revocationTime > 0n ? "revoked" : "valid") : "not found"}</p>
        <p><code>{attestation.data?.uid ?? "—"}</code></p>
      </article>
      <article>
        <h2>useRecipientAttestations(account)</h2>
        <p>Account: <code>{demoAccount}</code></p>
        <p>{recipient.isLoading ? "Loading…" : `${recipient.data?.length ?? 0} attestation(s)`}</p>
        <p className="error">{recipient.error?.message}</p>
      </article>
      <article>
        <h2>useSchema(uid)</h2>
        <p>Schema: <code>{schema.data?.schema ?? "—"}</code></p>
        <p className="error">{schema.error?.message}</p>
      </article>
      <article>
        <h2>useAttest() / useRevoke()</h2>
        <p>Attest: {issue.status} {issue.txHash ? `(${issue.txHash})` : ""}</p>
        <p>Revoke: {revocation.status} {revocation.txHash ? `(${revocation.txHash})` : ""}</p>
        <button disabled={issue.isLoading || !attestation.data} onClick={() => void submitDemo()}>Simulate attest</button>
        <button disabled={revocation.isLoading || !attestation.data} onClick={() => void revokeDemo()}>Simulate revoke</button>
        <p role="status">{message}</p>
      </article>
    </main>
  );
}

export default function Page() {
  return <Providers><AttestationDemo /></Providers>;
}
