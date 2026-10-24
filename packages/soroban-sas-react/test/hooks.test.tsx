import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { type ReactNode, useState } from "react";
import type { Attestation, SASClientConfig, SchemaRecord } from "@soroban-sas/sdk";
import { SasProvider, useAttestation, useRecipientAttestations, useSchema, useAttest, useRevoke, type SasHooksClient } from "../src/index.js";

afterEach(cleanup);

const config: SASClientConfig = {
  contractId: "C_SAS", registryContractId: "C_REGISTRY", indexerContractId: "C_INDEXER",
  rpcUrl: "https://test.example/rpc",
  networkPassphrase: "Test SDF Network ; September 2015",
};

const attestation: Attestation = {
  uid: "a".repeat(64), schemaUid: "b".repeat(64),
  time: 1n, expirationTime: 0n, revocationTime: 0n,
  refUid: "0".repeat(64), recipient: "G_RECIPIENT", attester: "G_ATTESTER",
  revocable: true, data: new Uint8Array([1, 2]),
};
const schema: SchemaRecord = { uid: attestation.schemaUid, schema: "bool verified", resolver: "C_RESOLVER", revocable: true };

function makeClient() {
  return {
    getAttestation: vi.fn(async (_uid: string) => attestation as Attestation | null),
    getRecipientAttestations: vi.fn(async (_address: string) => [attestation.uid]),
    getSchema: vi.fn(async (_uid: string) => schema as SchemaRecord | null),
    attest: vi.fn(async (_row: Attestation) => ({ hash: "tx-attested" })),
    revoke: vi.fn(async (_uid: string) => ({ hash: "tx-revoked" })),
  } satisfies SasHooksClient;
}

function setup(children: ReactNode, client: SasHooksClient, overrideConfig = config) {
  return render(<SasProvider config={overrideConfig} client={client}>{children}</SasProvider>);
}

function Queries({ uid, recipient }: { uid?: string; recipient?: string }) {
  const a = useAttestation(uid);
  const r = useRecipientAttestations(recipient);
  const s = useSchema(uid ? schema.uid : undefined);
  return <div>
    <span data-testid="attestation">{a.data?.uid ?? (a.error ? "error" : "none")}</span>
    <span data-testid="recipient">{r.data?.length ?? "none"}</span>
    <span data-testid="schema">{s.data?.schema ?? "none"}</span>
  </div>;
}

describe("SAS query hooks", () => {
  it("requires an explicit wallet-aware client, not a browser secret signer", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      expect(() => render(<SasProvider config={config}><div /></SasProvider>)).toThrow(/requires a client/);
      expect(() => setup(<div />, makeClient(), { ...config, secret: "S_SECRET_NOT_ALLOWED" }))
        .toThrow(/never receive a secret key/);
    } finally {
      spy.mockRestore();
    }
  });

  it("does not fetch when identifiers are empty or missing", async () => {
    const client = makeClient();
    setup(<Queries />, client);
    await act(async () => {});
    expect(client.getAttestation).not.toHaveBeenCalled();
    expect(client.getRecipientAttestations).not.toHaveBeenCalled();
    expect(client.getSchema).not.toHaveBeenCalled();
  });

  it("fetches attestation, recipient records and schema using the injected client", async () => {
    const client = makeClient();
    setup(<Queries uid={attestation.uid} recipient="G_RECIPIENT" />, client);
    await waitFor(() => expect(screen.getByTestId("recipient").textContent).toBe("1"));
    expect(screen.getByTestId("attestation").textContent).toBe(attestation.uid);
    expect(screen.getByTestId("schema").textContent).toBe(schema.schema);
    expect(client.getRecipientAttestations).toHaveBeenCalledWith("G_RECIPIENT");
    expect(client.getAttestation).toHaveBeenCalledWith(attestation.uid);
  });

  it("deduplicates simultaneous consumers via SWR and refetches on key changes", async () => {
    const client = makeClient();
    function Two() {
      const [uid, setUid] = useState("a".repeat(64));
      return <><button onClick={() => setUid("c".repeat(64))}>change</button><Queries uid={uid} /><Queries uid={uid} /></>;
    }
    setup(<Two />, client);
    await waitFor(() => expect(client.getAttestation).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByText("change"));
    await waitFor(() => expect(client.getAttestation).toHaveBeenCalledTimes(2));
    expect(client.getAttestation).toHaveBeenLastCalledWith("c".repeat(64));
  });

  it("isolate caches for separate SasProviders", async () => {
    const first = makeClient();
    const second = makeClient();
    second.getAttestation.mockResolvedValueOnce({ ...attestation, uid: "c".repeat(64) });
    render(<>
      <SasProvider config={config} client={first}><Queries uid={attestation.uid} /></SasProvider>
      <SasProvider config={config} client={second}><Queries uid={attestation.uid} /></SasProvider>
    </>);
    await waitFor(() => expect(first.getAttestation).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(second.getAttestation).toHaveBeenCalledTimes(1));
    expect(screen.getAllByTestId("attestation").map(x => x.textContent)).toContain("c".repeat(64));
  });

  it("ignores late read responses after a query component is unmounted", async () => {
    let resolve!: (att: Attestation | null) => void;
    const client = makeClient();
    client.getAttestation.mockImplementationOnce(() => new Promise((r) => { resolve = r; }));
    const view = setup(<Queries uid={attestation.uid} />, client);
    await waitFor(() => expect(client.getAttestation).toHaveBeenCalledOnce());
    view.unmount();
    await act(async () => resolve(attestation));
    expect(client.getAttestation).toHaveBeenCalledOnce();
  });
});

function MutationUI() {
  const issue = useAttest();
  const revoke = useRevoke();
  return <div>
    <button onClick={() => void issue.attest(attestation).catch(() => undefined)}>attest</button>
    <button onClick={() => void revoke.revoke(attestation.uid).catch(() => undefined)}>revoke</button>
    <span data-testid="issue-status">{issue.status}</span>
    <span data-testid="issue-hash">{issue.txHash}</span>
    <span data-testid="issue-error">{issue.error?.message}</span>
    <span data-testid="revoke-status">{revoke.status}</span>
    <span data-testid="revoke-hash">{revoke.txHash}</span>
  </div>;
}

describe("SAS mutation hooks", () => {
  it("reports pending, success and hash and revalidates attestation caches", async () => {
    let resolve!: (result: { hash: string }) => void;
    const client = makeClient();
    client.attest.mockImplementationOnce(() => new Promise((r) => { resolve = r; }));
    setup(<><Queries uid={attestation.uid} recipient="G_RECIPIENT" /><MutationUI /></>, client);
    await waitFor(() => expect(screen.getByTestId("recipient").textContent).toBe("1"));
    fireEvent.click(screen.getByText("attest"));
    expect(screen.getByTestId("issue-status").textContent).toBe("pending");
    await act(async () => resolve({ hash: "tx-real" }));
    await waitFor(() => expect(screen.getByTestId("issue-status").textContent).toBe("success"));
    expect(screen.getByTestId("issue-hash").textContent).toBe("tx-real");
    await waitFor(() => expect(client.getRecipientAttestations.mock.calls.length).toBeGreaterThan(1));
    expect(client.getSchema).toHaveBeenCalledTimes(1); // schema cache is unrelated
  });

  it("reports a rejected wallet signature and allows recovery", async () => {
    const client = makeClient();
    client.attest.mockRejectedValueOnce(new Error("User rejected the signature"));
    setup(<MutationUI />, client);
    fireEvent.click(screen.getByText("attest"));
    await waitFor(() => expect(screen.getByTestId("issue-status").textContent).toBe("error"));
    expect(screen.getByTestId("issue-error").textContent).toContain("rejected");
    fireEvent.click(screen.getByText("attest"));
    await waitFor(() => expect(screen.getByTestId("issue-status").textContent).toBe("success"));
  });

  it("exposes revocation submission and its transaction hash", async () => {
    const client = makeClient();
    setup(<MutationUI />, client);
    fireEvent.click(screen.getByText("revoke"));
    await waitFor(() => expect(screen.getByTestId("revoke-status").textContent).toBe("success"));
    expect(screen.getByTestId("revoke-hash").textContent).toBe("tx-revoked");
    expect(client.revoke).toHaveBeenCalledWith(attestation.uid);
  });

  it("does not update React state after unmount while a transaction is pending", async () => {
    let resolve!: (result: { hash: string }) => void;
    const client = makeClient();
    client.attest.mockImplementationOnce(() => new Promise((r) => { resolve = r; }));
    const view = setup(<MutationUI />, client);
    fireEvent.click(screen.getByText("attest"));
    view.unmount();
    await act(async () => resolve({ hash: "finished-after-unmount" }));
    expect(client.attest).toHaveBeenCalledOnce();
  });
});
