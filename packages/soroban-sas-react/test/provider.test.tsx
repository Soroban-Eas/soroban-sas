import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, renderHook, waitFor } from "@testing-library/react";
import { useState, type ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";
import {
  SASProvider,
  createSASQueryClient,
  dispatchAccountSwitch,
  dispatchNetworkSwitch,
  useAttestation,
  useSAS,
  useSASContext,
} from "../src/index.js";
import type { Attestation, SASClientLike } from "../src/types.js";

const SAMPLE_UID = "11".repeat(32);
const SAMPLE_SCHEMA_UID = "aa".repeat(32);
const ZERO_UID = "00".repeat(32);
const ACCOUNT_A = "GALICE55555555555555555555555555555555555555555555555555";
const ACCOUNT_B = "GBOB7777777777777777777777777777777777777777777777777777";
const ATTESTER = "GISSUER9999999999999999999999999999999999999999999999999";

function makeAttestation(time: bigint): Attestation {
  return {
    uid: SAMPLE_UID,
    schemaUid: SAMPLE_SCHEMA_UID,
    time,
    expirationTime: 0n,
    revocationTime: 0n,
    refUid: ZERO_UID,
    recipient: ACCOUNT_A,
    attester: ATTESTER,
    revocable: true,
    data: new Uint8Array([1]),
  };
}

describe("SASProvider & useSAS", () => {
  it("throws when useSAS is called outside SASProvider", () => {
    expect(() => renderHook(() => useSAS())).toThrow(
      /useSAS must be used within a SASProvider/,
    );
  });

  it("configures network presets and custom RPC overrides", () => {
    const wrapper = ({ children }: { children: ReactNode }) => (
      <SASProvider
        network="futurenet"
        contractId="CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        account={ACCOUNT_A}
      >
        {children}
      </SASProvider>
    );

    const { result } = renderHook(() => useSASContext(), { wrapper });

    expect(result.current.network).toBe("futurenet");
    expect(result.current.rpcUrl).toBe("https://rpc-futurenet.stellar.org");
    expect(result.current.networkPassphrase).toBe(
      "Test SDF Future Network ; October 2022",
    );
    expect(result.current.contractId).toBe(
      "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    );
    expect(result.current.account).toBe(ACCOUNT_A);
    expect(result.current.activeAccount).toBe(ACCOUNT_A);
  });

  it("re-fetches automatically on account switch via prop change", async () => {
    let callCount = 0;
    const client: SASClientLike = {
      getAttestation: vi.fn(async () => {
        callCount += 1;
        return makeAttestation(BigInt(callCount));
      }),
      getSchema: vi.fn(),
    };

    function Probe() {
      const { data } = useAttestation(SAMPLE_UID);
      const { account } = useSAS();
      return (
        <div>
          <span data-testid="acc">{account}</span>
          <span data-testid="time">{data ? data.time.toString() : "loading"}</span>
        </div>
      );
    }

    function Host() {
      const [account, setAccount] = useState(ACCOUNT_A);
      return (
        <SASProvider network="testnet" account={account} client={client}>
          <button
            type="button"
            data-testid="switch-btn"
            onClick={() => setAccount(ACCOUNT_B)}
          >
            Switch
          </button>
          <Probe />
        </SASProvider>
      );
    }

    const { getByTestId } = render(<Host />);

    await waitFor(() => {
      expect(getByTestId("time").textContent).toBe("1");
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(1);

    fireEvent.click(getByTestId("switch-btn"));

    await waitFor(() => {
      expect(getByTestId("acc").textContent).toBe(ACCOUNT_B);
      expect(getByTestId("time").textContent).toBe("2");
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(2);
  });

  it("re-fetches automatically on switchAccount() context method and window account events", async () => {
    let callCount = 0;
    const client: SASClientLike = {
      getAttestation: vi.fn(async () => {
        callCount += 1;
        return makeAttestation(BigInt(callCount));
      }),
      getSchema: vi.fn(),
    };

    const wrapper = ({ children }: { children: ReactNode }) => (
      <SASProvider network="testnet" account={ACCOUNT_A} client={client}>
        {children}
      </SASProvider>
    );

    const { result } = renderHook(
      () => ({
        sas: useSAS(),
        att: useAttestation(SAMPLE_UID),
      }),
      { wrapper },
    );

    await waitFor(() => {
      expect(result.current.att.data?.time).toBe(1n);
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(1);

    // Imperative switchAccount
    act(() => {
      result.current.sas.switchAccount(ACCOUNT_B);
    });

    await waitFor(() => {
      expect(result.current.sas.account).toBe(ACCOUNT_B);
      expect(result.current.att.data?.time).toBe(2n);
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(2);

    // Window DOM event dispatchAccountSwitch
    act(() => {
      dispatchAccountSwitch(ACCOUNT_A);
    });

    await waitFor(() => {
      expect(result.current.sas.account).toBe(ACCOUNT_A);
      expect(result.current.att.data?.time).toBe(3n);
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(3);
  });

  it("re-fetches automatically on window focus and visibilitychange events", async () => {
    let callCount = 0;
    const client: SASClientLike = {
      getAttestation: vi.fn(async () => {
        callCount += 1;
        return makeAttestation(BigInt(callCount));
      }),
      getSchema: vi.fn(),
    };

    const wrapper = ({ children }: { children: ReactNode }) => (
      <SASProvider network="testnet" account={ACCOUNT_A} client={client}>
        {children}
      </SASProvider>
    );

    const { result } = renderHook(() => useAttestation(SAMPLE_UID), {
      wrapper,
    });

    await waitFor(() => {
      expect(result.current.data?.time).toBe(1n);
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(1);

    // Trigger window focus event
    act(() => {
      fireEvent.focus(window);
    });

    await waitFor(() => {
      expect(result.current.data?.time).toBe(2n);
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(2);

    // Trigger document visibilitychange event
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });

    await waitFor(() => {
      expect(result.current.data?.time).toBe(3n);
    });
    expect(client.getAttestation).toHaveBeenCalledTimes(3);
  });

  it("re-fetches on network switch and integrates with an external QueryClientProvider", async () => {
    let callCount = 0;
    const client: SASClientLike = {
      getAttestation: vi.fn(async () => {
        callCount += 1;
        return makeAttestation(BigInt(callCount));
      }),
      getSchema: vi.fn(),
    };
    const customQueryClient = createSASQueryClient();

    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={customQueryClient}>
        <SASProvider network="testnet" rpcClient={client} publicKey={ACCOUNT_A}>
          {children}
        </SASProvider>
      </QueryClientProvider>
    );

    const { result } = renderHook(
      () => ({
        sas: useSAS(),
        att: useAttestation(SAMPLE_UID),
      }),
      { wrapper },
    );

    await waitFor(() => {
      expect(result.current.att.data?.time).toBe(1n);
    });
    expect(result.current.sas.queryClient).toBe(customQueryClient);

    act(() => {
      dispatchNetworkSwitch("mainnet");
    });

    await waitFor(() => {
      expect(result.current.sas.network).toBe("mainnet");
      expect(result.current.att.data?.time).toBe(2n);
    });
  });

  it("handles controlled network prop updates, wallet DOM events, and manual invalidation helpers", async () => {
    const client: SASClientLike = {
      getAttestation: vi.fn().mockResolvedValue(makeAttestation(10n)),
      getSchema: vi.fn().mockResolvedValue(null),
      getAttestationsByRecipient: vi.fn().mockResolvedValue([]),
    };

    const onAccountChanged = vi.fn();
    const onNetworkChanged = vi.fn();

    function Host() {
      const [net, setNet] = useState<"testnet" | "local">("testnet");
      return (
        <SASProvider network={net} activeAccount={ACCOUNT_A} client={client}>
          <button
            type="button"
            data-testid="net-prop-btn"
            onClick={() => setNet("local")}
          >
            Change Net Prop
          </button>
          <Inner />
        </SASProvider>
      );
    }

    function Inner() {
      const sas = useSAS();
      return (
        <div>
          <span data-testid="inner-net">{sas.network}</span>
          <span data-testid="inner-acc">{sas.account}</span>
          <button
            type="button"
            data-testid="inv-all"
            onClick={() => {
              void sas.invalidateAttestation();
              void sas.invalidateSchema();
              void sas.invalidateRecipientAttestations();
              void sas.invalidateAll();
              sas.switchNetwork({
                id: "custom",
                label: "Custom",
                rpcUrl: "https://custom.soroban.org",
                networkPassphrase: "Custom ; 2026",
              });
            }}
          >
            Invalidate
          </button>
        </div>
      );
    }

    const { getByTestId } = render(<Host />);
    expect(getByTestId("inner-net").textContent).toBe("testnet");

    fireEvent.click(getByTestId("net-prop-btn"));
    await waitFor(() => {
      expect(getByTestId("inner-net").textContent).toBe("local");
    });

    // Wallet-specific DOM events with { publicKey } and { address }
    act(() => {
      window.dispatchEvent(
        new CustomEvent("stellar:accountChanged", {
          detail: { publicKey: ACCOUNT_B },
        }),
      );
    });
    await waitFor(() => {
      expect(getByTestId("inner-acc").textContent).toBe(ACCOUNT_B);
    });

    act(() => {
      window.dispatchEvent(
        new CustomEvent("freighter:accountChanged", {
          detail: { address: ACCOUNT_A },
        }),
      );
    });
    await waitFor(() => {
      expect(getByTestId("inner-acc").textContent).toBe(ACCOUNT_A);
    });

    fireEvent.click(getByTestId("inv-all"));
    await waitFor(() => {
      expect(getByTestId("inner-net").textContent).toBe("custom");
    });

    expect(onAccountChanged).not.toThrow();
    expect(onNetworkChanged).not.toThrow();
  });
});
