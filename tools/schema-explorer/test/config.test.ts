import { describe, expect, it } from "vitest";
import { PRESETS, configFromQuery, configToQuery, validateConfig } from "../src/config.js";
import { DEMO_REGISTRY_ID } from "../src/fixtures.js";

const valid = {
  rpcUrl: "https://soroban-testnet.stellar.org",
  networkPassphrase: "Test SDF Network ; September 2015",
  registryContractId: DEMO_REGISTRY_ID,
};

describe("validateConfig", () => {
  it("accepts a well-formed https config and trims whitespace", () => {
    const result = validateConfig({ ...valid, registryContractId: `  ${DEMO_REGISTRY_ID}\n` });
    expect(result).toEqual({ ok: true, config: valid });
  });

  it.each(["http://localhost:8000/soroban/rpc", "http://127.0.0.1:8000/soroban/rpc", "http://[::1]:8000/soroban/rpc"])(
    "allows plain http for loopback %s",
    (rpcUrl) => {
      expect(validateConfig({ ...valid, rpcUrl }).ok).toBe(true);
    },
  );

  it.each([
    ["http://rpc.example.com", "only allowed for localhost"],
    ["ftp://rpc.example.com", "http:// or https://"],
    ["javascript:alert(1)", "http:// or https://"],
    ["not a url", "not a valid URL"],
    ["https://user:pass@rpc.example.com", "credentials"],
  ])("rejects RPC URL %s", (rpcUrl, message) => {
    const result = validateConfig({ ...valid, rpcUrl });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors.join(" ")).toContain(message);
  });

  it.each([
    "",
    "GCI7YTLFUAWQ2Y5MAWAOFICWUWC5MUMARISUEPVMB3KYUH46WII5MS7T", // account, not contract
    "CAKQQH7GRMMREU44ZOBMU2JJWCT4I5YRYXBWCWLQYAW2QYAF7Q2VPAPE", // bad checksum
  ])("rejects registry id %j", (registryContractId) => {
    const result = validateConfig({ ...valid, registryContractId });
    expect(result.ok).toBe(false);
  });

  it("requires a passphrase and reports every error at once", () => {
    const result = validateConfig({ rpcUrl: "nope", networkPassphrase: " ", registryContractId: "" });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.errors).toHaveLength(3);
  });
});

describe("query string round trip", () => {
  it("uses the preset name for known networks", () => {
    const testnet = PRESETS.find((p) => p.id === "testnet")!;
    const config = { ...valid, rpcUrl: testnet.rpcUrl, networkPassphrase: testnet.networkPassphrase };
    const query = configToQuery(config);
    expect(query).toBe(`?network=testnet&registry=${DEMO_REGISTRY_ID}`);
    expect(configFromQuery(query)).toEqual(config);
  });

  it("spells out custom networks", () => {
    const config = { ...valid, rpcUrl: "https://rpc.example.com/soroban", networkPassphrase: "My Net ; 2026" };
    expect(configFromQuery(configToQuery(config))).toEqual(config);
  });

  it("ignores unknown presets", () => {
    expect(configFromQuery("?network=nowhere")).toEqual({});
  });
});
