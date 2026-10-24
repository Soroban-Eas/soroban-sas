// Connection settings: network presets and validation of user-supplied
// values before anything is sent to an RPC endpoint.

import { StrKey } from "@stellar/stellar-sdk";

export interface ExplorerConfig {
  rpcUrl: string;
  networkPassphrase: string;
  /** Schema Registry contract id (C...). */
  registryContractId: string;
  /** SAS attestation contract id (C...). Optional; enables the Attestations tab. */
  sasContractId?: string;
  /** Indexer contract id (C...). Optional; enables bulk attestation lookups. */
  indexerContractId?: string;
}

export interface NetworkPreset {
  id: string;
  label: string;
  rpcUrl: string;
  networkPassphrase: string;
}

export const PRESETS: readonly NetworkPreset[] = [
  {
    id: "local",
    label: "Local (docker compose)",
    rpcUrl: "http://localhost:8000/soroban/rpc",
    networkPassphrase: "Standalone Network ; February 2017",
  },
  {
    id: "testnet",
    label: "Testnet",
    rpcUrl: "https://soroban-testnet.stellar.org",
    networkPassphrase: "Test SDF Network ; September 2015",
  },
];

export function findPreset(id: string): NetworkPreset | undefined {
  return PRESETS.find((p) => p.id === id);
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export type ConfigValidation = { ok: true; config: ExplorerConfig } | { ok: false; errors: string[] };

/**
 * Validates connection settings. Plain `http://` is accepted only for
 * loopback hosts (the local Quickstart node); anything remote must use
 * `https://` so contract reads can't be tampered with in transit.
 */
export function validateConfig(input: ExplorerConfig): ConfigValidation {
  const errors: string[] = [];
  const rpcUrl = input.rpcUrl.trim();
  const networkPassphrase = input.networkPassphrase.trim();
  const registryContractId = input.registryContractId.trim();

  let url: URL | undefined;
  try {
    url = new URL(rpcUrl);
  } catch {
    errors.push("RPC URL is not a valid URL.");
  }
  if (url) {
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      errors.push("RPC URL must use http:// or https://.");
    } else if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) {
      errors.push("Plain http:// is only allowed for localhost; use https:// for remote RPC servers.");
    }
    if (url.username || url.password) {
      errors.push("RPC URL must not embed credentials.");
    }
  }

  if (!networkPassphrase) errors.push("Network passphrase is required.");

  if (!StrKey.isValidContract(registryContractId)) {
    errors.push("Registry contract id must be a valid C... contract address.");
  }

  // Optional attestation contract IDs — validate only when supplied.
  const sasContractId = input.sasContractId?.trim() || undefined;
  if (sasContractId && !StrKey.isValidContract(sasContractId)) {
    errors.push("SAS contract id must be a valid C... contract address.");
  }
  const indexerContractId = input.indexerContractId?.trim() || undefined;
  if (indexerContractId && !StrKey.isValidContract(indexerContractId)) {
    errors.push("Indexer contract id must be a valid C... contract address.");
  }

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    config: {
      rpcUrl,
      networkPassphrase,
      registryContractId,
      ...(sasContractId ? { sasContractId } : {}),
      ...(indexerContractId ? { indexerContractId } : {}),
    },
  };
}

/** Reads `?rpc=&passphrase=&registry=` (or `?network=<preset>`) from a query string. */
export function configFromQuery(search: string): Partial<ExplorerConfig> {
  const params = new URLSearchParams(search);
  const out: Partial<ExplorerConfig> = {};
  const preset = params.get("network");
  if (preset) {
    const p = findPreset(preset);
    if (p) {
      out.rpcUrl = p.rpcUrl;
      out.networkPassphrase = p.networkPassphrase;
    }
  }
  const rpc = params.get("rpc");
  if (rpc) out.rpcUrl = rpc;
  const passphrase = params.get("passphrase");
  if (passphrase) out.networkPassphrase = passphrase;
  const registry = params.get("registry");
  if (registry) out.registryContractId = registry;
  const sas = params.get("sas");
  if (sas) out.sasContractId = sas;
  const indexer = params.get("indexer");
  if (indexer) out.indexerContractId = indexer;
  return out;
}

/** Builds a shareable query string for `config` (the inverse of `configFromQuery`). */
export function configToQuery(config: ExplorerConfig): string {
  const preset = PRESETS.find(
    (p) => p.rpcUrl === config.rpcUrl && p.networkPassphrase === config.networkPassphrase,
  );
  const params = new URLSearchParams();
  if (preset) {
    params.set("network", preset.id);
  } else {
    params.set("rpc", config.rpcUrl);
    params.set("passphrase", config.networkPassphrase);
  }
  params.set("registry", config.registryContractId);
  if (config.sasContractId) params.set("sas", config.sasContractId);
  if (config.indexerContractId) params.set("indexer", config.indexerContractId);
  return `?${params.toString()}`;
}
