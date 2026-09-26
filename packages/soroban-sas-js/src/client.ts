// A minimal, real client for the SAS and Schema Registry contracts.
//
// Rather than hand-encoding each contract function's ScVal argument list,
// this builds on `@stellar/stellar-sdk/contract`'s `Client`, which fetches
// the deployed contract's on-chain XDR spec (`Client.from({ contractId,
// rpcUrl, ... })`) and uses it to convert plain JS values into the exact
// InvokeHostFunction operation the contract expects — the same approach
// `stellar-cli`'s `contract invoke` and generated TS contract clients use.
// This defers argument encoding to code that reads the contract's own
// metadata, rather than this package guessing struct layouts by hand.
//
// Scope note: the `UID` newtype (`soroban_sas_common::UID(BytesN<32>)`) is
// passed here as a one-element array wrapping its 32 bytes, matching the
// "single-element ScVec" shape documented in
// packages/soroban-sas-sdk/src/events.rs's `decode_uid`. This has not been
// exercised against a live RPC node in this environment — see
// packages/soroban-sas-js/README.md's "Scope and limitations" section.

import { Client as ContractClient, basicNodeSigner } from "@stellar/stellar-sdk/contract";
import { Keypair } from "@stellar/stellar-sdk";
import type { Attestation, DelegatedAttestation, SchemaRecord, UID } from "./types.js";

export interface SASClientConfig {
  /** SAS contract id (C...). */
  contractId: string;
  /** Schema Registry contract id (C...); required for schema methods. */
  registryContractId?: string;
  rpcUrl: string;
  networkPassphrase: string;
  /** Account (G...) that pays for and authorizes submitted transactions. */
  publicKey?: string;
  /** ed25519 secret seed (S...) for `publicKey`; enables signAndSend. */
  secret?: string;
}

export interface SubmitResult {
  hash: string;
}

function uidArg(uid: UID): [Buffer] {
  return [Buffer.from(uid, "hex")];
}

function attestationArg(a: Attestation): Record<string, unknown> {
  return {
    uid: uidArg(a.uid),
    schema_uid: uidArg(a.schemaUid),
    time: a.time,
    expiration_time: a.expirationTime,
    revocation_time: a.revocationTime,
    ref_uid: uidArg(a.refUid),
    recipient: a.recipient,
    attester: a.attester,
    revocable: a.revocable,
    data: Buffer.from(a.data),
  };
}

/** Client for `SAS::*` and `SchemaRegistry::*` contract entry points. */
export class SASClient {
  private sasClient?: ContractClient;
  private registryClient?: ContractClient;

  constructor(private readonly config: SASClientConfig) {}

  private signer() {
    if (!this.config.secret) return undefined;
    return basicNodeSigner(
      Keypair.fromSecret(this.config.secret),
      this.config.networkPassphrase,
    );
  }

  private publicKey(): string | undefined {
    return this.config.publicKey ?? (this.config.secret ? Keypair.fromSecret(this.config.secret).publicKey() : undefined);
  }

  private async sas(): Promise<ContractClient> {
    if (!this.sasClient) {
      this.sasClient = await ContractClient.from({
        contractId: this.config.contractId,
        rpcUrl: this.config.rpcUrl,
        networkPassphrase: this.config.networkPassphrase,
        publicKey: this.publicKey(),
        ...this.signer(),
      });
    }
    return this.sasClient;
  }

  private async registry(): Promise<ContractClient> {
    if (!this.config.registryContractId) {
      throw new Error("SASClientConfig.registryContractId is required for schema methods");
    }
    if (!this.registryClient) {
      this.registryClient = await ContractClient.from({
        contractId: this.config.registryContractId,
        rpcUrl: this.config.rpcUrl,
        networkPassphrase: this.config.networkPassphrase,
        publicKey: this.publicKey(),
        ...this.signer(),
      });
    }
    return this.registryClient;
  }

  /** Calls `SchemaRegistry::register(owner, schema, resolver, revocable)`. */
  async registerSchema(schema: string, resolver: string, revocable: boolean): Promise<UID> {
    const owner = this.publicKey();
    if (!owner) throw new Error("registerSchema requires config.publicKey or config.secret");
    const client = await this.registry();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tx = await (client as any).register({ owner, schema, resolver, revocable });
    const sent = await tx.signAndSend();
    return Buffer.from(sent.result as unknown as Uint8Array).toString("hex");
  }

  /** Calls `SchemaRegistry::get_schema(uid)`. Read-only (simulated, not submitted). */
  async getSchema(uid: UID): Promise<SchemaRecord | null> {
    const client = await this.registry();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tx = await (client as any).get_schema({ uid: uidArg(uid) });
    const record = tx.result as unknown as
      | { uid: [Buffer]; resolver: string; revocable: boolean; schema: string }
      | null;
    if (!record) return null;
    return {
      uid: Buffer.from(record.uid[0]).toString("hex"),
      resolver: record.resolver,
      revocable: record.revocable,
      schema: record.schema,
    };
  }

  /** Calls `SAS::attest(attestation)` and submits the signed transaction. */
  async attest(attestation: Attestation): Promise<SubmitResult> {
    const client = await this.sas();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tx = await (client as any).attest({ attestation: attestationArg(attestation) });
    const sent = await tx.signAndSend();
    return { hash: sent.sendTransactionResponse?.hash ?? "" };
  }

  /** Calls `SAS::attest_by_delegation`, relaying an off-chain-signed attestation. */
  async attestByDelegation(delegated: DelegatedAttestation): Promise<SubmitResult> {
    const client = await this.sas();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tx = await (client as any).attest_by_delegation({
      attestation: attestationArg(delegated.attestation),
      nonce: delegated.nonce,
      signature: Buffer.from(delegated.signature),
      public_key: Buffer.from(delegated.publicKey),
    });
    const sent = await tx.signAndSend();
    return { hash: sent.sendTransactionResponse?.hash ?? "" };
  }

  /** Calls `SAS::revoke(uid)`. */
  async revoke(uid: UID): Promise<SubmitResult> {
    const client = await this.sas();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tx = await (client as any).revoke({ uid: uidArg(uid) });
    const sent = await tx.signAndSend();
    return { hash: sent.sendTransactionResponse?.hash ?? "" };
  }

  /** Calls `SAS::get_attestation(uid)`. Read-only (simulated, not submitted). */
  async getAttestation(uid: UID): Promise<Attestation | null> {
    const client = await this.sas();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tx = await (client as any).get_attestation({ uid: uidArg(uid) });
    const raw = tx.result as unknown as
      | {
          uid: [Buffer];
          schema_uid: [Buffer];
          time: bigint;
          expiration_time: bigint;
          revocation_time: bigint;
          ref_uid: [Buffer];
          recipient: string;
          attester: string;
          revocable: boolean;
          data: Buffer;
        }
      | null;
    if (!raw) return null;
    return {
      uid: Buffer.from(raw.uid[0]).toString("hex"),
      schemaUid: Buffer.from(raw.schema_uid[0]).toString("hex"),
      time: raw.time,
      expirationTime: raw.expiration_time,
      revocationTime: raw.revocation_time,
      refUid: Buffer.from(raw.ref_uid[0]).toString("hex"),
      recipient: raw.recipient,
      attester: raw.attester,
      revocable: raw.revocable,
      data: new Uint8Array(raw.data),
    };
  }
}
