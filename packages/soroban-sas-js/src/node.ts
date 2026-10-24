import { Keypair } from "@stellar/stellar-sdk";
import { basicNodeSigner } from "@stellar/stellar-sdk/contract";
import { SASClient, type SASClientConfig } from "./client.js";

export interface NodeSASClientConfig
  extends Omit<SASClientConfig, "publicKey" | "signTransaction"> {
  /** Test-only or server-side secret seed. Never use this in browser code. */
  secret: string;
}

/** Creates an SAS client using server-side secret-seed signing. */
export function createNodeSASClient(config: NodeSASClientConfig): SASClient {
  const keypair = Keypair.fromSecret(config.secret);
  const signer = basicNodeSigner(keypair, config.networkPassphrase);
  return new SASClient({
    ...config,
    publicKey: keypair.publicKey(),
    signTransaction: signer.signTransaction,
  });
}

export { SASClient } from "./client.js";
export type { SASClientConfig, SubmitResult } from "./client.js";
