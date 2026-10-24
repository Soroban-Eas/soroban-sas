import { describe, expect, it } from "vitest";
import {
  Account,
  Asset,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
} from "@stellar/stellar-sdk";
import { basicNodeSigner } from "@stellar/stellar-sdk/contract";

describe("Node signing compatibility", () => {
  it("signs and verifies a constructed transaction envelope", async () => {
    const keypair = Keypair.random();
    const transaction = new TransactionBuilder(
      new Account(keypair.publicKey(), "0"),
      { fee: "100", networkPassphrase: Networks.TESTNET },
    )
      .addOperation(
        Operation.payment({
          destination: keypair.publicKey(),
          asset: Asset.native(),
          amount: "1",
        }),
      )
      .setTimeout(300)
      .build();

    const signer = basicNodeSigner(keypair, Networks.TESTNET);
    const walletSignTransaction = (xdr: string, opts?: { networkPassphrase?: string; address?: string }) =>
      signer.signTransaction(xdr, opts);
    const signed = await walletSignTransaction(transaction.toXDR(), {
      networkPassphrase: Networks.TESTNET,
      address: keypair.publicKey(),
    });
    const envelope = TransactionBuilder.fromXDR(signed.signedTxXdr, Networks.TESTNET);
    const signature = envelope.signatures[0];

    expect(signature).toBeDefined();
    expect(
      keypair.verify(envelope.hash(), signature.signature()),
    ).toBe(true);
    expect(signed.signerAddress).toBe(keypair.publicKey());
  });
});
