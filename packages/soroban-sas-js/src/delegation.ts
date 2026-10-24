import { ed25519 } from "@noble/curves/ed25519.js";
import { Buffer } from "buffer";
import { decodeAccount, decodeSeed, encodeAccount } from "./strkey.js";
import { hashTypedData } from "./hashing.js";
import type { Attestation, AttestationDomain, DelegatedAttestation } from "./types.js";

export function signDelegatedAttestation(attestation: Attestation, domain: AttestationDomain, nonce: bigint, secret: string): DelegatedAttestation {
  const seed = decodeSeed(secret); const publicKey = ed25519.getPublicKey(seed); const expectedAttester = encodeAccount(publicKey);
  if (attestation.attester !== expectedAttester) throw new Error(`attester ${attestation.attester} does not match signing key account ${expectedAttester}`);
  return { attestation, nonce, signature: Buffer.from(ed25519.sign(hashTypedData(attestation, domain), seed)), publicKey: Buffer.from(publicKey) };
}
export function verifyDelegatedAttestation(delegated: DelegatedAttestation, domain: AttestationDomain): boolean {
  try {
    if (!(delegated.publicKey instanceof Uint8Array) || delegated.publicKey.length !== 32) return false;
    if (!(delegated.signature instanceof Uint8Array) || delegated.signature.length !== 64) return false;
    if (encodeAccount(decodeAccount(delegated.attestation.attester)) !== encodeAccount(delegated.publicKey)) return false;
    return ed25519.verify(delegated.signature, hashTypedData(delegated.attestation, domain), delegated.publicKey);
  } catch { return false; }
}
