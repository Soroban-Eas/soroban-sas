# DID + Verifiable Credential → Soroban Attestation (issue #496)

Runnable example of **W3C DID Core** `did:key` documents, a **W3C Verifiable
Credentials Data Model v1.1** JSON-LD credential encoded as a **VC-JWT**
(`alg: EdDSA`), and a Soroban schema resolver that checks Ed25519 proofs.

## Run locally

At repository root:

```bash
cargo run --example did_vc_resolver
cargo test --example did_vc_resolver
```

No wallet, RPC, secret configuration or running node is required. The example
uses deterministic **demo-only** Ed25519 seeds, deploys the real `SchemaRegistry`,
`SAS` and `DidVcResolver` into the Soroban in-memory test host, registers a
schema and a key for both DID controllers, then calls `SAS::attest`. SAS calls
the resolver's `on_attest` hook. It prints both DID documents, the JSON-LD VC,
the signed JWT and `SAS::verify_attestation` result.

## Architecture and trust boundaries

1. **DID subject / verification method**: `did:key:z...` embeds the Ed25519
   multicodec prefix `0xed01` plus the issuer's or holder's public key,
   base58btc encoded. The JSON DID document references the same key using
   `verificationMethod` / `assertionMethod`. In a hosted production service
   this would come from a genuine DID resolver. Here the DID document is
   deterministically derived from the key (no network).
2. **Identity registration**: `DidVcResolver::bind_controller` requires
   Soroban authorization from a controller address, and stores that
   controller's Ed25519 key. The example uses `env.mock_all_auths()` ONLY
   because there are no real transactions; never use it in production.
3. **W3C VC**: the client builds the normal JSON-LD fields `@context`,
   `id`, `type`, `issuer`, `issuanceDate`, `credentialSubject`,
   including a schema-specific `credentialSchema` reference. It validates DID document subject
   bindings, issuer, subject, claim and SAS schema UID before signing.
   The JWT contains `iss`, `sub`, `nbf`, `jti`, `vc` and a JOSE EdDSA
   header with a verification-method `kid`.
4. **Cryptographic proof**: the JWT issuer signs
   `base64url(header) + "." + base64url(claims)` with Ed25519.
   A second, **SAS-specific** signature covers the domain-separated hash of
   the JWT signing input, DID identifiers, SAS schema UID, attester and
   recipient (encoded using protocol XDR). The latter prevents replaying
   a legitimately signed credential against another SAS schema or address.
5. **On-chain**: Soroban cannot read arbitrary remote JSON-LD contexts.
   The resolver receives a bounded versioned binary envelope inside SAS's
   `Attestation.data`; it verifies both controller keys, reconstructs
   the two self-certifying `did:key` identifiers, checks the JWT's EdDSA
   signature and the SAS binding signature. Any failure reverts issuance.
   SAS still manages attestation storage, authorization, revocation and UID.

### Deliberate limits

This is an **educational local simulation**, not a fully generic W3C VC
verification product. The on-chain resolver verifies the signatures, DIDs
and SAS binding, **not the semantic content of arbitrary JWT JSON**. The
client performs JSON-LD claim and DID document checks before calling SAS;
a production verifier should also check issuer policy, expiry, audience,
revocation/status lists, trusted contexts, JWT claim/VC equivalence and
independent DID method resolution. The VC uses the standard `credentialSchema` field with a `urn:sas:schema:`
identifier and an example-specific type. The inline JSON-LD context maps
custom terms; external deployments must publish and resolve a real vocabulary. In production, the resolver key registry
also needs key rotation, revocation, and lifecycle/TTL management.

The wire envelope stores *signed JWT bytes and cryptographic proofs* in SAS.
Do not reuse this format as a generic JWT parser or assume signature
verification alone makes arbitrary JSON-LD content trustworthy.
