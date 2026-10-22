# Privacy Implications of Public Attestations

Soroban SAS runs on a public ledger. Anything written to an attestation, an
event or an index is readable by anyone, immediately, and stays readable
after the attestation is revoked or expires. This page lists what is exposed,
what revocation and expiry do and do not change, and the patterns the
protocol offers for keeping sensitive facts off the chain. It is engineering
guidance, not legal advice; data-protection law such as the GDPR or the
Nigeria Data Protection Act may apply to what you attest and needs its own
review.

## What is public

| Where | What anyone can read |
|---|---|
| Attestation record (persistent storage) | `uid`, `schema_uid`, `time`, `expiration_time`, `revocation_time`, `valid_from`, `ref_uid`, `recipient`, `attester`, `revocable` and the full `data` payload |
| `AttestationIssued` event | topics `(ATTESTED, schema_uid, attester)`; body `uid`, `schema_uid`, `attester`, `recipient` |
| `AttestationRevoked` event | topics `(REVOKED, uid)`; body `uid` and the revocation time |
| Indexer lookups | every UID attested by an address, for an address, or under a schema, in insertion order |
| Timestamp anchors | the ledger sequence and close time of issuance and of revocation (`get_issuance_timestamp`, `get_revocation_timestamp`) |
| Schema registry | schema definitions and resolver addresses |
| The transaction itself | the source account that paid for it, which for delegated issuance is the relayer, and the signed payload |

The `data` field is the largest exposure. The contract stores it verbatim and
never encrypts, hashes or redacts it.

## Consequences to design for

**Permanence.** `revoke` sets `revocation_time` and emits an event; it does
not delete anything. Expiry changes how `verify_attestation` answers; it does
not remove the record. When a storage entry's TTL lapses it is archived, not
erased, and the ledger history that already contained it is kept by
validators, archives, RPC providers and indexers. Treat every byte as
permanently published at the moment of `attest`. There is no erasure path to
promise a data subject.

**Linkability.** The recipient and attester are plain addresses, and the
indexer exists to make them searchable. Anyone can list every attestation an
address has received, which schemas they came from, and when. Reusing one
address across relationships links all of them. Attesting the same
recipient under many schemas builds a profile even when each payload is
harmless.

**Low-entropy commitments are not private.** Publishing `sha256(value)` for a
value drawn from a small set (a birth year, a country, a yes/no flag, a
postcode) lets anyone hash every candidate and read the answer. An unsalted
hash only hides values an attacker cannot enumerate.

**Metadata is data.** Even with an opaque payload, the schema, the attester,
the recipient, the issuance time, the expiry and the existence of a
revocation say something: who vouched for whom, about what kind of fact, and
when it stopped being true.

## Keeping sensitive facts off the chain

1. **Do not store personal data in `data`.** Store a commitment and keep the
   facts with the holder. Prefer coarse attributes ("over 18") to raw ones
   (a date of birth), and never put free text, names, government identifiers,
   contact details or health information in a payload.
2. **Commit to a Merkle root and disclose selectively.** Attest to a 32-byte
   root over salted leaves. The holder later reveals only the leaves a
   verifier needs, each with its proof, and `verify_merkle_leaf` checks them
   on-chain without exposing the others. See
   [Selective Disclosure](selective-disclosure.md), including how to format
   leaves.
3. **Salt every committed value.** Give each leaf its own random salt of at
   least 16 bytes so that equal values commit differently and cannot be
   guessed by hashing candidates.
4. **Use off-chain attestations when the claim never needs to be on-chain.**
   The issuer signs the payload and the holder shows it directly to the
   verifier; nothing is published until someone chooses to. See
   [Off-Chain Attestations](offchain-attestations.md).
5. **Use zero-knowledge proofs when a predicate is enough.** Proving "the
   holder qualifies" without revealing why is what the
   [ZK verifier](zk-private-attestations.md) is for.
6. **Separate identities.** Use a fresh recipient address per relationship
   or per credential, and a relayer you control for delegated issuance, so
   that addresses do not become a stable pseudonym that joins everything.
7. **Mind what you index.** Indexing is optional per deployment, but the
   underlying ledger entries remain readable without it. Do not rely on a
   deployment omitting the indexer as a privacy control.

## Checklist before issuing

- Would I be comfortable if this payload were printed in a newspaper and
  could never be corrected? If not, it does not belong in `data`.
- Is every committed value either high-entropy or salted?
- Does the recipient address link to anything the holder wants kept apart?
- Is revocation the right tool? It records that a claim stopped being true;
  it does not retract that it was once published.
- Has the holder agreed to publication, and do they understand that it is
  permanent?

## Related

- [Selective Disclosure](selective-disclosure.md)
- [Off-Chain Attestations](offchain-attestations.md)
- [Zero-Knowledge Private Attestations](zk-private-attestations.md)
- [Security Assumptions and Threat Model](security.md)
- [Attestation Lifecycle](attestations.md)
