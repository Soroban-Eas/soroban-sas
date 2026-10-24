//! FROST threshold aggregation tests for schemas that declare a group key
//! (#534).
//!
//! The module has three layers:
//!
//! 1. [`support`] is a small, test-only FROST signer over the Ed25519 group. It
//!    implements the signing equation a real FROST ceremony produces
//!    (`s = r + c * lambda_i * a_i`, with `c = H(R || A || M)`), so the
//!    aggregates it emits are verifiable by any standard Ed25519 verifier.
//! 2. The golden vectors in
//!    `packages/soroban-sas-common/test_vectors/frost_threshold.tsv` are
//!    parsed, verified with `ed25519-dalek` (independent of this signer), and
//!    regenerated from their pinned seeds.
//! 3. End-to-end tests deploy the real `SchemaRegistry` and `SAS` contracts,
//!    declare a FROST group on a schema, and relay aggregate signatures
//!    through `attest_by_delegation`, `revoke_by_delegation`, and the
//!    `verify_offchain_attestation` view.
//!
//! The key material here is public by design and must never be reused for a
//! real signing group.

use crate::{SASClient, SAS};
use ed25519_dalek::{Signature, VerifyingKey};
use schema_registry::SchemaRegistry;
use soroban_sas_common::{
    hash_delegated_revocation, hash_offchain_attestation, validate_frost_group, Attestation,
    AttestationDomain, FrostGroup, SASError, FROST_GROUP_PUBLIC_KEY_BYTES, FROST_SIGNATURE_BYTES,
    MAX_FROST_SIGNERS, UID,
};
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, String as SorobanString,
};

/// The TSV table consumed in both directions: the tests verify it and the
/// ignored regeneration test prints it.
const VECTORS_TSV: &str =
    include_str!("../../../packages/soroban-sas-common/test_vectors/frost_threshold.tsv");

mod support {
    //! Deterministic, test-only FROST dealer/signer for the Ed25519 group.
    //!
    //! This is *not* a production FROST implementation: there is no DKG, no
    //! proof of possession, and no binding factors. It implements the final
    //! aggregation equation that FROST produces, which is all SAS sees on
    //! chain. The vectors generated here therefore double as an
    //! interoperability check for any real FROST signer that emits RFC 8032
    //! Ed25519 signatures.

    use curve25519_dalek::{
        edwards::{CompressedEdwardsY, EdwardsPoint},
        scalar::Scalar,
    };
    use sha2::{Digest, Sha512};

    /// A t-of-n Ed25519 key set derived deterministically from `seed`.
    pub struct FrostKeySet {
        pub threshold: usize,
        pub max_signers: usize,
        shares: Vec<Scalar>,
        public_shares: Vec<EdwardsPoint>,
        group_public: EdwardsPoint,
    }

    impl FrostKeySet {
        /// Runs the trusted-dealer step: derives the polynomial coefficients
        /// from `seed`, evaluates the polynomial at `x = 1..=max_signers`, and
        /// takes `a0 * B` as the group public key.
        pub fn from_seed(seed: &[u8; 32], threshold: usize, max_signers: usize) -> Self {
            assert!(threshold > 0 && threshold <= max_signers && max_signers <= 255);

            let coefficients: Vec<Scalar> = (0..threshold)
                .map(|k| hash_to_scalar(&[b"frost-coefficient", &seed[..], &[k as u8]]))
                .collect();

            let mut shares = Vec::with_capacity(max_signers);
            let mut public_shares = Vec::with_capacity(max_signers);
            for i in 0..max_signers {
                let x = Scalar::from((i as u64) + 1);
                let mut share = Scalar::ZERO;
                for coefficient in coefficients.iter().rev() {
                    share = share * x + *coefficient;
                }
                shares.push(share);
                public_shares.push(EdwardsPoint::mul_base(&share));
            }

            Self {
                threshold,
                max_signers,
                shares,
                public_shares,
                group_public: EdwardsPoint::mul_base(&coefficients[0]),
            }
        }

        pub fn group_public_bytes(&self) -> [u8; 32] {
            self.group_public.compress().to_bytes()
        }

        pub fn public_share_bytes(&self, index: usize) -> [u8; 32] {
            self.public_shares[index].compress().to_bytes()
        }

        /// Produces `R || s` from the listed zero-based signers.
        ///
        /// Every signer derives a deterministic nonce, the nonces are summed
        /// into `R`, and each response is weighted by its Lagrange coefficient
        /// at zero. Fewer than `threshold` signers still yields a `64`-byte
        /// string — but not a signature that verifies under the group key.
        pub fn sign(&self, message: &[u8; 32], signers: &[usize]) -> [u8; 64] {
            assert!(!signers.is_empty());

            let lambdas: Vec<Scalar> = signers
                .iter()
                .map(|&index| lagrange_at_zero(index, signers))
                .collect();

            let nonces: Vec<Scalar> = signers
                .iter()
                .map(|&index| {
                    hash_to_scalar(&[b"frost-nonce", &self.shares[index].to_bytes(), &message[..]])
                })
                .collect();

            let mut nonce_points: Vec<EdwardsPoint> =
                nonces.iter().map(EdwardsPoint::mul_base).collect();
            let mut r_point = nonce_points.remove(0);
            for point in nonce_points {
                r_point += point;
            }

            let challenge = challenge(&r_point, &self.group_public, message);
            let mut s = Scalar::ZERO;
            for (position, &index) in signers.iter().enumerate() {
                s += nonces[position] + challenge * lambdas[position] * self.shares[index];
            }

            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&r_point.compress().to_bytes());
            signature[32..].copy_from_slice(&s.to_bytes());
            signature
        }
    }

    /// Recomputes the group public key from a signing set's public shares:
    /// `A = sum_i lambda_i * A_i`, the FROST verification-key relation.
    pub fn group_key_from_shares(public_shares: &[[u8; 32]], signers: &[usize]) -> [u8; 32] {
        let mut group: Option<EdwardsPoint> = None;
        for (position, &index) in signers.iter().enumerate() {
            let share = CompressedEdwardsY(public_shares[position])
                .decompress()
                .expect("public share must be a valid Ed25519 point");
            let term = lagrange_at_zero(index, signers) * share;
            group = Some(match group {
                Some(acc) => acc + term,
                None => term,
            });
        }
        group
            .expect("at least one signing share is required")
            .compress()
            .to_bytes()
    }

    fn lagrange_at_zero(index: usize, signers: &[usize]) -> Scalar {
        let xi = Scalar::from(index as u64 + 1);
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for &other in signers {
            if other == index {
                continue;
            }
            let xj = Scalar::from(other as u64 + 1);
            numerator *= xj;
            denominator *= xj - xi;
        }
        numerator * denominator.invert()
    }

    fn challenge(r_point: &EdwardsPoint, group: &EdwardsPoint, message: &[u8; 32]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(r_point.compress().to_bytes());
        hasher.update(group.compress().to_bytes());
        hasher.update(message);
        Scalar::from_hash(hasher)
    }

    fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
        let mut hasher = Sha512::new();
        for part in parts {
            hasher.update(part);
        }
        Scalar::from_hash(hasher)
    }
}

use support::{group_key_from_shares, FrostKeySet};

struct VectorRow {
    expected: String,
    threshold: usize,
    max_signers: usize,
    seed: [u8; 32],
    group_public_key: [u8; 32],
    signer_indices: Vec<usize>,
    signer_public_shares: Vec<[u8; 32]>,
    message: [u8; 32],
    signature: [u8; 64],
}

impl VectorRow {
    fn is_valid(&self) -> bool {
        self.expected == "ok"
    }
}

fn parse_vectors() -> Vec<VectorRow> {
    let mut rows = Vec::new();
    for (line_number, line) in VECTORS_TSV.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            columns.len(),
            9,
            "vector line {} must have 9 tab-separated columns",
            line_number + 1
        );

        let signer_indices: Vec<usize> = columns[5]
            .split(',')
            .map(|value| value.parse::<usize>().expect("signer index") - 1)
            .collect();
        let signer_public_shares: Vec<[u8; 32]> =
            columns[6].split(',').map(hex_array::<32>).collect();

        rows.push(VectorRow {
            expected: columns[0].to_string(),
            threshold: columns[1].parse().expect("threshold"),
            max_signers: columns[2].parse().expect("max_signers"),
            seed: hex_array::<32>(columns[3]),
            group_public_key: hex_array::<32>(columns[4]),
            signer_indices,
            signer_public_shares,
            message: hex_array::<32>(columns[7]),
            signature: hex_array::<64>(columns[8]),
        });
    }
    rows
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    let decoded = hex::decode(value).expect("valid hex");
    decoded
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("expected {} bytes, got {}", N, decoded.len()))
}

fn signers_argument(signers: &[usize]) -> String {
    signers
        .iter()
        .map(|index| (index + 1).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn public_shares_argument(keys: &FrostKeySet, signers: &[usize]) -> String {
    signers
        .iter()
        .map(|&index| hex::encode(keys.public_share_bytes(index)))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn frost_vectors_are_well_formed() {
    let rows = parse_vectors();
    assert!(rows.len() >= 4, "expected at least four pinned vectors");

    let mut valid = 0;
    let mut insufficient = 0;
    for row in &rows {
        assert!(
            row.threshold >= 2,
            "a FROST threshold vector must require at least two shares"
        );
        assert!(row.threshold <= row.max_signers);
        assert!(row.max_signers <= MAX_FROST_SIGNERS as usize);
        assert_eq!(row.signer_indices.len(), row.signer_public_shares.len());

        if row.is_valid() {
            valid += 1;
            assert!(
                row.signer_indices.len() >= row.threshold,
                "a valid vector must combine at least threshold shares"
            );
        } else {
            insufficient += 1;
            assert_eq!(row.expected, "insufficient-threshold");
            assert!(
                row.signer_indices.len() < row.threshold,
                "an insufficient-threshold vector must combine fewer than threshold shares"
            );
        }
    }

    assert!(valid >= 2, "expected 2-of-3 and 3-of-5 valid vectors");
    assert!(insufficient >= 1);
}

#[test]
fn frost_vectors_verify_with_standard_ed25519() {
    for row in parse_vectors() {
        let verifying_key =
            VerifyingKey::from_bytes(&row.group_public_key).expect("valid Ed25519 group key");
        let signature = Signature::from_bytes(&row.signature);

        let verdict = verifying_key.verify_strict(&row.message, &signature);
        if row.is_valid() {
            verdict.unwrap_or_else(|error| {
                panic!(
                    "{}-of-{} vector must verify with a standard Ed25519 verifier: {error}",
                    row.threshold, row.max_signers
                )
            });
        } else {
            assert!(
                verdict.is_err(),
                "an aggregate with fewer than {} shares must not verify under the group key",
                row.threshold
            );
        }
    }
}

#[test]
fn frost_vectors_regenerate_from_their_pinned_seeds() {
    for row in parse_vectors() {
        let keys = FrostKeySet::from_seed(&row.seed, row.threshold, row.max_signers);
        assert_eq!(keys.threshold, row.threshold);
        assert_eq!(keys.max_signers, row.max_signers);

        assert_eq!(
            keys.group_public_bytes(),
            row.group_public_key,
            "group public key must be reproducible from the pinned seed"
        );

        for (&index, expected_share) in row
            .signer_indices
            .iter()
            .zip(row.signer_public_shares.iter())
        {
            assert_eq!(
                keys.public_share_bytes(index),
                *expected_share,
                "public share for signer {} must match",
                index + 1
            );
        }

        assert_eq!(
            keys.sign(&row.message, &row.signer_indices),
            row.signature,
            "aggregate signature must be reproducible from the pinned seed"
        );
    }
}

#[test]
fn frost_group_key_is_the_lagrange_combination_of_signing_shares() {
    for row in parse_vectors() {
        let recomputed = group_key_from_shares(&row.signer_public_shares, &row.signer_indices);
        if row.is_valid() {
            assert_eq!(
                recomputed, row.group_public_key,
                "group public key must equal sum(lambda_i * A_i) over the signing set"
            );
        } else {
            assert_ne!(
                recomputed, row.group_public_key,
                "an under-threshold signing set must not reconstruct the group key"
            );
        }
    }
}

#[test]
fn frost_group_validation_rejects_unsafe_configurations() {
    let env = Env::default();
    let key = BytesN::from_array(&env, &[7u8; 32]);

    let valid = FrostGroup {
        group_public_key: key.clone(),
        threshold: 2,
        max_signers: 3,
    };
    assert!(validate_frost_group(&valid).is_ok());

    let single_signer = FrostGroup {
        group_public_key: key.clone(),
        threshold: 1,
        max_signers: 3,
    };
    assert_eq!(
        validate_frost_group(&single_signer),
        Err(SASError::InvalidValue)
    );

    let unreachable = FrostGroup {
        group_public_key: key.clone(),
        threshold: 4,
        max_signers: 3,
    };
    assert_eq!(
        validate_frost_group(&unreachable),
        Err(SASError::InvalidValue)
    );

    let too_large = FrostGroup {
        group_public_key: key.clone(),
        threshold: 2,
        max_signers: MAX_FROST_SIGNERS + 1,
    };
    assert_eq!(
        validate_frost_group(&too_large),
        Err(SASError::LimitExceeded)
    );

    let zero_key = FrostGroup {
        group_public_key: BytesN::from_array(&env, &[0u8; 32]),
        threshold: 2,
        max_signers: 3,
    };
    assert_eq!(validate_frost_group(&zero_key), Err(SASError::InvalidValue));
}

// ---------------------------------------------------------------------------
// End-to-end contract tests
// ---------------------------------------------------------------------------

#[soroban_sdk::contract]
struct FrostMockResolver;

#[soroban_sdk::contractimpl]
impl FrostMockResolver {
    pub fn on_attest(_env: Env, _attestation: Attestation) {}
    pub fn on_revoke(_env: Env, _attestation: Attestation) {}
}

struct Fixture {
    env: Env,
    sas: SASClient<'static>,
    sas_id: Address,
    keys: FrostKeySet,
    attestation: Attestation,
}

/// Deploys the real registry + SAS, registers a schema, and (optionally)
/// declares the FROST group on it.
fn setup(seed: [u8; 32], threshold: usize, max_signers: usize, declare_group: bool) -> Fixture {
    let env = Env::default();
    env.mock_all_auths();

    let registry_id = env.register_contract(None, SchemaRegistry);
    let registry = schema_registry::SchemaRegistryClient::new(&env, &registry_id);

    let sas_id = env.register_contract(None, SAS);
    let sas = SASClient::new(&env, &sas_id);

    let admin = Address::generate(&env);
    sas.init(&admin, &registry_id);

    let resolver_id = env.register_contract(None, FrostMockResolver);
    let owner = Address::generate(&env);
    let schema_uid = registry.register(
        &owner,
        &SorobanString::from_str(&env, "bool frost_endorsed"),
        &resolver_id,
        &true,
    );

    let keys = FrostKeySet::from_seed(&seed, threshold, max_signers);
    if declare_group {
        let group = FrostGroup {
            group_public_key: BytesN::from_array(&env, &keys.group_public_bytes()),
            threshold: threshold as u32,
            max_signers: max_signers as u32,
        };
        registry.set_schema_frost_group(&owner, &schema_uid, &group);
    }

    let recipient = Address::generate(&env);
    let data = Bytes::from_slice(&env, b"jointly endorsed by the consortium");
    let uid = soroban_sas_common::attestation_uid(&env, &schema_uid, &recipient, &owner, &data);
    let attestation = Attestation {
        uid,
        schema_uid,
        time: 1_000,
        expiration_time: 0,
        revocation_time: 0,
        ref_uid: UID(BytesN::from_array(&env, &[0u8; 32])),
        recipient,
        attester: owner,
        revocable: true,
        data,
        valid_from: 0,
    };

    Fixture {
        env,
        sas,
        sas_id,
        keys,
        attestation,
    }
}

fn domain(fixture: &Fixture, nonce: u64) -> AttestationDomain {
    AttestationDomain {
        network_id: fixture.env.ledger().network_id(),
        contract: fixture.sas_id.clone(),
        nonce,
    }
}

fn attestation_digest(fixture: &Fixture, nonce: u64) -> [u8; 32] {
    hash_offchain_attestation(&fixture.env, &fixture.attestation, &domain(fixture, nonce))
        .to_array()
}

fn aggregate(fixture: &Fixture, nonce: u64, signers: &[usize]) -> BytesN<64> {
    let digest = attestation_digest(fixture, nonce);
    BytesN::from_array(&fixture.env, &fixture.keys.sign(&digest, signers))
}

fn group_key(fixture: &Fixture) -> BytesN<32> {
    BytesN::from_array(&fixture.env, &fixture.keys.group_public_bytes())
}

#[test]
fn frost_2_of_3_attest_by_delegation_issues_the_attestation() {
    let fixture = setup([0x21; 32], 2, 3, true);
    let nonce = 1;
    // Shares 1 and 3 out of 3.
    let signature = aggregate(&fixture, nonce, &[0, 2]);

    let uid = fixture.sas.attest_by_delegation(
        &fixture.attestation,
        &nonce,
        &signature,
        &group_key(&fixture),
    );

    assert_eq!(uid, fixture.attestation.uid);
    assert!(fixture.sas.get_attestation(&uid).is_some());
    assert_eq!(
        fixture
            .sas
            .get_delegation_nonce(&fixture.attestation.attester),
        Some(nonce)
    );

    let replay = fixture.sas.try_attest_by_delegation(
        &fixture.attestation,
        &nonce,
        &signature,
        &group_key(&fixture),
    );
    assert_eq!(replay, Err(Ok(SASError::DelegationReplay.into())));
}

#[test]
fn frost_multi_attest_by_delegation_relays_aggregates_for_each_item() {
    let fixture = setup([0x53; 32], 3, 5, true);
    let group_key = group_key(&fixture);

    let second_recipient = Address::generate(&fixture.env);
    let second_data = Bytes::from_slice(&fixture.env, b"second jointly endorsed claim");
    let second_uid = soroban_sas_common::attestation_uid(
        &fixture.env,
        &fixture.attestation.schema_uid,
        &second_recipient,
        &fixture.attestation.attester,
        &second_data,
    );
    let second = Attestation {
        uid: second_uid,
        recipient: second_recipient,
        data: second_data,
        ..fixture.attestation.clone()
    };

    let nonce_one = 1;
    let nonce_two = 2;
    let first_digest = hash_offchain_attestation(
        &fixture.env,
        &fixture.attestation,
        &domain(&fixture, nonce_one),
    )
    .to_array();
    let second_digest =
        hash_offchain_attestation(&fixture.env, &second, &domain(&fixture, nonce_two)).to_array();
    let signatures = soroban_sdk::vec![
        &fixture.env,
        BytesN::from_array(&fixture.env, &fixture.keys.sign(&first_digest, &[0, 2, 4])),
        BytesN::from_array(&fixture.env, &fixture.keys.sign(&second_digest, &[1, 3, 4])),
    ];

    let uids = fixture.sas.multi_attest_by_delegation(
        &soroban_sdk::vec![&fixture.env, fixture.attestation.clone(), second.clone()],
        &soroban_sdk::vec![&fixture.env, nonce_one, nonce_two],
        &signatures,
        &soroban_sdk::vec![&fixture.env, group_key.clone(), group_key],
    );

    assert_eq!(
        uids,
        soroban_sdk::vec![
            &fixture.env,
            fixture.attestation.uid.clone(),
            second.uid.clone()
        ]
    );
    assert!(fixture
        .sas
        .get_attestation(&fixture.attestation.uid)
        .is_some());
    assert!(fixture.sas.get_attestation(&second.uid).is_some());
    assert_eq!(
        fixture
            .sas
            .get_delegation_nonce(&fixture.attestation.attester),
        Some(nonce_two)
    );
}

#[test]
fn frost_3_of_5_attest_by_delegation_issues_the_attestation() {
    let fixture = setup([0x53; 32], 3, 5, true);
    let nonce = 9;
    // Shares 1, 3 and 5 out of 5.
    let signature = aggregate(&fixture, nonce, &[0, 2, 4]);

    let uid = fixture.sas.attest_by_delegation(
        &fixture.attestation,
        &nonce,
        &signature,
        &group_key(&fixture),
    );

    assert_eq!(uid, fixture.attestation.uid);
    assert!(fixture.sas.get_attestation(&uid).is_some());
}

#[test]
fn frost_aggregate_with_too_few_shares_fails_validation() {
    let fixture = setup([0x21; 32], 2, 3, true);
    let nonce = 1;
    // A partial aggregate: one share contributes, below the 2-of-3 threshold.
    let signature = aggregate(&fixture, nonce, &[0]);

    let result = fixture.sas.try_attest_by_delegation(
        &fixture.attestation,
        &nonce,
        &signature,
        &group_key(&fixture),
    );

    assert!(
        result.is_err(),
        "under-threshold aggregate must be rejected"
    );
    assert!(fixture
        .sas
        .get_attestation(&fixture.attestation.uid)
        .is_none());
    assert_eq!(
        fixture
            .sas
            .get_delegation_nonce(&fixture.attestation.attester),
        None,
        "a failed verification must not consume the nonce"
    );
}

#[test]
fn frost_rejects_a_signature_made_with_a_single_member_key() {
    let fixture = setup([0x21; 32], 2, 3, true);
    let nonce = 1;
    let signature = aggregate(&fixture, nonce, &[0, 2]);

    // A valid group aggregate paired with one member's public key must not be
    // accepted: the schema requires the group key, not a participant key.
    let member_key = BytesN::from_array(&fixture.env, &fixture.keys.public_share_bytes(0));
    let result =
        fixture
            .sas
            .try_attest_by_delegation(&fixture.attestation, &nonce, &signature, &member_key);

    assert_eq!(result, Err(Ok(SASError::Unauthorized.into())));
}

#[test]
fn frost_rejects_a_tampered_attestation_payload() {
    let fixture = setup([0x53; 32], 3, 5, true);
    let nonce = 3;
    let signature = aggregate(&fixture, nonce, &[0, 1, 4]);

    let mut tampered = fixture.attestation.clone();
    tampered.data = Bytes::from_slice(&fixture.env, b"different claim");
    tampered.uid = soroban_sas_common::attestation_uid(
        &fixture.env,
        &tampered.schema_uid,
        &tampered.recipient,
        &tampered.attester,
        &tampered.data,
    );

    let result =
        fixture
            .sas
            .try_attest_by_delegation(&tampered, &nonce, &signature, &group_key(&fixture));
    assert!(result.is_err());
}

#[test]
fn non_frost_schema_does_not_accept_a_group_signature() {
    let fixture = setup([0x21; 32], 2, 3, false);
    let nonce = 1;
    let signature = aggregate(&fixture, nonce, &[0, 2]);

    let result = fixture.sas.try_attest_by_delegation(
        &fixture.attestation,
        &nonce,
        &signature,
        &group_key(&fixture),
    );

    // Falls back to the attester-key binding: the group key is not the
    // attester's account key, so the call is unauthorized.
    assert_eq!(result, Err(Ok(SASError::Unauthorized.into())));
}

#[test]
fn frost_verify_offchain_attestation_accepts_a_group_aggregate() {
    let fixture = setup([0x21; 32], 2, 3, true);
    let nonce = 4;
    let signature = aggregate(&fixture, nonce, &[0, 2]);

    assert!(fixture.sas.verify_offchain_attestation(
        &fixture.attestation,
        &nonce,
        &group_key(&fixture),
        &signature,
    ));
}

#[test]
fn frost_group_controls_delegated_revocation() {
    let fixture = setup([0x53; 32], 3, 5, true);
    let issue_nonce = 1;
    let issue_signature = aggregate(&fixture, issue_nonce, &[0, 2, 4]);
    let group_key = group_key(&fixture);

    fixture.sas.attest_by_delegation(
        &fixture.attestation,
        &issue_nonce,
        &issue_signature,
        &group_key,
    );

    fixture
        .env
        .ledger()
        .with_mut(|ledger| ledger.timestamp = 100);
    let revoke_nonce = 2;
    let revocation_digest = hash_delegated_revocation(
        &fixture.env,
        &fixture.attestation.uid,
        &fixture.attestation.attester,
        &domain(&fixture, revoke_nonce),
    )
    .to_array();
    let revocation_signature = BytesN::from_array(
        &fixture.env,
        &fixture.keys.sign(&revocation_digest, &[0, 1, 3]),
    );

    fixture.sas.revoke_by_delegation(
        &fixture.attestation.uid,
        &revoke_nonce,
        &revocation_signature,
        &group_key,
    );

    assert!(!fixture.sas.verify_attestation(&fixture.attestation.uid));

    // The previous single-key path is no longer available for this schema,
    // even for the attester's own would-be key. Use a fresh nonce so the
    // rejection comes from the key binding, not replay protection.
    let member_key = BytesN::from_array(&fixture.env, &fixture.keys.public_share_bytes(1));
    let replay = fixture.sas.try_revoke_by_delegation(
        &fixture.attestation.uid,
        &(revoke_nonce + 1),
        &revocation_signature,
        &member_key,
    );
    assert_eq!(replay, Err(Ok(SASError::Unauthorized.into())));
}

#[test]
fn frost_calldata_is_identical_to_single_signature_delegated_attestation() {
    let fixture = setup([0x21; 32], 2, 3, true);
    let nonce = 1;
    let frost_signature = aggregate(&fixture, nonce, &[0, 2]);
    let single_key_signature = BytesN::from_array(&fixture.env, &[0x44u8; 64]);
    let single_key = BytesN::from_array(&fixture.env, &[0x55u8; 32]);

    assert_eq!(
        encoded_argument_footprint(&fixture, &frost_signature, &group_key(&fixture)),
        encoded_argument_footprint(&fixture, &single_key_signature, &single_key),
        "FROST aggregates must not add any calldata beyond the existing \
         attestation/nonce/signature/public-key argument list"
    );
    assert_eq!(FROST_SIGNATURE_BYTES, 64);
    assert_eq!(FROST_GROUP_PUBLIC_KEY_BYTES, 32);
}

/// Encodes the `attest_by_delegation` argument list with the same field
/// layout for either signing mode, for a footprint comparison.
fn encoded_argument_footprint(
    fixture: &Fixture,
    signature: &BytesN<64>,
    public_key: &BytesN<32>,
) -> u32 {
    let mut encoded = Bytes::new(&fixture.env);
    encoded.append(&fixture.attestation.clone().to_xdr(&fixture.env));
    encoded.append(&Bytes::from_slice(&fixture.env, &1u64.to_be_bytes()));
    encoded.append(&signature.clone().to_xdr(&fixture.env));
    encoded.append(&public_key.clone().to_xdr(&fixture.env));
    encoded.len()
}

/// Maintenance helper: prints the canonical TSV rows for the pinned groups.
///
/// Run with `cargo test -p sas --lib frost_test::dump_frost_vectors -- --ignored --nocapture`
/// and paste the output into
/// `packages/soroban-sas-common/test_vectors/frost_threshold.tsv`.
#[test]
#[ignore = "prints regenerated golden vectors; not part of the normal suite"]
fn dump_frost_vectors() {
    type DumpVector = (
        [u8; 32],
        usize,
        usize,
        &'static [usize],
        &'static [u8; 32],
        &'static str,
    );

    let vectors: [DumpVector; 4] = [
        ([0x21; 32], 2, 3, &[0, 2], &[0x5a; 32], "ok"),
        ([0x53; 32], 3, 5, &[0, 2, 4], &[0xa5; 32], "ok"),
        (
            [0x21; 32],
            2,
            3,
            &[0],
            &[0x5a; 32],
            "insufficient-threshold",
        ),
        (
            [0x53; 32],
            3,
            5,
            &[0, 1],
            &[0xa5; 32],
            "insufficient-threshold",
        ),
    ];

    for (seed, threshold, max_signers, signers, message, expected) in vectors {
        let keys = FrostKeySet::from_seed(&seed, threshold, max_signers);
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            expected,
            threshold,
            max_signers,
            hex::encode(seed),
            hex::encode(keys.group_public_bytes()),
            signers_argument(signers),
            public_shares_argument(&keys, signers),
            hex::encode(message),
            hex::encode(keys.sign(message, signers)),
        );
    }
}
