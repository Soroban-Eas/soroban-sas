#![no_std]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use soroban_sas_common::{hash_attestation_struct, Attestation};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Bytes,
    BytesN, Env, Symbol, Vec,
};

const CONFIG_KEY: Symbol = symbol_short!("CFG");

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endorsement {
    pub signer: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverConfig {
    pub threshold: u32,
    pub signers: Vec<BytesN<32>>,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ResolverError {
    NotInitialized = 1,
    InvalidConfig = 2,
    InvalidSignature = 3,
    SignerNotAuthorized = 4,
    DuplicateSignature = 5,
    InsufficientSignatures = 6,
}

fn require_config(env: &Env) -> Result<ResolverConfig, ResolverError> {
    env.storage()
        .instance()
        .get(&CONFIG_KEY)
        .ok_or(ResolverError::NotInitialized)
}

fn extend_ttl(env: &Env) {
    env.storage().instance().extend_ttl(500_000, 6_307_200);
}

fn validate_config(threshold: u32, signers: &Vec<BytesN<32>>) -> Result<(), ResolverError> {
    if threshold == 0 || signers.is_empty() || threshold > signers.len() {
        return Err(ResolverError::InvalidConfig);
    }
    Ok(())
}

fn parse_endorsements(env: &Env, payload: &Bytes) -> Result<Vec<Endorsement>, ResolverError> {
    if payload.is_empty() {
        return Ok(Vec::new(env));
    }
    if payload.len() % 96 != 0 {
        return Err(ResolverError::InvalidSignature);
    }

    let mut endorsements = Vec::new(env);
    let mut offset = 0u32;
    while offset < payload.len() {
        let mut signer = [0u8; 32];
        let mut signature = [0u8; 64];
        for i in 0..32u32 {
            signer[i as usize] = payload
                .get(offset + i)
                .ok_or(ResolverError::InvalidSignature)?;
        }
        offset += 32;
        for i in 0..64u32 {
            signature[i as usize] = payload
                .get(offset + i)
                .ok_or(ResolverError::InvalidSignature)?;
        }
        offset += 64;

        endorsements.push_back(Endorsement {
            signer: BytesN::from_array(env, &signer),
            signature: BytesN::from_array(env, &signature),
        });
    }
    Ok(endorsements)
}

fn signer_is_authorized(config: &ResolverConfig, signer: &BytesN<32>) -> bool {
    for allowed in config.signers.iter() {
        if allowed == *signer {
            return true;
        }
    }
    false
}

fn attestation_without_endorsements(env: &Env, attestation: &Attestation) -> Attestation {
    let mut unsigned = attestation.clone();
    unsigned.data = Bytes::new(env);
    unsigned
}

fn verify_payload_signature(
    signer: &BytesN<32>,
    signature: &BytesN<64>,
    digest: &BytesN<32>,
) -> Result<(), ResolverError> {
    let verifying_key = VerifyingKey::from_bytes(&signer.to_array())
        .map_err(|_| ResolverError::InvalidSignature)?;
    let sig = Signature::from_bytes(&signature.to_array());
    verifying_key
        .verify(&digest.to_array(), &sig)
        .map_err(|_| ResolverError::InvalidSignature)?;
    Ok(())
}

fn resolve_valid_count(
    env: &Env,
    attestation: &Attestation,
    config: &ResolverConfig,
) -> Result<u32, ResolverError> {
    let endorsements = parse_endorsements(env, &attestation.data)?;
    let unsigned = attestation_without_endorsements(env, attestation);
    let digest = hash_attestation_struct(env, &unsigned);

    let mut seen = Vec::new(env);
    let mut valid_count = 0u32;

    for endorsement in endorsements.iter() {
        let signer = endorsement.signer.clone();
        if seen.iter().any(|existing| existing == signer) {
            continue;
        }
        seen.push_back(signer.clone());

        if !signer_is_authorized(config, &signer) {
            return Err(ResolverError::SignerNotAuthorized);
        }

        verify_payload_signature(&signer, &endorsement.signature, &digest)?;
        valid_count += 1;
    }

    if valid_count < config.threshold {
        return Err(ResolverError::InsufficientSignatures);
    }
    Ok(valid_count)
}

fn check_approval(env: &Env, attestation: &Attestation) -> Result<(), ResolverError> {
    let config = require_config(env)?;
    let _ = resolve_valid_count(env, attestation, &config)?;
    Ok(())
}

pub mod multisig {
    use super::*;

    #[contract]
    pub struct MultisigResolver;

    #[contractimpl]
    impl MultisigResolver {
        pub fn init(env: Env, threshold: u32, signers: Vec<BytesN<32>>) {
            validate_config(threshold, &signers).unwrap_or_else(|err| panic_with_error!(&env, err));
            env.storage()
                .instance()
                .set(&CONFIG_KEY, &ResolverConfig { threshold, signers });
            extend_ttl(&env);
        }

        pub fn initialize(env: Env, threshold: u32, signers: Vec<BytesN<32>>) {
            Self::init(env, threshold, signers);
        }

        pub fn configure(env: Env, threshold: u32, signers: Vec<BytesN<32>>) {
            Self::init(env, threshold, signers);
        }

        pub fn set_policy(env: Env, threshold: u32, signers: Vec<BytesN<32>>) {
            Self::init(env, threshold, signers);
        }

        pub fn set_threshold(env: Env, threshold: u32) {
            let mut config =
                require_config(&env).unwrap_or_else(|err| panic_with_error!(&env, err));
            validate_config(threshold, &config.signers)
                .unwrap_or_else(|err| panic_with_error!(&env, err));
            config.threshold = threshold;
            env.storage().instance().set(&CONFIG_KEY, &config);
            extend_ttl(&env);
        }

        pub fn set_signers(env: Env, signers: Vec<BytesN<32>>) {
            let mut config =
                require_config(&env).unwrap_or_else(|err| panic_with_error!(&env, err));
            validate_config(config.threshold, &signers)
                .unwrap_or_else(|err| panic_with_error!(&env, err));
            config.signers = signers;
            env.storage().instance().set(&CONFIG_KEY, &config);
            extend_ttl(&env);
        }

        pub fn config(env: Env) -> Option<ResolverConfig> {
            env.storage().instance().get(&CONFIG_KEY)
        }

        pub fn threshold(env: Env) -> Option<u32> {
            require_config(&env).ok().map(|config| config.threshold)
        }

        pub fn signers(env: Env) -> Option<Vec<BytesN<32>>> {
            require_config(&env).ok().map(|config| config.signers)
        }

        pub fn verify_endorsements(env: Env, attestation: Attestation) -> u32 {
            let config = require_config(&env).unwrap_or_else(|err| panic_with_error!(&env, err));
            resolve_valid_count(&env, &attestation, &config)
                .unwrap_or_else(|err| panic_with_error!(&env, err))
        }

        pub fn on_attest(env: Env, attestation: Attestation) {
            check_approval(&env, &attestation).unwrap_or_else(|err| panic_with_error!(&env, err));
        }

        pub fn on_revoke(env: Env, attestation: Attestation) {
            check_approval(&env, &attestation).unwrap_or_else(|err| panic_with_error!(&env, err));
        }
    }
}

pub mod endorsement {
    use super::*;

    #[contract]
    pub struct EndorsementResolver;

    #[contractimpl]
    impl EndorsementResolver {
        pub fn init(env: Env, threshold: u32, signers: Vec<BytesN<32>>) {
            crate::multisig::MultisigResolver::init(env, threshold, signers);
        }

        pub fn initialize(env: Env, threshold: u32, signers: Vec<BytesN<32>>) {
            crate::multisig::MultisigResolver::initialize(env, threshold, signers);
        }

        pub fn configure(env: Env, threshold: u32, signers: Vec<BytesN<32>>) {
            crate::multisig::MultisigResolver::configure(env, threshold, signers);
        }

        pub fn set_policy(env: Env, threshold: u32, signers: Vec<BytesN<32>>) {
            crate::multisig::MultisigResolver::set_policy(env, threshold, signers);
        }

        pub fn on_attest(env: Env, attestation: Attestation) {
            crate::multisig::MultisigResolver::on_attest(env, attestation);
        }

        pub fn on_revoke(env: Env, attestation: Attestation) {
            crate::multisig::MultisigResolver::on_revoke(env, attestation);
        }

        pub fn verify_endorsements(env: Env, attestation: Attestation) -> u32 {
            crate::multisig::MultisigResolver::verify_endorsements(env, attestation)
        }
    }
}

pub use endorsement::EndorsementResolver;
pub use multisig::MultisigResolver;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use soroban_sas_common::UID;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env};

    fn make_attestation(env: &Env) -> Attestation {
        Attestation {
            uid: UID(BytesN::from_array(env, &[9u8; 32])),
            schema_uid: UID(BytesN::from_array(env, &[1u8; 32])),
            time: 1_700_000_000,
            valid_from: 0,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
            recipient: Address::generate(env),
            attester: Address::generate(env),
            revocable: true,
            data: Bytes::new(env),
        }
    }

    fn encode_endorsements(
        env: &Env,
        signing_keys: &[SigningKey],
        attestation: &Attestation,
    ) -> Bytes {
        let mut data = Bytes::new(env);
        for key in signing_keys {
            let digest = hash_attestation_struct(env, attestation);
            let sig = key.sign(&digest.to_array());
            let signer = key.verifying_key().to_bytes();
            let signature = sig.to_bytes();
            let mut rec = Bytes::new(env);
            rec.append(&Bytes::from_slice(env, &signer));
            rec.append(&Bytes::from_slice(env, &signature));
            data.append(&rec);
        }
        data
    }

    fn install(env: &Env, threshold: u32, keys: &[SigningKey]) -> (Address, Vec<BytesN<32>>) {
        let mut signers = Vec::new(env);
        for key in keys {
            signers.push_back(BytesN::from_array(env, &key.verifying_key().to_bytes()));
        }
        let contract_id = env.register_contract(None, multisig::MultisigResolver);
        let client = multisig::MultisigResolverClient::new(env, &contract_id);
        client.init(&threshold, &signers);
        (contract_id, signers)
    }

    #[test]
    fn accepts_2_of_3_endorsements() {
        let env = Env::default();
        let key_a = SigningKey::generate(&mut rand::thread_rng());
        let key_b = SigningKey::generate(&mut rand::thread_rng());
        let key_c = SigningKey::generate(&mut rand::thread_rng());
        let unsigned = make_attestation(&env);
        let (contract_id, _) = install(&env, 2, &[key_a.clone(), key_b.clone(), key_c.clone()]);
        let client = multisig::MultisigResolverClient::new(&env, &contract_id);
        let payload = encode_endorsements(&env, &[key_a.clone(), key_b.clone()], &unsigned);

        let mut attestation = unsigned;
        attestation.data = payload;

        client.on_attest(&attestation);
        assert_eq!(client.verify_endorsements(&attestation), 2);
    }

    #[test]
    fn accepts_3_of_5_endorsements() {
        let env = Env::default();
        let key_a = SigningKey::generate(&mut rand::thread_rng());
        let key_b = SigningKey::generate(&mut rand::thread_rng());
        let key_c = SigningKey::generate(&mut rand::thread_rng());
        let key_d = SigningKey::generate(&mut rand::thread_rng());
        let key_e = SigningKey::generate(&mut rand::thread_rng());
        let unsigned = make_attestation(&env);
        let (contract_id, _) = install(
            &env,
            3,
            &[
                key_a.clone(),
                key_b.clone(),
                key_c.clone(),
                key_d.clone(),
                key_e.clone(),
            ],
        );
        let client = multisig::MultisigResolverClient::new(&env, &contract_id);
        let payload = encode_endorsements(
            &env,
            &[key_a.clone(), key_c.clone(), key_e.clone()],
            &unsigned,
        );
        let mut attestation = unsigned;
        attestation.data = payload;

        client.on_attest(&attestation);
        assert_eq!(client.verify_endorsements(&attestation), 3);
    }

    #[test]
    fn ignores_duplicate_signers_and_rejects_missing_threshold() {
        let env = Env::default();
        let key_a = SigningKey::generate(&mut rand::thread_rng());
        let key_b = SigningKey::generate(&mut rand::thread_rng());
        let key_c = SigningKey::generate(&mut rand::thread_rng());
        let base = make_attestation(&env);
        let contract_id = env.register_contract(None, multisig::MultisigResolver);
        let client = multisig::MultisigResolverClient::new(&env, &contract_id);
        let mut signers = Vec::new(&env);
        signers.push_back(BytesN::from_array(&env, &key_a.verifying_key().to_bytes()));
        signers.push_back(BytesN::from_array(&env, &key_b.verifying_key().to_bytes()));
        signers.push_back(BytesN::from_array(&env, &key_c.verifying_key().to_bytes()));
        client.init(&2, &signers);

        let payload =
            encode_endorsements(&env, &[key_a.clone(), key_a.clone(), key_b.clone()], &base);
        let mut attestation = base.clone();
        attestation.data = payload;
        client.on_attest(&attestation);

        let payload = encode_endorsements(&env, &[key_a.clone()], &base);
        let mut attestation = base;
        attestation.data = payload;
        let res = client.try_on_attest(&attestation);
        assert_eq!(res, Err(Ok(ResolverError::InsufficientSignatures.into())));
    }
}
