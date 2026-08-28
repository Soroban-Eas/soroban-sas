//! Strongly-typed wrappers for contract clients.

use crate::account;
use crate::errors::SdkError;
use crate::rpc::{GetTransactionResult, RpcClient};
use crate::signature;
use crate::simulate;
use crate::transaction::TransactionSubmitter;
use soroban_sas_common::{Attestation, SchemaRecord, UID};
use soroban_sdk::xdr::{Limits, ReadXdr, ScVal, SorobanTransactionData, TransactionExt, VecM};
use soroban_sdk::{Address, Bytes, BytesN, Env, String as SorobanString};
use std::time::Duration;

/// Classic per-operation fee, in stroops, before the Soroban resource fee
/// simulation reports is added on top.
const BASE_FEE: u32 = 100;
const DEFAULT_MAX_POLL_ATTEMPTS: u32 = 10;
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The primary client for interacting with the SAS contract.
pub struct SASClient {
    /// The Soroban contract ID.
    pub contract_id: String,
}

impl SASClient {
    /// Instantiates a new SASClient with the given contract ID.
    pub fn new(contract_id: String) -> Self {
        Self { contract_id }
    }

    /// Calls `SAS::verify_attestation(uid)` via `simulateTransaction` — a
    /// pure read: no signing key or transaction submission required.
    pub fn verify_attestation(
        &self,
        env: &Env,
        rpc: &RpcClient,
        uid: &[u8; 32],
    ) -> Result<bool, SdkError> {
        let uid = UID(BytesN::from_array(env, uid));
        let arg = simulate::encode_arg(env, &uid)?;
        invoke_read_only(env, rpc, &self.contract_id, "verify_attestation", vec![arg])
    }

    /// Calls `SchemaRegistry::get_schema(uid)` on `registry_contract_id` via
    /// `simulateTransaction` — a pure read, same as `verify_attestation`.
    ///
    /// Takes the registry's contract ID explicitly: `get_schema` lives on
    /// the Schema Registry contract, a separate deployment from the SAS
    /// contract this client otherwise talks to.
    pub fn get_schema(
        &self,
        env: &Env,
        rpc: &RpcClient,
        registry_contract_id: &str,
        uid: &[u8; 32],
    ) -> Result<Option<SchemaRecord>, SdkError> {
        let uid = UID(BytesN::from_array(env, uid));
        let arg = simulate::encode_arg(env, &uid)?;
        invoke_read_only(env, rpc, registry_contract_id, "get_schema", vec![arg])
    }

    /// Calls `SchemaRegistry::register(owner, schema, resolver, revocable)`
    /// on `registry_contract_id`, same signing/submission flow as `attest`.
    ///
    /// `owner` is derived from `secret_seed`, not taken as a parameter:
    /// `register` requires `owner.require_auth()`, so it must be the same
    /// account as the transaction's signer (see `attest`'s doc comment).
    #[allow(clippy::too_many_arguments)]
    pub fn register_schema(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        registry_contract_id: &str,
        schema: &str,
        resolver: &str,
        revocable: bool,
    ) -> Result<GetTransactionResult, SdkError> {
        let owner_public_key = signature::derive_public_key(secret_seed);
        let owner_strkey = stellar_strkey::ed25519::PublicKey(owner_public_key).to_string();
        let owner = Address::from_string(&SorobanString::from_str(env, &owner_strkey));
        let resolver = Address::from_string(&SorobanString::from_str(env, resolver));
        let schema = SorobanString::from_str(env, schema);

        let args = vec![
            simulate::encode_arg(env, &owner)?,
            simulate::encode_arg(env, &schema)?,
            simulate::encode_arg(env, &resolver)?,
            simulate::encode_arg(env, &revocable)?,
        ];
        invoke_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            registry_contract_id,
            "register",
            args,
        )
    }

    /// Calls `SAS::attest(attestation)`: builds the invoke transaction,
    /// signs it with the ed25519 key derived from `secret_seed`, and
    /// submits it — then polls until it settles.
    ///
    /// Requires `secret_seed`'s account to be both the transaction's source
    /// account and `attestation.attester` (see `simulate::sign_transaction`
    /// for why): the common case of an attester submitting and authorizing
    /// its own attestation. A relayer submitting on someone else's behalf
    /// needs a separately signed `SorobanAuthorizationEntry`, which this
    /// does not build.
    pub fn attest(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        attestation: Attestation,
    ) -> Result<GetTransactionResult, SdkError> {
        ensure_attester_matches_secret(env, secret_seed, &attestation)?;
        let arg = simulate::encode_arg(env, &attestation)?;
        invoke_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "attest",
            vec![arg],
        )
    }

    /// Calls `SAS::multi_attest(attestations)`: encodes each attestation into
    /// one Soroban vector argument, signs the batch invoke with `secret_seed`,
    /// submits it, and polls until it settles.
    pub fn multi_attest(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        attestations: Vec<Attestation>,
    ) -> Result<GetTransactionResult, SdkError> {
        for attestation in &attestations {
            ensure_attester_matches_secret(env, secret_seed, attestation)?;
        }
        invoke_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "multi_attest",
            vec![encode_multi_attest_arg(env, &attestations)?],
        )
    }

    /// Calls `SAS::revoke(uid)`, same signing/submission flow as `attest`.
    /// Requires `secret_seed`'s account to be the attestation's attester.
    pub fn revoke(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        uid: &[u8; 32],
    ) -> Result<GetTransactionResult, SdkError> {
        let uid = UID(BytesN::from_array(env, uid));
        let arg = simulate::encode_arg(env, &uid)?;
        invoke_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "revoke",
            vec![arg],
        )
    }

    /// Calls `SAS::attest_by_delegation(attestation, nonce, signature,
    /// public_key)`: submits an already off-chain-signed attestation.
    ///
    /// Unlike `attest`, `relayer_secret_seed` does not need to be the
    /// attester — the contract authenticates the attestation via the
    /// ed25519 `signature` over the typed-data payload, not
    /// `require_auth()`, so any funded account can pay for and submit this
    /// on the attester's behalf (see `offchain::sign_offchain_attestation`
    /// in the CLI for producing `signature`/`public_key`/`nonce`).
    #[allow(clippy::too_many_arguments)]
    pub fn attest_by_delegation(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        relayer_secret_seed: &[u8; 32],
        attestation: Attestation,
        nonce: u64,
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> Result<GetTransactionResult, SdkError> {
        let signature = BytesN::from_array(env, signature);
        let public_key = BytesN::from_array(env, public_key);
        let args = vec![
            simulate::encode_arg(env, &attestation)?,
            simulate::encode_arg(env, &nonce)?,
            simulate::encode_arg(env, &signature)?,
            simulate::encode_arg(env, &public_key)?,
        ];
        invoke_write(
            env,
            rpc,
            network_passphrase,
            relayer_secret_seed,
            &self.contract_id,
            "attest_by_delegation",
            args,
        )
    }

    /// Calls `SAS::revoke_by_delegation(uid, nonce, signature,
    /// public_key)`, same relayer model as `attest_by_delegation`.
    #[allow(clippy::too_many_arguments)]
    pub fn revoke_by_delegation(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        relayer_secret_seed: &[u8; 32],
        uid: &[u8; 32],
        nonce: u64,
        signature: &[u8; 64],
        public_key: &[u8; 32],
    ) -> Result<GetTransactionResult, SdkError> {
        let uid = UID(BytesN::from_array(env, uid));
        let signature = BytesN::from_array(env, signature);
        let public_key = BytesN::from_array(env, public_key);
        let args = vec![
            simulate::encode_arg(env, &uid)?,
            simulate::encode_arg(env, &nonce)?,
            simulate::encode_arg(env, &signature)?,
            simulate::encode_arg(env, &public_key)?,
        ];
        invoke_write(
            env,
            rpc,
            network_passphrase,
            relayer_secret_seed,
            &self.contract_id,
            "revoke_by_delegation",
            args,
        )
    }

    /// Calls `SAS::replace_attestation(old_uid, new_data)`, same
    /// signing/submission flow as `attest`. Requires `secret_seed`'s
    /// account to be both `old_uid`'s attester and `new_data.attester`
    /// (the contract itself enforces the latter matches the former).
    pub fn replace_attestation(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        old_uid: &[u8; 32],
        new_data: Attestation,
    ) -> Result<GetTransactionResult, SdkError> {
        ensure_attester_matches_secret(env, secret_seed, &new_data)?;
        let old_uid = UID(BytesN::from_array(env, old_uid));
        let args = vec![
            simulate::encode_arg(env, &old_uid)?,
            simulate::encode_arg(env, &new_data)?,
        ];
        invoke_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "replace_attestation",
            args,
        )
    }
}

fn encode_multi_attest_arg(env: &Env, attestations: &[Attestation]) -> Result<ScVal, SdkError> {
    let encoded: Vec<ScVal> = attestations
        .iter()
        .map(|attestation| simulate::encode_arg(env, attestation))
        .collect::<Result<_, _>>()?;
    let encoded: VecM<ScVal> = encoded
        .try_into()
        .map_err(|e| SdkError::RpcError(format!("too many attestations: {e:?}")))?;
    Ok(ScVal::Vec(Some(encoded.into())))
}

fn ensure_attester_matches_secret(
    env: &Env,
    secret_seed: &[u8; 32],
    attestation: &Attestation,
) -> Result<(), SdkError> {
    let public_key = signature::derive_public_key(secret_seed);
    let attester_strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    let expected_attester = Address::from_string(&SorobanString::from_str(env, &attester_strkey));
    if attestation.attester != expected_attester {
        return Err(SdkError::DecodingError(
            "attestation attester does not match signing key".to_string(),
        ));
    }
    Ok(())
}

/// Client for the Indexer contract's read-only attestation lookups.
pub struct IndexerClient {
    /// The Indexer contract's Soroban contract ID.
    pub contract_id: String,
}

impl IndexerClient {
    /// Instantiates a new IndexerClient with the given contract ID.
    pub fn new(contract_id: String) -> Self {
        Self { contract_id }
    }

    /// Calls `Indexer::get_attestations_by_recipient(recipient)` via
    /// `simulateTransaction` — a pure read, same as `SASClient::get_schema`.
    pub fn get_attestations_by_recipient(
        &self,
        env: &Env,
        rpc: &RpcClient,
        recipient: &str,
    ) -> Result<soroban_sdk::Vec<UID>, SdkError> {
        let recipient = Address::from_string(&SorobanString::from_str(env, recipient));
        let arg = simulate::encode_arg(env, &recipient)?;
        invoke_read_only(
            env,
            rpc,
            &self.contract_id,
            "get_attestations_by_recipient",
            vec![arg],
        )
    }

    /// Calls `Indexer::get_attestations_by_schema(schema_uid)` via
    /// `simulateTransaction`.
    pub fn get_attestations_by_schema(
        &self,
        env: &Env,
        rpc: &RpcClient,
        schema_uid: &[u8; 32],
    ) -> Result<soroban_sdk::Vec<UID>, SdkError> {
        let schema_uid = UID(BytesN::from_array(env, schema_uid));
        let arg = simulate::encode_arg(env, &schema_uid)?;
        invoke_read_only(
            env,
            rpc,
            &self.contract_id,
            "get_attestations_by_schema",
            vec![arg],
        )
    }
}

/// Simulates a read-only call to `function_name` on `contract_id` and
/// decodes its return value as `T`.
fn invoke_read_only<T>(
    env: &Env,
    rpc: &RpcClient,
    contract_id: &str,
    function_name: &str,
    args: Vec<ScVal>,
) -> Result<T, SdkError>
where
    T: soroban_sdk::TryFromVal<Env, soroban_sdk::Val>,
{
    let tx_xdr = simulate::build_simulate_transaction_xdr(contract_id, function_name, args)?;
    let result = rpc.simulate_transaction(&tx_xdr)?;
    if let Some(error) = result.error {
        return Err(SdkError::RpcError(error));
    }
    let xdr = result
        .results
        .first()
        .ok_or_else(|| SdkError::RpcError("simulateTransaction returned no results".to_string()))?
        .xdr
        .clone();
    simulate::decode_result(env, &xdr)
}

/// Builds, simulates (to get the real resource footprint/fee), signs, and
/// submits a write call to `function_name` on `contract_id`, then polls
/// until the transaction settles.
fn invoke_write(
    env: &Env,
    rpc: &RpcClient,
    network_passphrase: &str,
    secret_seed: &[u8; 32],
    contract_id: &str,
    function_name: &str,
    args: Vec<ScVal>,
) -> Result<GetTransactionResult, SdkError> {
    let public_key = signature::derive_public_key(secret_seed);
    let next_seq = account::fetch_sequence_number(rpc, &public_key)? + 1;

    // 1. Simulate a draft (V0, base-fee) transaction to get the real
    //    resource footprint and fee a submittable one needs to carry.
    let draft_tx = simulate::build_invoke_transaction(
        &public_key,
        next_seq,
        BASE_FEE,
        TransactionExt::V0,
        contract_id,
        function_name,
        args.clone(),
    )?;
    let draft_xdr = simulate::unsigned_envelope_xdr(draft_tx)?;
    let sim = rpc.simulate_transaction(&draft_xdr)?;
    if let Some(error) = sim.error {
        return Err(SdkError::RpcError(error));
    }
    let transaction_data_b64 = sim.transaction_data.ok_or_else(|| {
        SdkError::RpcError("simulation succeeded but returned no transactionData".to_string())
    })?;
    let soroban_data =
        SorobanTransactionData::from_xdr_base64(transaction_data_b64, Limits::none())
            .map_err(|e| SdkError::RpcError(format!("failed to decode transactionData: {e:?}")))?;
    let resource_fee: i64 = sim
        .min_resource_fee
        .as_deref()
        .unwrap_or("0")
        .parse()
        .map_err(|e| SdkError::RpcError(format!("invalid minResourceFee: {e:?}")))?;
    let fee = u32::try_from(i64::from(BASE_FEE) + resource_fee)
        .map_err(|_| SdkError::RpcError("computed fee overflowed u32".to_string()))?;

    // 2. Build the real transaction with that resource data and fee, and
    //    sign it.
    let final_tx = simulate::build_invoke_transaction(
        &public_key,
        next_seq,
        fee,
        TransactionExt::V1(soroban_data),
        contract_id,
        function_name,
        args,
    )?;
    let network_id: [u8; 32] = env
        .crypto()
        .sha256(&Bytes::from_slice(env, network_passphrase.as_bytes()))
        .to_array();
    let signed_xdr = simulate::sign_transaction(env, &network_id, final_tx, secret_seed)?;

    // 3. Submit and poll until it settles.
    TransactionSubmitter::submit_with_retries(
        rpc,
        &signed_xdr,
        DEFAULT_MAX_POLL_ATTEMPTS,
        DEFAULT_POLL_INTERVAL,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::xdr::{HostFunction, OperationBody, TransactionEnvelope};
    use soroban_sdk::BytesN;
    use soroban_sdk::{testutils::Address as _, TryFromVal, Val};

    fn attestation_fixture(
        env: &Env,
        seed: u8,
        data: &[u8],
        expiration_time: u64,
        revocable: bool,
    ) -> Attestation {
        let attester = Address::generate(env);
        let recipient = Address::generate(env);
        Attestation {
            uid: UID(BytesN::from_array(env, &[seed; 32])),
            schema_uid: UID(BytesN::from_array(env, &[2u8; 32])),
            time: 1000,
            expiration_time,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
            recipient,
            attester,
            revocable,
            data: Bytes::from_slice(env, data),
        }
    }

    #[test]
    fn multi_attest_round_trips_empty_single_and_multi_batches() {
        let env = Env::default();
        let batches = vec![
            vec![],
            vec![attestation_fixture(&env, 1, &[0], u64::MAX, false)],
            vec![
                attestation_fixture(&env, 2, &[], 0, true),
                attestation_fixture(&env, 3, &[0, 1, 2, 0xff], u64::MAX, false),
            ],
        ];

        for attestations in batches {
            let arg = encode_multi_attest_arg(&env, &attestations).unwrap();
            let decoded = decode_multi_attest_arg(&env, &arg);

            assert_eq!(decoded.len(), attestations.len() as u32);
            for (idx, expected) in attestations.iter().enumerate() {
                assert_eq!(decoded.get(idx as u32).unwrap(), *expected);
            }
        }
    }

    #[test]
    fn multi_attest_preserves_contract_spec_field_order() {
        let env = Env::default();
        let attestations = vec![attestation_fixture(&env, 4, &[0, 0xff], u64::MAX, false)];

        let arg = encode_multi_attest_arg(&env, &attestations).unwrap();
        let ScVal::Vec(Some(values)) = arg else {
            panic!("expected multi_attest argument to be an ScVal vector");
        };
        let ScVal::Map(Some(fields)) = &values[0] else {
            panic!("expected encoded attestation to be an ScVal map");
        };

        let names: Vec<String> = fields
            .iter()
            .map(|entry| match &entry.key {
                ScVal::Symbol(symbol) => symbol.0.to_string(),
                other => panic!("expected symbol field key, got {other:?}"),
            })
            .collect();
        assert_eq!(
            names,
            vec![
                "attester",
                "data",
                "expiration_time",
                "recipient",
                "ref_uid",
                "revocable",
                "revocation_time",
                "schema_uid",
                "time",
                "uid",
            ]
        );
    }

    #[test]
    fn multi_attest_arg_is_submitted_as_single_contract_client_argument() {
        let env = Env::default();
        let contract = stellar_strkey::Contract([9u8; 32]).to_string();
        let attestations = vec![
            attestation_fixture(&env, 5, &[], 0, true),
            attestation_fixture(&env, 6, &[1, 2, 3], u64::MAX, false),
        ];
        let arg = encode_multi_attest_arg(&env, &attestations).unwrap();
        let tx = simulate::build_invoke_transaction(
            &[1u8; 32],
            1,
            BASE_FEE,
            TransactionExt::V0,
            &contract,
            "multi_attest",
            vec![arg.clone()],
        )
        .unwrap();
        let envelope = simulate::unsigned_envelope_xdr(tx).unwrap();
        let envelope = TransactionEnvelope::from_xdr_base64(envelope, Limits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = envelope else {
            panic!("expected a V1 transaction envelope");
        };
        let OperationBody::InvokeHostFunction(op) = &v1.tx.operations[0].body else {
            panic!("expected InvokeHostFunction operation");
        };
        let HostFunction::InvokeContract(args) = &op.host_function else {
            panic!("expected InvokeContract host function");
        };

        assert_eq!(args.function_name.0.to_string(), "multi_attest");
        assert_eq!(args.args.len(), 1);
        assert_eq!(args.args[0], arg);
    }

    #[test]
    fn register_schema_uses_secret_key_as_authenticated_owner() {
        let env = Env::default();
        let seed = [7u8; 32];
        let public_key = signature::derive_public_key(&seed);
        let owner_strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
        let owner = Address::from_string(&SorobanString::from_str(&env, &owner_strkey));
        let encoded_owner = simulate::encode_arg(&env, &owner).unwrap();
        let decoded_owner = decode_arg::<Address>(&env, &encoded_owner);

        assert_eq!(decoded_owner, owner);
    }

    #[test]
    fn attest_rejects_wrong_secret_key_before_state_changes() {
        let env = Env::default();
        let seed = [8u8; 32];
        let wrong_seed = [9u8; 32];
        let mut attestation = attestation_fixture(&env, 7, &[], 0, true);
        let public_key = signature::derive_public_key(&seed);
        let attester_strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
        attestation.attester =
            Address::from_string(&SorobanString::from_str(&env, &attester_strkey));

        let err = ensure_attester_matches_secret(&env, &wrong_seed, &attestation).unwrap_err();
        match err {
            SdkError::DecodingError(msg) => {
                assert!(msg.contains("attester does not match signing key"));
            }
            other => panic!("expected DecodingError, got {other:?}"),
        }
    }

    fn decode_multi_attest_arg(env: &Env, sc_val: &ScVal) -> soroban_sdk::Vec<Attestation> {
        decode_arg(env, sc_val)
    }

    fn decode_arg<T: TryFromVal<Env, Val>>(env: &Env, sc_val: &ScVal) -> T {
        let val = Val::try_from_val(env, sc_val).unwrap();
        T::try_from_val(env, &val).unwrap()
    }
}
