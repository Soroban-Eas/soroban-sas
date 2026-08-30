//! Builds unsigned transactions for Soroban RPC's `simulateTransaction`, and
//! converts between Rust values and `ScVal` contract-call arguments/results.
//!
//! Simulation never touches ledger state or requires a valid signature, so
//! read-only contract calls (`get_schema`, `verify_attestation`, ...) can go
//! through it without any signing key. A fixed placeholder source account is
//! used for every simulated call, since RPC only needs *a* syntactically
//! valid account to build the envelope, not one that actually exists — this
//! was verified against live `soroban-testnet.stellar.org`: a simulated call
//! built this way is accepted and actually executed by the host (it fails
//! only on `Storage, MissingValue` for the placeholder contract address,
//! confirming the envelope, and the invoked function/args, are well-formed).
//!
//! Argument/result conversion goes through the host `Val` type rather than
//! the direct `TryFrom<T> for ScVal` impls `soroban-sdk` generates for
//! `#[contracttype]` types, because those direct impls are gated behind the
//! `test`/`testutils` cfg (they exist for test-assertion convenience, not
//! for production use) — the `Val`-mediated path is not gated and is the
//! one contract tooling is meant to use off-chain.

use crate::errors::SdkError;
use soroban_sdk::xdr::{
    DecoratedSignature, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo,
    MuxedAccount, Operation, OperationBody, Preconditions, ReadXdr, ScAddress, ScSymbol, ScVal,
    SequenceNumber, Signature, SignatureHint, StringM, Transaction, TransactionEnvelope,
    TransactionExt, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};
use soroban_sdk::{Bytes, Env, TryFromVal, TryIntoVal, Val};

/// Placeholder source account used for read-only `simulateTransaction`
/// calls, which never touch ledger state or require a real signer — RPC
/// only needs *a* syntactically valid account to build the envelope, not
/// one that actually exists.
const PLACEHOLDER_SOURCE_ACCOUNT: [u8; 32] = [0; 32];

/// Builds an unsigned `Transaction` invoking `function_name` on
/// `contract_id` with `args`, from a single `InvokeHostFunction` operation.
///
/// `fee` and `ext` are left to the caller: a read-only simulate call and a
/// real write call that will be signed and submitted need different values
/// (see `build_simulate_transaction_xdr` and `client::invoke_write`).
#[allow(clippy::too_many_arguments)]
pub fn build_invoke_transaction(
    source_account_public_key: &[u8; 32],
    seq_num: i64,
    fee: u32,
    ext: TransactionExt,
    contract_id: &str,
    function_name: &str,
    args: Vec<ScVal>,
) -> Result<Transaction, SdkError> {
    let contract = stellar_strkey::Contract::from_string(contract_id).map_err(|e| {
        SdkError::DecodingError(format!("invalid contract id {contract_id}: {e:?}"))
    })?;

    let function_name = ScSymbol(
        StringM::try_from(function_name.as_bytes().to_vec())
            .map_err(|e| SdkError::RpcError(format!("invalid function name: {e:?}")))?,
    );
    let args: VecM<ScVal> = args
        .try_into()
        .map_err(|e| SdkError::RpcError(format!("too many arguments: {e:?}")))?;

    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: ScAddress::Contract(Hash(contract.0)),
        function_name,
        args,
    });

    let operation = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function,
            auth: VecM::default(),
        }),
    };

    Ok(Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*source_account_public_key)),
        fee,
        seq_num: SequenceNumber(seq_num),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![operation]
            .try_into()
            .expect("a single operation is always within the 100-operation limit"),
        ext,
    })
}

/// Builds a base64-encoded unsigned `TransactionEnvelope` invoking
/// `function_name` on `contract_id` with `args`, suitable for
/// `simulateTransaction`. Uses a fixed placeholder source account, sequence
/// number 0, and `TransactionExt::V0` — none of these are validated by
/// simulation, only by real submission (see `client::invoke_write`, which
/// builds the real, signed transaction from a simulation's resource data).
///
/// Verified against live `soroban-testnet.stellar.org`: a simulated call
/// built this way is accepted and actually executed by the host (it fails
/// only on `Storage, MissingValue` for the placeholder contract address,
/// confirming the envelope, and the invoked function/args, are well-formed).
pub fn build_simulate_transaction_xdr(
    contract_id: &str,
    function_name: &str,
    args: Vec<ScVal>,
) -> Result<String, SdkError> {
    let tx = build_invoke_transaction(
        &PLACEHOLDER_SOURCE_ACCOUNT,
        0,
        100,
        TransactionExt::V0,
        contract_id,
        function_name,
        args,
    )?;
    unsigned_envelope_xdr(tx)
}

pub(crate) fn unsigned_envelope_xdr(tx: Transaction) -> Result<String, SdkError> {
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| SdkError::DecodingError(format!("failed to encode transaction xdr: {e:?}")))
}

/// Validates that a simulated transaction matches the original invocation request,
/// ensuring operation count, type, and invoke arguments are unchanged. Returns
/// `Err` if the simulation response was malformed or contained substitutions
/// that would cross a trust boundary before signing.
pub(crate) fn validate_simulated_transaction(
    tx: &Transaction,
    contract_id: &str,
    function_name: &str,
    args: &[ScVal],
) -> Result<(), SdkError> {
    if tx.operations.len() != 1 {
        return Err(SdkError::ValidationError(format!(
            "expected exactly 1 operation, got {}",
            tx.operations.len()
        )));
    }

    let operation = &tx.operations[0];
    let OperationBody::InvokeHostFunction(op) = &operation.body else {
        return Err(SdkError::ValidationError(format!(
            "expected InvokeHostFunction operation, got {:?}",
            operation.body
        )));
    };

    let HostFunction::InvokeContract(invoke_args) = &op.host_function else {
        return Err(SdkError::ValidationError(
            "expected InvokeContract host function".to_string(),
        ));
    };

    let contract = stellar_strkey::Contract::from_string(contract_id).map_err(|e| {
        SdkError::ValidationError(format!("invalid contract id {contract_id}: {e:?}"))
    })?;

    if invoke_args.contract_address != ScAddress::Contract(Hash(contract.0)) {
        return Err(SdkError::ValidationError(format!(
            "contract address mismatch: expected {contract_id}"
        )));
    }

    if invoke_args.function_name.0.to_string() != function_name {
        return Err(SdkError::ValidationError(format!(
            "function name mismatch: expected {function_name}, got {}",
            invoke_args.function_name.0.to_string()
        )));
    }

    if invoke_args.args.len() != args.len() {
        return Err(SdkError::ValidationError(format!(
            "argument count mismatch: expected {}, got {}",
            args.len(),
            invoke_args.args.len()
        )));
    }

    for (i, (expected, actual)) in args.iter().zip(invoke_args.args.iter()).enumerate() {
        if expected != actual {
            return Err(SdkError::ValidationError(format!(
                "argument {} mismatch: invocation was modified by server",
                i
            )));
        }
    }

    Ok(())
}

/// Signs `tx` for `network_id` with the ed25519 key derived from
/// `secret_seed` (via `crate::signature::generate_delegated_signature`),
/// and returns the base64-encoded, submission-ready `TransactionEnvelope`.
///
/// Only supports the single-signature case where the signing key is also
/// the transaction's source account — the common case for a party
/// submitting and authorizing its own call. A relayer submitting on behalf
/// of a different `require_auth` address would need an explicit, separately
/// signed `SorobanAuthorizationEntry`, which this does not build.
pub fn sign_transaction(
    env: &Env,
    network_id: &[u8; 32],
    tx: Transaction,
    secret_seed: &[u8; 32],
) -> Result<String, SdkError> {
    let public_key = crate::signature::derive_public_key(secret_seed);
    match tx.source_account {
        MuxedAccount::Ed25519(Uint256(source)) if source == public_key => {}
        MuxedAccount::Ed25519(_) => {
            return Err(SdkError::DecodingError(
                "transaction source account does not match signing key".to_string(),
            ));
        }
        _ => {
            return Err(SdkError::DecodingError(
                "unsupported transaction source account variant".to_string(),
            ));
        }
    }

    let payload = TransactionSignaturePayload {
        network_id: Hash(*network_id),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    let payload_bytes = payload.to_xdr(Limits::none()).map_err(|e| {
        SdkError::DecodingError(format!("failed to encode signature payload: {e:?}"))
    })?;
    let hash: [u8; 32] = env
        .crypto()
        .sha256(&Bytes::from_slice(env, &payload_bytes))
        .to_array();

    let signature_bytes = crate::signature::generate_delegated_signature(secret_seed, &hash);
    let hint = SignatureHint([
        public_key[28],
        public_key[29],
        public_key[30],
        public_key[31],
    ]);
    let decorated = DecoratedSignature {
        hint,
        signature: Signature(
            signature_bytes
                .to_vec()
                .try_into()
                .map_err(|e| SdkError::DecodingError(format!("invalid signature bytes: {e:?}")))?,
        ),
    };

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![decorated]
            .try_into()
            .expect("a single signature is always within the 20-signature limit"),
    });
    envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| SdkError::DecodingError(format!("failed to encode signed transaction: {e:?}")))
}

/// Converts a Rust value into an `ScVal` contract-call argument, via the
/// host `Val` bridge (see module docs for why not the direct `ScVal` impl).
pub fn encode_arg<T>(env: &Env, value: &T) -> Result<ScVal, SdkError>
where
    T: TryIntoVal<Env, Val>,
{
    let val: Val = value
        .try_into_val(env)
        .map_err(|_| SdkError::DecodingError("failed to convert value to host Val".to_string()))?;
    ScVal::try_from_val(env, &val)
        .map_err(|_| SdkError::DecodingError("failed to convert Val to ScVal".to_string()))
}

/// Decodes the base64 `ScVal` XDR returned in a successful simulation's
/// `results[0].xdr` field into a typed value `T`.
///
/// Goes through the host `Val` type (`ScVal` -> `Val` -> `T`) rather than a
/// direct `T: TryFromVal<Env, ScVal>` bound, since `soroban-sdk` only
/// generates that direct impl for `#[contracttype]` types behind the
/// `test`/`testutils` cfg (see module docs).
pub fn decode_result<T>(env: &Env, result_xdr_base64: &str) -> Result<T, SdkError>
where
    T: TryFromVal<Env, Val>,
{
    let sc_val = ScVal::from_xdr_base64(result_xdr_base64, Limits::none())
        .map_err(|e| SdkError::DecodingError(format!("failed to decode result xdr: {e:?}")))?;
    let val: Val = Val::try_from_val(env, &sc_val)
        .map_err(|_| SdkError::DecodingError("failed to convert ScVal to host Val".to_string()))?;
    T::try_from_val(env, &val)
        .map_err(|_| SdkError::DecodingError("failed to convert Val to target type".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sas_common::UID;
    use soroban_sdk::xdr::Limits as XdrLimits;
    use soroban_sdk::BytesN;

    #[test]
    fn builds_a_well_formed_invoke_transaction() {
        let contract = stellar_strkey::Contract([0u8; 32]).to_string();
        let xdr =
            build_simulate_transaction_xdr(&contract, "get_schema", vec![ScVal::Void]).unwrap();

        // Round-trips through the same XDR parser Soroban RPC uses, and has
        // exactly the InvokeHostFunction operation we asked for.
        let envelope = TransactionEnvelope::from_xdr_base64(xdr, XdrLimits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = envelope else {
            panic!("expected a V1 transaction envelope");
        };
        assert_eq!(v1.tx.operations.len(), 1);
        let OperationBody::InvokeHostFunction(op) = &v1.tx.operations[0].body else {
            panic!("expected an InvokeHostFunction operation");
        };
        let HostFunction::InvokeContract(args) = &op.host_function else {
            panic!("expected an InvokeContract host function");
        };
        assert_eq!(args.function_name.0.to_string(), "get_schema");
        assert_eq!(args.args.len(), 1);
    }

    #[test]
    fn rejects_an_invalid_contract_id() {
        let err = build_simulate_transaction_xdr("not-a-contract-id", "get_schema", vec![]);
        assert!(matches!(err, Err(SdkError::DecodingError(_))));
    }

    #[test]
    fn signed_transaction_has_a_verifiable_signature_over_the_correct_payload() {
        use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};

        let env = Env::default();
        let seed = [3u8; 32];
        let network_id = [4u8; 32];
        let contract = stellar_strkey::Contract([0u8; 32]).to_string();

        let public_key = crate::signature::derive_public_key(&seed);
        let tx = build_invoke_transaction(
            &public_key,
            41,
            100,
            TransactionExt::V0,
            &contract,
            "attest",
            vec![],
        )
        .unwrap();

        let signed_xdr = sign_transaction(&env, &network_id, tx.clone(), &seed).unwrap();
        let envelope = TransactionEnvelope::from_xdr_base64(signed_xdr, XdrLimits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = envelope else {
            panic!("expected a V1 transaction envelope");
        };
        assert_eq!(v1.tx, tx);
        assert_eq!(v1.signatures.len(), 1);

        let sig = &v1.signatures[0];
        assert_eq!(
            sig.hint.0,
            [
                public_key[28],
                public_key[29],
                public_key[30],
                public_key[31]
            ]
        );

        // The signature must verify over sha256(network_id || Tx(tx)), the
        // exact payload `sign_transaction` is documented to sign.
        let payload = TransactionSignaturePayload {
            network_id: Hash(network_id),
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx),
        };
        let payload_bytes = payload.to_xdr(Limits::none()).unwrap();
        let hash: [u8; 32] = env
            .crypto()
            .sha256(&Bytes::from_slice(&env, &payload_bytes))
            .to_array();

        let verifying_key = VerifyingKey::from_bytes(&public_key).unwrap();
        let signature = DalekSignature::from_slice(sig.signature.0.as_slice()).unwrap();
        assert!(verifying_key.verify(&hash, &signature).is_ok());
    }

    #[test]
    fn signing_rejects_mismatched_source_account_before_submission() {
        let env = Env::default();
        let seed = [3u8; 32];
        let contract = stellar_strkey::Contract([0u8; 32]).to_string();
        let tx = build_invoke_transaction(
            &[9u8; 32],
            41,
            100,
            TransactionExt::V0,
            &contract,
            "attest",
            vec![],
        )
        .unwrap();

        let err = sign_transaction(&env, &[4u8; 32], tx, &seed).unwrap_err();
        match err {
            SdkError::DecodingError(msg) => {
                assert!(msg.contains("source account does not match signing key"));
            }
            other => panic!("expected DecodingError, got {other:?}"),
        }
    }

    #[test]
    fn encode_then_decode_round_trips_a_uid() {
        let env = Env::default();
        let uid = UID(BytesN::from_array(&env, &[9u8; 32]));

        let encoded = encode_arg(&env, &uid).unwrap();
        let decoded: UID = decode_result_from_scval(&env, &encoded);

        assert_eq!(decoded, uid);
    }

    #[test]
    fn encode_then_decode_round_trips_a_bool() {
        let env = Env::default();
        let encoded = encode_arg(&env, &true).unwrap();
        let decoded: bool = decode_result_from_scval(&env, &encoded);
        assert!(decoded);
    }

    /// Test-only helper: same conversion `decode_result` does, but starting
    /// from an in-memory `ScVal` instead of a base64 string, so encode/decode
    /// round-trip tests don't need to go through XDR text encoding.
    fn decode_result_from_scval<T: TryFromVal<Env, Val>>(env: &Env, sc_val: &ScVal) -> T {
        let val: Val = Val::try_from_val(env, sc_val).unwrap();
        T::try_from_val(env, &val).unwrap()
    }

    // Negative test cases for Issue #91: malformed simulation XDR construction
    #[test]
    fn rejects_invalid_contract_id_format() {
        let err = build_simulate_transaction_xdr("invalid-strkey-format", "get_schema", vec![]);
        assert!(matches!(err, Err(SdkError::DecodingError(_))));
    }

    #[test]
    fn rejects_contract_id_with_wrong_prefix() {
        // "G" prefix is for public keys, not contracts (which start with "C")
        let err = build_simulate_transaction_xdr(
            "GBBD47UZQ22JPUPU4DSFH2HXV6IA7D5VSCCLETT4QSN3ZI33UJEKMFDX",
            "get_schema",
            vec![],
        );
        assert!(matches!(err, Err(SdkError::DecodingError(_))));
    }

    #[test]
    fn validates_simulated_transaction_contract_mismatch() {
        let contract1 = stellar_strkey::Contract([1u8; 32]).to_string();
        let contract2 = stellar_strkey::Contract([2u8; 32]).to_string();
        let public_key = [3u8; 32];

        let tx = build_invoke_transaction(
            &public_key,
            0,
            100,
            TransactionExt::V0,
            &contract1,
            "test_func",
            vec![ScVal::Void],
        )
        .unwrap();

        let result = validate_simulated_transaction(&tx, &contract2, "test_func", &[ScVal::Void]);
        assert!(matches!(result, Err(SdkError::ValidationError(_))));
    }

    #[test]
    fn validates_simulated_transaction_function_name_mismatch() {
        let contract = stellar_strkey::Contract([1u8; 32]).to_string();
        let public_key = [3u8; 32];

        let tx = build_invoke_transaction(
            &public_key,
            0,
            100,
            TransactionExt::V0,
            &contract,
            "func_a",
            vec![ScVal::Void],
        )
        .unwrap();

        let result = validate_simulated_transaction(&tx, &contract, "func_b", &[ScVal::Void]);
        assert!(matches!(result, Err(SdkError::ValidationError(_))));
    }

    #[test]
    fn validates_simulated_transaction_argument_count_mismatch() {
        let contract = stellar_strkey::Contract([1u8; 32]).to_string();
        let public_key = [3u8; 32];

        let tx = build_invoke_transaction(
            &public_key,
            0,
            100,
            TransactionExt::V0,
            &contract,
            "test_func",
            vec![ScVal::Void, ScVal::Bool(true)],
        )
        .unwrap();

        let result = validate_simulated_transaction(&tx, &contract, "test_func", &[ScVal::Void]);
        assert!(matches!(result, Err(SdkError::ValidationError(_))));
    }

    #[test]
    fn validates_simulated_transaction_argument_value_mismatch() {
        let contract = stellar_strkey::Contract([1u8; 32]).to_string();
        let public_key = [3u8; 32];

        let tx = build_invoke_transaction(
            &public_key,
            0,
            100,
            TransactionExt::V0,
            &contract,
            "test_func",
            vec![ScVal::Bool(true)],
        )
        .unwrap();

        let result =
            validate_simulated_transaction(&tx, &contract, "test_func", &[ScVal::Bool(false)]);
        assert!(matches!(result, Err(SdkError::ValidationError(_))));
    }

    #[test]
    fn validates_simulated_transaction_succeeds_for_matching_transaction() {
        let contract = stellar_strkey::Contract([1u8; 32]).to_string();
        let public_key = [3u8; 32];
        let args = vec![ScVal::Void];

        let tx = build_invoke_transaction(
            &public_key,
            0,
            100,
            TransactionExt::V0,
            &contract,
            "test_func",
            args.clone(),
        )
        .unwrap();

        let result = validate_simulated_transaction(&tx, &contract, "test_func", &args);
        assert!(result.is_ok());
    }

    #[test]
    fn validates_operation_count() {
        let contract = stellar_strkey::Contract([1u8; 32]).to_string();
        let public_key = [3u8; 32];

        // Build a transaction with 2 operations to test validation
        let op1 = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(Hash([1u8; 32])),
                    function_name: ScSymbol(StringM::try_from(b"test_func".to_vec()).unwrap()),
                    args: vec![ScVal::Void].try_into().unwrap(),
                }),
                auth: VecM::default(),
            }),
        };

        let op2 = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(InvokeContractArgs {
                    contract_address: ScAddress::Contract(Hash([0u8; 32])),
                    function_name: ScSymbol(StringM::try_from(b"extra".to_vec()).unwrap()),
                    args: VecM::default(),
                }),
                auth: VecM::default(),
            }),
        };

        let tx = Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(public_key)),
            fee: 100,
            seq_num: SequenceNumber(0),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![op1, op2].try_into().unwrap(),
            ext: TransactionExt::V0,
        };

        let result = validate_simulated_transaction(&tx, &contract, "test_func", &[ScVal::Void]);
        assert!(matches!(result, Err(SdkError::ValidationError(_))));
    }
}
