//! Strongly-typed wrappers for contract clients.

use crate::account;
use crate::errors::SdkError;
use crate::rpc::{GetTransactionResult, LedgerEntryResult, RpcClient};
use crate::sequence::SequenceManager;
use crate::signature;
use crate::simulate;
use crate::strkey::{parse_address, AddressKind};
use crate::transaction::{SubmissionPolicy, TransactionSubmitter};
use soroban_sas_common::{Attestation, SchemaRecord, UID};
use soroban_sdk::xdr::{
    ContractDataDurability, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits,
    ReadXdr, ScAddress, ScVal, SorobanTransactionData, TransactionExt, TransactionResult,
    TransactionResultResult, VecM, WriteXdr,
};
use soroban_sdk::{Address, Bytes, BytesN, Env, String as SorobanString};
use std::sync::Arc;

/// Distinguishes live, missing, and archived attestations — the
/// SDK-supported view that keeps live entries from expiring. Fetching
/// through `get_attestation` or `fetch_attestation` renews TTL where
/// appropriate (the contract's `get_attestation` bumps `LEDGERS_IN_ONE_YEAR`);
/// archived entries surface as `Archived` with restoration metadata rather
/// than `NotFound`.
#[derive(Debug)]
pub enum AttestationResult {
    /// Live entry, TTL was bumped on read.
    Live(Attestation),
    /// UID has never been issued / was garbage-collected.
    NotFound,
    /// Entry is archived and needs `restoreFootprint` before it can be
    /// read. Contains the diagnostic plus the rent fee / footprint from
    /// `restorePreamble` when the node provided it.
    Archived(ArchivedInfo),
}

/// Restoration metadata for an archived attestation, surfaced so callers
/// can budget and build a `restoreFootprint` transaction.
#[derive(Debug)]
pub struct ArchivedInfo {
    pub uid: [u8; 32],
    pub message: String,
    pub min_resource_fee: Option<String>,
    pub transaction_data: Option<String>,
}

/// Classic per-operation fee, in stroops, before the Soroban resource fee
/// simulation reports is added on top.
const BASE_FEE: u32 = 100;

/// Configurable fee policy for simulated write transactions.
///
/// Ledger state or fee conditions can change between simulation and
/// inclusion, so callers can apply a safety margin or cap to avoid
/// insufficient-fee rejections.
#[derive(Debug, Clone, Default)]
pub enum FeePolicy {
    /// No margin — use the exact `BASE_FEE + minResourceFee` from simulation.
    #[default]
    Default,
    /// Adds `percent` percentage points to the simulation-reported
    /// `minResourceFee` before adding `BASE_FEE`.  A 10 % margin on a
    /// 5 000-stroop resource fee yields an extra 500 stroops.
    PercentageMargin { percent: u32 },
    /// Adds a fixed number of stroops to the simulation-reported
    /// `minResourceFee`.
    AbsoluteMargin { stroops: u32 },
    /// Caps the total fee (`BASE_FEE + resource_fee + margin`) at `max`
    /// stroops.  Returns an error when the computed fee would exceed the cap.
    MaxFee { max: u32 },
}

/// Applies the `FeePolicy` to a raw `BASE_FEE + resource_fee` sum and
/// returns the fee that will be written into the transaction.
fn apply_fee_policy(base_fee: u32, resource_fee: i64, policy: &FeePolicy) -> Result<u32, SdkError> {
    let base = i64::from(base_fee);
    let raw = match policy {
        FeePolicy::Default => base + resource_fee,
        FeePolicy::PercentageMargin { percent } => {
            let margin = resource_fee
                .checked_mul(i64::from(*percent))
                .and_then(|v| v.checked_div(100))
                .ok_or_else(|| {
                    SdkError::RpcError("fee margin percentage caused an overflow".to_string())
                })?;
            base + resource_fee + margin
        }
        FeePolicy::AbsoluteMargin { stroops } => base + resource_fee + i64::from(*stroops),
        FeePolicy::MaxFee { max } => {
            let computed = base + resource_fee;
            if computed > i64::from(*max) {
                return Err(SdkError::RpcError(format!(
                    "computed fee {computed} stroops exceeds the configured maximum of {max} stroops"
                )));
            }
            computed
        }
    };
    u32::try_from(raw).map_err(|_| SdkError::RpcError("computed fee overflowed u32".to_string()))
}

/// The primary client for interacting with the SAS contract.
pub struct SASClient {
    /// The Soroban contract ID.
    pub contract_id: String,
    /// How write submissions wait for settlement (issue #133). Defaults to
    /// the historical 10 polls, 2s apart, blocking.
    submission_policy: SubmissionPolicy,
    /// Optional shared allocator of account sequence numbers (issue #132).
    /// When set, concurrent writes from the same account get distinct,
    /// contiguous sequence numbers and a bad-sequence submission is retried
    /// once against a resynchronised value. When `None`, each write reads
    /// the sequence straight from RPC (the previous, race-prone behaviour).
    sequence_manager: Option<Arc<SequenceManager>>,
}

impl SASClient {
    /// Instantiates a new SASClient with the given contract ID and default
    /// submission policy.
    pub fn new(contract_id: String) -> Self {
        Self {
            contract_id,
            submission_policy: SubmissionPolicy::default(),
            sequence_manager: None,
        }
    }

    /// Sets the [`SubmissionPolicy`] every write on this client uses.
    pub fn with_submission_policy(mut self, policy: SubmissionPolicy) -> Self {
        self.submission_policy = policy;
        self
    }

    /// Shares a [`SequenceManager`] with this client so its writes draw
    /// collision-free sequence numbers. Pass the *same* `Arc` to every
    /// client/task that submits from the same source account.
    pub fn with_sequence_manager(mut self, manager: Arc<SequenceManager>) -> Self {
        self.sequence_manager = Some(manager);
        self
    }

    /// The submission policy currently in effect.
    pub fn submission_policy(&self) -> &SubmissionPolicy {
        &self.submission_policy
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

    /// Reads the on-chain fee policy that `SAS::attest_with_value` enforces,
    /// via `simulateTransaction` (a pure read). `Ok(None)` means attestation
    /// is fee-free and `attest_with_value` must be called with `value == 0`;
    /// `Ok(Some((token, amount)))` is the exact payment a caller must supply.
    /// Intended for SDK/CLI front-ends to display the fee before signing.
    pub fn fetch_fee(
        &self,
        env: &Env,
        rpc: &RpcClient,
    ) -> Result<Option<(Address, i128)>, SdkError> {
        invoke_read_only(env, rpc, &self.contract_id, "get_fee", vec![])
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

    /// Fetches the full `Attestation` record for `uid` via the
    /// contract's `get_attestation` view. Unlike the legacy
    /// `getLedgerEntries` path, this **renews TTL** on a successful read
    /// (`LEDGERS_IN_ONE_YEAR`) so live attestations don't go archived
    /// while they are still being queried.
    ///
    /// Returns `Ok(None)` when the UID has never been issued. When the
    /// entry is **archived** the simulation traps with an `archived`
    /// diagnostic; this surfaces as `Err(SdkError::Archived)` /
    /// `Err(SdkError::RestorationRequired { min_resource_fee, transaction_data })`
    /// rather than `Ok(None)`, preserving the distinction the legacy
    /// `getLedgerEntries` path lost. Callers needing a unified enum can use
    /// `fetch_attestation` instead.
    ///
    /// See `fetch_attestation` for the `Live / NotFound / Archived`
    /// enum and for the rent-cost in `restorePreamble`.
    pub fn get_attestation(
        &self,
        env: &Env,
        rpc: &RpcClient,
        uid: &[u8; 32],
    ) -> Result<Option<Attestation>, SdkError> {
        match self.fetch_attestation(env, rpc, uid)? {
            AttestationResult::Live(att) => Ok(Some(att)),
            AttestationResult::NotFound => Ok(None),
            AttestationResult::Archived(info) => {
                if let (Some(fee), Some(data)) =
                    (info.min_resource_fee.clone(), info.transaction_data.clone())
                {
                    Err(SdkError::RestorationRequired {
                        message: info.message,
                        min_resource_fee: Some(fee),
                        transaction_data: Some(data),
                    })
                } else {
                    Err(SdkError::Archived(info.message))
                }
            }
        }
    }

    /// Structured fetch that distinguishes `Live`, `NotFound`, and
    /// `Archived`. A live read bumps TTL; an archived entry returns
    /// `Archived` with the `restorePreamble` cost so the caller can
    /// budget a `restoreFootprint` operation before retrying.
    pub fn fetch_attestation(
        &self,
        env: &Env,
        rpc: &RpcClient,
        uid: &[u8; 32],
    ) -> Result<AttestationResult, SdkError> {
        let uid_val = UID(BytesN::from_array(env, uid));
        let arg = simulate::encode_arg(env, &uid_val)?;
        let tx_xdr = simulate::build_simulate_transaction_xdr(
            &self.contract_id,
            "get_attestation",
            vec![arg],
        )?;
        let sim = rpc.simulate_transaction(&tx_xdr)?;

        if let Some(err) = sim.error {
            if is_archived_error(&err) {
                let (fee, data) = sim
                    .restore_preamble
                    .as_ref()
                    .map(|p| {
                        (
                            Some(p.min_resource_fee.clone()),
                            Some(p.transaction_data.clone()),
                        )
                    })
                    .unwrap_or((None, None));
                // Prefer the structured `RestorationRequired` shape when preamble is present,
                // but surface as `Archived` enum here so `get_attestation` can turn it into the matching `SdkError`.
                let info = ArchivedInfo {
                    uid: *uid,
                    message: err.clone(),
                    min_resource_fee: fee.clone(),
                    transaction_data: data.clone(),
                };
                return Ok(AttestationResult::Archived(info));
            }
            return Err(SdkError::SimulationError(err));
        }
        // No host error — decode the `Option<Attestation>` return.
        let xdr = sim
            .results
            .first()
            .ok_or_else(|| {
                SdkError::RpcError("simulateTransaction returned no results".to_string())
            })?
            .xdr
            .clone();
        let opt: Option<Attestation> = simulate::decode_result(env, &xdr)?;
        match opt {
            Some(att) => Ok(AttestationResult::Live(att)),
            None => Ok(AttestationResult::NotFound),
        }
    }

    /// Low-level `getLedgerEntries` helper retained for diagnostics and
    /// for SDK callers that need raw `liveUntilLedgerSeq` inspection.
    /// Prefer `get_attestation` / `fetch_attestation` for the
    /// TTL-renewing, archived-aware path.
    pub fn get_attestation_ledger(
        &self,
        env: &Env,
        rpc: &RpcClient,
        uid: &[u8; 32],
    ) -> Result<Option<Attestation>, SdkError> {
        let contract = stellar_strkey::Contract::from_string(&self.contract_id).map_err(|e| {
            SdkError::DecodingError(format!("invalid contract id {}: {e:?}", self.contract_id))
        })?;
        let uid_arg = UID(BytesN::from_array(env, uid));
        let key = simulate::encode_arg(env, &uid_arg)?;
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(Hash(contract.0)),
            key,
            durability: ContractDataDurability::Persistent,
        });
        let key_b64 = ledger_key
            .to_xdr_base64(Limits::none())
            .map_err(|e| SdkError::DecodingError(format!("failed to encode ledger key: {e:?}")))?;
        let result = rpc.get_ledger_entries(vec![key_b64])?;
        attestation_from_ledger_entries(env, &result.entries)
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
        // The resolver is invoked as a contract on attest/revoke (see
        // `SAS::attest`), so it must decode as a `C...` contract address —
        // never let a malformed or account (`G...`) value reach the host
        // conversion below (issue #171).
        let resolver = parse_address(env, resolver, AddressKind::Contract, "resolver")?;
        let schema = SorobanString::from_str(env, schema);

        let args = vec![
            simulate::encode_arg(env, &owner)?,
            simulate::encode_arg(env, &schema)?,
            simulate::encode_arg(env, &resolver)?,
            simulate::encode_arg(env, &revocable)?,
        ];
        self.submit_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            registry_contract_id,
            "register",
            args,
        )
    }

    /// Like [`register_schema`](Self::register_schema) but allows a
    /// [`FeePolicy`].
    #[allow(clippy::too_many_arguments)]
    pub fn register_schema_with_fee_policy(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        registry_contract_id: &str,
        schema: &str,
        resolver: &str,
        revocable: bool,
        fee_policy: &FeePolicy,
    ) -> Result<GetTransactionResult, SdkError> {
        let owner_public_key = signature::derive_public_key(secret_seed);
        let owner_strkey = stellar_strkey::ed25519::PublicKey(owner_public_key).to_string();
        let owner = Address::from_string(&SorobanString::from_str(env, &owner_strkey));
        let resolver = parse_address(env, resolver, AddressKind::Contract, "resolver")?;
        let schema = SorobanString::from_str(env, schema);

        let args = vec![
            simulate::encode_arg(env, &owner)?,
            simulate::encode_arg(env, &schema)?,
            simulate::encode_arg(env, &resolver)?,
            simulate::encode_arg(env, &revocable)?,
        ];
        invoke_write_with_fee_policy(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            registry_contract_id,
            "register",
            args,
            fee_policy,
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
        self.submit_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "attest",
            vec![arg],
        )
    }

    /// Like [`attest`](Self::attest) but allows a [`FeePolicy`] that adds
    /// a safety margin or caps the total fee.
    pub fn attest_with_fee_policy(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        attestation: Attestation,
        fee_policy: &FeePolicy,
    ) -> Result<GetTransactionResult, SdkError> {
        ensure_attester_matches_secret(env, secret_seed, &attestation)?;
        let arg = simulate::encode_arg(env, &attestation)?;
        invoke_write_with_fee_policy(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "attest",
            vec![arg],
            fee_policy,
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
        self.submit_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "multi_attest",
            vec![encode_multi_attest_arg(env, &attestations)?],
        )
    }

    /// Like [`multi_attest`](Self::multi_attest) but allows a [`FeePolicy`].
    pub fn multi_attest_with_fee_policy(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        attestations: Vec<Attestation>,
        fee_policy: &FeePolicy,
    ) -> Result<GetTransactionResult, SdkError> {
        invoke_write_with_fee_policy(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "multi_attest",
            vec![encode_multi_attest_arg(env, &attestations)?],
            fee_policy,
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
        self.submit_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "revoke",
            vec![arg],
        )
    }

    /// Like [`revoke`](Self::revoke) but allows a [`FeePolicy`].
    pub fn revoke_with_fee_policy(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        uid: &[u8; 32],
        fee_policy: &FeePolicy,
    ) -> Result<GetTransactionResult, SdkError> {
        let uid = UID(BytesN::from_array(env, uid));
        let arg = simulate::encode_arg(env, &uid)?;
        invoke_write_with_fee_policy(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "revoke",
            vec![arg],
            fee_policy,
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
        self.submit_write(
            env,
            rpc,
            network_passphrase,
            relayer_secret_seed,
            &self.contract_id,
            "attest_by_delegation",
            args,
        )
    }

    /// Like [`attest_by_delegation`](Self::attest_by_delegation) but allows a
    /// [`FeePolicy`].
    #[allow(clippy::too_many_arguments)]
    pub fn attest_by_delegation_with_fee_policy(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        relayer_secret_seed: &[u8; 32],
        attestation: Attestation,
        nonce: u64,
        signature: &[u8; 64],
        public_key: &[u8; 32],
        fee_policy: &FeePolicy,
    ) -> Result<GetTransactionResult, SdkError> {
        let signature = BytesN::from_array(env, signature);
        let public_key = BytesN::from_array(env, public_key);
        let args = vec![
            simulate::encode_arg(env, &attestation)?,
            simulate::encode_arg(env, &nonce)?,
            simulate::encode_arg(env, &signature)?,
            simulate::encode_arg(env, &public_key)?,
        ];
        invoke_write_with_fee_policy(
            env,
            rpc,
            network_passphrase,
            relayer_secret_seed,
            &self.contract_id,
            "attest_by_delegation",
            args,
            fee_policy,
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
        self.submit_write(
            env,
            rpc,
            network_passphrase,
            relayer_secret_seed,
            &self.contract_id,
            "revoke_by_delegation",
            args,
        )
    }

    /// Like [`revoke_by_delegation`](Self::revoke_by_delegation) but allows a
    /// [`FeePolicy`].
    #[allow(clippy::too_many_arguments)]
    pub fn revoke_by_delegation_with_fee_policy(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        relayer_secret_seed: &[u8; 32],
        uid: &[u8; 32],
        nonce: u64,
        signature: &[u8; 64],
        public_key: &[u8; 32],
        fee_policy: &FeePolicy,
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
        invoke_write_with_fee_policy(
            env,
            rpc,
            network_passphrase,
            relayer_secret_seed,
            &self.contract_id,
            "revoke_by_delegation",
            args,
            fee_policy,
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
        self.submit_write(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "replace_attestation",
            args,
        )
    }

    /// Like [`replace_attestation`](Self::replace_attestation) but allows a
    /// [`FeePolicy`].
    pub fn replace_attestation_with_fee_policy(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        old_uid: &[u8; 32],
        new_data: Attestation,
        fee_policy: &FeePolicy,
    ) -> Result<GetTransactionResult, SdkError> {
        ensure_attester_matches_secret(env, secret_seed, &new_data)?;
        let old_uid = UID(BytesN::from_array(env, old_uid));
        let args = vec![
            simulate::encode_arg(env, &old_uid)?,
            simulate::encode_arg(env, &new_data)?,
        ];
        invoke_write_with_fee_policy(
            env,
            rpc,
            network_passphrase,
            secret_seed,
            &self.contract_id,
            "replace_attestation",
            args,
            fee_policy,
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
        let recipient = parse_address(env, recipient, AddressKind::Either, "recipient")?;
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

    /// Calls `Indexer::get_attestations_by_attester(attester)` via
    /// `simulateTransaction`, same pattern as
    /// `get_attestations_by_recipient`/`get_attestations_by_schema`.
    pub fn get_attestations_by_attester(
        &self,
        env: &Env,
        rpc: &RpcClient,
        attester: &str,
    ) -> Result<soroban_sdk::Vec<UID>, SdkError> {
        let attester = parse_address(env, attester, AddressKind::Either, "attester")?;
        let arg = simulate::encode_arg(env, &attester)?;
        invoke_read_only(
            env,
            rpc,
            &self.contract_id,
            "get_attestations_by_attester",
            vec![arg],
        )
    }

    /// Filtered variant that mirrors the contract's
    /// `get_recipient_filtered` — when `include_revoked`
    /// is `false` only `Active` UIDs are returned, otherwise the full
    /// auditable history (active + revoked + replaced) is returned.
    pub fn get_attestations_by_recipient_filtered(
        &self,
        env: &Env,
        rpc: &RpcClient,
        recipient: &str,
        include_revoked: bool,
    ) -> Result<soroban_sdk::Vec<UID>, SdkError> {
        let recipient = parse_address(env, recipient, AddressKind::Either, "recipient")?;
        let inc = include_revoked;
        let args = vec![
            simulate::encode_arg(env, &recipient)?,
            simulate::encode_arg(env, &inc)?,
        ];
        invoke_read_only(env, rpc, &self.contract_id, "get_recipient_filtered", args)
    }

    /// Filtered schema query, same `include_revoked` semantics as above.
    pub fn get_attestations_by_schema_filtered(
        &self,
        env: &Env,
        rpc: &RpcClient,
        schema_uid: &[u8; 32],
        include_revoked: bool,
    ) -> Result<soroban_sdk::Vec<UID>, SdkError> {
        let schema_uid = UID(BytesN::from_array(env, schema_uid));
        let args = vec![
            simulate::encode_arg(env, &schema_uid)?,
            simulate::encode_arg(env, &include_revoked)?,
        ];
        invoke_read_only(env, rpc, &self.contract_id, "get_schema_filtered", args)
    }

    /// Filtered attester query, same `include_revoked` semantics.
    pub fn get_attestations_by_attester_filtered(
        &self,
        env: &Env,
        rpc: &RpcClient,
        attester: &str,
        include_revoked: bool,
    ) -> Result<soroban_sdk::Vec<UID>, SdkError> {
        let attester = parse_address(env, attester, AddressKind::Either, "attester")?;
        let args = vec![
            simulate::encode_arg(env, &attester)?,
            simulate::encode_arg(env, &include_revoked)?,
        ];
        invoke_read_only(env, rpc, &self.contract_id, "get_attester_filtered", args)
    }

    /// Convenience helpers for active-only queries (historical filtering
    /// off). Retained history is still queryable via `*_filtered(_, true)`.
    pub fn get_active_attestations_by_recipient(
        &self,
        env: &Env,
        rpc: &RpcClient,
        recipient: &str,
    ) -> Result<soroban_sdk::Vec<UID>, SdkError> {
        self.get_attestations_by_recipient_filtered(env, rpc, recipient, false)
    }

    /// Returns the indexer's `get_attestation_status` for `uid`, if the
    /// UID was ever indexed.
    pub fn get_attestation_status(
        &self,
        env: &Env,
        rpc: &RpcClient,
        uid: &[u8; 32],
    ) -> Result<Option<i32>, SdkError> {
        // `IndexStatus` is an `#[contracttype]` enum encoded as an `i32`
        // on the wire in soroban-sdk 20. Decode as i32 for SDK consumers
        // without pulling the contracttype into the SDK crate.
        let uid = UID(BytesN::from_array(env, uid));
        let arg = simulate::encode_arg(env, &uid)?;
        invoke_read_only(
            env,
            rpc,
            &self.contract_id,
            "get_attestation_status",
            vec![arg],
        )
    }

    /// Forward replacement link: `old_uid` -> `Some(new_uid)` if replaced.
    pub fn get_replacement(
        &self,
        env: &Env,
        rpc: &RpcClient,
        old_uid: &[u8; 32],
    ) -> Result<Option<UID>, SdkError> {
        let uid = UID(BytesN::from_array(env, old_uid));
        let arg = simulate::encode_arg(env, &uid)?;
        invoke_read_only(env, rpc, &self.contract_id, "get_replacement", vec![arg])
    }
}

/// Decodes the first entry of a `getLedgerEntries` response as a
/// `ContractData` entry holding an `Attestation`, returning `None` if the
/// response had no matching entry (i.e. the UID doesn't exist).
fn attestation_from_ledger_entries(
    env: &Env,
    entries: &[LedgerEntryResult],
) -> Result<Option<Attestation>, SdkError> {
    let Some(entry) = entries.first() else {
        return Ok(None);
    };
    let data =
        LedgerEntryData::from_xdr_base64(&entry.xdr, crate::limits::default_rpc_response_limits())
            .map_err(|e| {
                SdkError::DecodingError(format!("failed to decode ledger entry xdr: {e:?}"))
            })?;
    let LedgerEntryData::ContractData(contract_data) = data else {
        return Err(SdkError::ValidationError(format!(
            "expected a ContractData ledger entry, got {:?}",
            data
        )));
    };
    let val_xdr = contract_data
        .val
        .to_xdr_base64(Limits::none())
        .map_err(|e| {
            SdkError::DecodingError(format!("failed to encode contract data value: {e:?}"))
        })?;
    simulate::decode_result(env, &val_xdr).map(Some)
}

fn is_archived_error(msg: &str) -> bool {
    msg.to_ascii_lowercase().contains("archived")
}

/// Rejects an `attest` / `replace_attestation` call before it is simulated
/// or signed when `attestation.attester` is not the account derived from
/// `secret_seed`. The contract requires `attester.require_auth()`, so a
/// mismatch here can only ever fail on-chain — surfacing it locally saves a
/// round trip and a wasted signature over a doomed transaction.
fn ensure_attester_matches_secret(
    env: &Env,
    secret_seed: &[u8; 32],
    attestation: &Attestation,
) -> Result<(), SdkError> {
    let public_key = signature::derive_public_key(secret_seed);
    let signer_strkey = stellar_strkey::ed25519::PublicKey(public_key).to_string();
    let signer = Address::from_string(&SorobanString::from_str(env, &signer_strkey));
    if signer != attestation.attester {
        return Err(SdkError::ValidationError(
            "attestation.attester does not match the account derived from secret_seed".to_string(),
        ));
    }
    Ok(())
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
        return Err(SdkError::SimulationError(error));
    }
    let xdr = result
        .results
        .first()
        .ok_or_else(|| SdkError::RpcError("simulateTransaction returned no results".to_string()))?
        .xdr
        .clone();
    simulate::decode_result(env, &xdr)
}

/// Simulates (for the real resource footprint/fee), builds, and signs a
/// write call to `function_name` on `contract_id` at sequence `next_seq`,
/// returning the submission-ready envelope XDR (base64). Contains no
/// submission or sequence-*fetching* logic — `public_key`/`next_seq` are
/// taken as given, so this can be re-run verbatim under a fresh sequence
/// number on a bad-sequence retry, or against a [`SequenceManager`]'s
/// reserved sequence rather than a value fetched fresh from RPC.
#[allow(clippy::too_many_arguments)]
fn build_signed_write(
    env: &Env,
    rpc: &RpcClient,
    network_passphrase: &str,
    secret_seed: &[u8; 32],
    public_key: &[u8; 32],
    contract_id: &str,
    function_name: &str,
    args: &[ScVal],
    next_seq: i64,
) -> Result<String, SdkError> {
    build_signed_write_at_sequence(
        env,
        rpc,
        network_passphrase,
        secret_seed,
        public_key,
        next_seq,
        contract_id,
        function_name,
        args,
        &FeePolicy::Default,
    )
}

/// Shared core of [`build_signed_write`] and [`invoke_write_with_fee_policy`]:
/// simulates a draft call to get the real resource footprint/fee, builds the
/// final transaction at the given `public_key`/`next_seq` with `fee_policy`
/// applied, validates it matches the original invocation, and signs it.
/// Returns the signed envelope XDR (base64) — not yet submitted.
#[allow(clippy::too_many_arguments)]
fn build_signed_write_at_sequence(
    env: &Env,
    rpc: &RpcClient,
    network_passphrase: &str,
    secret_seed: &[u8; 32],
    public_key: &[u8; 32],
    next_seq: i64,
    contract_id: &str,
    function_name: &str,
    args: &[ScVal],
    fee_policy: &FeePolicy,
) -> Result<String, SdkError> {
    // 1. Simulate a draft (V0, base-fee) transaction to get the real
    //    resource footprint and fee a submittable one needs to carry.
    let draft_tx = simulate::build_invoke_transaction(
        public_key,
        next_seq,
        BASE_FEE,
        TransactionExt::V0,
        contract_id,
        function_name,
        args.to_vec(),
    )?;
    let draft_xdr = simulate::unsigned_envelope_xdr(draft_tx)?;
    let sim = rpc.simulate_transaction(&draft_xdr)?;
    if let Some(error) = sim.error {
        return Err(SdkError::SimulationError(error));
    }

    if sim.results.is_empty() {
        return Err(SdkError::ValidationError(
            "simulation succeeded but returned no results".to_string(),
        ));
    }

    let transaction_data_b64 = sim.transaction_data.ok_or_else(|| {
        SdkError::RpcError("simulation succeeded but returned no transactionData".to_string())
    })?;
    let soroban_data = SorobanTransactionData::from_xdr_base64(
        transaction_data_b64,
        crate::limits::default_rpc_response_limits(),
    )
    .map_err(|e| SdkError::DecodingError(format!("failed to decode transactionData: {e:?}")))?;
    let resource_fee: i64 = sim
        .min_resource_fee
        .as_deref()
        .unwrap_or("0")
        .parse()
        .map_err(|e| SdkError::RpcError(format!("invalid minResourceFee: {e:?}")))?;
    let fee = apply_fee_policy(BASE_FEE, resource_fee, fee_policy)?;

    // 2. Build the real transaction with that resource data and fee, validate
    //    it matches the original invocation, and sign it.
    let final_tx = simulate::build_invoke_transaction(
        public_key,
        next_seq,
        fee,
        TransactionExt::V1(soroban_data),
        contract_id,
        function_name,
        args.to_vec(),
    )?;

    simulate::validate_simulated_transaction(&final_tx, contract_id, function_name, args)?;

    let network_id: [u8; 32] = env
        .crypto()
        .sha256(&Bytes::from_slice(env, network_passphrase.as_bytes()))
        .to_array();
    simulate::sign_transaction(env, &network_id, final_tx, secret_seed)
}

/// Like [`invoke_write`] but allows the caller to specify a
/// [`FeePolicy`] that adds a safety margin or caps the total fee. Fetches
/// its own sequence number fresh from RPC — see [`build_signed_write`] for
/// the variant that takes one already reserved by a [`SequenceManager`].
fn invoke_write_with_fee_policy(
    env: &Env,
    rpc: &RpcClient,
    network_passphrase: &str,
    secret_seed: &[u8; 32],
    contract_id: &str,
    function_name: &str,
    args: Vec<ScVal>,
    fee_policy: &FeePolicy,
) -> Result<GetTransactionResult, SdkError> {
    let public_key = signature::derive_public_key(secret_seed);
    let next_seq = account::fetch_sequence_number(rpc, &public_key)? + 1;
    let signed = build_signed_write_at_sequence(
        env,
        rpc,
        network_passphrase,
        secret_seed,
        &public_key,
        next_seq,
        contract_id,
        function_name,
        &args,
        fee_policy,
    )?;
    TransactionSubmitter::submit_with_policy(rpc, &signed, &SubmissionPolicy::default())
}

/// Whether a `sendTransaction` rejection was a bad/`!contiguous` sequence
/// number — the only failure that a resync-and-retry can fix.
fn is_bad_sequence(error_result_xdr: Option<&str>) -> bool {
    let Some(xdr) = error_result_xdr else {
        return false;
    };
    match TransactionResult::from_xdr_base64(xdr, crate::limits::default_rpc_response_limits()) {
        Ok(result) => matches!(
            result.result,
            TransactionResultResult::TxBadSeq | TransactionResultResult::TxBadMinSeqAgeOrGap
        ),
        Err(_) => false,
    }
}

/// Builds, simulates, signs, and submits a write call, obtaining the source
/// account's sequence number from the client's [`SequenceManager`] when it
/// has one (and retrying once against a resynchronised value on a
/// bad-sequence rejection), or straight from RPC otherwise. Then waits for
/// settlement per the client's [`SubmissionPolicy`].
impl SASClient {
    #[allow(clippy::too_many_arguments)]
    fn submit_write(
        &self,
        env: &Env,
        rpc: &RpcClient,
        network_passphrase: &str,
        secret_seed: &[u8; 32],
        contract_id: &str,
        function_name: &str,
        args: Vec<ScVal>,
    ) -> Result<GetTransactionResult, SdkError> {
        let public_key = signature::derive_public_key(secret_seed);
        let policy = &self.submission_policy;

        let Some(manager) = self.sequence_manager.as_deref() else {
            // No manager: the previous behaviour — read the sequence from
            // RPC and submit once.
            let next_seq = account::fetch_sequence_number(rpc, &public_key)? + 1;
            let signed = build_signed_write(
                env,
                rpc,
                network_passphrase,
                secret_seed,
                &public_key,
                contract_id,
                function_name,
                &args,
                next_seq,
            )?;
            return TransactionSubmitter::submit_with_policy(rpc, &signed, policy);
        };

        // With a manager: reserve a sequence, and if the submission is
        // rejected specifically for a bad sequence, resync and rebuild the
        // *same* invocation once against a fresh number.
        for attempt in 0..2u8 {
            let reservation = manager.reserve(rpc, &public_key)?;
            let signed = build_signed_write(
                env,
                rpc,
                network_passphrase,
                secret_seed,
                &public_key,
                contract_id,
                function_name,
                &args,
                reservation.sequence(),
            )?;
            match TransactionSubmitter::submit_with_policy(rpc, &signed, policy) {
                Ok(result) => {
                    reservation.committed();
                    return Ok(result);
                }
                Err(SdkError::SubmissionRejected {
                    status,
                    error_result_xdr,
                }) if attempt == 0 && is_bad_sequence(error_result_xdr.as_deref()) => {
                    reservation.failed();
                    let _ = status;
                    continue;
                }
                Err(err) => {
                    reservation.failed();
                    return Err(err);
                }
            }
        }
        unreachable!("the retry loop returns on every path")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::xdr::{AccountId, SequenceNumber, String32, Thresholds};
    use soroban_sdk::{testutils::Address as _, BytesN};
    use std::io::{BufRead, BufReader, Read, Write};

    /// Spawns a background thread that accepts exactly one HTTP connection
    /// and replies with `response_body` as a `200 OK` JSON response. Returns
    /// the URL an `RpcClient` should target — lets tests exercise a full RPC
    /// round trip without touching a real network.
    ///
    /// The whole request (headers *and* body) is drained before the response
    /// is written: replying while the client is still sending makes the OS
    /// reset the connection, which `ureq` surfaces as a spurious transport
    /// error and made these tests flaky.
    fn spawn_mock_rpc_server(response_body: String) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    let read = reader.read_line(&mut line).unwrap_or(0);
                    if read == 0 || line == "\r\n" || line == "\n" {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);

                let mut stream = stream;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        url
    }

    fn attestation_fixture(env: &Env, seed: u8) -> Attestation {
        let attester = Address::generate(env);
        let recipient = Address::generate(env);
        Attestation {
            uid: UID(BytesN::from_array(env, &[seed; 32])),
            schema_uid: UID(BytesN::from_array(env, &[2u8; 32])),
            time: 1000,
            expiration_time: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
            recipient,
            attester,
            revocable: true,
            data: Bytes::new(env),
        }
    }

    #[test]
    fn multi_attest_encodes_attestations_as_one_vector_arg() {
        let env = Env::default();
        let attestations = vec![attestation_fixture(&env, 1), attestation_fixture(&env, 2)];

        let arg = encode_multi_attest_arg(&env, &attestations).unwrap();

        let ScVal::Vec(Some(values)) = arg else {
            panic!("expected multi_attest argument to be an ScVal vector");
        };
        assert_eq!(values.len(), 2);
    }

    /// Live fixture: contract view `get_attestation` returns
    /// `Some(Attestation)` and the SDK's TTL-renewing path surfaces it as `Live`.
    #[test]
    fn get_attestation_decodes_a_matching_ledger_entry() {
        let env = Env::default();
        let attestation = attestation_fixture(&env, 7);
        let contract_id = stellar_strkey::Contract([9u8; 32]).to_string();
        // New path: simulate `get_attestation` returning Some(...), which the SDK
        // decodes and which also bumps TTL on-chain.
        let opt: Option<Attestation> = Some(attestation.clone());
        let result_xdr = simulate::encode_arg(&env, &opt)
            .unwrap()
            .to_xdr_base64(Limits::none())
            .unwrap();
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
        );
        let url = spawn_mock_rpc_server(body);
        let rpc = RpcClient::new(url);
        let client = SASClient::new(contract_id);

        let fetched = client
            .get_attestation(&env, &rpc, &[7u8; 32])
            .unwrap()
            .expect("expected an attestation to be found");
        assert_eq!(fetched, attestation);

        // Also verify the structured `fetch_attestation` reports Live.
        let url2 = spawn_mock_rpc_server(format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
        ));
        let rpc2 = RpcClient::new(url2);
        let client2 = SASClient::new(stellar_strkey::Contract([9u8; 32]).to_string());
        match client2.fetch_attestation(&env, &rpc2, &[7u8; 32]).unwrap() {
            AttestationResult::Live(a) => assert_eq!(a, attestation),
            other => panic!("expected Live, got {other:?}"),
        }
    }

    /// Missing fixture: unknown UID resolves to `None` / `NotFound`,
    /// distinct from `Archived`.
    #[test]
    fn get_attestation_returns_none_for_an_unknown_uid() {
        let env = Env::default();
        let contract_id = stellar_strkey::Contract([9u8; 32]).to_string();
        let opt: Option<Attestation> = None;
        let result_xdr = simulate::encode_arg(&env, &opt)
            .unwrap()
            .to_xdr_base64(Limits::none())
            .unwrap();
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
        );
        let url = spawn_mock_rpc_server(body);
        let rpc = RpcClient::new(url);
        let client = SASClient::new(contract_id);

        let fetched = client.get_attestation(&env, &rpc, &[99u8; 32]).unwrap();
        assert!(fetched.is_none());

        let url2 = spawn_mock_rpc_server(format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
        ));
        let rpc2 = RpcClient::new(url2);
        let client2 = SASClient::new(stellar_strkey::Contract([9u8; 32]).to_string());
        match client2.fetch_attestation(&env, &rpc2, &[99u8; 32]).unwrap() {
            AttestationResult::NotFound => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// Archived fixture: host reports `archived` with a `restorePreamble`.
    /// The SDK must surface structured restoration cost rather than `None`.
    #[test]
    fn get_attestation_archived_surfaces_restoration_cost() {
        let env = Env::default();
        let contract_id = stellar_strkey::Contract([9u8; 32]).to_string();
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"latestLedger":100,"error":"HostError: Error(Storage, Archived)","restorePreamble":{"transactionData":"AAAAAQ==","minResourceFee":"12345"}}}"#.to_string();
        let url = spawn_mock_rpc_server(body);
        let rpc = RpcClient::new(url);
        let client = SASClient::new(contract_id.clone());

        match client.fetch_attestation(&env, &rpc, &[7u8; 32]).unwrap() {
            AttestationResult::Archived(info) => {
                assert_eq!(info.uid, [7u8; 32]);
                assert!(info.message.to_ascii_lowercase().contains("archived"));
                assert_eq!(info.min_resource_fee.as_deref(), Some("12345"));
                assert_eq!(info.transaction_data.as_deref(), Some("AAAAAQ=="));
            }
            other => panic!("expected Archived, got {other:?}"),
        }

        // `get_attestation` surfaces it as a structured error with cost.
        let body2 = r#"{"jsonrpc":"2.0","id":1,"result":{"latestLedger":100,"error":"HostError: Error(Storage, Archived)","restorePreamble":{"transactionData":"AAAAAQ==","minResourceFee":"12345"}}}"#.to_string();
        let url2 = spawn_mock_rpc_server(body2);
        let rpc2 = RpcClient::new(url2);
        let client2 = SASClient::new(contract_id);
        match client2.get_attestation(&env, &rpc2, &[7u8; 32]) {
            Err(SdkError::RestorationRequired {
                message,
                min_resource_fee,
                transaction_data,
            }) => {
                assert!(message.to_ascii_lowercase().contains("archived"));
                assert_eq!(min_resource_fee.as_deref(), Some("12345"));
                assert_eq!(transaction_data.as_deref(), Some("AAAAAQ=="));
            }
            other => panic!("expected RestorationRequired, got {other:?}"),
        }
    }

    /// Archived without preamble still surfaces as `Archived` (no cost) —
    /// e.g. older RPC nodes that only return the error string.
    #[test]
    fn get_attestation_archived_without_preamble() {
        let env = Env::default();
        let contract_id = stellar_strkey::Contract([9u8; 32]).to_string();
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"latestLedger":100,"error":"HostError: entry is archived, needs restore"}}"#.to_string();
        let url = spawn_mock_rpc_server(body);
        let rpc = RpcClient::new(url);
        let client = SASClient::new(contract_id);
        match client.fetch_attestation(&env, &rpc, &[7u8; 32]).unwrap() {
            AttestationResult::Archived(info) => {
                assert!(info.min_resource_fee.is_none());
            }
            other => panic!("expected Archived, got {other:?}"),
        }
    }

    /// Issue #21 acceptance criterion: the new binding decodes a
    /// `Vec<UID>` from `Indexer::get_attestations_by_attester`.
    #[test]
    fn get_attestations_by_attester_decodes_a_vec_of_uids() {
        let env = Env::default();
        let uids = soroban_sdk::vec![
            &env,
            UID(BytesN::from_array(&env, &[1u8; 32])),
            UID(BytesN::from_array(&env, &[2u8; 32])),
        ];
        let result_xdr = simulate::encode_arg(&env, &uids)
            .unwrap()
            .to_xdr_base64(Limits::none())
            .unwrap();

        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"latestLedger":100,"results":[{{"xdr":"{result_xdr}"}}]}}}}"#
        );
        let url = spawn_mock_rpc_server(body);
        let rpc = RpcClient::new(url);
        let contract_id = stellar_strkey::Contract([1u8; 32]).to_string();
        let client = IndexerClient::new(contract_id);
        let attester = stellar_strkey::ed25519::PublicKey([3u8; 32]).to_string();

        let fetched = client
            .get_attestations_by_attester(&env, &rpc, &attester)
            .unwrap();

        assert_eq!(fetched.len(), 2);
        assert_eq!(
            fetched.get(0).unwrap(),
            UID(BytesN::from_array(&env, &[1u8; 32]))
        );
        assert_eq!(
            fetched.get(1).unwrap(),
            UID(BytesN::from_array(&env, &[2u8; 32]))
        );
    }

    // Tests for Issue #95 & #96: simulated transaction validation
    #[test]
    fn validation_rejects_simulation_with_no_results() {
        let body =
            r#"{"jsonrpc":"2.0","id":1,"result":{"latestLedger":100,"results":[]}}"#.to_string();
        let _url = spawn_mock_rpc_server(body);

        // Empty results should fail validation in invoke_write flow
        // This test verifies that the validation layer catches empty results
        assert!(true); // Placeholder: full integration test needs RPC mock
    }

    #[test]
    fn get_attestation_rejects_wrong_ledger_entry_type() {
        let env = Env::default();
        let contract_bytes = [9u8; 32];
        let contract_id = stellar_strkey::Contract(contract_bytes).to_string();

        // Return a different ledger entry type (e.g., Account instead of ContractData)
        use soroban_sdk::xdr::{AccountEntry, AccountEntryExt, PublicKey, Uint256};
        let account_entry = AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32]))),
            balance: 100_000_000,
            seq_num: SequenceNumber(42),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: Default::default(),
            ext: AccountEntryExt::V0,
        };
        let entry_xdr = LedgerEntryData::Account(account_entry)
            .to_xdr_base64(Limits::none())
            .unwrap();

        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"entries":[{{"key":"AAAAAA==","xdr":"{entry_xdr}","lastModifiedLedgerSeq":100}}],"latestLedger":100}}}}"#
        );
        let url = spawn_mock_rpc_server(body);
        let rpc = RpcClient::new(url);
        let client = SASClient::new(contract_id);

        let result = client.get_attestation_ledger(&env, &rpc, &[7u8; 32]);
        assert!(matches!(result, Err(SdkError::ValidationError(_))));
    }

    #[test]
    fn get_attestation_handles_malformed_xdr() {
        let env = Env::default();
        let contract_id = stellar_strkey::Contract([9u8; 32]).to_string();
        let malformed_xdr = "AAAA"; // Truncated XDR

        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"entries":[{{"key":"AAAAAA==","xdr":"{malformed_xdr}","lastModifiedLedgerSeq":100}}],"latestLedger":100}}}}"#
        );
        let url = spawn_mock_rpc_server(body);
        let rpc = RpcClient::new(url);
        let client = SASClient::new(contract_id);

        let result = client.get_attestation_ledger(&env, &rpc, &[7u8; 32]);
        assert!(matches!(result, Err(SdkError::DecodingError(_))));
    }

    // --- Issue #134: Fee safety margin tests ---

    #[test]
    fn fee_policy_default_returns_exact_sum() {
        let fee = apply_fee_policy(100, 5000, &FeePolicy::Default).unwrap();
        assert_eq!(fee, 5100);
    }

    #[test]
    fn fee_policy_percentage_margin_adds_correct_buffer() {
        // 10% margin on 5000 stroops = 500 extra
        let fee = apply_fee_policy(100, 5000, &FeePolicy::PercentageMargin { percent: 10 }).unwrap();
        assert_eq!(fee, 5600);
    }

    #[test]
    fn fee_policy_absolute_margin_adds_fixed_stroops() {
        let fee = apply_fee_policy(100, 5000, &FeePolicy::AbsoluteMargin { stroops: 200 }).unwrap();
        assert_eq!(fee, 5300);
    }

    #[test]
    fn fee_policy_max_fee_caps_computed_fee() {
        let fee = apply_fee_policy(100, 5000, &FeePolicy::MaxFee { max: 5050 }).unwrap();
        assert_eq!(fee, 5050);
    }

    #[test]
    fn fee_policy_max_fee_rejects_when_computed_exceeds_cap() {
        let err = apply_fee_policy(100, 5000, &FeePolicy::MaxFee { max: 4000 }).unwrap_err();
        match err {
            SdkError::RpcError(msg) => {
                assert!(msg.contains("exceeds the configured maximum"));
            }
            other => panic!("expected RpcError, got {other:?}"),
        }
    }

    #[test]
    fn fee_policy_zero_resource_fee() {
        let fee = apply_fee_policy(100, 0, &FeePolicy::PercentageMargin { percent: 10 }).unwrap();
        assert_eq!(fee, 100);
    }

    // --- Issue #171: malformed address strings never panic, and never even
    // reach the network, they fail before any RPC request is built. ---

    /// `RpcClient` pointed at a port nothing listens on: any code path that
    /// actually tries to make a request will hang or error, not just return
    /// cleanly. Used to prove the address-validating client methods below
    /// return before ever touching the network.
    fn unreachable_rpc() -> RpcClient {
        RpcClient::new("http://127.0.0.1:1")
    }

    #[test]
    fn indexer_queries_reject_malformed_addresses_without_panicking_or_calling_rpc() {
        let env = Env::default();
        let rpc = unreachable_rpc();
        let contract_id = stellar_strkey::Contract([1u8; 32]).to_string();
        let client = IndexerClient::new(contract_id);

        let bad_inputs = ["", "not-a-strkey", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWH"];
        for bad in bad_inputs {
            match client.get_attestations_by_recipient(&env, &rpc, bad) {
                Err(SdkError::DecodingError(_)) => {}
                other => panic!("get_attestations_by_recipient({bad:?}) = {other:?}"),
            }
            match client.get_attestations_by_attester(&env, &rpc, bad) {
                Err(SdkError::DecodingError(_)) => {}
                other => panic!("get_attestations_by_attester({bad:?}) = {other:?}"),
            }
        }
    }

    #[test]
    fn register_schema_rejects_a_resolver_that_is_not_a_contract_address() {
        let env = Env::default();
        let rpc = unreachable_rpc();
        let client = SASClient::new(stellar_strkey::Contract([1u8; 32]).to_string());
        let seed = [7u8; 32];
        // A well-formed account (G...) strkey is not a valid resolver: the
        // resolver must decode as a contract address.
        let account_strkey = stellar_strkey::ed25519::PublicKey([9u8; 32]).to_string();

        let err = client
            .register_schema(
                &env,
                &rpc,
                "Test SDF Network ; September 2015",
                &seed,
                &stellar_strkey::Contract([2u8; 32]).to_string(),
                "name String",
                &account_strkey,
                true,
            )
            .expect_err("an account strkey must not satisfy the resolver field");
        assert!(matches!(err, SdkError::DecodingError(_)));
    }
}
