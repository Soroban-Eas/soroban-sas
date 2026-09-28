#![allow(unexpected_cfgs)]
#![no_std]
#![allow(unused_variables)]

use soroban_sas_common::{
    events::{
        CONTRACT_UPGRADED, SCHEMA_DELEGATE_ADDED, SCHEMA_DELEGATE_REMOVED, SCHEMA_DEPRECATED,
        SCHEMA_FEE_UPDATED, SCHEMA_OWNERSHIP_TRANSFERRED, TREASURY_UPDATED,
    },
    validate_schema_syntax, ContractUpgradedEvent, PreviousAddress, SASError,
    SchemaDelegateAddedEvent, SchemaDelegateRemovedEvent, SchemaDeprecatedEvent,
    SchemaFeeUpdatedEvent, SchemaOwnershipTransferredEvent, SchemaRecord, TreasuryUpdatedEvent,
    LEDGERS_IN_ONE_YEAR, UID,
};
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, token, Address, BytesN, Env, String,
    Vec,
};

#[contract]
pub struct SchemaRegistry;

/// Highest version whose upgrade path this build knows and has been audited
/// to activate. Genesis `1` -> only `2` is known; expand this allow-list as
/// new releases are audited and their WASM hashes are pinned.
pub const MAX_KNOWN_VERSION: u32 = 2;

mod storage;
use storage::*;

fn extend_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
}

/// Pushes a schema record's archival horizon back out to the shared
/// retention window ([`LEDGERS_IN_ONE_YEAR`], used as both the renewal
/// threshold and the extend-to target, matching every other persistent
/// write in this contract).
///
/// Call this only once `uid` is known to exist: read views renew an active
/// record so that a schema which is heavily read but never rewritten is not
/// archived, breaking downstream validation and discovery. The missing-UID
/// path must stay side-effect free.
fn renew_schema_record(env: &Env, uid: &UID) {
    env.storage()
        .persistent()
        .extend_ttl(uid, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
}

/// Reads the registry admin, or `Err(NotInitialized)` when the registry has
/// not been initialized yet. The non-panicking counterpart of
/// [`require_registry_admin`], used by the upgrade validation path so a
/// candidate can be rejected with a typed error before any state is written.
fn registry_admin(env: &Env) -> Result<Address, SASError> {
    match env.storage().instance().get(&REGISTRY_ADMIN) {
        Some(admin) => Ok(admin),
        None => Err(SASError::NotInitialized),
    }
}

fn require_registry_admin(env: &Env) -> Address {
    match registry_admin(env) {
        Ok(admin) => admin,
        Err(error) => panic_with_error!(env, error),
    }
}

/// Validates an upgrade candidate without mutating any state, returning the
/// registry admin that must authorize the activation.
///
/// Split out of [`SchemaRegistry::upgrade`] so every validation rule can be
/// exercised in unit tests without going through
/// `update_current_contract_wasm`, which requires a real, previously uploaded
/// WASM blob to target — the same split `sas` and `indexer` use.
fn validate_upgrade(
    env: &Env,
    new_wasm_hash: &BytesN<32>,
    new_version: u32,
) -> Result<Address, SASError> {
    // The admin that authorizes the upgrade must still be readable, so a
    // candidate that would orphan the registry's own configuration is
    // rejected before anything is written.
    let admin = registry_admin(env)?;

    // Storage-migration gate: existing persistent keys must still be
    // readable after the upgrade path. This is a lightweight sanity check
    // that the new contract's storage layout still contains the
    // `SCHEMA_COUNT` key; a real migration would compare full schema counts
    // before/after via simulation.
    let _count: Option<u32> = env.storage().persistent().get(&SCHEMA_COUNT);

    let old_version: u32 = env.storage().instance().get(&REGISTRY_VERSION).unwrap_or(1);

    // Reject unknown future versions before writing any state.
    if new_version > MAX_KNOWN_VERSION {
        return Err(SASError::IncompatibleDependency);
    }
    if new_version != old_version.saturating_add(1) {
        return Err(SASError::InvalidValue);
    }
    // Hash must be non-zero.
    if new_wasm_hash.to_array() == [0u8; 32] {
        return Err(SASError::InvalidValue);
    }
    Ok(admin)
}

/// Commits an already-validated upgrade: persists the new version and the
/// targeted WASM hash, then publishes the events that describe it.
///
/// Emits the versioned `UPGRADE` event (`(old_version, new_version,
/// new_wasm_hash)`) and the standardized `ContractUpgraded` event
/// (`(old_wasm_hash, new_wasm_hash, authorizer)`), so off-chain indexers can
/// follow registry activations either by version or by WASM hash. Both are
/// published before `update_current_contract_wasm` is requested; Soroban
/// rolls the whole invocation back if the swap fails, so an event a consumer
/// actually observes always corresponds to an activation that durably stuck.
fn commit_upgrade(env: &Env, admin: &Address, new_wasm_hash: &BytesN<32>, new_version: u32) {
    let old_version: u32 = env.storage().instance().get(&REGISTRY_VERSION).unwrap_or(1);
    // Soroban does not expose a way to read the currently installed WASM hash
    // from within the contract itself, so the first upgrade on a given
    // deployment has no prior tracked hash and reports the all-zero "unknown"
    // sentinel instead of asserting a genesis hash it cannot verify. Every
    // upgrade after that carries the hash it is replacing (matching `sas` and
    // `indexer`).
    let old_wasm_hash: BytesN<32> = env
        .storage()
        .instance()
        .get(&CURRENT_WASM_HASH)
        .unwrap_or_else(|| BytesN::from_array(env, &[0u8; 32]));

    env.storage()
        .instance()
        .set(&REGISTRY_VERSION, &new_version);
    env.storage()
        .instance()
        .set(&CURRENT_WASM_HASH, new_wasm_hash);
    extend_instance_ttl(env);

    env.events().publish(
        (UPGRADE_EVENT, old_version, new_version),
        (old_version, new_version, new_wasm_hash.clone()),
    );
    env.events().publish(
        (CONTRACT_UPGRADED, admin.clone()),
        ContractUpgradedEvent {
            old_wasm_hash,
            new_wasm_hash: new_wasm_hash.clone(),
            authorizer: admin.clone(),
        },
    );
}

const MAX_SCAN_BUDGET: u32 = 100;

// ===== MULTI-SIGNATURE SCHEMA OWNERS (#288) =====

/// Multi-signature owner configuration for one schema.
///
/// When a set is configured, ownership-changing operations must collect at
/// least `threshold` approvals from distinct members of `owners` instead of
/// relying on a single creator signature.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerSet {
    /// Distinct addresses allowed to own and approve operations for the schema.
    pub owners: Vec<Address>,
    /// Number of distinct approvals required to execute an ownership transfer.
    /// Always in `1..=owners.len()`.
    pub threshold: u32,
    /// Bumped on every reconfiguration. In-flight approvals are stamped with
    /// the version they were collected under, so a set change invalidates them.
    pub version: u32,
}

/// An ownership transfer that is waiting for enough owner approvals.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOwnershipTransfer {
    /// `OwnerSet::version` the collected approvals belong to.
    pub owner_set_version: u32,
    /// Address that takes over as creator once the threshold is reached.
    pub new_owner: Address,
    /// Distinct owners that have approved so far, in approval order.
    pub approvals: Vec<Address>,
    /// Ledger timestamp of the first approval.
    pub created_at: u64,
}

/// Result of proposing or approving a multi-signature ownership transfer.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipTransferStatus {
    /// Address that takes over once `executed` is true (or will, if not yet).
    pub new_owner: Address,
    /// Distinct approvals collected so far.
    pub approvals: u32,
    /// Approvals required by the schema's owner set (1 when none is configured).
    pub threshold: u32,
    /// True when this call reached the threshold and moved ownership.
    pub executed: bool,
}

/// Reads a schema's configured owner set, if one exists.
fn owner_set(env: &Env, uid: &UID) -> Option<OwnerSet> {
    env.storage().persistent().get(&(SCHEMA_OWNERS, uid.clone()))
}

/// Reads a schema's creator/owner, kept in its own key so `SchemaRecord`
/// stays byte-stable.
fn schema_creator(env: &Env, uid: &UID) -> Option<Address> {
    env.storage()
        .persistent()
        .get(&(SCHEMA_CREATOR, uid.clone()))
}

/// Version-aligned membership test that avoids relying on `Vec: PartialEq`
/// so the check stays valid across SDK releases.
fn members_contain(members: &Vec<Address>, needle: &Address) -> bool {
    let mut index = 0;
    while index < members.len() {
        if let Some(member) = members.get(index) {
            if &member == needle {
                return true;
            }
        }
        index = index.saturating_add(1);
    }
    false
}

/// Returns the owner set that governs `uid` together with the number of
/// approvals required. A schema without a configured set behaves exactly as
/// before: the creator alone is the owner and one approval is enough.
fn effective_owner_set(env: &Env, uid: &UID) -> (Option<OwnerSet>, u32) {
    match owner_set(env, uid) {
        Some(set) => {
            let threshold = set.threshold;
            (Some(set), threshold)
        }
        None => (None, 1),
    }
}

/// True when `who` may act as an owner of `uid`: a member of the configured
/// owner set when one exists, the creator otherwise, or the registry admin.
fn is_owner_address(env: &Env, uid: &UID, who: &Address) -> bool {
    if let Some(set) = owner_set(env, uid) {
        if members_contain(&set.owners, who) {
            return true;
        }
    }

    if let Some(creator) = schema_creator(env, uid) {
        if &creator == who {
            return true;
        }
    }

    match env.storage().instance().get::<_, Address>(&REGISTRY_ADMIN) {
        Some(admin) => &admin == who,
        None => false,
    }
}

/// Rejects owner sets that could never reach their own threshold or that
/// contain duplicate/absent members.
fn validate_owner_set(env: &Env, owners: &Vec<Address>, threshold: u32) {
    let length = owners.len();
    if length == 0 || length > MAX_OWNER_SET {
        panic_with_error!(env, SASError::LimitExceeded);
    }
    if threshold == 0 || threshold > length {
        panic_with_error!(env, SASError::InvalidValue);
    }

    let mut seen: Vec<Address> = Vec::new(env);
    let mut index = 0;
    while index < length {
        let Some(owner) = owners.get(index) else {
            panic_with_error!(env, SASError::InvalidValue);
        };
        if members_contain(&seen, &owner) {
            panic_with_error!(env, SASError::InvalidValue);
        }
        seen.push_back(owner);
        index = index.saturating_add(1);
    }
}

/// Commits an ownership transfer: rewrites the creator key, drops any pending
/// approval state, and publishes the standard ownership event.
fn finalize_ownership_transfer(env: &Env, uid: &UID, old_owner: &Address, new_owner: &Address) {
    let creator_key = (SCHEMA_CREATOR, uid.clone());
    env.storage().persistent().set(&creator_key, new_owner);
    env.storage().persistent().extend_ttl(
        &creator_key,
        LEDGERS_IN_ONE_YEAR,
        LEDGERS_IN_ONE_YEAR,
    );
    env.storage()
        .persistent()
        .remove(&(PENDING_OWNERSHIP, uid.clone()));
    renew_schema_record(env, uid);

    env.events().publish(
        (SCHEMA_OWNERSHIP_TRANSFERRED, uid.clone()),
        SchemaOwnershipTransferredEvent {
            schema_uid: uid.clone(),
            old_owner: old_owner.clone(),
            new_owner: new_owner.clone(),
        },
    );

    extend_instance_ttl(env);
}

/// Shared guard for the single-signature ownership entrypoints: a schema that
/// requires more than one approval must move ownership through
/// `propose_ownership_transfer`/`approve_ownership_transfer`, so no individual
/// owner can bypass the set.
fn reject_single_sig_transfer_for_multisig(env: &Env, uid: &UID) {
    let (_, threshold) = effective_owner_set(env, uid);
    if threshold > 1 {
        panic_with_error!(env, SASError::Unauthorized);
    }
}

/// Shared precondition check for ownership-transfer entrypoints.
fn require_transferable_schema(env: &Env, uid: &UID) {
    if !env.storage().persistent().has(uid) {
        panic_with_error!(env, SASError::SchemaNotFound);
    }
    if env
        .storage()
        .persistent()
        .get(&(DEPRECATED, uid.clone()))
        .unwrap_or(false)
    {
        panic_with_error!(env, SASError::InvalidSchema);
    }
}

/// Records one distinct owner approval and returns the updated pending state.
fn record_approval(env: &Env, uid: &UID, approver: &Address) -> PendingOwnershipTransfer {
    let pending_key = (PENDING_OWNERSHIP, uid.clone());
    let Some(mut pending) = env
        .storage()
        .persistent()
        .get::<_, PendingOwnershipTransfer>(&pending_key)
    else {
        panic_with_error!(env, SASError::SchemaNotFound);
    };

    let (set, _) = effective_owner_set(env, uid);
    let expected_version = set.map(|s| s.version).unwrap_or(0);
    if pending.owner_set_version != expected_version {
        panic_with_error!(env, SASError::Unauthorized);
    }

    if !is_owner_address(env, uid, approver) {
        panic_with_error!(env, SASError::Unauthorized);
    }
    if members_contain(&pending.approvals, approver) {
        panic_with_error!(env, SASError::InvalidValue);
    }

    pending.approvals.push_back(approver.clone());
    env.storage()
        .persistent()
        .set(&pending_key, &pending);
    env.storage().persistent().extend_ttl(
        &pending_key,
        LEDGERS_IN_ONE_YEAR,
        LEDGERS_IN_ONE_YEAR,
    );

    let count = pending.approvals.len();
    env.events().publish(
        (SCHEMA_OWNER_APPROVED, uid.clone()),
        (approver.clone(), count),
    );

    pending
}

#[contractimpl]
impl SchemaRegistry {
    /// Compatibility probe used by SAS::init before storing this registry.
    pub fn sasreg(_env: Env) -> bool {
        true
    }

    pub fn init(env: Env, admin: soroban_sdk::Address) {
        extend_instance_ttl(&env);
        if env.storage().instance().has(&REGISTRY_ADMIN) {
            panic_with_error!(&env, SASError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&REGISTRY_ADMIN, &admin);
        extend_instance_ttl(&env);
        // Genesis version = 1. Stored so upgrades can enforce monotonic
        // version increments and storage-migration gates.
        if !env.storage().instance().has(&REGISTRY_VERSION) {
            env.storage().instance().set(&REGISTRY_VERSION, &1u32);
        }
    }

    /// Returns the registry's current version (1 = genesis). Useful for
    /// off-chain upgrade orchestration and for the `UPGRADE` event's old/new
    /// version fields.
    pub fn get_version(env: Env) -> u32 {
        extend_instance_ttl(&env);
        env.storage().instance().get(&REGISTRY_VERSION).unwrap_or(1)
    }

    /// Versioned upgrade. Validates the candidate before activation:
    ///  - the registry admin must still be readable
    ///  - `new_version` must be exactly `current + 1` (no skips/downgrades)
    ///  - only known versions (currently 2, i.e. next after genesis) are
    ///    accepted — unknown future versions are rejected before any WASM
    ///    is written
    ///  - the WASM hash must be non-zero
    ///  - storage schema check: `SCHEMA_COUNT` must still be readable (so a
    ///    faulty WASM that would orphan existing schemas is caught on the
    ///    upgrade path itself)
    /// Emits an `UPGRADE` event with `(old_version, new_version, wasm_hash)`
    /// and a `ContractUpgraded` event with `(old_wasm_hash, new_wasm_hash,
    /// authorizer)`, then bumps the stored version and hash before calling
    /// `update_current_contract_wasm`. See `docs/UPGRADE_RUNBOOK.md` for the
    /// staged activation / rollback procedure.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>, new_version: u32) {
        extend_instance_ttl(&env);
        let layout_admin = match validate_upgrade(&env, &new_wasm_hash, new_version) {
            Ok(admin) => admin,
            Err(error) => panic_with_error!(&env, error),
        };
        // Re-read through the panicking accessor so the address that actually
        // authorizes the activation is re-checked against the admin the
        // candidate was validated against, matching `sas` and `indexer`.
        let admin = require_registry_admin(&env);
        if admin != layout_admin {
            panic_with_error!(&env, SASError::IncompatibleDependency);
        }
        admin.require_auth();
        extend_instance_ttl(&env);

        commit_upgrade(&env, &admin, &new_wasm_hash, new_version);

        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Pins the asset and exact amount `register_with_value` charges for
    /// schema registration. Requires the registry admin's authorization.
    /// `amount` must be positive; call `clear_fee` for fee-free
    /// registration instead of encoding "no fee" as an arbitrary zero.
    /// Emits `SchemaFeeUpdated` with the previous fee (`None` the first
    /// time a fee is set) after the new fee has already been written to
    /// storage.
    pub fn set_fee(env: Env, token: Address, amount: i128) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        let old_fee: Option<(Address, i128)> = env.storage().instance().get(&SCHEMA_FEE);
        env.storage()
            .instance()
            .set(&SCHEMA_FEE, &(token.clone(), amount));
        extend_instance_ttl(&env);

        let (old_fee_token, old_fee_amount) = match old_fee {
            Some((t, a)) => (PreviousAddress::Some(t), Some(a)),
            None => (PreviousAddress::None, None),
        };
        env.events().publish(
            (SCHEMA_FEE_UPDATED, admin.clone()),
            SchemaFeeUpdatedEvent {
                old_fee_token,
                old_fee_amount,
                new_fee_token: token,
                new_fee_amount: amount,
                authorizer: admin,
            },
        );
    }

    /// Removes the registration fee requirement, so `register` (and
    /// `register_with_value` called with `value == 0`) are free again.
    /// Requires the registry admin's authorization.
    pub fn clear_fee(env: Env) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
        env.storage().instance().remove(&SCHEMA_FEE);
        extend_instance_ttl(&env);
    }

    /// Returns the `(token, amount)` fee `register_with_value` requires, or
    /// `None` when registration is fee-free.
    pub fn get_fee(env: Env) -> Option<(Address, i128)> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&SCHEMA_FEE)
    }

    pub fn get_treasury(env: Env) -> Option<Address> {
        extend_instance_ttl(&env);
        env.storage().instance().get(&TREASURY)
    }

    /// Sets the treasury address that receives registration fees. Requires
    /// the registry admin's authorization. Emits `TreasuryUpdated` with the
    /// previous treasury (`None` the first time a treasury is set) after
    /// the new address has already been written to storage.
    pub fn set_treasury(env: Env, treasury: soroban_sdk::Address) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();

        let old_treasury: Option<Address> = env.storage().instance().get(&TREASURY);
        env.storage().instance().set(&TREASURY, &treasury);
        extend_instance_ttl(&env);

        env.events().publish(
            (TREASURY_UPDATED, admin.clone()),
            TreasuryUpdatedEvent {
                old_treasury: old_treasury.into(),
                new_treasury: treasury,
                authorizer: admin,
            },
        );
    }

    pub fn withdraw_fees(env: Env, amount: i128) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);
        admin.require_auth();
        extend_instance_ttl(&env);
        // Native token transfer logic goes here
    }

    /// Deprecates a schema. Only creator or admin may call.
    /// Panics NotInitialized if not init, SchemaNotFound if uid unknown
    /// (no tombstone written). Repeated calls are idempotent.
    pub fn deprecate(env: Env, uid: UID, authorizer: Address) {
        extend_instance_ttl(&env);
        let admin = require_registry_admin(&env);

        if !env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaNotFound);
        }

        authorizer.require_auth();

        let creator: Option<Address> = env
            .storage()
            .persistent()
            .get(&(SCHEMA_CREATOR, uid.clone()));
        if authorizer != admin && creator.as_ref() != Some(&authorizer) {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let deprecated_key = (DEPRECATED, uid.clone());
        if env
            .storage()
            .persistent()
            .get::<_, bool>(&deprecated_key)
            .unwrap_or(false)
        {
            return;
        }
        env.storage().persistent().set(&deprecated_key, &true);
        env.storage().persistent().extend_ttl(
            &deprecated_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        env.events().publish(
            (SCHEMA_DEPRECATED, uid.clone()),
            SchemaDeprecatedEvent {
                schema_uid: uid,
                deprecated_by: authorizer,
            },
        );

        extend_instance_ttl(&env);
    }

    /// Authorizes `delegate` to issue and revoke attestations under schema `uid`.
    ///
    /// Requires authorization from the primary schema owner (creator).
    /// Emits `SchemaDelegateAdded`.
    pub fn add_delegate(env: Env, uid: UID, delegate: Address) {
        extend_instance_ttl(&env);
        if !env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaNotFound);
        }

        let creator_key = (SCHEMA_CREATOR, uid.clone());
        let creator: Option<Address> = env.storage().persistent().get(&creator_key);
        let Some(owner) = creator else {
            panic_with_error!(&env, SASError::SchemaNotFound);
        };

        owner.require_auth();

        let delegate_key = (AUTHORIZED_DELEGATES, uid.clone(), delegate.clone());
        env.storage().persistent().set(&delegate_key, &true);
        env.storage().persistent().extend_ttl(
            &delegate_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        env.events().publish(
            (SCHEMA_DELEGATE_ADDED, uid.clone()),
            SchemaDelegateAddedEvent {
                schema_uid: uid,
                delegate,
                authorizer: owner,
            },
        );

        extend_instance_ttl(&env);
    }

    /// Revokes `delegate`'s authorization to issue or revoke attestations under schema `uid`.
    ///
    /// Requires authorization from the primary schema owner (creator).
    /// Emits `SchemaDelegateRemoved`.
    pub fn remove_delegate(env: Env, uid: UID, delegate: Address) {
        extend_instance_ttl(&env);
        if !env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaNotFound);
        }

        let creator_key = (SCHEMA_CREATOR, uid.clone());
        let creator: Option<Address> = env.storage().persistent().get(&creator_key);
        let Some(owner) = creator else {
            panic_with_error!(&env, SASError::SchemaNotFound);
        };

        owner.require_auth();

        let delegate_key = (AUTHORIZED_DELEGATES, uid.clone(), delegate.clone());
        env.storage().persistent().remove(&delegate_key);

        env.events().publish(
            (SCHEMA_DELEGATE_REMOVED, uid.clone()),
            SchemaDelegateRemovedEvent {
                schema_uid: uid,
                delegate,
                authorizer: owner,
            },
        );

        extend_instance_ttl(&env);
    }

    /// Transfers ownership of schema `uid` to `new_owner` (#229).
    ///
    /// Requires authorization from the current schema owner (creator).
    /// Rejects non-existent schemas (`SASError::SchemaNotFound`) and deprecated
    /// schemas (`SASError::InvalidSchema`).
    /// Emits `SchemaOwnershipTransferred`.
    pub fn transfer_schema_ownership(env: Env, uid: UID, new_owner: Address) {
        extend_instance_ttl(&env);
        if !env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaNotFound);
        }

        if env
            .storage()
            .persistent()
            .get(&(DEPRECATED, uid.clone()))
            .unwrap_or(false)
        {
            panic_with_error!(&env, SASError::InvalidSchema);
        }

        // A schema owned by a multi-signature set can only change hands
        // through propose/approve, so a single owner cannot bypass it.
        reject_single_sig_transfer_for_multisig(&env, &uid);

        let creator_key = (SCHEMA_CREATOR, uid.clone());
        let creator: Option<Address> = env.storage().persistent().get(&creator_key);
        let Some(old_owner) = creator else {
            panic_with_error!(&env, SASError::SchemaNotFound);
        };

        old_owner.require_auth();

        env.storage().persistent().set(&creator_key, &new_owner);
        env.storage().persistent().extend_ttl(
            &creator_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );
        renew_schema_record(&env, &uid);

        env.events().publish(
            (SCHEMA_OWNERSHIP_TRANSFERRED, uid.clone()),
            SchemaOwnershipTransferredEvent {
                schema_uid: uid,
                old_owner,
                new_owner,
            },
        );

        extend_instance_ttl(&env);
    }

    /// Registers a new schema in the registry, free of charge.
    ///
    /// See `docs/schemas.md` for the schema syntax specification.

    pub fn transfer_ownership(env: Env, sender: Address, uid: UID, new_owner: Address) {
        sender.require_auth();
        extend_instance_ttl(&env);

        // Ensure schema exists
        let _record = Self::get_schema(env.clone(), uid.clone()).unwrap_or_else(|| {
            panic_with_error!(&env, SASError::SchemaNotFound);
        });

        // Multi-signature schemas must move ownership through
        // propose/approve so the threshold cannot be bypassed.
        reject_single_sig_transfer_for_multisig(&env, &uid);

        // Validate sender is current creator/owner
        let creator: Option<Address> = env
            .storage()
            .persistent()
            .get(&(SCHEMA_CREATOR, uid.clone()));
        let mut authorized = false;
        if let Some(ref c) = creator {
            if *c == sender {
                authorized = true;
            }
        }

        // Admins can also transfer ownership (optional, but robust)
        if !authorized {
            let admin: Option<Address> = env.storage().instance().get(&REGISTRY_ADMIN);
            if let Some(a) = admin {
                if a == sender {
                    authorized = true;
                }
            }
        }

        if !authorized {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        // Set new owner
        env.storage()
            .persistent()
            .set(&(SCHEMA_CREATOR, uid.clone()), &new_owner);
        env.events()
            .publish((SCHEMA_OWNERSHIP_TRANSFERRED, uid), (sender, new_owner));
    }

    /// Configures (or replaces) the multi-signature owner set for schema `uid` (#288).
    ///
    /// `authorizer` must be a current owner of the schema (the creator, a
    /// member of the existing owner set, or the registry admin) and must
    /// authorize the call. `owners` must be a non-empty list of at most
    /// `MAX_OWNER_SET` distinct addresses and `threshold` must be in
    /// `1..=owners.len()`.
    ///
    /// Reconfiguring the set bumps `OwnerSet::version` and drops any in-flight
    /// ownership transfer, because approvals are only meaningful against the
    /// owner set they were collected under.
    ///
    /// Emits `(SCHEMA_OWNER_SET_UPDATED, uid)` with `(authorizer, OwnerSet)`.
    pub fn configure_owner_set(
        env: Env,
        uid: UID,
        authorizer: Address,
        owners: Vec<Address>,
        threshold: u32,
    ) -> OwnerSet {
        extend_instance_ttl(&env);
        require_transferable_schema(&env, &uid);

        authorizer.require_auth();
        if !is_owner_address(&env, &uid, &authorizer) {
            panic_with_error!(&env, SASError::Unauthorized);
        }
        validate_owner_set(&env, &owners, threshold);

        let version = match owner_set(&env, &uid) {
            Some(existing) => existing.version.saturating_add(1),
            None => 1,
        };
        let set = OwnerSet {
            owners,
            threshold,
            version,
        };

        let set_key = (SCHEMA_OWNERS, uid.clone());
        env.storage().persistent().set(&set_key, &set);
        env.storage().persistent().extend_ttl(
            &set_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        // Approvals gathered under the previous set can no longer authorize
        // anything, so the transfer is abandoned rather than left to be
        // completed by addresses that may no longer be owners.
        env.storage()
            .persistent()
            .remove(&(PENDING_OWNERSHIP, uid.clone()));

        env.events().publish(
            (SCHEMA_OWNER_SET_UPDATED, uid.clone()),
            (authorizer, set.clone()),
        );

        extend_instance_ttl(&env);
        set
    }

    /// Returns the schema's multi-signature owner set, or `None` when the
    /// schema is still single-signature (creator-only).
    pub fn get_owner_set(env: Env, uid: UID) -> Option<OwnerSet> {
        extend_instance_ttl(&env);
        owner_set(&env, &uid)
    }

    /// True when `who` may act as an owner of schema `uid`: a member of the
    /// configured owner set, the creator, or the registry admin.
    pub fn is_schema_owner(env: Env, uid: UID, who: Address) -> bool {
        extend_instance_ttl(&env);
        if !env.storage().persistent().has(&uid) {
            return false;
        }
        is_owner_address(&env, &uid, &who)
    }

    /// Returns the pending multi-signature ownership transfer for `uid`, if any.
    pub fn get_pending_ownership_transfer(env: Env, uid: UID) -> Option<PendingOwnershipTransfer> {
        extend_instance_ttl(&env);
        env.storage()
            .persistent()
            .get(&(PENDING_OWNERSHIP, uid.clone()))
    }

    /// Proposes a multi-signature ownership transfer and casts the proposer's
    /// approval (#288).
    ///
    /// When the schema has no owner set (or a threshold of 1) the transfer
    /// executes immediately, which keeps the single-owner flow unchanged.
    /// Otherwise the proposal is stored until enough distinct owners approve
    /// it with `approve_ownership_transfer`.
    ///
    /// The creator cannot be replaced by itself (`InvalidValue`), and a
    /// multi-signature schema must go through this path — its single-signature
    /// entrypoints reject the transfer outright.
    pub fn propose_ownership_transfer(
        env: Env,
        uid: UID,
        proposer: Address,
        new_owner: Address,
    ) -> OwnershipTransferStatus {
        extend_instance_ttl(&env);
        require_transferable_schema(&env, &uid);

        proposer.require_auth();
        if !is_owner_address(&env, &uid, &proposer) {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let Some(current_owner) = schema_creator(&env, &uid) else {
            panic_with_error!(&env, SASError::SchemaNotFound);
        };
        if current_owner == new_owner {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        let (set, threshold) = effective_owner_set(&env, &uid);
        let version = set.map(|s| s.version).unwrap_or(0);

        let mut approvals: Vec<Address> = Vec::new(&env);
        approvals.push_back(proposer.clone());

        let pending = PendingOwnershipTransfer {
            owner_set_version: version,
            new_owner: new_owner.clone(),
            approvals,
            created_at: env.ledger().timestamp(),
        };

        if threshold <= 1 {
            finalize_ownership_transfer(&env, &uid, &current_owner, &new_owner);
            return OwnershipTransferStatus {
                new_owner,
                approvals: 1,
                threshold,
                executed: true,
            };
        }

        let pending_key = (PENDING_OWNERSHIP, uid.clone());
        env.storage().persistent().set(&pending_key, &pending);
        env.storage().persistent().extend_ttl(
            &pending_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        env.events().publish(
            (SCHEMA_OWNER_PROPOSED, uid.clone()),
            (proposer, pending.clone()),
        );

        extend_instance_ttl(&env);
        OwnershipTransferStatus {
            new_owner,
            approvals: 1,
            threshold,
            executed: false,
        }
    }

    /// Adds `approver`'s approval to the in-flight ownership transfer for `uid`.
    ///
    /// `approver` must be an owner and must not have approved already
    /// (`SchemaAlreadyExists`); each owner counts once. Once `threshold`
    /// distinct owners have approved, the transfer executes inside this call
    /// and `executed` is `true`.
    pub fn approve_ownership_transfer(
        env: Env,
        uid: UID,
        approver: Address,
    ) -> OwnershipTransferStatus {
        extend_instance_ttl(&env);
        require_transferable_schema(&env, &uid);

        approver.require_auth();

        let pending = record_approval(&env, &uid, &approver);
        let (_, threshold) = effective_owner_set(&env, &uid);
        let collected = pending.approvals.len();

        if collected < threshold {
            extend_instance_ttl(&env);
            return OwnershipTransferStatus {
                new_owner: pending.new_owner,
                approvals: collected,
                threshold,
                executed: false,
            };
        }

        let old_owner = schema_creator(&env, &uid).unwrap_or_else(|| {
            panic_with_error!(&env, SASError::SchemaNotFound);
        });
        finalize_ownership_transfer(&env, &uid, &old_owner, &pending.new_owner);

        OwnershipTransferStatus {
            new_owner: pending.new_owner,
            approvals: collected,
            threshold,
            executed: true,
        }
    }

    /// Abandons the in-flight ownership transfer for `uid`. Caller must be a
    /// current owner of the schema.
    ///
    /// Emits `(SCHEMA_OWNER_TRANSFER_CANCELLED, uid)` with the cancelling owner.
    pub fn cancel_ownership_transfer(env: Env, uid: UID, canceller: Address) {
        extend_instance_ttl(&env);
        require_transferable_schema(&env, &uid);

        canceller.require_auth();
        if !is_owner_address(&env, &uid, &canceller) {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        let pending_key = (PENDING_OWNERSHIP, uid.clone());
        if !env.storage().persistent().has(&pending_key) {
            panic_with_error!(&env, SASError::SchemaNotFound);
        }
        env.storage().persistent().remove(&pending_key);

        env.events()
            .publish((SCHEMA_OWNER_TRANSFER_CANCELLED, uid.clone()), canceller);

        extend_instance_ttl(&env);
    }

    pub fn deprecate_schema(env: Env, sender: Address, uid: UID) {
        sender.require_auth();
        extend_instance_ttl(&env);

        let mut record = Self::get_schema(env.clone(), uid.clone()).unwrap_or_else(|| {
            panic_with_error!(&env, SASError::SchemaNotFound);
        });

        // Deprecation is an owner action: the creator, any member of the
        // configured multi-signature owner set, or the registry admin may
        // perform it. Unlike ownership transfer it is not irreversible
        // ownership movement, so a single owner's signature is enough.
        if !is_owner_address(&env, &uid, &sender) {
            panic_with_error!(&env, SASError::Unauthorized);
        }

        record.deprecated = true;
        env.storage().persistent().set(&uid, &record);
        env.events().publish((SCHEMA_DEPRECATED, uid), sender);
    }

    pub fn register(
        env: Env,
        owner: Address,
        schema: String,
        resolver: Address,
        revocable: bool,
    ) -> UID {
        // The owner must authorize the registration so the emitted event
        // carries a caller identity that off-chain indexers can trust.
        owner.require_auth();
        Self::register_internal(env, owner, schema, resolver, revocable)
    }

    /// Registers a new schema, paying the configured registration fee (#1).
    ///
    /// Mirrors `SAS::attest_with_value`'s payment discipline: the fee asset
    /// and exact amount are pinned by `set_fee`, not supplied by the
    /// caller. `token`/`value` here are the caller's declaration of what
    /// they expect to pay — a mismatch against the live configuration
    /// fails with `SASError::FeeMismatch` before anything is registered or
    /// transferred, so a fee raised after the caller signed never silently
    /// overcharges them. With no fee configured, only `value == 0` is
    /// accepted. The transfer goes straight to the configured treasury
    /// (`SASError::TreasuryNotSet` if none is set) and happens before the
    /// schema is stored, so a failed payment aborts the whole invocation.
    pub fn register_with_value(
        env: Env,
        owner: Address,
        schema: String,
        resolver: Address,
        revocable: bool,
        token: Address,
        value: i128,
    ) -> UID {
        if value < 0 {
            panic_with_error!(&env, SASError::InvalidValue);
        }

        let configured: Option<(Address, i128)> = env.storage().instance().get(&SCHEMA_FEE);
        match &configured {
            Some((fee_token, fee_amount)) => {
                if &token != fee_token || value != *fee_amount {
                    panic_with_error!(&env, SASError::FeeMismatch);
                }
            }
            None => {
                if value != 0 {
                    panic_with_error!(&env, SASError::FeeMismatch);
                }
            }
        }

        // The owner must authorize both the registration and (when a fee
        // applies) the token transfer below.
        owner.require_auth();

        if value > 0 {
            let treasury: Address = env
                .storage()
                .instance()
                .get(&TREASURY)
                .unwrap_or_else(|| panic_with_error!(&env, SASError::TreasuryNotSet));
            token::Client::new(&env, &token).transfer(&owner, &treasury, &value);
        }

        Self::register_internal(env, owner, schema, resolver, revocable)
    }

    fn register_internal(
        env: Env,
        owner: Address,
        schema: String,
        resolver: Address,
        revocable: bool,
    ) -> UID {
        extend_instance_ttl(&env);
        if let Err(err) = validate_schema_syntax(&env, &schema) {
            panic_with_error!(&env, err);
        }

        // Canonical schema identity includes the schema string, resolver
        // address, and revocability flag. Including all policy-defining fields
        // in the UID preimage ensures two registrations with identical field
        // definitions but different resolver or revocability policies do not
        // collide. See specs/protocol-v1.md#schema-identity.
        let uid = soroban_sas_common::schema_uid(&env, &schema, &resolver, revocable);

        if env.storage().persistent().has(&uid) {
            panic_with_error!(&env, SASError::SchemaAlreadyExists);
        }

        let record = SchemaRecord {
            uid: uid.clone(),
            resolver,
            revocable,
            schema,
            deprecated: false,
        };
        env.storage().persistent().set(&uid, &record);
        env.storage()
            .persistent()
            .extend_ttl(&uid, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        let creator_key = (SCHEMA_CREATOR, uid.clone());
        env.storage().persistent().set(&creator_key, &owner);
        env.storage().persistent().extend_ttl(
            &creator_key,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        let mut count: u32 = if let Some(c) = env.storage().persistent().get(&SCHEMA_COUNT) {
            env.storage().persistent().extend_ttl(
                &SCHEMA_COUNT,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
            c
        } else if env.storage().persistent().has::<u32>(&0u32) {
            // Count is missing but a record exists at index 0 — metadata expired.
            panic_with_error!(&env, SASError::CountMetadataExpired);
        } else {
            0
        };
        env.storage().persistent().set(&count, &uid);
        env.storage()
            .persistent()
            .extend_ttl(&count, LEDGERS_IN_ONE_YEAR, LEDGERS_IN_ONE_YEAR);
        count += 1;
        env.storage().persistent().set(&SCHEMA_COUNT, &count);
        env.storage().persistent().extend_ttl(
            &SCHEMA_COUNT,
            LEDGERS_IN_ONE_YEAR,
            LEDGERS_IN_ONE_YEAR,
        );

        env.events().publish(
            (soroban_sas_common::events::REGISTERED, uid.clone()),
            soroban_sas_common::SchemaRegisteredEvent {
                schema_uid: uid.clone(),
                owner,
            },
        );

        extend_instance_ttl(&env);

        uid
    }

    /// Returns the active [`SchemaRecord`] for `uid`, renewing its TTL when it
    /// exists. An unknown or deprecated UID returns `None` and creates no
    /// storage.
    pub fn get_schema(env: Env, uid: UID) -> Option<SchemaRecord> {
        extend_instance_ttl(&env);
        if env
            .storage()
            .persistent()
            .get(&(DEPRECATED, uid.clone()))
            .unwrap_or(false)
        {
            return None;
        }
        let record: Option<SchemaRecord> = env.storage().persistent().get(&uid);
        if record.is_some() {
            renew_schema_record(&env, &uid);
        }
        record
    }

    /// Returns the active [`SchemaRecord`] for a raw schema definition,
    /// deriving the content-addressed UID with exactly the same canonical
    /// derivation [`register`](Self::register) uses.
    ///
    /// Off-chain callers that cannot reproduce the host's XDR hashing rules
    /// would otherwise have to hand-roll `schema_uid`, and a byte-encoding
    /// mismatch makes a registered schema look missing — which leads callers
    /// into duplicate registrations that revert. Passing the definition they
    /// already hold removes that failure mode.
    ///
    /// A malformed `schema` string panics with [`SASError::InvalidSchema`], the
    /// same error `register` raises, so a caller is told the definition is
    /// invalid rather than receiving a misleading `None`. Unknown or deprecated
    /// content returns `None`, matching [`get_schema`](Self::get_schema).
    pub fn get_schema_by_content(
        env: Env,
        schema: String,
        resolver: Address,
        revocable: bool,
    ) -> Option<SchemaRecord> {
        if let Err(err) = validate_schema_syntax(&env, &schema) {
            panic_with_error!(&env, err);
        }
        let uid = soroban_sas_common::schema_uid(&env, &schema, &resolver, revocable);
        Self::get_schema(env, uid)
    }

    /// Reports whether `uid` names an active (non-deprecated) schema. SAS
    /// calls this view during issuance, so a successful check renews the
    /// record's TTL to keep an actively used schema hot. A missing or
    /// deprecated UID returns `false` without creating or extending an entry.
    pub fn validate_schema(env: Env, uid: UID) -> bool {
        extend_instance_ttl(&env);
        if env
            .storage()
            .persistent()
            .get(&(DEPRECATED, uid.clone()))
            .unwrap_or(false)
        {
            return false;
        }
        if env.storage().persistent().has(&uid) {
            renew_schema_record(&env, &uid);
            true
        } else {
            false
        }
    }

    /// Returns true if `delegate` is currently an authorized delegate for `uid`.
    pub fn is_delegate(env: Env, uid: UID, delegate: Address) -> bool {
        extend_instance_ttl(&env);
        let delegate_key = (AUTHORIZED_DELEGATES, uid, delegate);
        if env
            .storage()
            .persistent()
            .get::<_, bool>(&delegate_key)
            .unwrap_or(false)
        {
            env.storage().persistent().extend_ttl(
                &delegate_key,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
            true
        } else {
            false
        }
    }

    /// Returns the creator/owner address recorded when schema `uid` was registered.
    pub fn get_creator(env: Env, uid: UID) -> Option<Address> {
        extend_instance_ttl(&env);
        let creator_key = (SCHEMA_CREATOR, uid.clone());
        let creator: Option<Address> = env.storage().persistent().get(&creator_key);
        if creator.is_some() {
            env.storage().persistent().extend_ttl(
                &creator_key,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
        }
        creator
    }

    /// Checks whether `attester` is authorized to issue attestations under
    /// `uid` — returns true if `attester` is either the primary schema owner
    /// or an authorized delegate, provided the schema exists and is not
    /// deprecated.
    ///
    /// Single cross-contract call for SAS issuance checks to prevent excessive
    /// gas usage.
    pub fn is_authorized(env: Env, uid: UID, attester: Address) -> bool {
        extend_instance_ttl(&env);
        if env
            .storage()
            .persistent()
            .get(&(DEPRECATED, uid.clone()))
            .unwrap_or(false)
        {
            return false;
        }

        let creator_key = (SCHEMA_CREATOR, uid.clone());
        if let Some(creator) = env.storage().persistent().get::<_, Address>(&creator_key) {
            if creator == attester {
                env.storage().persistent().extend_ttl(
                    &creator_key,
                    LEDGERS_IN_ONE_YEAR,
                    LEDGERS_IN_ONE_YEAR,
                );
                return true;
            }
        } else {
            return false;
        }

        let delegate_key = (AUTHORIZED_DELEGATES, uid.clone(), attester);
        if env
            .storage()
            .persistent()
            .get::<_, bool>(&delegate_key)
            .unwrap_or(false)
        {
            env.storage().persistent().extend_ttl(
                &delegate_key,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
            return true;
        }

        false
    }

    /// Returns up to `limit` active schemas from `start`, skipping deprecated.
    /// Scans until page full, budget (100) or end. Use paginated for cursor.
    pub fn get_schemas(env: Env, start: u32, limit: u32) -> soroban_sdk::Vec<SchemaRecord> {
        extend_instance_ttl(&env);
        if limit == 0 {
            return soroban_sdk::Vec::new(&env);
        }
        let count: u32 = env.storage().persistent().get(&SCHEMA_COUNT).unwrap_or(0);
        if count > 0 {
            env.storage().persistent().extend_ttl(
                &SCHEMA_COUNT,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
        }
        if start >= count {
            return soroban_sdk::Vec::new(&env);
        }
        let mut schemas = soroban_sdk::Vec::new(&env);
        let mut index = start;
        let mut scanned: u32 = 0;
        while index < count && schemas.len() < limit && scanned < MAX_SCAN_BUDGET {
            if let Some(uid) = env.storage().persistent().get::<u32, UID>(&index) {
                env.storage().persistent().extend_ttl(
                    &index,
                    LEDGERS_IN_ONE_YEAR,
                    LEDGERS_IN_ONE_YEAR,
                );
                let is_deprecated: bool = env
                    .storage()
                    .persistent()
                    .get(&(DEPRECATED, uid.clone()))
                    .unwrap_or(false);
                if !is_deprecated {
                    if let Some(record) = env.storage().persistent().get::<UID, SchemaRecord>(&uid)
                    {
                        env.storage().persistent().extend_ttl(
                            &uid,
                            LEDGERS_IN_ONE_YEAR,
                            LEDGERS_IN_ONE_YEAR,
                        );
                        schemas.push_back(record);
                    }
                }
            }
            index = index.saturating_add(1);
            scanned = scanned.saturating_add(1);
        }
        schemas
    }

    /// Paginated: returns (schemas, next_cursor). Same semantics as get_schemas.
    pub fn get_schemas_paginated(
        env: Env,
        start: u32,
        limit: u32,
    ) -> (soroban_sdk::Vec<SchemaRecord>, u32) {
        extend_instance_ttl(&env);
        let count: u32 = env.storage().persistent().get(&SCHEMA_COUNT).unwrap_or(0);
        if count > 0 {
            env.storage().persistent().extend_ttl(
                &SCHEMA_COUNT,
                LEDGERS_IN_ONE_YEAR,
                LEDGERS_IN_ONE_YEAR,
            );
        }
        if limit == 0 || start >= count {
            return (
                soroban_sdk::Vec::new(&env),
                if start >= count { count } else { start },
            );
        }
        let mut schemas = soroban_sdk::Vec::new(&env);
        let mut index = start;
        let mut scanned: u32 = 0;
        while index < count && schemas.len() < limit && scanned < MAX_SCAN_BUDGET {
            if let Some(uid) = env.storage().persistent().get::<u32, UID>(&index) {
                env.storage().persistent().extend_ttl(
                    &index,
                    LEDGERS_IN_ONE_YEAR,
                    LEDGERS_IN_ONE_YEAR,
                );
                let is_deprecated: bool = env
                    .storage()
                    .persistent()
                    .get(&(DEPRECATED, uid.clone()))
                    .unwrap_or(false);
                if !is_deprecated {
                    if let Some(record) = env.storage().persistent().get::<UID, SchemaRecord>(&uid)
                    {
                        env.storage().persistent().extend_ttl(
                            &uid,
                            LEDGERS_IN_ONE_YEAR,
                            LEDGERS_IN_ONE_YEAR,
                        );
                        schemas.push_back(record);
                    }
                }
            }
            index = index.saturating_add(1);
            scanned = scanned.saturating_add(1);
        }
        (schemas, index)
    }
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_extra;
#[cfg(test)]
mod owner_multisig_test;
