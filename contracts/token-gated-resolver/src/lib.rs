#![no_std]

use soroban_sas_common::Attestation;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, token,
    Address, Env, Symbol,
};

/// Error codes returned by the TokenGatedResolver.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ResolverError {
    /// The resolver has already been initialized.
    AlreadyInitialized = 1,
    /// The resolver has not been initialized.
    NotInitialized = 2,
    /// The caller is not authorized to perform the operation.
    Unauthorized = 3,
    /// The recipient's token balance is below the configured minimum.
    ResolverRejected = 4,
    /// The configured token contract is invalid or unreachable.
    InvalidToken = 5,
    /// The configured minimum balance is invalid.
    InvalidThreshold = 6,
    /// The fee configuration is invalid.
    InvalidFee = 7,
    /// The attester does not hold enough tokens to pay the fee.
    InsufficientFee = 8,
}

/// How the configured fee should be handled on attestation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeeDisposal {
    /// No fee is charged.
    None,
    /// Transfer the fee from the attester to the resolver admin.
    Transfer,
    /// Burn the fee from the attester.
    Burn,
}

/// Persistent configuration for the resolver.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    /// Admin authorized to update configuration.
    pub admin: Address,
    /// SAC token contract used for gating.
    pub token: Address,
    /// Minimum token balance required of the recipient.
    pub min_balance: i128,
    /// Fee amount charged on attestation.
    pub fee_amount: i128,
    /// How the fee is disposed of.
    pub fee_disposal: FeeDisposal,
}

const CONFIG_KEY: Symbol = symbol_short!("CONFIG");

#[contract]
pub struct TokenGatedResolver;

#[contractimpl]
impl TokenGatedResolver {
    /// Initialize the resolver with its admin and token gating configuration.
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        min_balance: i128,
        fee_amount: i128,
        fee_disposal: FeeDisposal,
    ) {
        if env.storage().persistent().has(&CONFIG_KEY) {
            panic_with_error!(&env, ResolverError::AlreadyInitialized);
        }
        if min_balance < 0 {
            panic_with_error!(&env, ResolverError::InvalidThreshold);
        }
        if fee_amount < 0 {
            panic_with_error!(&env, ResolverError::InvalidFee);
        }
        if fee_amount > 0 && fee_disposal == FeeDisposal::None {
            panic_with_error!(&env, ResolverError::InvalidFee);
        }

        let config = Config {
            admin,
            token,
            min_balance,
            fee_amount,
            fee_disposal,
        };
        env.storage().persistent().set(&CONFIG_KEY, &config);
    }

    /// Return the current configuration.
    pub fn config(env: Env) -> Config {
        load_config(&env)
    }

    /// Update the admin. Only callable by the current admin.
    pub fn set_admin(env: Env, new_admin: Address) {
        let mut config = load_config(&env);
        config.admin.require_auth();
        config.admin = new_admin;
        env.storage().persistent().set(&CONFIG_KEY, &config);
    }

    /// Update the minimum required balance. Only callable by the admin.
    pub fn set_min_balance(env: Env, min_balance: i128) {
        let mut config = load_config(&env);
        config.admin.require_auth();
        if min_balance < 0 {
            panic_with_error!(&env, ResolverError::InvalidThreshold);
        }
        config.min_balance = min_balance;
        env.storage().persistent().set(&CONFIG_KEY, &config);
    }

    /// Update the token contract. Only callable by the admin.
    pub fn set_token(env: Env, token: Address) {
        let mut config = load_config(&env);
        config.admin.require_auth();
        config.token = token;
        env.storage().persistent().set(&CONFIG_KEY, &config);
    }

    /// Update the fee configuration. Only callable by the admin.
    pub fn set_fee(env: Env, fee_amount: i128, fee_disposal: FeeDisposal) {
        let mut config = load_config(&env);
        config.admin.require_auth();
        if fee_amount < 0 {
            panic_with_error!(&env, ResolverError::InvalidFee);
        }
        if fee_amount > 0 && fee_disposal == FeeDisposal::None {
            panic_with_error!(&env, ResolverError::InvalidFee);
        }
        config.fee_amount = fee_amount;
        config.fee_disposal = fee_disposal;
        env.storage().persistent().set(&CONFIG_KEY, &config);
    }

    /// Return the current balance of `account` in the configured token.
    pub fn balance_of(env: Env, account: Address) -> i128 {
        let config = load_config(&env);
        token::Client::new(&env, &config.token).balance(&account)
    }

    /// Return whether `account` is eligible for attestation.
    pub fn is_eligible(env: Env, account: Address) -> bool {
        let config = load_config(&env);
        let balance = token::Client::new(&env, &config.token).balance(&account);
        balance >= config.min_balance
    }

    /// Resolver hook invoked by the SAS contract on attestation.
    ///
    /// The recipient must hold at least `min_balance` of the configured token.
    /// If a fee is configured, it is charged from the attester.
    pub fn on_attest(env: Env, attestation: Attestation) {
        let config = load_config(&env);

        let token_client = token::Client::new(&env, &config.token);
        let recipient_balance = token_client.balance(&attestation.recipient);
        if recipient_balance < config.min_balance {
            panic_with_error!(&env, ResolverError::ResolverRejected);
        }

        if config.fee_amount > 0 {
            attestation.attester.require_auth();
            match config.fee_disposal {
                FeeDisposal::None => {}
                FeeDisposal::Transfer => {
                    let attester_balance = token_client.balance(&attestation.attester);
                    if attester_balance < config.fee_amount {
                        panic_with_error!(&env, ResolverError::InsufficientFee);
                    }
                    token_client.transfer(&attestation.attester, &config.admin, &config.fee_amount);
                }
                FeeDisposal::Burn => {
                    let attester_balance = token_client.balance(&attestation.attester);
                    if attester_balance < config.fee_amount {
                        panic_with_error!(&env, ResolverError::InsufficientFee);
                    }
                    token_client.burn(&attestation.attester, &config.fee_amount);
                }
            }
        }
    }

    /// Resolver hook invoked by the SAS contract on revocation.
    pub fn on_revoke(_env: Env, _attestation: Attestation) {
        // No-op for token-gated attestation revocation.
    }
}

fn load_config(env: &Env) -> Config {
    env.storage()
        .persistent()
        .get(&CONFIG_KEY)
        .unwrap_or_else(|| panic_with_error!(env, ResolverError::NotInitialized))
}

#[cfg(test)]
mod test;
