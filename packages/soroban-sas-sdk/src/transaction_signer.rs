//! External transaction signing for hardware wallets and remote signers.
use crate::errors::SdkError;
use soroban_sdk::xdr::Transaction;

/// Return a signature over the unchanged, already-simulated transaction.
pub trait TransactionSigner: Send + Sync {
    fn public_key(&self) -> Result<[u8; 32], SdkError>;
    fn sign_transaction(
        &self,
        network_passphrase: &str,
        transaction: Transaction,
    ) -> Result<String, SdkError>;
}
