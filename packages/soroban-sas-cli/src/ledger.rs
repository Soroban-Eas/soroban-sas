//! Ledger signing using the official Stellar CLI hardware-wallet USB/APDU
//! transport. This module never accepts or stores private keys.

use soroban_sas_sdk::errors::SdkError;
use soroban_sas_sdk::transaction_signer::TransactionSigner;
use soroban_sdk::xdr::{Limits, MuxedAccount, ReadXdr, TransactionEnvelope};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn account_from_bip44(path: &str) -> Result<u32, String> {
    let account = if let Some(suffix) = path.strip_prefix("m/44'/148'/") {
        suffix
            .strip_suffix('\'')
            .ok_or_else(|| "BIP-44 account component must be hardened".to_owned())?
    } else if path.chars().all(|c| c.is_ascii_digit()) && !path.is_empty() {
        path
    } else {
        return Err("expected m/44'/148'/N' or account index N".into());
    };
    let account: u32 = account
        .parse()
        .map_err(|_| "invalid BIP-44 account index".to_owned())?;
    if account >= (1u32 << 31) {
        return Err("BIP-44 account index must be less than 2^31".into());
    }
    Ok(account)
}

fn stellar_cli(args: &[&str], input: Option<&str>) -> Result<String, String> {
    let mut command = Command::new("stellar");
    command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|err| {
        format!("cannot start Stellar CLI: {err}. Install the official Stellar CLI and ensure stellar is on PATH")
    })?;
    if let Some(input) = input {
        let Some(mut stdin) = child.stdin.take() else {
            return Err("could not open Stellar CLI stdin".into());
        };
        stdin
            .write_all(input.as_bytes())
            .map_err(|err| format!("send transaction to Stellar CLI: {err}"))?;
    }
    let result = child
        .wait_with_output()
        .map_err(|err| format!("Stellar CLI signing failed: {err}"))?;
    if !result.status.success() {
        let detail = String::from_utf8_lossy(&result.stderr);
        let message = detail.trim();
        return Err(format!(
            "Ledger signing cancelled or failed (device disconnected, Stellar app not open, or request rejected). {}",
            if message.is_empty() { "Unlock the device, open the Stellar app, and approve on-device." } else { message }
        ));
    }
    String::from_utf8(result.stdout)
        .map(|value| value.trim().to_string())
        .map_err(|_| "Stellar CLI returned non-UTF-8 output".to_owned())
}

pub fn read_public_key(account: u32) -> Result<[u8; 32], String> {
    let path = account.to_string();
    let output = stellar_cli(
        &["keys", "public-key", "--ledger", "--hd-path", &path],
        None,
    )?;
    let key = stellar_strkey::ed25519::PublicKey::from_string(output.trim())
        .map_err(|err| format!("Ledger returned an invalid public key: {err:?}"))?;
    Ok(key.0)
}

/// Hardware signer shared by every SAS SDK write method.
pub struct LedgerSigner {
    account: u32,
    key: [u8; 32],
}

impl LedgerSigner {
    pub fn connect(account: u32) -> Result<Self, String> {
        Ok(Self {
            account,
            key: read_public_key(account)?,
        })
    }
}

impl TransactionSigner for LedgerSigner {
    fn public_key(&self) -> Result<[u8; 32], SdkError> {
        Ok(self.key)
    }

    fn sign_transaction(
        &self,
        network_passphrase: &str,
        transaction: soroban_sdk::xdr::Transaction,
    ) -> Result<String, SdkError> {
        let unsigned = soroban_sas_sdk::simulate::unsigned_envelope_xdr(transaction)?;
        let path = format!("m/44'/148'/{}'", self.account);
        let (signed, _) =
            sign_xdr(&unsigned, network_passphrase, &path).map_err(SdkError::TransportError)?;
        Ok(signed)
    }
}

/// Sign an already-simulated unsigned transaction envelope with a Ledger.
/// The caller must verify the intended operations, fee, and network first.
pub fn sign_xdr(
    unsigned_xdr: &str,
    network_passphrase: &str,
    bip44_path: &str,
) -> Result<(String, String), String> {
    let account = account_from_bip44(bip44_path)?;
    let original = TransactionEnvelope::from_xdr_base64(unsigned_xdr.trim(), Limits::none())
        .map_err(|err| format!("invalid unsigned transaction XDR: {err:?}"))?;
    let TransactionEnvelope::Tx(original_tx) = original else {
        return Err("Ledger signer requires a V1 transaction envelope".into());
    };
    let key = read_public_key(account)?;
    let source = match &original_tx.tx.source_account {
        MuxedAccount::Ed25519(ref id) => id.0,
        _ => return Err("Ledger signer only supports ordinary G... source accounts".into()),
    };
    if source != key {
        return Err("Ledger account does not match the transaction's source account".into());
    }
    eprintln!(
        "Ledger approval required: source {}, fee {} stroops, sequence {:?}, {} operation(s).",
        stellar_strkey::ed25519::PublicKey(key),
        original_tx.tx.fee,
        original_tx.tx.seq_num,
        original_tx.tx.operations.len()
    );
    eprintln!("Open Stellar app on Ledger; review and approve or reject the transaction.");
    let account_string = account.to_string();
    let signed_xdr = stellar_cli(
        &[
            "tx",
            "sign",
            "--sign-with-ledger",
            "--hd-path",
            &account_string,
            "--network-passphrase",
            network_passphrase,
        ],
        Some(unsigned_xdr.trim()),
    )?;
    let signed = TransactionEnvelope::from_xdr_base64(&signed_xdr, Limits::none())
        .map_err(|err| format!("Stellar CLI produced invalid signed XDR: {err:?}"))?;
    let TransactionEnvelope::Tx(signed_tx) = signed else {
        return Err("device returned an unexpected envelope version".into());
    };
    if signed_tx.tx != original_tx.tx {
        return Err("device signer modified transaction contents".into());
    }
    if signed_tx.signatures.len() <= original_tx.signatures.len() {
        return Err("Ledger did not append a transaction signature".into());
    }
    let matching_hint = signed_tx
        .signatures
        .iter()
        .any(|signature| signature.hint.0.as_slice() == &key[28..]);
    if !matching_hint {
        return Err("Ledger response did not contain a signature from the selected account".into());
    }
    let hash = stellar_cli(
        &["tx", "hash", "--network-passphrase", network_passphrase],
        Some(&signed_xdr),
    )?;
    if hash.is_empty() {
        return Err("Stellar CLI returned no transaction hash".into());
    }
    let digest = hex::decode(&hash)
        .map_err(|_| "Stellar CLI transaction hash was not hexadecimal".to_string())?;
    if digest.len() != 32 {
        return Err("Stellar CLI returned a transaction hash of invalid length".into());
    }
    let public = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|err| format!("Ledger returned an invalid verification key: {err}"))?;
    let verified = signed_tx
        .signatures
        .iter()
        .filter(|signature| signature.hint.0.as_slice() == &key[28..])
        .any(|signature| {
            ed25519_dalek::Signature::from_slice(signature.signature.0.as_slice())
                .map(|signature| public.verify_strict(&digest, &signature).is_ok())
                .unwrap_or(false)
        });
    if !verified {
        return Err(
            "Ledger returned a signature that does not verify against the transaction hash".into(),
        );
    }
    Ok((signed_xdr, hash))
}

pub fn save_signed_xdr(path: &Path, signed: &str) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| format!("create {}: {err}", path.display()))?;
    file.write_all(signed.as_bytes())
        .map_err(|err| format!("write {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_stellar_bip44_paths() {
        assert_eq!(account_from_bip44("m/44'/148'/0'"), Ok(0));
        assert_eq!(account_from_bip44("m/44'/148'/42'"), Ok(42));
        assert_eq!(account_from_bip44("7"), Ok(7));
        for path in [
            "",
            "m/44'/60'/0'",
            "m/44'/148'/0",
            "m/44'/148'/-1'",
            "2147483648",
            "../0",
        ] {
            assert!(
                account_from_bip44(path).is_err(),
                "{path} should be rejected"
            );
        }
    }

    #[test]
    fn input_must_be_valid_xdr_before_any_device_invocation() {
        let err =
            sign_xdr("not-an-envelope", "Test SDF Network ; September 2015", "0").unwrap_err();
        assert!(err.contains("invalid unsigned transaction XDR"));
    }
    #[test]
    fn verifies_only_signatures_from_the_selected_ledger_account() {
        use ed25519_dalek::Signer as _;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let other = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let digest = [3u8; 32];
        let sig = sk.sign(&digest);
        assert!(sk.verifying_key().verify_strict(&digest, &sig).is_ok());
        assert!(other.verifying_key().verify_strict(&digest, &sig).is_err());
        assert!(sk.verifying_key().verify_strict(&[4; 32], &sig).is_err());
    }
}
