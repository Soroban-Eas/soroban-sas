//! Hardware-wallet signing surface for the CLI (issue #328).
//!
//! `--hardware-wallet` selects a Ledger or Trezor account in place of
//! `--secret-key`. This build does not speak the device USB protocol. When a
//! signing command is asked to use a hardware wallet it fails closed and
//! never substitutes a software key.

use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum HardwareWalletKind {
    /// Ledger device running the Stellar app.
    Ledger,
    /// Trezor device running the Stellar app.
    Trezor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardwareWallet {
    pub kind: HardwareWalletKind,
    pub account: u32,
}

impl HardwareWallet {
    pub fn kind_name(self) -> &'static str {
        match self.kind {
            HardwareWalletKind::Ledger => "Ledger",
            HardwareWalletKind::Trezor => "Trezor",
        }
    }

    fn device_env(self) -> &'static str {
        match self.kind {
            HardwareWalletKind::Ledger => "SAS_LEDGER_DEVICE",
            HardwareWalletKind::Trezor => "SAS_TREZOR_DEVICE",
        }
    }

    /// Message returned when a signing command must use this wallet.
    pub fn signing_error(self) -> String {
        let name = self.kind_name();
        let env_key = self.device_env();
        match std::env::var(env_key) {
            Ok(path) if Path::new(&path).exists() => format!(
                "{name} device path {path} is present (account index {}), but this CLI \
                 build cannot submit a Stellar signature request to the device. Unlock the \
                 {name}, open the Stellar app, and retry. The CLI will not fall back to \
                 --secret-key.",
                self.account
            ),
            Ok(path) => format!(
                "{name} device path {path} from {env_key} was not found (account index {}). \
                 Connect the device, set {env_key} to its path, unlock it, and open the \
                 Stellar app. The CLI will not fall back to --secret-key.",
                self.account
            ),
            Err(_) => format!(
                "hardware-wallet signing requested for {name} account index {account}, but no \
                 device path is configured. Connect the {name}, export its path as {env_key}, \
                 unlock it, and open the Stellar app. The CLI will not fall back to \
                 --secret-key.",
                account = self.account
            ),
        }
    }
}
