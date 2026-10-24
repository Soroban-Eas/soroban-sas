//! Configuration profiles for the `sas` CLI (issue #474).
//!
//! Stores named environment profiles in `~/.sas/config.toml` (e.g. `testnet`,
//! `mainnet`, `local`), with automatic resolution of RPC URLs, network passphrases,
//! and contract IDs. The active profile can be switched via `sas config use <profile>`
//! or overridden per invocation with `--profile <name>`.
//!
//! The configuration file is created and updated with user-only permissions (0600 on Unix).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

pub const DEFAULT_ACTIVE_PROFILE: &str = "testnet";

pub const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
pub const TESTNET_CONTRACT_ID: &str = "CCJJJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub const MAINNET_RPC_URL: &str = "https://mainnet.sorobanrpc.com";
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
pub const MAINNET_CONTRACT_ID: &str = "CBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

pub const LOCAL_RPC_URL: &str = "http://localhost:8000/soroban/rpc";
pub const LOCAL_PASSPHRASE: &str = "Standalone Network ; February 2017";
pub const LOCAL_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static ACTIVE_PROFILE_OVERRIDE: RwLock<Option<String>> = RwLock::new(None);

pub fn set_active_profile_override(name: &str) {
    if let Ok(mut lock) = ACTIVE_PROFILE_OVERRIDE.write() {
        *lock = Some(name.to_string());
    }
}

pub fn get_active_profile_override() -> Option<String> {
    if let Ok(lock) = ACTIVE_PROFILE_OVERRIDE.read() {
        lock.clone()
    } else {
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub rpc_url: String,
    pub network_passphrase: String,
    pub contract_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_contract_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "default_active")]
    pub active_profile: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

fn default_active() -> String {
    DEFAULT_ACTIVE_PROFILE.to_string()
}

impl Default for Config {
    fn default() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "testnet".to_string(),
            Profile {
                rpc_url: TESTNET_RPC_URL.to_string(),
                network_passphrase: TESTNET_PASSPHRASE.to_string(),
                contract_id: TESTNET_CONTRACT_ID.to_string(),
                secondary_contract_id: None,
            },
        );
        profiles.insert(
            "mainnet".to_string(),
            Profile {
                rpc_url: MAINNET_RPC_URL.to_string(),
                network_passphrase: MAINNET_PASSPHRASE.to_string(),
                contract_id: MAINNET_CONTRACT_ID.to_string(),
                secondary_contract_id: None,
            },
        );
        profiles.insert(
            "local".to_string(),
            Profile {
                rpc_url: LOCAL_RPC_URL.to_string(),
                network_passphrase: LOCAL_PASSPHRASE.to_string(),
                contract_id: LOCAL_CONTRACT_ID.to_string(),
                secondary_contract_id: None,
            },
        );
        Self {
            active_profile: default_active(),
            profiles,
        }
    }
}

pub fn config_path() -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("SAS_CONFIG_PATH") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(dir) = std::env::var("SAS_CONFIG_DIR") {
        return Ok(PathBuf::from(dir).join("config.toml"));
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            "cannot determine home directory; set SAS_CONFIG_PATH or HOME explicitly".to_string()
        })?;
    Ok(PathBuf::from(home).join(".sas").join("config.toml"))
}

pub fn load_existing_config() -> Result<Option<Config>, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read config at {}: {e}", path.display()))?;
    toml::from_str(&content)
        .map(Some)
        .map_err(|e| format!("failed to parse config at {}: {e}", path.display()))
}

pub fn load_config() -> Result<Config, String> {
    match load_existing_config()? {
        Some(cfg) => Ok(cfg),
        None => Ok(Config::default()),
    }
}

pub fn save_config(config: &Config) -> Result<PathBuf, String> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create config directory {}: {e}",
                parent.display()
            )
        })?;
    }
    let content =
        toml::to_string_pretty(config).map_err(|e| format!("failed to serialize config: {e}"))?;
    fs::write(&path, content)
        .map_err(|e| format!("failed to write config at {}: {e}", path.display()))?;
    set_restricted_permissions(&path)?;
    Ok(path)
}

#[cfg(unix)]
pub fn set_restricted_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to set permissions on {}: {e}", path.display()))
}

#[cfg(not(unix))]
pub fn set_restricted_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

impl Config {
    pub fn resolve(&self, profile_override: Option<&str>) -> Result<(String, Profile), String> {
        let name = profile_override.unwrap_or(&self.active_profile);
        if let Some(profile) = self.profiles.get(name) {
            Ok((name.to_string(), profile.clone()))
        } else {
            let mut available: Vec<_> = self.profiles.keys().cloned().collect();
            available.sort();
            Err(format!(
                "unknown profile '{name}'; available profiles: {}",
                available.join(", ")
            ))
        }
    }
}

#[allow(dead_code)]
pub fn resolve_contract_id(explicit: Option<String>) -> Result<String, String> {
    if let Some(id) = explicit {
        return Ok(id);
    }
    if let Ok(cfg) = load_config() {
        let override_name = get_active_profile_override();
        if let Ok((_, p)) = cfg.resolve(override_name.as_deref()) {
            if !p.contract_id.is_empty() {
                return Ok(p.contract_id);
            }
        }
    }
    Err(
        "missing --contract-id: pass it directly, set SAS_CONTRACT_ID, or configure a profile"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_has_all_profiles() {
        let config = Config::default();
        assert_eq!(config.active_profile, "testnet");
        assert!(config.profiles.contains_key("testnet"));
        assert!(config.profiles.contains_key("mainnet"));
        assert!(config.profiles.contains_key("local"));

        let (name, testnet) = config.resolve(None).unwrap();
        assert_eq!(name, "testnet");
        assert_eq!(testnet.rpc_url, TESTNET_RPC_URL);
        assert_eq!(testnet.network_passphrase, TESTNET_PASSPHRASE);
        assert_eq!(testnet.contract_id, TESTNET_CONTRACT_ID);
    }

    #[test]
    fn test_resolve_override() {
        let config = Config::default();
        let (name, mainnet) = config.resolve(Some("mainnet")).unwrap();
        assert_eq!(name, "mainnet");
        assert_eq!(mainnet.rpc_url, MAINNET_RPC_URL);
        assert_eq!(mainnet.network_passphrase, MAINNET_PASSPHRASE);

        let err = config.resolve(Some("nonexistent")).unwrap_err();
        assert!(err.contains("unknown profile 'nonexistent'"));
    }

    #[test]
    fn test_save_and_load_config() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "sas_test_config_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let config_file = tmp_dir.join("config.toml");
        std::env::set_var("SAS_CONFIG_PATH", &config_file);

        let config = Config {
            active_profile: "mainnet".to_string(),
            ..Default::default()
        };
        save_config(&config).unwrap();

        assert!(config_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&config_file).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "config file must have 0600 permissions");
        }

        let loaded = load_config().unwrap();
        assert_eq!(loaded.active_profile, "mainnet");

        std::env::remove_var("SAS_CONFIG_PATH");
        let _ = fs::remove_dir_all(tmp_dir);
    }
}
