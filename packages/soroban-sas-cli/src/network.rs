//! Named-network resolution for the global `--network` option (issue #174).
//!
//! Wires `--network <name>` to a concrete RPC URL and network passphrase so
//! the flag actually changes command behavior instead of being accepted and
//! silently ignored. Precedence, applied uniformly by every subcommand via
//! [`crate::resolve_rpc_url`] / [`crate::resolve_network_passphrase`]:
//!
//! 1. An explicit subcommand flag (`--rpc-url`, `--network-passphrase`).
//! 2. The matching environment variable (`SOROBAN_RPC_URL`,
//!    `SOROBAN_NETWORK_PASSPHRASE`) — clap fills the subcommand flag from
//!    these automatically when the flag itself is absent.
//! 3. The global `--network <name>` shorthand, resolved by this module.
//! 4. Otherwise: a clear error naming what's missing.

/// Resolved connection details for a named network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConfig {
    pub rpc_url: String,
    pub network_passphrase: String,
}

/// Resolves a `--network` shorthand to its RPC URL and passphrase.
///
/// Recognized names: `testnet`, `futurenet`, `mainnet` (alias `pubnet`), and
/// `local` (alias `standalone`, for `stellar-core`/`soroban-rpc` run via the
/// quickstart image). Matching is case-insensitive.
pub fn resolve_network(name: &str) -> Result<NetworkConfig, String> {
    let config = match name.to_ascii_lowercase().as_str() {
        "testnet" => NetworkConfig {
            rpc_url: "https://soroban-testnet.stellar.org".to_string(),
            network_passphrase: "Test SDF Network ; September 2015".to_string(),
        },
        "futurenet" => NetworkConfig {
            rpc_url: "https://rpc-futurenet.stellar.org".to_string(),
            network_passphrase: "Test SDF Future Network ; October 2022".to_string(),
        },
        "mainnet" | "pubnet" => NetworkConfig {
            rpc_url: "https://mainnet.sorobanrpc.com".to_string(),
            network_passphrase: "Public Global Stellar Network ; September 2015".to_string(),
        },
        "local" | "standalone" => NetworkConfig {
            rpc_url: "http://localhost:8000/soroban/rpc".to_string(),
            network_passphrase: "Standalone Network ; February 2017".to_string(),
        },
        other => {
            return Err(format!(
                "unknown --network {other:?}: expected one of \
                 testnet, futurenet, mainnet (or pubnet), local (or standalone)"
            ))
        }
    };
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_every_documented_network_name_and_its_aliases() {
        for name in [
            "testnet",
            "futurenet",
            "mainnet",
            "pubnet",
            "local",
            "standalone",
            "TESTNET",
        ] {
            resolve_network(name).unwrap_or_else(|e| panic!("resolve_network({name:?}): {e}"));
        }
    }

    #[test]
    fn mainnet_and_pubnet_resolve_to_the_same_network() {
        assert_eq!(
            resolve_network("mainnet").unwrap(),
            resolve_network("pubnet").unwrap()
        );
    }

    #[test]
    fn rejects_an_unknown_network_name_with_a_clear_message() {
        let err = resolve_network("nonexistent-net").unwrap_err();
        assert!(err.contains("nonexistent-net"));
        assert!(err.contains("testnet"));
    }

    #[test]
    fn different_networks_resolve_to_different_endpoints() {
        let testnet = resolve_network("testnet").unwrap();
        let futurenet = resolve_network("futurenet").unwrap();
        assert_ne!(testnet.rpc_url, futurenet.rpc_url);
        assert_ne!(testnet.network_passphrase, futurenet.network_passphrase);
    }
}
