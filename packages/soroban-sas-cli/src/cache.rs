//! Disk-backed cache for read-only RPC query results (issue #331).
//!
//! Repeated invocations of a read-only subcommand (e.g. `schema get`, `sas
//! get-fee`) from a script or pipeline re-run the exact same
//! `simulateTransaction` round trip every time, even when the on-chain value
//! hasn't changed since the last call. This caches each such command's
//! already-formatted result (human text + JSON payload) to a per-query file
//! under `~/.soroban-sas/cache` (override via `SAS_CACHE_DIR`), valid for
//! `SAS_CACHE_TTL_SECS` seconds (default 30, `0` disables the cache
//! entirely). Pass the global `--no-cache` flag to always bypass it for one
//! invocation; a bypassed fetch still refreshes the cache for the next
//! lookup (write-through).
//!
//! Only read-only query commands ever call into this module — mutating
//! commands never consult or populate it, so a cached value can never stand
//! in for the result of a state change.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_DIR_ENV: &str = "SAS_CACHE_DIR";
const CACHE_TTL_ENV: &str = "SAS_CACHE_TTL_SECS";
const DEFAULT_TTL_SECS: u64 = 30;

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    cached_at: u64,
    human: String,
    json: serde_json::Value,
}

fn cache_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var(CACHE_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            "cannot determine home directory to locate the RPC cache; set SAS_CACHE_DIR explicitly"
                .to_string()
        })?;
    Ok(PathBuf::from(home).join(".soroban-sas").join("cache"))
}

/// TTL in seconds a cache entry stays valid for. `0` means "never valid" —
/// every lookup is a forced miss, effectively disabling the cache without
/// needing a separate on/off switch.
fn ttl_secs() -> u64 {
    std::env::var(CACHE_TTL_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_TTL_SECS)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// FNV-1a 64-bit hash — not cryptographic, and doesn't need to be: a cache
/// key only has to be collision-resistant enough for on-disk file naming
/// (issue #331 is a perf cache, not a security boundary), and this avoids
/// pulling in a crypto dependency for the sole purpose of naming files.
fn fnv1a_hex(bytes: &[u8]) -> String {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

/// Content-addresses a cache entry from the pieces that make its result
/// unique: the RPC endpoint, contract, function, and arguments. Two calls
/// with identical inputs land on the same file; anything different
/// (including the RPC endpoint, so testnet and mainnet reads never collide)
/// lands on a different one. `\u{1}` (a control byte no legitimate argument
/// contains) separates fields so `["ab", "c"]` and `["a", "bc"]` can never
/// hash to the same key.
fn cache_key(parts: &[&str]) -> String {
    let joined = parts.join("\u{1}");
    fnv1a_hex(joined.as_bytes())
}

/// Looks up a cached result for `parts`, calling `fetch` on a miss (expired,
/// absent, or unreadable entry) and writing its result back to the cache.
/// `no_cache` forces a miss (still write-through) — the CLI's `--no-cache`
/// flag threads through here rather than skipping this function, so a
/// bypassed call still refreshes the cache for the next lookup.
///
/// Returns `(human, json)` exactly as `fetch` produced them; caching is
/// transparent to the caller.
pub fn cached_or<F>(
    parts: &[&str],
    no_cache: bool,
    fetch: F,
) -> Result<(String, serde_json::Value), String>
where
    F: FnOnce() -> Result<(String, serde_json::Value), String>,
{
    let ttl = ttl_secs();
    let key = cache_key(parts);
    let path = cache_dir().ok().map(|dir| dir.join(format!("{key}.json")));

    if !no_cache && ttl > 0 {
        if let Some(path) = &path {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(entry) = serde_json::from_str::<CacheEntry>(&contents) {
                    let age = now_secs().saturating_sub(entry.cached_at);
                    if age < ttl {
                        return Ok((entry.human, entry.json));
                    }
                }
            }
        }
    }

    let (human, json) = fetch()?;

    if let Some(path) = &path {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let entry = CacheEntry {
            cached_at: now_secs(),
            human: human.clone(),
            json: json.clone(),
        };
        // Caching is a pure optimization: a write failure (read-only
        // filesystem, permissions, disk full) must never fail the command
        // that already has a good result in hand.
        if let Ok(serialized) = serde_json::to_string(&entry) {
            let _ =
                crate::io_safety::write_atomic_private(&path.to_string_lossy(), &serialized, true);
        }
    }

    Ok((human, json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Cache tests read/write `SAS_CACHE_DIR`/`SAS_CACHE_TTL_SECS`, which are
    // global process state — serialize them so parallel test threads don't
    // race each other's environment mutations.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_cache_env<T>(ttl_secs: Option<&str>, f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("sas-cache-test-{}", uid()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var(CACHE_DIR_ENV, &dir);
        match ttl_secs {
            Some(v) => std::env::set_var(CACHE_TTL_ENV, v),
            None => std::env::remove_var(CACHE_TTL_ENV),
        }
        let result = f(&dir);
        std::env::remove_var(CACHE_DIR_ENV);
        std::env::remove_var(CACHE_TTL_ENV);
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    fn uid() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn second_call_is_served_from_cache_without_invoking_fetch() {
        with_cache_env(Some("30"), |_dir| {
            let calls = std::cell::Cell::new(0);
            let do_fetch = || {
                calls.set(calls.get() + 1);
                Ok((
                    "live value".to_string(),
                    serde_json::json!({"n": calls.get()}),
                ))
            };

            let first = cached_or(&["schema-get", "uid123"], false, do_fetch).unwrap();
            assert_eq!(first.0, "live value");
            assert_eq!(calls.get(), 1);

            let second = cached_or(&["schema-get", "uid123"], false, do_fetch).unwrap();
            assert_eq!(second, first);
            assert_eq!(calls.get(), 1, "second call must not re-invoke fetch");
        });
    }

    #[test]
    fn no_cache_flag_forces_a_fresh_fetch_but_still_refreshes_the_cache() {
        with_cache_env(Some("30"), |_dir| {
            let calls = std::cell::Cell::new(0);
            let do_fetch = || {
                calls.set(calls.get() + 1);
                Ok((format!("value-{}", calls.get()), serde_json::json!({})))
            };

            cached_or(&["schema-get", "uidABC"], false, do_fetch).unwrap();
            let bypassed = cached_or(&["schema-get", "uidABC"], true, do_fetch).unwrap();
            assert_eq!(calls.get(), 2, "--no-cache must force a real fetch");
            assert_eq!(bypassed.0, "value-2");

            // The bypassed fetch still wrote through: a subsequent
            // non-bypassed call sees its result, not the original.
            let cached = cached_or(&["schema-get", "uidABC"], false, do_fetch).unwrap();
            assert_eq!(calls.get(), 2, "write-through must be served from cache");
            assert_eq!(cached.0, "value-2");
        });
    }

    #[test]
    fn expired_entry_is_refetched() {
        with_cache_env(Some("0"), |_dir| {
            // TTL of 0 means every lookup is a forced miss.
            let calls = std::cell::Cell::new(0);
            let do_fetch = || {
                calls.set(calls.get() + 1);
                Ok((format!("value-{}", calls.get()), serde_json::json!({})))
            };

            cached_or(&["sas-get-fee", "C..."], false, do_fetch).unwrap();
            cached_or(&["sas-get-fee", "C..."], false, do_fetch).unwrap();
            assert_eq!(calls.get(), 2, "a zero TTL must never serve a cached value");
        });
    }

    #[test]
    fn different_keys_never_collide() {
        with_cache_env(Some("30"), |_dir| {
            cached_or(&["schema-get", "uid1"], false, || {
                Ok(("first".to_string(), serde_json::json!({})))
            })
            .unwrap();
            let second = cached_or(&["schema-get", "uid2"], false, || {
                Ok(("second".to_string(), serde_json::json!({})))
            })
            .unwrap();
            assert_eq!(second.0, "second");
        });
    }

    #[test]
    fn cache_write_failure_still_returns_the_live_result() {
        // Point SAS_CACHE_DIR at a path that can never be created (a file,
        // not a directory, sitting where the cache dir would go) so every
        // write attempt fails — the command must still succeed with the
        // freshly fetched value rather than propagating the I/O error.
        let _guard_dummy = ();
        with_cache_env(Some("30"), |dir| {
            let blocking_file = dir.join("blocked");
            std::fs::write(&blocking_file, "not a directory").unwrap();
            std::env::set_var(CACHE_DIR_ENV, &blocking_file);

            let result = cached_or(&["schema-get", "uidX"], false, || {
                Ok(("live".to_string(), serde_json::json!({"ok": true})))
            })
            .unwrap();
            assert_eq!(result.0, "live");
        });
    }
}
