//! Named-identity resolution for the global `--identity` option (issue #174).
//!
//! Each identity is a plain-text file holding one signing key (an `S...`
//! strkey seed or a 32-byte hex seed — the same formats every `--secret-key`
//! flag already accepts), named `<identity-dir>/<name>`. This is a *lookup*
//! convenience, not a keystore: it exists so a secret never has to be typed
//! on the command line (visible in shell history and `ps`) or exported to an
//! environment variable just to be reused across invocations. Callers still
//! get the same `[u8; 32]` seed `--secret-key`/`SAS_SECRET_KEY` would have
//! produced, via `offchain::parse_secret_seed`.
//!
//! The directory defaults to `~/.soroban-sas/identities`, overridable via
//! `SAS_IDENTITY_DIR` (primarily for tests, but also for anyone who wants
//! identities scoped to a project rather than the whole machine).

use std::path::PathBuf;

const IDENTITY_DIR_ENV: &str = "SAS_IDENTITY_DIR";

fn identity_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var(IDENTITY_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            "cannot determine home directory to locate identities; set SAS_IDENTITY_DIR explicitly"
                .to_string()
        })?;
    Ok(PathBuf::from(home).join(".soroban-sas").join("identities"))
}

/// Reads the named identity's signing key. `name` must not contain path
/// separators — identities are flat files, never a path into arbitrary
/// filesystem locations.
pub fn resolve_identity_secret(name: &str) -> Result<String, String> {
    if name.is_empty() || name.contains(['/', '\\']) {
        return Err(format!(
            "invalid --identity {name:?}: identity names may not be empty or contain a path separator"
        ));
    }
    let path = identity_dir()?.join(name);
    let contents = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "cannot read identity {name:?} from {}: {e}",
            path.display()
        )
    })?;
    let secret = contents.trim();
    if secret.is_empty() {
        return Err(format!("identity {name:?} at {} is empty", path.display()));
    }
    Ok(secret.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `resolve_identity_secret` reads `SAS_IDENTITY_DIR` from the process
    // environment, which is global state — serialize the tests that touch it
    // so they don't race each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_identity_dir<T>(f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("sas-identities-test-{}", uid()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var(IDENTITY_DIR_ENV, &dir);
        let result = f(&dir);
        std::env::remove_var(IDENTITY_DIR_ENV);
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    fn uid() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn reads_a_trimmed_secret_from_the_identity_file() {
        with_identity_dir(|dir| {
            std::fs::write(dir.join("alice"), "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF7U\n").unwrap();
            let secret = resolve_identity_secret("alice").unwrap();
            assert_eq!(
                secret,
                "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF7U"
            );
        });
    }

    #[test]
    fn errors_clearly_when_the_identity_file_is_missing() {
        with_identity_dir(|_dir| {
            let err = resolve_identity_secret("nobody").unwrap_err();
            assert!(err.contains("nobody"));
        });
    }

    #[test]
    fn rejects_identity_names_containing_path_separators() {
        let err = resolve_identity_secret("../escape").unwrap_err();
        assert!(err.contains("path separator"));
        let err = resolve_identity_secret("a/b").unwrap_err();
        assert!(err.contains("path separator"));
    }

    #[test]
    fn rejects_an_empty_identity_file() {
        with_identity_dir(|dir| {
            std::fs::write(dir.join("blank"), "   \n").unwrap();
            let err = resolve_identity_secret("blank").unwrap_err();
            assert!(err.contains("empty"));
        });
    }
}
