//! Gas profiling history tests for the SAS contract entrypoints.
//!
//! These tests measure the Soroban compute budget (CPU instructions and
//! memory bytes) consumed by each contract entrypoint under representative
//! workloads.  On every run the measurements are serialised as a JSON
//! snapshot and written to `gas_profile_history/` relative to the workspace
//! root so that the history accumulates over time and regressions can be
//! spotted by diffing successive runs (or by running
//! `tools/gas_dashboard.sh`).
//!
//! ## Running
//! ```sh
//! cargo test -p sas --test-threads=1 gas_profile
//! ```
//!
//! ## How it works
//! Each test:
//! 1. Sets up a minimal but realistic multi-contract stack using the real
//!    `SchemaRegistry` and `Indexer` test-utils registrations.
//! 2. Calls `env.budget().reset_unlimited()` immediately before the
//!    operation under measurement so that setup costs are excluded.
//! 3. Reads `env.budget().cpu_instruction_cost()` and `env.budget().memory_bytes_cost()` after
//!    the call.
//! 4. Appends the reading to a shared in-process `GasProfiler` instance that
//!    is flushed to disk when the last profiling test completes (or via the
//!    `flush_gas_profile` test that is always listed last).
//!
//! Because the budget counters are cumulative within a test, each test owns
//! its own `Env` so measurements are independent.

#[cfg(test)]
mod gas_profiling {
    use crate::{SASClient, SAS};
    use schema_registry::{SchemaRegistry, SchemaRegistryClient};
    use soroban_sas_common::{Attestation, UID};
    use soroban_sas_indexer::{Indexer, IndexerClient};
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Address, Bytes, BytesN, Env, String as SorobanString,
    };

    use std::collections::BTreeMap;
    use std::sync::Mutex;

    // -----------------------------------------------------------------------
    // In-process gas accumulator
    // -----------------------------------------------------------------------

    /// One measured sample for a single entry point.
    #[derive(Debug, Clone)]
    struct GasSample {
        entrypoint: String,
        cpu_insns: u64,
        mem_bytes: u64,
        /// Optional tag carried in the entrypoint label (e.g. batch size).
        tag: Option<String>,
    }

    /// Global accumulator: every profiling test appends here; `flush_gas_profile`
    /// drains and persists it.
    static SAMPLES: Mutex<Vec<GasSample>> = Mutex::new(Vec::new());

    fn record(entrypoint: &str, cpu_insns: u64, mem_bytes: u64, tag: Option<&str>) {
        let mut guard = SAMPLES.lock().unwrap();
        guard.push(GasSample {
            entrypoint: entrypoint.to_string(),
            cpu_insns,
            mem_bytes,
            tag: tag.map(|s| s.to_string()),
        });
    }

    // -----------------------------------------------------------------------
    // Test stack helpers
    // -----------------------------------------------------------------------

    mod permissive_resolver {
        use super::*;
        #[soroban_sdk::contract]
        pub struct PermissiveResolver;

        #[soroban_sdk::contractimpl]
        impl PermissiveResolver {
            pub fn on_attest(_env: Env, _attestation: Attestation) {}
            pub fn on_revoke(_env: Env, _attestation: Attestation) {}
        }
    }

    struct Stack {
        env: Env,
        registry: SchemaRegistryClient<'static>,
        sas: SASClient<'static>,
        #[allow(dead_code)]
        indexer: IndexerClient<'static>,
        admin: Address,
        schema_uid: UID,
    }

    fn make_stack() -> Stack {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        env.ledger().with_mut(|li| li.timestamp = 1_000);

        let admin = Address::generate(&env);

        let registry_id = env.register_contract(None, SchemaRegistry);
        let registry = SchemaRegistryClient::new(&env, &registry_id);
        registry.init(&admin);

        let sas_id = env.register_contract(None, SAS);
        let sas = SASClient::new(&env, &sas_id);
        sas.init(&admin, &registry_id);

        let indexer_id = env.register_contract(None, Indexer);
        let indexer = IndexerClient::new(&env, &indexer_id);
        indexer.init(&admin, &sas_id);
        sas.set_indexer(&indexer_id);

        let resolver_id = env.register_contract(None, permissive_resolver::PermissiveResolver);

        // Register a benchmark schema once and reuse it across tests.
        let schema_uid = registry.register(
            &admin,
            &SorobanString::from_str(&env, "string name,bool verified"),
            &resolver_id,
            &true,
        );

        Stack {
            env,
            registry,
            sas,
            indexer,
            admin,
            schema_uid: UID(schema_uid.0),
        }
    }

    /// Build a minimal, correctly content-addressed `Attestation`.
    fn mk_attestation(
        env: &Env,
        schema_uid: &UID,
        attester: &Address,
        recipient: &Address,
        seed: u8,
    ) -> Attestation {
        let data = Bytes::from_array(env, &[seed; 32]);
        let uid = soroban_sas_common::attestation_uid(env, schema_uid, recipient, attester, &data);
        Attestation {
            uid,
            schema_uid: schema_uid.clone(),
            time: 1_000,
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
            recipient: recipient.clone(),
            attester: attester.clone(),
            revocable: true,
            data,
        }
    }

    // -----------------------------------------------------------------------
    // Profiling tests
    // -----------------------------------------------------------------------

    /// `SchemaRegistry::register` — register a single schema.
    #[test]
    fn profile_schema_registry_register() {
        let s = make_stack();
        let env = &s.env;

        env.budget().reset_unlimited();
        s.registry.register(
            &s.admin,
            &SorobanString::from_str(env, "string bench_field"),
            &s.admin,
            &true,
        );
        let cpu = env.budget().cpu_instruction_cost();
        let mem = env.budget().memory_bytes_cost();
        record("schema_registry::register", cpu, mem, None);
    }

    /// `SAS::attest` — issue a single attestation with a 32-byte payload.
    #[test]
    fn profile_sas_attest_minimal() {
        let s = make_stack();
        let env = &s.env;
        let attester = s.admin.clone();
        let recipient = Address::generate(env);
        let att = mk_attestation(env, &s.schema_uid, &attester, &recipient, 0xAA);

        env.budget().reset_unlimited();
        s.sas.attest(&att);
        let cpu = env.budget().cpu_instruction_cost();
        let mem = env.budget().memory_bytes_cost();
        record("sas::attest (minimal 32B)", cpu, mem, None);
    }

    /// `SAS::attest` — issue an attestation with a 1 KB payload.
    #[test]
    fn profile_sas_attest_1kb() {
        let s = make_stack();
        let env = &s.env;
        let attester = s.admin.clone();
        let recipient = Address::generate(env);

        let data = Bytes::from_slice(env, &[0xABu8; 1024]);
        let uid =
            soroban_sas_common::attestation_uid(env, &s.schema_uid, &recipient, &attester, &data);
        let att = Attestation {
            uid,
            schema_uid: s.schema_uid.clone(),
            time: 1_000,
            expiration_time: 0,
            valid_from: 0,
            revocation_time: 0,
            ref_uid: UID(BytesN::from_array(env, &[0u8; 32])),
            recipient: recipient.clone(),
            attester: attester.clone(),
            revocable: true,
            data,
        };

        env.budget().reset_unlimited();
        s.sas.attest(&att);
        let cpu = env.budget().cpu_instruction_cost();
        let mem = env.budget().memory_bytes_cost();
        record("sas::attest (1 KB payload)", cpu, mem, None);
    }

    /// `SAS::revoke` — revoke a previously issued attestation.
    #[test]
    fn profile_sas_revoke() {
        let s = make_stack();
        let env = &s.env;
        let attester = s.admin.clone();
        let recipient = Address::generate(env);
        let att = mk_attestation(env, &s.schema_uid, &attester, &recipient, 0xBB);
        let uid = s.sas.attest(&att);

        env.budget().reset_unlimited();
        s.sas.revoke(&uid);
        let cpu = env.budget().cpu_instruction_cost();
        let mem = env.budget().memory_bytes_cost();
        record("sas::revoke", cpu, mem, None);
    }

    /// `SAS::verify_attestation` — verify a live attestation.
    #[test]
    fn profile_sas_verify_attestation() {
        let s = make_stack();
        let env = &s.env;
        let attester = s.admin.clone();
        let recipient = Address::generate(env);
        let att = mk_attestation(env, &s.schema_uid, &attester, &recipient, 0xCC);
        let uid = s.sas.attest(&att);

        env.budget().reset_unlimited();
        s.sas.verify_attestation(&uid);
        let cpu = env.budget().cpu_instruction_cost();
        let mem = env.budget().memory_bytes_cost();
        record("sas::verify_attestation", cpu, mem, None);
    }

    /// `SAS::get_attestation` — read a stored attestation.
    #[test]
    fn profile_sas_get_attestation() {
        let s = make_stack();
        let env = &s.env;
        let attester = s.admin.clone();
        let recipient = Address::generate(env);
        let att = mk_attestation(env, &s.schema_uid, &attester, &recipient, 0xDD);
        let uid = s.sas.attest(&att);

        env.budget().reset_unlimited();
        s.sas.get_attestation(&uid);
        let cpu = env.budget().cpu_instruction_cost();
        let mem = env.budget().memory_bytes_cost();
        record("sas::get_attestation", cpu, mem, None);
    }

    /// `SAS::multi_attest` — batch issuance at several sizes.
    fn profile_multi_attest_n(n: usize) {
        let s = make_stack();
        let env = &s.env;
        let attester = s.admin.clone();

        let mut attestations = soroban_sdk::Vec::new(env);
        for i in 0..n {
            let recipient = Address::generate(env);
            let att = mk_attestation(env, &s.schema_uid, &attester, &recipient, i as u8);
            attestations.push_back(att);
        }

        env.budget().reset_unlimited();
        s.sas.multi_attest(&attestations);
        let cpu = env.budget().cpu_instruction_cost();
        let mem = env.budget().memory_bytes_cost();
        let tag = format!("n={n}");
        record("sas::multi_attest", cpu, mem, Some(&tag));
    }

    #[test]
    fn profile_sas_multi_attest_n1() {
        profile_multi_attest_n(1);
    }

    #[test]
    fn profile_sas_multi_attest_n10() {
        profile_multi_attest_n(10);
    }

    #[test]
    fn profile_sas_multi_attest_n50() {
        profile_multi_attest_n(50);
    }

    #[test]
    fn profile_sas_multi_attest_n100() {
        profile_multi_attest_n(100);
    }

    // -----------------------------------------------------------------------
    // JSON serialization helpers (no external serde dependency)
    // -----------------------------------------------------------------------

    fn escape_json_str(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }

    fn samples_to_json(samples: &[GasSample], timestamp: &str, git_rev: &str) -> String {
        let mut entries = Vec::new();

        // Group by entrypoint for the compact per-entry summary object.
        let mut grouped: BTreeMap<String, Vec<&GasSample>> = BTreeMap::new();
        for s in samples {
            let key = match &s.tag {
                Some(t) => format!("{} ({})", s.entrypoint, t),
                None => s.entrypoint.clone(),
            };
            grouped.entry(key).or_default().push(s);
        }

        for (label, group) in &grouped {
            // Average over repeated measurements (tests can be run multiple times).
            let count = group.len() as u64;
            let avg_cpu = group.iter().map(|s| s.cpu_insns).sum::<u64>() / count;
            let avg_mem = group.iter().map(|s| s.mem_bytes).sum::<u64>() / count;
            entries.push(format!(
                r#"    {{
      "entrypoint": "{label}",
      "cpu_insns": {avg_cpu},
      "mem_bytes": {avg_mem}
    }}"#,
                label = escape_json_str(label),
                avg_cpu = avg_cpu,
                avg_mem = avg_mem,
            ));
        }

        format!(
            r#"{{
  "timestamp": "{ts}",
  "git_rev": "{rev}",
  "measurements": [
{body}
  ]
}}"#,
            ts = escape_json_str(timestamp),
            rev = escape_json_str(git_rev),
            body = entries.join(",\n"),
        )
    }

    // -----------------------------------------------------------------------
    // Flush: must run last — writes the accumulated samples to disk
    // -----------------------------------------------------------------------

    /// Serialises the accumulated gas samples from this test run and appends
    /// them to `gas_profile_history/` as a timestamped JSON file.
    ///
    /// This test is named with the `z_` prefix so that cargo's default
    /// alphabetical ordering ensures it runs after all the `profile_*` tests.
    /// Run with `-- --test-threads=1` to guarantee ordering.
    #[test]
    fn z_flush_gas_profile() {
        let samples = {
            let mut guard = SAMPLES.lock().unwrap();
            std::mem::take(&mut *guard)
        };

        if samples.is_empty() {
            // Nothing to flush — the profiling tests may have been filtered out.
            return;
        }

        // Determine the repo root (CARGO_MANIFEST_DIR points to the crate).
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let repo_root = std::path::Path::new(manifest_dir)
            .parent() // contracts/sas -> contracts
            .and_then(|p| p.parent()) // contracts -> repo root
            .expect("unexpected directory structure");

        let history_dir = repo_root.join("gas_profile_history");
        std::fs::create_dir_all(&history_dir)
            .expect("failed to create gas_profile_history directory");

        // Timestamp: prefer SOURCE_DATE_EPOCH for reproducibility in CI, else
        // fall back to seconds since epoch via the standard library.
        let now_secs: u64 = std::env::var("SOURCE_DATE_EPOCH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });

        // Format as YYYYMMDD_HHMMSS (UTC approximation via integer arithmetic).
        let timestamp = unix_secs_to_iso(now_secs);

        let git_rev = std::env::var("GIT_COMMIT_SHA")
            .unwrap_or_else(|_| git_rev_short().unwrap_or_else(|| "unknown".to_string()));

        let json = samples_to_json(&samples, &timestamp, &git_rev);

        let filename = format!("{}.json", timestamp.replace(':', "-").replace(' ', "_"));
        let path = history_dir.join(&filename);
        std::fs::write(&path, json.as_bytes())
            .unwrap_or_else(|e| panic!("failed to write gas profile to {}: {}", path.display(), e));

        eprintln!("[gas_profiler] wrote {}", path.display());
        eprintln!("[gas_profiler] run `tools/gas_dashboard.sh` to view the history dashboard");
    }

    // -----------------------------------------------------------------------
    // Utility: ISO-like timestamp from Unix seconds (no external deps)
    // -----------------------------------------------------------------------

    fn unix_secs_to_iso(secs: u64) -> String {
        // Gregorian calendar arithmetic (good for years 1970–2199).
        let s = secs % 60;
        let m = (secs / 60) % 60;
        let h = (secs / 3600) % 24;
        let days = secs / 86400;

        let (year, month, day) = days_to_ymd(days);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, h, m, s
        )
    }

    fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
        // Reference: 1970-01-01 = day 0.
        let mut year = 1970u64;
        loop {
            let dy = if is_leap(year) { 366 } else { 365 };
            if days < dy {
                break;
            }
            days -= dy;
            year += 1;
        }
        let months = if is_leap(year) {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };
        let mut month = 1u64;
        for &dm in &months {
            if days < dm {
                break;
            }
            days -= dm;
            month += 1;
        }
        (year, month, days + 1)
    }

    fn is_leap(y: u64) -> bool {
        (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
    }

    fn git_rev_short() -> Option<String> {
        std::process::Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
}
