//! # soroban-gas-profiler
//!
//! A lightweight, dependency-free library for collecting, comparing, and
//! persisting Soroban contract gas measurements gathered inside Rust unit
//! tests via the `soroban_sdk` testutils `Budget` API.
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use soroban_gas_profiler::{GasProfiler, GasSample};
//!
//! let mut profiler = GasProfiler::new();
//!
//! // Reset budget, run your contract call, then record the result.
//! env.budget().reset_unlimited();
//! sas_client.attest(&attestation);
//! profiler.record("sas::attest", env.budget().cpu_insns(), env.budget().mem_bytes());
//!
//! // Write a timestamped JSON snapshot.
//! profiler.flush_to_dir("gas_profile_history").unwrap();
//!
//! // Compare against the previous run.
//! let prev = GasProfiler::load_latest("gas_profile_history").unwrap();
//! for diff in profiler.compare(&prev) {
//!     println!("{}", diff);
//! }
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A single gas measurement for one named entrypoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasSample {
    /// Human-readable label (e.g. `"sas::attest"` or `"sas::multi_attest (n=10)"`).
    pub entrypoint: String,
    /// Soroban CPU instruction count reported by `env.budget().cpu_insns()`.
    pub cpu_insns: u64,
    /// Soroban memory byte count reported by `env.budget().mem_bytes()`.
    pub mem_bytes: u64,
}

/// A comparison between two runs for a single entrypoint.
#[derive(Debug, Clone)]
pub struct GasDiff {
    pub entrypoint: String,
    /// CPU delta: positive means the new run consumed more instructions.
    pub cpu_delta: i64,
    /// Memory delta: positive means the new run consumed more memory.
    pub mem_delta: i64,
    pub cpu_pct: f64,
    pub mem_pct: f64,
}

impl std::fmt::Display for GasDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:50}  cpu: {:+} ({:+.1}%)  mem: {:+} ({:+.1}%)",
            self.entrypoint, self.cpu_delta, self.cpu_pct, self.mem_delta, self.mem_pct
        )
    }
}

// ---------------------------------------------------------------------------
// GasProfiler
// ---------------------------------------------------------------------------

/// Accumulates gas samples and can persist / load them as JSON.
#[derive(Debug, Default)]
pub struct GasProfiler {
    samples: Vec<GasSample>,
    /// UTC timestamp set when the profiler is first constructed or loaded.
    pub timestamp: String,
    /// Short Git revision set from the `GIT_COMMIT_SHA` env var when present.
    pub git_rev: String,
}

impl GasProfiler {
    /// Create a new, empty profiler with the current timestamp.
    pub fn new() -> Self {
        let now = current_timestamp();
        let git_rev = std::env::var("GIT_COMMIT_SHA")
            .unwrap_or_else(|_| git_rev_short().unwrap_or_else(|| "unknown".to_string()));
        Self {
            samples: Vec::new(),
            timestamp: now,
            git_rev,
        }
    }

    /// Record a gas sample.
    pub fn record(&mut self, entrypoint: &str, cpu_insns: u64, mem_bytes: u64) {
        self.samples.push(GasSample {
            entrypoint: entrypoint.to_string(),
            cpu_insns,
            mem_bytes,
        });
    }

    /// All recorded samples.
    pub fn samples(&self) -> &[GasSample] {
        &self.samples
    }

    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    /// Serialise the profiler state as a JSON string (no external dependencies).
    pub fn to_json(&self) -> String {
        let mut entries = Vec::new();

        // Deduplicate by averaging repeated measurements for the same label.
        let mut grouped: BTreeMap<&str, Vec<&GasSample>> = BTreeMap::new();
        for s in &self.samples {
            grouped.entry(&s.entrypoint).or_default().push(s);
        }

        for (label, group) in &grouped {
            let count = group.len() as u64;
            let avg_cpu = group.iter().map(|s| s.cpu_insns).sum::<u64>() / count;
            let avg_mem = group.iter().map(|s| s.mem_bytes).sum::<u64>() / count;
            entries.push(format!(
                "    {{\"entrypoint\":\"{}\",\"cpu_insns\":{},\"mem_bytes\":{}}}",
                escape_json(label),
                avg_cpu,
                avg_mem,
            ));
        }

        format!(
            "{{\n  \"timestamp\":\"{}\",\n  \"git_rev\":\"{}\",\n  \"measurements\":[\n{}\n  ]\n}}",
            escape_json(&self.timestamp),
            escape_json(&self.git_rev),
            entries.join(",\n"),
        )
    }

    /// Parse a profiler from a JSON string produced by [`to_json`].
    ///
    /// Returns `None` when the input is not a recognisable snapshot.
    pub fn from_json(s: &str) -> Option<Self> {
        let timestamp = extract_json_str(s, "timestamp")?;
        let git_rev = extract_json_str(s, "git_rev").unwrap_or_else(|| "unknown".to_string());

        let meas_start = s.find("\"measurements\"")?;
        let arr_start = s[meas_start..].find('[')? + meas_start;
        let arr_end = s[arr_start..].rfind(']')? + arr_start;
        let array_body = &s[arr_start + 1..arr_end];

        let mut samples = Vec::new();
        for obj in split_json_objects(array_body) {
            let entrypoint = extract_json_str(&obj, "entrypoint")?;
            let cpu_insns = extract_json_u64(&obj, "cpu_insns")?;
            let mem_bytes = extract_json_u64(&obj, "mem_bytes")?;
            samples.push(GasSample { entrypoint, cpu_insns, mem_bytes });
        }

        Some(Self { samples, timestamp, git_rev })
    }

    /// Write the profiler to `dir/<timestamp>.json`, creating `dir` if needed.
    pub fn flush_to_dir<P: AsRef<Path>>(&self, dir: P) -> std::io::Result<PathBuf> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir)?;
        let safe_ts = self
            .timestamp
            .replace(':', "-")
            .replace(' ', "_")
            .replace('/', "-");
        let filename = format!("{}.json", safe_ts);
        let path = dir.join(filename);
        std::fs::write(&path, self.to_json().as_bytes())?;
        Ok(path)
    }

    /// Load the most-recently-written snapshot from `dir`.
    ///
    /// Returns `None` when the directory is empty or does not exist.
    pub fn load_latest<P: AsRef<Path>>(dir: P) -> Option<Self> {
        let dir = dir.as_ref();
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .ok()?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        files.sort();
        let latest = files.last()?;
        let content = std::fs::read_to_string(latest).ok()?;
        Self::from_json(&content)
    }

    /// Load all snapshots from `dir`, sorted chronologically.
    pub fn load_all<P: AsRef<Path>>(dir: P) -> Vec<Self> {
        let dir = dir.as_ref();
        let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        files.sort();
        files
            .iter()
            .filter_map(|p| {
                std::fs::read_to_string(p)
                    .ok()
                    .and_then(|s| Self::from_json(&s))
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Comparison / regression detection
    // -----------------------------------------------------------------------

    /// Compare `self` (the new run) against `baseline` (a previous run).
    ///
    /// Returns one [`GasDiff`] per entrypoint that appears in both runs.
    /// Entrypoints present only in one run are silently skipped.
    pub fn compare(&self, baseline: &GasProfiler) -> Vec<GasDiff> {
        let base_map: BTreeMap<&str, &GasSample> =
            baseline.samples.iter().map(|s| (s.entrypoint.as_str(), s)).collect();

        let mut diffs = Vec::new();
        for s in &self.samples {
            if let Some(b) = base_map.get(s.entrypoint.as_str()) {
                let cpu_delta = s.cpu_insns as i64 - b.cpu_insns as i64;
                let mem_delta = s.mem_bytes as i64 - b.mem_bytes as i64;
                let cpu_pct = if b.cpu_insns == 0 {
                    0.0
                } else {
                    cpu_delta as f64 / b.cpu_insns as f64 * 100.0
                };
                let mem_pct = if b.mem_bytes == 0 {
                    0.0
                } else {
                    mem_delta as f64 / b.mem_bytes as f64 * 100.0
                };
                diffs.push(GasDiff {
                    entrypoint: s.entrypoint.clone(),
                    cpu_delta,
                    mem_delta,
                    cpu_pct,
                    mem_pct,
                });
            }
        }
        diffs
    }

    /// Returns all diffs where the CPU or memory regression exceeds the given
    /// percentage threshold (e.g. `5.0` for a 5 % regression budget).
    pub fn regressions(&self, baseline: &GasProfiler, threshold_pct: f64) -> Vec<GasDiff> {
        self.compare(baseline)
            .into_iter()
            .filter(|d| d.cpu_pct > threshold_pct || d.mem_pct > threshold_pct)
            .collect()
    }

    // -----------------------------------------------------------------------
    // Text report
    // -----------------------------------------------------------------------

    /// Render a Markdown table summarising all measurements.
    pub fn to_markdown_table(&self) -> String {
        let mut lines = vec![
            format!("## Gas Profile — {}", self.timestamp),
            format!("Git revision: `{}`\n", self.git_rev),
            "| Entrypoint | CPU Instructions | Memory (bytes) |".to_string(),
            "|:-----------|----------------:|--------------:|".to_string(),
        ];
        for s in &self.samples {
            lines.push(format!(
                "| `{}` | {:>16} | {:>14} |",
                s.entrypoint, s.cpu_insns, s.mem_bytes
            ));
        }
        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers (no serde dependency)
// ---------------------------------------------------------------------------

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let after = &json[pos + needle.len()..];
    let colon = after.find(':')? + 1;
    let rest = after[colon..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let inner = &rest[1..];
    let mut result = String::new();
    let mut chars = inner.chars();
    loop {
        match chars.next()? {
            '"' => break,
            '\\' => match chars.next()? {
                '"' => result.push('"'),
                '\\' => result.push('\\'),
                'n' => result.push('\n'),
                'r' => result.push('\r'),
                't' => result.push('\t'),
                c => result.push(c),
            },
            c => result.push(c),
        }
    }
    Some(result)
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\"", key);
    let pos = json.find(&needle)?;
    let after = &json[pos + needle.len()..];
    let colon = after.find(':')? + 1;
    let rest = after[colon..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn split_json_objects(s: &str) -> Vec<String> {
    let mut objects = Vec::new();
    let mut depth = 0i32;
    let mut start = None;
    for (i, c) in s.char_indices() {
        match c {
            '{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s_idx) = start.take() {
                        objects.push(s[s_idx..=i].to_string());
                    }
                }
            }
            _ => {}
        }
    }
    objects
}

// ---------------------------------------------------------------------------
// Timestamp helpers
// ---------------------------------------------------------------------------

fn current_timestamp() -> String {
    let secs: u64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    unix_secs_to_iso(secs)
}

fn unix_secs_to_iso(secs: u64) -> String {
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
        [31u64, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31u64, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
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

// ---------------------------------------------------------------------------
// Unit tests for the library itself
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_json_roundtrip() {
        let mut p = GasProfiler {
            samples: Vec::new(),
            timestamp: "2026-10-17T12:00:00Z".to_string(),
            git_rev: "abc1234".to_string(),
        };
        p.record("sas::attest", 100_000, 50_000);
        p.record("sas::revoke", 80_000, 40_000);

        let json = p.to_json();
        assert!(json.contains("sas::attest"));
        assert!(json.contains("100000"));

        let loaded = GasProfiler::from_json(&json).expect("should parse back");
        assert_eq!(loaded.timestamp, "2026-10-17T12:00:00Z");
        assert_eq!(loaded.git_rev, "abc1234");
        assert_eq!(loaded.samples.len(), 2);
        assert_eq!(loaded.samples[0].cpu_insns, 100_000);
        assert_eq!(loaded.samples[1].entrypoint, "sas::revoke");
    }

    #[test]
    fn test_compare_detects_regression() {
        let mut baseline = GasProfiler {
            samples: Vec::new(),
            timestamp: "2026-10-17T11:00:00Z".to_string(),
            git_rev: "old".to_string(),
        };
        baseline.record("sas::attest", 100_000, 50_000);

        let mut current = GasProfiler {
            samples: Vec::new(),
            timestamp: "2026-10-17T12:00:00Z".to_string(),
            git_rev: "new".to_string(),
        };
        current.record("sas::attest", 110_000, 50_000); // +10% cpu

        let regressions = current.regressions(&baseline, 5.0);
        assert_eq!(regressions.len(), 1);
        assert_eq!(regressions[0].entrypoint, "sas::attest");
        assert!((regressions[0].cpu_pct - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_compare_no_regression_within_threshold() {
        let mut baseline = GasProfiler::new();
        baseline.record("sas::attest", 100_000, 50_000);

        let mut current = GasProfiler::new();
        current.record("sas::attest", 103_000, 51_000); // +3% / +2%

        let regressions = current.regressions(&baseline, 5.0);
        assert!(regressions.is_empty(), "should be within 5% threshold");
    }

    #[test]
    fn test_flush_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("soroban_gas_profiler_test");
        let _ = std::fs::remove_dir_all(&dir);

        let mut p = GasProfiler {
            samples: Vec::new(),
            timestamp: "2026-10-17T10:00:00Z".to_string(),
            git_rev: "test".to_string(),
        };
        p.record("sas::attest", 123_456, 78_901);
        let path = p.flush_to_dir(&dir).unwrap();
        assert!(path.exists());

        let loaded = GasProfiler::load_latest(&dir).expect("should find the file");
        assert_eq!(loaded.git_rev, "test");
        assert_eq!(loaded.samples[0].cpu_insns, 123_456);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_markdown_table_contains_entrypoints() {
        let mut p = GasProfiler::new();
        p.record("sas::attest", 100_000, 50_000);
        let md = p.to_markdown_table();
        assert!(md.contains("sas::attest"));
        assert!(md.contains("100000"));
    }

    #[test]
    fn test_json_str_with_special_chars() {
        let mut p = GasProfiler {
            samples: Vec::new(),
            timestamp: "2026-10-17T12:00:00Z".to_string(),
            git_rev: r#"rev\with"quotes"#.to_string(),
        };
        p.record(r#"sas::attest "minimal""#, 1, 2);
        let json = p.to_json();
        let loaded = GasProfiler::from_json(&json).unwrap();
        assert_eq!(loaded.samples[0].entrypoint, r#"sas::attest "minimal""#);
    }

    #[test]
    fn test_unix_secs_to_iso() {
        // 2026-10-17T22:02:40Z
        assert_eq!(unix_secs_to_iso(1_792_274_560), "2026-10-17T22:02:40Z");
        // Epoch itself
        assert_eq!(unix_secs_to_iso(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_load_all_sorted() {
        let dir = std::env::temp_dir().join("soroban_gas_profiler_all_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        for (ts, rev) in [
            ("2026-10-15T00:00:00Z", "rev1"),
            ("2026-10-16T00:00:00Z", "rev2"),
            ("2026-10-17T00:00:00Z", "rev3"),
        ] {
            let p = GasProfiler {
                samples: vec![GasSample {
                    entrypoint: "x".to_string(),
                    cpu_insns: 1,
                    mem_bytes: 2,
                }],
                timestamp: ts.to_string(),
                git_rev: rev.to_string(),
            };
            p.flush_to_dir(&dir).unwrap();
        }

        let all = GasProfiler::load_all(&dir);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].git_rev, "rev1");
        assert_eq!(all[2].git_rev, "rev3");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
