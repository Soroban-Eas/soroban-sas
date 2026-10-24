//! Shell completion script generation for `soroban-sas-cli` / `sas` (issue #475).

use clap::Command;
use clap_complete::{generate, Shell};
use std::io::Write;

/// Generates shell completion script for `sas` binary for the requested shell.
pub fn generate_completions<W: Write>(cmd: &mut Command, shell: Shell, buf: &mut W) {
    generate(shell, cmd, "sas", buf);
}
