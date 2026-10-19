#!/bin/bash -eu
# OSS-Fuzz build script for soroban-sas.
#
# OSS-Fuzz calls this script inside the builder container.  It must compile
# every fuzz target and place the resulting binaries (and any seed corpus
# archives) in $OUT.
#
# Environment variables set by OSS-Fuzz:
#   $SRC   – root of the checked-out source tree
#   $OUT   – destination directory for fuzzer binaries / corpora
#   $SANITIZER       – one of address, memory, undefined, coverage, introspector
#   $FUZZING_ENGINE  – one of libfuzzer, afl, honggfuzz (always libfuzzer for Rust)
#
# References:
#   https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/
#   https://google.github.io/oss-fuzz/further-reading/fuzzer-environment/

cd "$SRC/soroban-sas"

# Pinned nightly toolchain; matches CI (.github/workflows/fuzz.yml) and the
# Dockerfile ENV so every build environment uses the same compiler.
TOOLCHAIN="${FUZZ_TOOLCHAIN:-nightly-2024-06-13}"

# Ensure our pinned version of cargo-fuzz is available.  The base-builder-rust
# image ships cargo-fuzz but at an uncontrolled version; we pin to the same
# version used in CI to guarantee consistent flag handling.
#
# We install with the *stable* toolchain that ships in the base image so we
# avoid any nightly-only installer quirks.
cargo +stable install cargo-fuzz --version 0.13.2 --locked 2>/dev/null || true

# Build all fuzz targets in release mode with debug assertions enabled.
# cargo-fuzz translates $SANITIZER into the correct -fsanitize= RUSTFLAGS
# automatically when invoked with --sanitizer.
#
# -O        → release optimisations (equivalent to --release)
# --debug-assertions → keep assert!/debug_assert! active in the fuzz binary
cargo +"$TOOLCHAIN" fuzz build \
    --sanitizer "${SANITIZER:-address}" \
    --debug-assertions \
    -O

# ── Copy binaries to $OUT ─────────────────────────────────────────────────────
# Use the canonical glob pattern from the OSS-Fuzz Rust guide so any new
# target added to fuzz/fuzz_targets/ is picked up automatically.
FUZZ_TARGET_OUTPUT_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"

for f in fuzz/fuzz_targets/*.rs; do
    target="$(basename "${f%.rs}")"
    bin="$FUZZ_TARGET_OUTPUT_DIR/$target"
    if [[ -f "$bin" ]]; then
        cp "$bin" "$OUT/$target"
        echo "Installed $target -> $OUT/$target"
    else
        echo "WARNING: binary not found for $target at $bin" >&2
    fi
done

# ── Package seed corpora ──────────────────────────────────────────────────────
# OSS-Fuzz looks for $OUT/${target}_seed_corpus.zip.  Any committed seeds
# under fuzz/corpus/<target>/ are packaged here.
for corpus_dir in fuzz/corpus/*/; do
    target="$(basename "$corpus_dir")"
    if [[ -d "$corpus_dir" ]] && [[ -n "$(ls -A "$corpus_dir" 2>/dev/null)" ]]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "$corpus_dir"*
        echo "Packaged seed corpus for $target"
    fi
done

echo "=== OSS-Fuzz build complete ==="
