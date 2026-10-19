# OSS-Fuzz builder image for soroban-sas.
#
# The base image (gcr.io/oss-fuzz-base/base-builder-rust) ships with the
# latest nightly Rust toolchain and cargo-fuzz pre-installed.  All we need
# to do here is:
#   1. Clone the repository.
#   2. Install our pinned nightly toolchain so the build is reproducible.
#   3. Copy build.sh into the standard OSS-Fuzz location.
#
# Reference: https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/
FROM gcr.io/oss-fuzz-base/base-builder-rust

# Clone the repository at HEAD.  OSS-Fuzz overrides this with the current
# main-branch commit when it builds; the URL here is only used for local
# `docker build` testing.
RUN git clone --depth 1 https://github.com/Soroban-Eas/soroban-sas.git soroban-sas

# Install the exact nightly toolchain that fuzz/Cargo.toml requires and that
# CI uses, so the OSS-Fuzz build is bit-for-bit reproducible with local
# `cargo fuzz` runs.
#
# The toolchain name must match the version used in:
#   - fuzz/Cargo.toml (rust-version / toolchain channel)
#   - .github/workflows/fuzz.yml (RUSTUP_TOOLCHAIN env)
#   - oss-fuzz/build.sh (FUZZ_TOOLCHAIN variable)
ENV FUZZ_TOOLCHAIN=nightly-2024-06-13
RUN rustup toolchain install $FUZZ_TOOLCHAIN --profile minimal

# Copy the build script into the standard OSS-Fuzz location.
COPY build.sh $SRC/
