SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c

CARGO ?= cargo
DOCKER ?= docker
MAKE ?= make

# Auto-detect Docker Compose v2 (docker compose) vs v1 (docker-compose)
DOCKER_COMPOSE ?= $(shell if $(DOCKER) compose version >/dev/null 2>&1; then echo "$(DOCKER) compose"; elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; else echo "$(DOCKER) compose"; fi)

CONTRACT_PACKAGES := schema-registry sas soroban-sas-indexer soroban-sas-cross-chain-verifier soroban-sas-zk-verifier
WASM_TARGET := wasm32-unknown-unknown
RELEASE_DIR := target/$(WASM_TARGET)/release
CONTRACT_WASM := \
	$(RELEASE_DIR)/schema_registry.wasm \
	$(RELEASE_DIR)/sas.wasm \
	$(RELEASE_DIR)/soroban_sas_indexer.wasm \
	$(RELEASE_DIR)/soroban_sas_cross_chain_verifier.wasm \
	$(RELEASE_DIR)/soroban_sas_zk_verifier.wasm

.PHONY: all help build build-contracts build-native test bench bench-attestations coverage gas-profile gas-dashboard smoke-local clean print-contract-artifacts \
	fmt lint install-hooks localnet localnet-down deploy-local

all: build test

help:
	@echo "Available targets:"
	@echo "  build              Build all release contract WASM artifacts"
	@echo "  build-contracts    Build contract WASMs using $(CARGO)"
	@echo "  build-native       Build native workspace binaries"
	@echo "  test               Run cargo test across workspace"
	@echo "  bench              Run cargo benchmarks"
	@echo "  bench-attestations Run 10k-attestation-per-ledger benchmarks"
	@echo "  coverage           Run cargo-tarpaulin and open HTML report locally"
	@echo "  gas-profile        Run gas profiling tests and write JSON snapshot to gas_profile_history/"
	@echo "  gas-dashboard      Render the ASCII gas history dashboard from gas_profile_history/"
	@echo "  fmt                Format code across workspace"
	@echo "  lint               Run formatting check and clippy linter"
	@echo "  install-hooks      Install git hooks into .git/hooks"
	@echo "  localnet           Start localnet Quickstart node and wait for readiness"
	@echo "  localnet-down      Stop localnet containers"
	@echo "  deploy-local       Deploy contracts to local network"
	@echo "  smoke-local        Run local smoke test in docker"
	@echo "  clean              Clean build artifacts"

build: build-contracts

build-contracts:
	$(CARGO) build --release --target $(WASM_TARGET) $(foreach package,$(CONTRACT_PACKAGES),--package $(package))
	@$(MAKE) --no-print-directory print-contract-artifacts

build-native:
	$(CARGO) build --workspace

print-contract-artifacts:
	@echo "Expected contract artifacts:"
	@for artifact in $(CONTRACT_WASM); do \
		if [ -f "$$artifact" ]; then \
			echo "  $$artifact"; \
		else \
			echo "  missing: $$artifact"; \
			exit 1; \
		fi; \
	done

test:
	$(CARGO) test --workspace

# Generate an HTML + XML + JSON coverage report locally.
# Requires cargo-tarpaulin: cargo install cargo-tarpaulin --locked
# Open coverage-report/tarpaulin-report.html in a browser afterwards.
coverage:
	$(CARGO) tarpaulin \
		--config .cargo/tarpaulin.toml \
		--workspace \
		--out xml html json \
		--output-dir coverage-report \
		--skip-clean

smoke-local:
	bash ./scripts/docker_smoke_test.sh

fmt:
	$(CARGO) fmt --all

# Same gates as CI's Formatting and Clippy jobs (and the pre-push hook).
lint:
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings

install-hooks:
	bash ./scripts/install_hooks.sh

# Standalone node from docker-compose.yml; see docs/local-development.md.
localnet:
	@./scripts/docker_preflight.sh
	@echo "Starting Stellar Quickstart..."
	$(DOCKER_COMPOSE) up -d stellar-quickstart
	bash ./scripts/wait_for_localnet.sh

localnet-down:
	$(DOCKER_COMPOSE) down -v --remove-orphans

deploy-local:
	bash ./scripts/deploy.sh --network local

bench:
	$(CARGO) bench

# Focused benchmark for the 10k-attestations-per-ledger performance target.
# Runs the bench targets whose names match "attestations" (e.g. attestations_benchmark).
# Use BENCH_FILTER to narrow further.
bench-attestations:
	$(CARGO) bench --bench attestations_benchmark $(if $(BENCH_FILTER),-- $(BENCH_FILTER))

# Run the in-process gas profiling tests and write a JSON snapshot.
# Use --test-threads=1 so the flush test always runs last.
gas-profile:
	$(CARGO) test -p sas -- gas_profiling --nocapture --test-threads=1

# Render the ASCII dashboard from the accumulated gas_profile_history/ snapshots.
gas-dashboard:
	bash tools/gas_dashboard.sh

clean:
	$(CARGO) clean
