.PHONY: all build build-contracts build-native test bench smoke-local clean print-contract-artifacts \
	fmt lint install-hooks localnet localnet-down deploy-local

CONTRACT_PACKAGES := schema-registry sas soroban-sas-indexer
WASM_TARGET := wasm32-unknown-unknown
RELEASE_DIR := target/$(WASM_TARGET)/release
CONTRACT_WASM := \
	$(RELEASE_DIR)/schema_registry.wasm \
	$(RELEASE_DIR)/sas.wasm \
	$(RELEASE_DIR)/soroban_sas_indexer.wasm

all: build test

build: build-contracts

build-contracts:
	cargo build --release --target $(WASM_TARGET) $(foreach package,$(CONTRACT_PACKAGES),--package $(package))
	@$(MAKE) --no-print-directory print-contract-artifacts

build-native:
	cargo build --workspace

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
	cargo test --workspace

smoke-local:
	bash ./scripts/docker_smoke_test.sh

fmt:
	cargo fmt --all

# Same gates as CI's Formatting and Clippy jobs (and the pre-push hook).
lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

install-hooks:
	./scripts/install_hooks.sh

# Standalone node from docker-compose.yml; see docs/local-development.md.
localnet:
	docker compose up -d stellar-quickstart
	./scripts/wait_for_localnet.sh

localnet-down:
	docker compose down

deploy-local:
	./scripts/deploy.sh --network local

bench:
	cargo bench

clean:
	cargo clean