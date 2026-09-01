.PHONY: all build build-contracts build-native test bench clean print-contract-artifacts

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

bench:
	cargo bench

clean:
	cargo clean