.PHONY: all build test clean bench check-docs wait-localnet

all: build test

build:
	cargo build --release --target wasm32-unknown-unknown

test:
	cargo test --workspace

check-docs:
	./scripts/check_docs.sh

wait-localnet:
	./scripts/wait_for_localnet.sh

bench:
	cargo bench

clean:
	cargo clean
