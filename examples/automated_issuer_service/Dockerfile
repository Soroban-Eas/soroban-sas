FROM rust:1.83-slim AS builder
WORKDIR /workspace
COPY . .
RUN cargo build --release --example automated_issuer_service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/target/release/examples/automated_issuer_service /usr/local/bin/issuer
USER nobody
ENTRYPOINT ["/usr/local/bin/issuer"]
