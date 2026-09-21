# Multi-stage Dockerfile for ULPF
# Produces a lean (< 50MB) air-gapped container

# Stage 1: Build binary
FROM rust:1-slim AS builder
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates

# Build release binaries
RUN cargo build --release -p ulpf-cli -p ulpf-generator

# Stage 2: Minimal runtime
FROM debian:bookworm-slim
WORKDIR /opt/ulpf

RUN apt-get update && apt-get install -y ca-certificates python3 && rm -rf /var/lib/apt/lists/*

# Copy binaries
COPY --from=builder /app/target/release/ulpf /usr/local/bin/ulpf
COPY --from=builder /app/target/release/ulpf-generator /usr/local/bin/ulpf-generator

# Copy data and scripts
COPY data ./data
COPY scripts ./scripts
COPY docs ./docs

# Expose Syslog UDP and TCP ports
EXPOSE 5140/udp 5140/tcp

ENV RUST_LOG=info
ENTRYPOINT ["ulpf"]
CMD ["ingest", "--udp", "0.0.0.0:5140", "--tcp", "0.0.0.0:5140", "--parquet-dir", "/opt/ulpf/data/parquet", "--batch-size", "1000", "--batch-timeout", "2000"]
