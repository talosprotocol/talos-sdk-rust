# =============================================================================
# Talos Rust SDK - Tool Image (Monorepo-Root Context, Debian Slim)
# =============================================================================

# Builder stage
FROM rust:1.75-slim AS builder

WORKDIR /workspace

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files for caching
COPY sdks/rust/Cargo.toml sdks/rust/Cargo.lock ./sdks/rust/

# Create dummy source to cache dependencies
WORKDIR /workspace/sdks/rust
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source
WORKDIR /workspace
COPY sdks/rust ./sdks/rust
COPY scripts ./scripts

# Build tests
WORKDIR /workspace/sdks/rust
RUN cargo test --no-run

# Test runner stage
FROM rust:1.75-slim

# OCI labels
LABEL org.opencontainers.image.source="https://github.com/talosprotocol/talos"
LABEL org.opencontainers.image.description="Talos Rust SDK Tool Image"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /workspace/sdks/rust

# Install runtime dependencies (including for llvm-cov)
RUN apt-get update && apt-get install -y --no-install-recommends \
    make \
    bash \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy from builder
COPY --from=builder /workspace/sdks/rust ./
COPY --from=builder /workspace/scripts /workspace/scripts

# Create non-root user
RUN useradd -m -u 1000 talos && chown -R talos:talos /workspace
USER talos

# Default: run CI tests
CMD ["scripts/test.sh", "--ci"]
