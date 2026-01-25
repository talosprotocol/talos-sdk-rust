# =============================================================================
# Talos Rust SDK - Tool Image (Monorepo-Root Context, Debian Slim)
# =============================================================================

# Builder stage
FROM rust:slim AS builder

WORKDIR /workspace

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    python3 \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files for caching
COPY sdks/rust/Cargo.toml ./sdks/rust/
COPY sdks/rust/talos-ucp ./sdks/rust/talos-ucp
COPY core ./core
RUN rm -f ./core/Cargo.lock
COPY scripts ./scripts

# Copy actual source
COPY sdks/rust ./sdks/rust

# Build tests
WORKDIR /workspace/sdks/rust
RUN cargo update
RUN cargo test --no-run

# Test runner stage
FROM rust:slim

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
RUN useradd -m -u 1001 talos && chown -R talos:talos /workspace
USER talos

# Default: run CI tests
CMD ["scripts/test.sh", "--ci"]
