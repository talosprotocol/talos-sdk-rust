# =============================================================================
# Talos Rust SDK Makefile
# =============================================================================
SHELL := /bin/bash

# Variables
IMAGE_NAME ?= talos-sdk-rust
IMAGE_TAG ?= latest
REGISTRY ?= ghcr.io/talosprotocol
FULL_IMAGE := $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

.PHONY: all build test lint coverage coverage-html docker-build docker-push install-tools sbom release clean help

# Default target
all: build test

# Help
help:
	@echo "Talos Rust SDK - Available targets:"
	@echo "  make build          - Build the Rust crate"
	@echo "  make test           - Run all tests"
	@echo "  make lint           - Run linter (fmt + clippy)"
	@echo "  make coverage       - Generate coverage report (requires cargo-llvm-cov)"
	@echo "  make coverage-html  - Generate HTML coverage report"
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-push    - Push Docker image to registry"
	@echo "  make install-tools  - Install required Rust tools"
	@echo "  make sbom           - Generate Software Bill of Materials"
	@echo "  make release        - Build optimized release binary"
	@echo "  make clean          - Clean build artifacts"

# Build
build:
	@echo "🔨 Building Rust SDK..."
	cargo build

# Test (delegates to scripts/test.sh)
test:
	@echo "🧪 Running tests..."
	@./scripts/test.sh --unit

# Coverage (delegates to scripts/test.sh)
coverage:
	@echo "📊 Generating coverage report..."
	@./scripts/test.sh --coverage
lint:
	@echo "🔍 Running linter..."
	cargo fmt --check
	cargo clippy -- -D warnings


# HTML Coverage
coverage-html:
	@echo "📊 Generating HTML coverage report..."
	@mkdir -p artifacts/coverage
	@if command -v cargo-llvm-cov >/dev/null 2>&1; then \
		cargo llvm-cov --html --output-dir artifacts/coverage; \
		echo "✅ HTML coverage report: artifacts/coverage/index.html"; \
	else \
		echo "⚠️  cargo-llvm-cov not found. Install with: cargo install cargo-llvm-cov"; \
	fi

# Docker Build
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) -t $(FULL_IMAGE) -f Dockerfile .
	@echo "✅ Image built: $(IMAGE_NAME):$(IMAGE_TAG)"

# Docker Push
docker-push: docker-build
	@echo "📤 Pushing Docker image..."
	docker push $(FULL_IMAGE)
	@echo "✅ Image pushed: $(FULL_IMAGE)"

# Install Tools
install-tools:
	@echo "🔧 Installing Rust tools..."
	@which cargo-llvm-cov || (echo "Installing cargo-llvm-cov..." && cargo install cargo-llvm-cov)
	@which cargo-cyclonedx || (echo "Installing cargo-cyclonedx..." && cargo install cargo-cyclonedx)
	@echo "✅ All tools installed"

# SBOM
sbom:
	@echo "📋 Generating SBOM..."
	@which cargo-cyclonedx || cargo install cargo-cyclonedx
	cargo cyclonedx -f json
	@echo "✅ SBOM generated"

# Release Build
release:
	@echo "🚀 Building release binary..."
	cargo build --release
	@echo "✅ Release binary: target/release/"

# Clean
clean:
	@echo "🧹 Cleaning up..."
	cargo clean
	@rm -rf artifacts/
