#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Talos SDK Conformance Runner (Rust)
# =============================================================================
# Validation Level: Interop-Grade
# Release Set: Pinned in .talos-version
# =============================================================================

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION_FILE="$REPO_ROOT/.talos-version"

if [[ ! -f "$VERSION_FILE" ]]; then
    echo "❌ ERROR: Missing .talos-version file."
    exit 1
fi

RELEASE_SET=$(cat "$VERSION_FILE" | tr -d '[:space:]')
echo "🔒 Conformance Target: $RELEASE_SET"

# Resolve Monorepo Root (sdks/rust/../..)
MONOREPO_ROOT="$(cd "$REPO_ROOT/../.." && pwd)"
CONTRACTS_DIR="${TALOS_CONTRACTS_DIR:-$MONOREPO_ROOT/contracts}"
VECTORS_FILE="$CONTRACTS_DIR/test_vectors/sdk/release_sets/$RELEASE_SET.json"

if [[ ! -f "$VECTORS_FILE" ]]; then
    echo "❌ ERROR: Test vectors for $RELEASE_SET not found at $VECTORS_FILE"
    echo "   Ensure talos-contracts submodule is initialized."
    exit 1
fi

echo "✅ Vectors Found: $VECTORS_FILE"
cargo run --bin vector_runner -- "$VECTORS_FILE"
