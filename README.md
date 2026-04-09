# Talos SDK for Rust

This directory contains the core Rust SDK for the Talos Protocol, enabling high-performance, forward-secure agent-to-agent communication.

## Conformance

`scripts/test_conformance.sh` now passes the full pinned `v1.1.0` SDK release set, including canonical JSON, signing, capability verification, frame codec, MCP signing, ratchet micro-vectors, and the `v1_1_0_roundtrip.json` golden trace.

## A2A v1

`A2AJsonRpcClient` now provides Agent Card discovery, canonical `/rpc` helpers, Talos extension introspection, collect-style streaming helpers, callback-style per-event handling, and `Stream<Item = Result<...>>` returns for `SendStreamingMessage` and `SubscribeToTask`.

## Version Metadata

The crate root exports `SDK_VERSION`, `SUPPORTED_PROTOCOL_RANGE`, and `CONTRACT_MANIFEST_HASH`. Unit tests recompute the manifest digest from `contracts/sdk/contract_manifest.json` so the pinned metadata cannot silently drift.

## Quick Links

- [Talos Wiki](https://github.com/talosprotocol/talos/wiki)
- [Crates.io Package](https://crates.io/crates/talos-sdk)
- [API Documentation](https://docs.rs/talos-sdk)

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
