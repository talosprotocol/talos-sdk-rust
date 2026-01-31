# Agent workspace: sdks/rust

This folder contains agent-facing context, tasks, workflows, and planning artifacts for this submodule.

## Current State
Rust SDK is present or staged. Rust is also a candidate for a narrow performance wedge once DI boundaries are stable.

## Expected State
Clear separation between kernel-grade primitives and SDK ergonomics. Vector-driven compliance is mandatory.

## Behavior
Rust client SDK and potential home for performance-critical primitives, depending on architecture decisions.

## How to work here
- Run/tests:
- Local dev:
- CI notes:

## Interfaces and dependencies
- Owned APIs/contracts:
- Depends on:
- Data stores/events (if any):

## Global context
See `.agent/context.md` for monorepo-wide invariants and architecture.
