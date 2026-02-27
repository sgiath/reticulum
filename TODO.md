# Reticulum Elixir Near-Term TODO

This file is the short-term, low-level execution list.
Long-term capability direction lives in `ROADMAP.md`.

## Phase 1 - Runtime Ownership Toggles

Implemented in commit `95aa293`.

- [x] Make `transport_enabled` operational (forwarding role enabled/disabled at startup).
- [x] Make `shared_instance` operational (single-runtime ownership semantics).
- [x] Add integration tests for startup ownership semantics.

## Phase 2 - Bootstrap Config Pipeline

Implemented in commit `e85fa91`.

- [x] Add config-file driven node and interface bootstrap (not only imperative startup).
- [x] Add schema-validated bootstrap parser (TOML first) with explicit config-to-runtime mapping.
- [x] Add integration tests for config-driven bootstrap paths.

## Phase 3 - Startup Lifecycle Contracts

- [x] Add startup mode contract for cold start vs warm restore hooks.
- [x] Add integration tests for startup mode behavior.
- [x] Update `config/reticulum.example.toml` + README config section for startup mode options.

## Phase 4 - Packet Crypto Baseline

- [ ] Encrypt outbound payloads for supported destination types.
- [ ] Decrypt/validate inbound payloads for local destinations.
- [ ] Expand active packet-context handling to full supported set.

## Phase 5 - Proof and Receipt Semantics

- [ ] Implement implicit proof strategy behavior.
- [ ] Unify explicit + implicit proof parsing/validation through one receipt state machine.
- [ ] Add reference-vector coverage for proof edge cases.

## Phase 6 - Advanced Destination Crypto

- [ ] Implement group destination crypto flow (`:group`) and validation paths.
- [ ] Add destination ratchet lifecycle (ingest, persist policy, key selection, expiry).
- [ ] Add reference-vector coverage for encrypted data edge cases.

## Phase 7 - IFAC Auth End-to-End

- [ ] Validate authenticated IFAC (`ifac: :auth`) packet path end-to-end.
- [ ] Add targeted protocol-path tests for IFAC auth behavior.
- [ ] Update `config/reticulum.example.toml` + README config section for IFAC auth options.

## Phase 8 - Routing Core

- [ ] Implement full transit forwarding across multiple interfaces.
- [ ] Add route/path selection policy (hops, freshness, interface health).
- [ ] Add announce forwarding policy and loop protection.
- [ ] Update `config/reticulum.example.toml` + README config section for routing policy options.

## Phase 9 - Routing Resilience and Topology Tests

- [ ] Add path request retry/backoff and duplicate suppression tuning.
- [ ] Add forwarding policy tests under mixed interface/topology scenarios.

## Phase 10 - Interface Platform Foundation

- [ ] Add stable adapter contract for pluggable custom interfaces.
- [ ] Keep interface implementations OTP-native (supervised workers, no unmanaged spawned interface processes).
- [ ] Add per-interface queue limits, backpressure, and rate limiting.
- [ ] Update `config/reticulum.example.toml` + README config section for queue/backpressure/rate-limit options.

## Phase 11 - Interface Parity Implementations

- [ ] Add TCP interface support (client + listener modes).
- [ ] Add pipe/stdio interface for external modem/process integration.
- [ ] Add interface auth/segmentation controls and IFAC integration hooks.
- [ ] Update `config/reticulum.example.toml` + README config section with TCP + pipe + auth/segmentation examples.

## Phase 12 - Messaging API Core Ergonomics

- [ ] Add request/response correlation API (pending map + timeout + cancellation).
- [ ] Add unregister/introspection helpers to mirror all registration APIs.
- [ ] Add clearer caller-facing error taxonomy.
- [ ] Add payload fragmentation/reassembly helpers.
- [ ] Add optional synchronous convenience helpers built on async internals (no blocking `receive` loops in runtime servers).

## Phase 13 - Messaging Abstractions (Dependency-Gated)

- [ ] Add link-aware messaging API once link layer lands.
- [ ] Add a `GenDestination`-style destination server abstraction with supervised lifecycle and callback hooks.
