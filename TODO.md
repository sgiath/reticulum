# Reticulum Elixir Near-Term TODO

This file is the short-term, low-level execution list.
Long-term capability direction lives in `ROADMAP.md`.

## Phase 1 - Runtime Contracts and Bootstrap Foundation

- [ ] Make `transport_enabled` operational (forwarding role enabled/disabled at startup).
- [ ] Make `shared_instance` operational (single-runtime ownership semantics).
- [ ] Add config-file driven node and interface bootstrap (not only imperative startup).
- [ ] Add startup mode contract for cold start vs warm restore hooks.
- [ ] Add integration tests for startup ownership and bootstrap modes.

## Phase 2 - Packet and Crypto Semantics Completion

- [ ] Encrypt outbound payloads for supported destination types.
- [ ] Decrypt/validate inbound payloads for local destinations.
- [ ] Implement group destination crypto flow (`:group`) and validation paths.
- [ ] Implement implicit proof strategy behavior.
- [ ] Validate authenticated IFAC (`ifac: :auth`) packet path end-to-end.
- [ ] Expand active packet-context handling to full supported set.

## Phase 3 - Messaging API Completion and Caller Ergonomics

- [ ] Add request/response correlation API (pending map + timeout + cancellation).
- [ ] Add unregister/introspection helpers to mirror all registration APIs.
- [ ] Add clearer caller-facing error taxonomy.
- [ ] Add payload fragmentation/reassembly helpers.
- [ ] Add link-aware messaging API once link layer lands.

## Phase 4 - Transport and Routing Plane Completion

- [ ] Implement full transit forwarding across multiple interfaces.
- [ ] Add route/path selection policy (hops, freshness, interface health).
- [ ] Add path request retry/backoff and duplicate suppression tuning.
- [ ] Add announce forwarding policy and loop protection.
- [ ] Add forwarding policy tests under mixed interface/topology scenarios.

## Phase 5 - Interface Parity and Extensibility

- [ ] Add TCP interface support (client + listener modes).
- [ ] Add pipe/stdio interface for external modem/process integration.
- [ ] Add stable adapter contract for pluggable custom interfaces.
- [ ] Add interface auth/segmentation controls and IFAC integration hooks.
- [ ] Add per-interface queue limits, backpressure, and rate limiting.
