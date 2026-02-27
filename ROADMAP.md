# Reticulum Elixir Roadmap

## Goal

Move from MVP parity (runtime + UDP + basic messaging/proofs) to practical
feature completeness for core Reticulum behavior.

## Implemented So Far (Phases 1-7)

Condensed progress notes from `ROADMAP_OLD.md`:

- [x] Phase 1: Node runtime shell (config validation, supervision tree, runtime state).
- [x] Phase 2: Interface MVP (interface behavior/lifecycle + UDP interface + packet I/O framing).
- [x] Phase 3: Transport MVP (outbound/inbound pipelines + duplicate suppression + destination registry wiring).
- [x] Phase 4: Announces/path discovery (announce ingest, destination memory, path request/response, path expiry/refresh).
- [x] Phase 5: Messaging API baseline (destination callbacks, high-level send/announce APIs, request/response hooks).
- [x] Phase 6: Proofs/receipts baseline (receipt tracking, explicit proofs, delivery callbacks/status transitions).
- [x] Phase 7: Interop/hardening baseline (Elixir/Python E2E tests, malformed input property/fuzz tests, telemetry/docs).

## Why This Roadmap Exists

Current implementation is solid for the first slice, but several core protocol
areas are still partial:

- only UDP interface is implemented (`Node.start_udp_interface/2`)
- transport forwarding is minimal (no full multi-hop forwarding plane)
- packet encryption/decryption semantics are not complete for all destination types
- link/channel/resource flows are not implemented
- runtime persistence/config bootstrap are minimal
- some config fields exist but are not operational (`transport_enabled`, `shared_instance`)

## Roadmap

### Phase 8 - Interface Parity

- [ ] Add TCP interface support (client + listener modes).
- [ ] Add pipe/stdio interface for external modem/process integration.
- [ ] Add pluggable custom interface loading through a stable behavior/adapter contract.
- [ ] Add interface auth/segmentation controls (IFAC/auth key material per interface).
- [ ] Add per-interface rate limiting, queue/backpressure, and MTU metadata.

Candidate modules:

- `Reticulum.Interface.TCP`
- `Reticulum.Interface.Pipe`
- `Reticulum.Interface.Loader`

Candidate tests:

- `test/reticulum/interface/tcp_test.exs`
- `test/reticulum/interface/pipe_test.exs`
- `test/reticulum/interface/auth_test.exs`

### Phase 9 - Packet and Crypto Semantics Completion

- [ ] Implement outbound payload encryption for `:single` destinations and matching inbound decryption.
- [ ] Implement group destination crypto flow (`:group`) and validation paths.
- [ ] Implement implicit proof behavior and proof strategy handling (`Destination.proof_strategy`).
- [ ] Validate/handle authenticated interface packets (`ifac: :auth`) end-to-end.
- [ ] Expand packet context handling to full reference-compatible set for active features.

Candidate modules:

- `Reticulum.Packet`
- `Reticulum.Transport`
- `Reticulum.Destination`
- `Reticulum.Identity`

Candidate tests:

- `test/reticulum/transport/crypto_flow_test.exs`
- `test/reticulum/reference/crypto_interop_test.exs`

### Phase 10 - Transport and Routing Plane Completion

- [ ] Implement full forwarding behavior for transit traffic across interfaces.
- [ ] Add route/path selection policy (hops, freshness, interface availability).
- [ ] Add path request retry/backoff and duplicate request suppression policy tuning.
- [ ] Add announce forwarding policy and loop protection across multi-interface nodes.
- [ ] Make `transport_enabled` operational (disable/enable forwarding roles at runtime start).

Candidate modules:

- `Reticulum.Transport`
- `Reticulum.Transport.Pathfinder`
- `Reticulum.Transport.Announce`

Candidate tests:

- `test/reticulum/transport/forwarding_test.exs`
- `test/reticulum/transport/path_selection_test.exs`

### Phase 11 - Link, Channel, and Resource Layer

- [ ] Implement link establishment and lifecycle state machine (`:link_request` flows).
- [ ] Add encrypted link sessions with key lifecycle/rotation behavior.
- [ ] Add channel semantics (ordered/reliable framed exchange over links).
- [ ] Add resource transfer primitives (segmentation, checks, resume/timeout paths).
- [ ] Add API surface for link open/close, send/receive, and transfer progress.

Candidate modules:

- `Reticulum.Link`
- `Reticulum.Channel`
- `Reticulum.Resource`

Candidate tests:

- `test/reticulum/link/handshake_test.exs`
- `test/reticulum/channel/reliability_test.exs`
- `test/reticulum/resource/transfer_test.exs`

### Phase 12 - Messaging API Completion

- [ ] Add request/response correlation API (pending map, timeout, cancellation).
- [ ] Add unregister/introspection helpers to mirror all registration APIs.
- [ ] Add message fragmentation/reassembly path for payloads beyond single-packet practical MTU.
- [ ] Add link-aware messaging API once link layer lands.
- [ ] Add clearer error taxonomy for callers (routing, crypto, interface, timeout classes).

Candidate modules:

- `Reticulum.Messaging`
- `Reticulum.Destination.Callbacks`
- `Reticulum.Node`

Candidate tests:

- `test/reticulum/messaging/request_response_test.exs`
- `test/reticulum/messaging/error_taxonomy_test.exs`

### Phase 13 - Persistence and Bootstrap

- [ ] Persist identities, known destinations, and path cache snapshots under `storage_path`.
- [ ] Add configurable restore policy at startup (cold start vs warm cache).
- [ ] Add config-file driven node and interface boot (not only imperative API startup).
- [ ] Implement distributed bootstrap/backbone discovery hooks for first connectivity.
- [ ] Make `shared_instance` operational (single runtime ownership semantics).

Candidate modules:

- `Reticulum.Storage`
- `Reticulum.Node.Config.Loader`
- `Reticulum.Bootstrap`

Candidate tests:

- `test/reticulum/storage/persistence_test.exs`
- `test/reticulum/bootstrap/discovery_test.exs`

### Phase 14 - Interop, Compliance, and Fault Tolerance

- [ ] Extend Elixir <-> Python interop suite to cover links, channels, and resources.
- [ ] Add protocol compliance vectors for packet contexts, authenticated interfaces, and proofs.
- [ ] Add deterministic fault-injection tests (packet loss, duplication, reordering, stale paths).
- [ ] Add property/fuzz campaigns for packet decode + transport ingress invariants.
- [ ] Build a compatibility matrix report per release.

Candidate tests:

- `test/reticulum/interop/link_session_test.exs`
- `test/reticulum/interop/resource_transfer_test.exs`
- `test/reticulum/faults/network_faults_test.exs`

### Phase 15 - Performance and Operations Hardening

- [ ] Add benchmark suite (latency, throughput, memory) across UDP/TCP/pipe.
- [ ] Add bounded memory policies for caches, receipts, and pending request state.
- [ ] Expand telemetry schema (per-interface tx/rx, queue depth, routing/proof outcomes).
- [ ] Add operational diagnostics APIs (status snapshots, counters, route table summaries).
- [ ] Publish tuning guide for low-bandwidth and high-latency networks.

Candidate modules:

- `Reticulum.Observability`
- `Reticulum.Diagnostics`

Candidate tests/benches:

- `test/reticulum/observability/metrics_schema_test.exs`
- `bench/transport_bench.exs`

## Definition of Done For This Roadmap

- [ ] Each phase has green unit + integration coverage and interop checks.
- [ ] `mix check --no-retry` passes for all changes.
- [ ] README/docs include runnable examples for each major capability.
- [ ] Compatibility notes list supported features vs Python reference scope.
