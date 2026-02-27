# Reticulum Elixir Roadmap

This file tracks implemented capability status and long-term direction.
Detailed short-term execution lives in `TODO.md`.

## Current Capability Snapshot

Status below is based on what is currently implemented in this repository.

### Interfaces

- [x] Runtime interface behavior and lifecycle contract (`Reticulum.Interface`).
- [x] UDP interface with inbound/outbound frame publishing (`Reticulum.Interface.UDP`).
- [x] Interface runtime management (start/list/stop/send via `Reticulum.Interface.Supervisor`).
- [ ] TCP client/listener interfaces.
- [ ] Pipe/stdio interface.
- [ ] External pluggable interface loading.
- [ ] Interface authentication and segmentation controls (IFAC key material).
- [ ] Per-interface queue/backpressure/rate-limiting metadata.

### Packets, Transport, and Messaging

- [x] Packet struct and wire-format encode/decode (`Reticulum.Packet`).
- [x] Packet hash and truncated hash parity with Python vectors.
- [x] Raw frame send/receive through runtime node APIs.
- [x] Transport ingress/egress pipeline with duplicate suppression.
- [x] Announce parse/validate/build and destination/path ingestion.
- [x] Path request/path response and path TTL expiration.
- [x] Local destination callbacks and request/response hook registration.
- [x] Delivery receipt tracking with explicit proof validation.
- [x] High-level messaging send/announce API wrappers.
- [ ] Payload encryption/decryption for destination packet data flows (`:single`/`:group`).
- [ ] Implicit proof behavior and `Destination.proof_strategy` semantics.
- [ ] Full authenticated IFAC (`ifac: :auth`) processing path.
- [ ] Multi-hop forwarding plane and route selection policy.
- [ ] Payload fragmentation/reassembly for large application messages.

### Link, Channel, and Resource Layers

- [ ] Link establishment/lifecycle (`:link_request` flow and session state machine).
- [ ] Channel semantics over links.
- [ ] Resource transfer primitives (segmenting/resume/timeout).

### Runtime, Persistence, and Operations

- [x] Node runtime shell, config validation, and supervision tree.
- [x] ETS-backed runtime tables for destinations/paths/interfaces/handlers.
- [x] Telemetry/log hooks for transport receipt/proof lifecycle.
- [ ] Persistent storage for identities/destinations/paths.
- [ ] Warm-start restore policy from persisted runtime state.
- [ ] Config-file driven bootstrap (instead of imperative-only startup).
- [ ] `transport_enabled` operational behavior.
- [ ] `shared_instance` ownership semantics.
- [ ] Diagnostics/status snapshots and bounded-memory policies.

### Interop and Test Coverage

- [x] Elixir <-> Python interop vectors for packet, crypto, identity, destination.
- [x] Integration interop tests for send/receive network sessions.
- [x] Malformed input and regression coverage for current packet/crypto scope.
- [ ] Interop coverage for links/channels/resources.
- [ ] Fault-injection campaigns (loss/duplication/reordering/stale paths).
- [ ] Release compatibility matrix reports.

## Long-Term Roadmap (Capability Horizons)

### Horizon 1 - Complete Core Reticulum Data Plane

- [ ] Implement links, channels, and resources as first-class layers.
- [ ] Add link session key lifecycle and keepalive/teardown behavior.
- [ ] Ensure end-to-end interoperability for link/channel/resource traffic.

### Horizon 2 - Durable and Config-Driven Runtime

- [ ] Persist identity, destination, and path state under `storage_path`.
- [ ] Add startup policy for cold vs warm restore.
- [ ] Add file-based configuration bootstrap for node + interfaces.
- [ ] Make `shared_instance` enforce single-runtime ownership semantics.

### Horizon 3 - Compliance and Fault Tolerance

- [ ] Extend interop suite to full packet context and authenticated-interface coverage.
- [ ] Add deterministic network fault simulation to CI.
- [ ] Publish compatibility matrix per release against reference behavior.

### Horizon 4 - Performance and Operability

- [ ] Add benchmark suite (latency, throughput, memory) across all active interfaces.
- [ ] Add bounded-memory eviction policies for packet/path/receipt/request caches.
- [ ] Add richer telemetry and diagnostics APIs for operations.
- [ ] Publish tuning guidance for constrained/high-latency links.

### Horizon 5 - Higher-Level RNS Protocols

- [ ] LXMF.
- [ ] LXST.
- [ ] RRTP.

## Definition of Done

- [ ] New phase capabilities have green unit/integration coverage.
- [ ] Interop checks are added for every newly completed protocol layer.
- [ ] `mix check --no-retry` passes for roadmap-delivering changes.
- [ ] README/docs include runnable examples for completed major capabilities.
- [ ] Release notes include updated compatibility/feature matrix.
