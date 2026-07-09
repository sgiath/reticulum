# Reticulum Elixir Roadmap

This library implements the [Reticulum Network Stack](https://reticulum.network/)
in Elixir. The goal is feature parity for core RNS node behavior with the
reference Python implementation, delivered as an idiomatic OTP application.

Granular ticket-level tracking lives in Linear
([Reticulum project](https://linear.app/sgiath/project/reticulum-294c3a046c97));
this document describes the direction in broad strokes.

## Where we are

The core data plane for direct packet traffic is done. A node can:

- Run as a supervised OTP runtime, bootstrapped imperatively or from a
  TOML config file, with cold/warm startup modes and single-instance
  ownership semantics.
- Exchange packets over UDP, including authenticated IFAC interfaces.
- Encrypt and decrypt traffic for `:single` and `:group` destinations,
  including destination ratchets (memory-only for now).
- Announce destinations, discover and expire paths, and route traffic
  across multiple hops and interfaces with retry, backoff, and
  duplicate suppression tuned under mixed-topology tests.
- Track delivery through explicit and implicit proofs with a unified
  receipt state machine.

All of the above is covered by unit, integration, and Python-interop tests.

## Phase: Interface platform and parity

Turn the interface layer into a stable platform, then grow the set of
supported transports.

First, land the pluggable adapter contract with per-interface queue limits,
backpressure, rate limiting, and health scoring that feeds route selection
(this work is already in progress). On top of that platform:

- TCP interfaces (client and listener modes), interoperable with the
  reference `TCPInterface`.
- Pipe/stdio interface for external modems and bridge processes.
- Automatic LAN peer discovery (AutoInterface-style multicast peering).
- Interface mode semantics (`full`, `point_to_point`, `access_point`,
  `roaming`, `boundary`, `gateway`).
- IFAC and segmentation parity across all interface types.

## Phase: Messaging ergonomics

Make the high-level API pleasant to build applications on:

- Request/response correlation with timeouts, cancellation, and
  synchronous convenience helpers.
- Unregister and introspection counterparts for every registration API.
- A clear, structured caller-facing error taxonomy.
- Payload fragmentation/reassembly for messages larger than one packet.

## Phase: Links, channels, and resources

The largest missing piece of the Reticulum data plane:

- Link establishment: the `:link_request` handshake, session state
  machine, session key lifecycle, keepalive/teardown, and MTU/mode
  negotiation — interoperable with Python RNS peers.
- Channel semantics over links: sequenced, retransmitted, typed messages.
- Resource transfer: segmented large transfers with resume, hash
  verification, and timeout handling.
- Link-aware messaging APIs and a `GenDestination`-style destination
  server abstraction for applications.

## Phase: Durable runtime

Make node state survive restarts:

- Persist identities, destinations, and paths under `storage_path`, and
  feed the existing warm-restore startup hook from disk.
- Persist operational state: packet/announce hash caches,
  known-destination metadata, and destination ratchets (moving ratchets
  from memory-only to disk).
- Shared-instance parity: a local socket IPC surface so multiple local
  programs can use one running node, as in the reference implementation.

## Phase: Transport parity and resilience

Close the remaining gaps against reference transport behavior:

- Announce queueing and ingress-control policy (caps, hold/release,
  stale-announce handling).
- Control-plane parity: tunnel synthesis, blackhole handling,
  remote-management packet classes, and full packet-context coverage.
- Deterministic fault-injection campaigns in CI (loss, duplication,
  reordering, stale paths).

## Phase: Operations

Make the library operable in production:

- Diagnostics/status snapshot APIs and bounded-memory eviction policies
  for all runtime caches.
- A benchmark suite (latency, throughput, memory) and tuning guidance
  for constrained/high-latency links.
- Operator tooling equivalent to `rnsd`/`rnstatus`/`rnpath`/`rnprobe`.
- A maintained parity checklist and per-release compatibility matrix
  against the reference implementation.

## Beyond: Higher-level protocols

Once the data plane is complete, higher-level Reticulum ecosystem
protocols become possible, likely as separate libraries built on this one:

- LXMF (message transfer)
- LXST (streaming)
- RRTP
