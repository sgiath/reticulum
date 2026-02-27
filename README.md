# Reticulum

[![Hex.pm](https://img.shields.io/hexpm/v/reticulum.svg?style=flat&color=blue)](https://hex.pm/packages/reticulum)
[![Docs](https://img.shields.io/badge/api-docs-green.svg?style=flat)](https://hexdocs.pm/reticulum)

Elixir implementation of [Reticulum](https://github.com/markqvist/Reticulum) protocol

## Status

Core roadmap phases are implemented through runtime shell, UDP transport,
announce/path discovery, messaging API, and proof/receipt handling.

Runtime node tables (destinations, paths, packet-hash cache, interfaces, local
destinations, and message handlers) are ETS-only and intentionally cold-start on
every restart.

## Quick Start

```elixir
alias Reticulum.Destination
alias Reticulum.Identity
alias Reticulum.Node

{:ok, _pid} =
  Node.start_link(
    name: Reticulum.Node.Example,
    storage_path: Path.join(System.tmp_dir!(), "reticulum-example"),
    receipt_timeout_seconds: 3
  )

{:ok, _iface} =
  Node.start_udp_interface(Reticulum.Node.Example,
    name: :udp,
    listen_ip: {127, 0, 0, 1},
    listen_port: 43_001,
    default_peer_ip: {127, 0, 0, 1},
    default_peer_port: 43_002
  )

identity = Identity.new()
{:ok, destination} = Destination.new(:in, :single, "example", identity, ["inbox"])

:ok =
  Node.register_local_announce_destination(Reticulum.Node.Example, destination, self(),
    callback: fn event ->
      IO.inspect({:inbound_payload, event.packet.data})
    end
  )
```

## Config-Driven Bootstrap

Use `Reticulum.Node.start_from_config/2` to start a node and its interfaces from TOML:

```elixir
alias Reticulum.Node

{:ok, _pid} =
  Node.start_from_config("config/reticulum.example.toml",
    name: Reticulum.Node.ConfigExample
  )
```

The file format uses `[node]` and `[interfaces.<name>]` sections. See
`config/reticulum.example.toml` for a runnable reference.

`[node]` supports `startup_mode = "cold" | "warm_restore"`.

- `cold` runs cold-start lifecycle hooks.
- `warm_restore` runs warm-restore lifecycle hooks.

`[node]` also supports `use_implicit_proof = true | false`.

- `true` sends implicit proofs (signature only, reference-aligned default).
- `false` sends explicit proofs (packet hash + signature).

`[node]` also supports `ratchet_expiry_seconds`.

- ratchet announcements are cached in memory and expire after this TTL.
- persistence is currently memory-only; disk persistence lands with general runtime persistence.

For imperative startup, pass `startup_lifecycle: YourModule` to
`Reticulum.Node.start_link/1`. Lifecycle modules implement the
`Reticulum.Node.StartupLifecycle` callbacks.

Current runtime tables are still ETS-only, so warm restore currently behaves as
a no-op restore hook contract (persistence lands in the next phase).

## Send With Delivery Receipt

```elixir
alias Reticulum.Node

destination_hash = <<0::128>>
public_key = :crypto.strong_rand_bytes(64)

:ok = Node.put_destination(Reticulum.Node.Example, destination_hash, public_key, nil)

{:ok, receipt_hash} =
  Node.send_data(Reticulum.Node.Example, :udp, destination_hash, "hello", track_receipt: true)

case Node.receipt(Reticulum.Node.Example, receipt_hash) do
  {:ok, receipt} -> IO.inspect(receipt.status)
  :error -> :not_found
end
```

Inbound destinations only return proofs when `destination.proof_strategy` is set to
`:all` or `:app`.

- `:none` (default) never sends a proof
- `:all` always sends a proof
- `:app` calls `proof_requested_callback.(event)` and sends a proof only on `true`

`Reticulum.Node.send_data/5` encrypts payloads for `destination: :single` and `destination: :group`
when context is active data transport. To send unencrypted payloads, use `destination: :plain`.

```elixir
:ok =
  Node.send_data(Reticulum.Node.Example, :udp, destination_hash, "plain-payload",
    destination: :plain
  )
```

## Observability

`Reticulum.Transport` emits runtime hooks through `Reticulum.Observability`:

- telemetry event names start with `[:reticulum, ...]`
- proof events include `[:reticulum, :transport, :proof, :sent]` and
  `[:reticulum, :transport, :proof, :invalid]`
- receipt lifecycle events include `[:reticulum, :transport, :receipt, :tracked]`,
  `[:reticulum, :transport, :receipt, :delivered]`, and
  `[:reticulum, :transport, :receipt, :timed_out]`

Attach telemetry handlers in your application to collect and export metrics.
