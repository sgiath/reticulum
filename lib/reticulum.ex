defmodule Reticulum do
  @moduledoc """
  Elixir implementation of core Reticulum protocol building blocks.

  This module is intentionally small and acts as an entry-point namespace.
  The implementation is split into focused modules:

  - `Reticulum.Crypto` - low-level primitives (HKDF, HMAC, X25519/Ed25519)
  - `Reticulum.Crypto.Fernet` - Reticulum token encryption format
  - `Reticulum.Identity` - key material, signatures, and ECIES-like encryption
  - `Reticulum.Destination` - destination naming and destination hash derivation
  - `Reticulum.Destination.Callbacks` - local destination callback registration
  - `Reticulum.Packet` - wire-format packet encode/decode and packet hashing
  - `Reticulum.PacketReceipt` - outbound delivery receipt tracking
  - `Reticulum.Node` - runtime shell and state tables for node lifecycle
  - `Reticulum.Node.StartupLifecycle` - startup mode callback contract
  - `Reticulum.Bootstrap.Config` - config-to-runtime bootstrap mapping
  - `Reticulum.Bootstrap.Parser.TOML` - TOML bootstrap parser/validator
  - `Reticulum.Interface` - contract for runtime network interfaces
  - `Reticulum.Interface.UDP` - UDP frame ingress/egress implementation
  - `Reticulum.Transport` - packet ingress/egress and duplicate filtering
  - `Reticulum.Transport.Announce` - announce payload validation and assembly
  - `Reticulum.Transport.Pathfinder` - path request/response and path maintenance
  - `Reticulum.Transport.Proofs` - explicit proof generation and validation
  - `Reticulum.Messaging` - high-level send/announce and request/response hooks
  - `Reticulum.Observability` - telemetry/logging runtime event hooks

  Reference material:

  - Reticulum manual: https://reticulum.network/manual/
  - Python reference implementation: `Reticulum/RNS/`
  """
end
