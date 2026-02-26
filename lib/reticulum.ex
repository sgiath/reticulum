defmodule Reticulum do
  @moduledoc """
  Elixir implementation of core Reticulum protocol building blocks.

  This module is intentionally small and acts as an entry-point namespace.
  The implementation is split into focused modules:

  - `Reticulum.Crypto` - low-level primitives (HKDF, HMAC, X25519/Ed25519)
  - `Reticulum.Crypto.Fernet` - Reticulum token encryption format
  - `Reticulum.Identity` - key material, signatures, and ECIES-like encryption
  - `Reticulum.Destination` - destination naming and destination hash derivation
  - `Reticulum.Packet` - wire-format packet encode/decode and packet hashing

  Reference material:

  - Reticulum manual: https://reticulum.network/manual/
  - Python reference implementation: `Reticulum/RNS/`
  """
end
