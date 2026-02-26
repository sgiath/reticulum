defmodule Reticulum.Crypto do
  @moduledoc """
  Cryptographic primitives used by Reticulum modules.

  This module intentionally contains only pure primitive operations and thin
  wrappers around OTP `:crypto`, while protocol-level composition is done in
  higher-level modules like `Reticulum.Identity` and `Reticulum.Packet`.

  References:

  - HKDF: RFC 5869 - https://www.rfc-editor.org/rfc/rfc5869
  - HMAC: RFC 2104 - https://www.rfc-editor.org/rfc/rfc2104
  - SHA-256: FIPS 180-4 - https://csrc.nist.gov/publications/detail/fips/180/4/final
  - X25519/Ed25519: RFC 7748 and RFC 8032

  For protocol semantics, see the Python reference implementation under
  `Reticulum/RNS/`.
  """

  @hash_len 32

  @doc """
  Derives key material with HKDF-SHA256.

  Parameters:

  - `ikm` - input keying material
  - `salt` - optional salt (defaults to zero salt per RFC 5869)
  - `info` - optional context/application info
  - `len` - output size in bytes

  Mirrors the behavior expected by the Reticulum reference implementation.
  """
  def hkdf(ikm, salt \\ <<>>, info \\ <<>>, len \\ 32)
      when len > 0 and is_binary(ikm) and byte_size(ikm) > 0 do
    salt
    |> hkdf_extract(ikm)
    |> hkdf_expand(info, len)
  end

  defp hkdf_extract(<<>>, ikm), do: hkdf_extract(<<0::size(256)>>, ikm)
  defp hkdf_extract(salt, ikm), do: hmac(salt, ikm)

  defp hkdf_expand(prk, info, len) do
    {<<okm::binary-size(len), _rest::binary>>, _t} =
      Enum.reduce(1..ceil(len / @hash_len), {<<>>, <<>>}, fn i, {okm, t} ->
        t = hmac(prk, t <> info <> <<i>>)
        {okm <> t, t}
      end)

    okm
  end

  @doc "Returns a SHA-256 digest for `data`."
  def sha256(data) do
    :crypto.hash(:sha256, data)
  end

  @doc "Returns HMAC-SHA256 over `data` using `key`."
  def hmac(key, data) do
    :crypto.mac(:hmac, :sha256, key, data)
  end

  @doc "Generates an Ed25519 keypair as `{public, private}` binaries."
  def ed25519 do
    :crypto.generate_key(:eddsa, :ed25519)
  end

  @doc "Generates an X25519 keypair as `{public, private}` binaries."
  def x25519 do
    :crypto.generate_key(:eddh, :x25519)
  end

  @doc "Computes X25519 shared secret from `%{sec: ..., pub: ...}`."
  def compute(%{sec: sec, pub: pub}) do
    :crypto.compute_key(:eddh, pub, sec, :x25519)
  end

  @doc "Produces an Ed25519 signature for `message` using private `key`."
  def sign(key, message) do
    :crypto.sign(:eddsa, :none, message, [key, :ed25519])
  end

  @doc "Validates an Ed25519 `signature` for `message` using public `key`."
  def validate(key, message, signature) do
    :crypto.verify(:eddsa, :none, message, signature, [key, :ed25519])
  end
end
