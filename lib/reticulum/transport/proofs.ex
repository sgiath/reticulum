defmodule Reticulum.Transport.Proofs do
  @moduledoc """
  Proof packet creation, parsing, and signature validation helpers.
  """

  alias Reticulum.Identity
  alias Reticulum.Packet
  alias Reticulum.Packet.Context

  @hash_len 32
  @truncated_hash_len 16
  @signature_len 64
  @public_key_len 64

  @type mode :: :explicit | :implicit

  @type parsed_proof :: %{
          mode: mode(),
          proved_packet_hash: binary() | nil,
          proof_destination_hash: binary(),
          signature: binary(),
          packet: Packet.t()
        }

  def build_proof_packet(proved_packet_hash, %Identity{} = identity, opts \\ [])
      when is_binary(proved_packet_hash) and is_list(opts) do
    context = Keyword.get(opts, :context, Context.none())
    hops = Keyword.get(opts, :hops, 0)
    implicit? = Keyword.get(opts, :implicit, true)

    with :ok <- validate_hash(proved_packet_hash, :invalid_packet_hash, @hash_len),
         :ok <- validate_signing_identity(identity),
         :ok <- validate_context(context),
         :ok <- validate_hops(hops),
         :ok <- validate_implicit(implicit?) do
      signature = Identity.sign(identity, proved_packet_hash)
      proof_destination_hash = binary_part(proved_packet_hash, 0, @truncated_hash_len)
      data = proof_payload(proved_packet_hash, signature, implicit?)

      {:ok,
       %Packet{
         ifac: :open,
         propagation: :broadcast,
         destination: :single,
         type: :proof,
         hops: hops,
         addresses: [proof_destination_hash],
         context: context,
         data: data
       }}
    end
  end

  def parse_proof_packet(
        %Packet{type: :proof, addresses: [destination_hash], data: data} = packet
      )
      when is_binary(destination_hash) and is_binary(data) do
    with :ok <-
           validate_hash(destination_hash, :invalid_proof_destination_hash, @truncated_hash_len),
         {:ok, mode, proved_packet_hash, signature} <- parse_proof_data(data),
         :ok <- validate_destination_binding(mode, destination_hash, proved_packet_hash) do
      {:ok,
       %{
         mode: mode,
         proved_packet_hash: proved_packet_hash,
         proof_destination_hash: destination_hash,
         signature: signature,
         packet: packet
       }}
    end
  end

  def parse_proof_packet(_packet), do: {:error, :not_proof_packet}

  def validate_proof(
        %{mode: mode, proved_packet_hash: proof_packet_hash, signature: signature},
        public_key,
        proved_packet_hash
      )
      when is_binary(public_key) and is_binary(proved_packet_hash) do
    with :ok <- validate_mode(mode),
         :ok <- validate_hash(proved_packet_hash, :invalid_packet_hash, @hash_len),
         :ok <- validate_explicit_binding(mode, proof_packet_hash, proved_packet_hash),
         :ok <- validate_hash(signature, :invalid_proof_signature, @signature_len),
         :ok <- validate_hash(public_key, :invalid_public_key, @public_key_len) do
      <<_enc_pub::binary-size(32), sig_pub::binary-size(32)>> = public_key
      identity = %Identity{sig_pub: sig_pub}

      if Identity.validate(identity, proved_packet_hash, signature) do
        :ok
      else
        {:error, :invalid_proof_signature}
      end
    end
  end

  def validate_proof(_proof, _public_key, _proved_packet_hash), do: {:error, :invalid_proof}

  defp proof_payload(_proved_packet_hash, signature, true), do: signature
  defp proof_payload(proved_packet_hash, signature, false), do: proved_packet_hash <> signature

  defp parse_proof_data(
         <<packet_hash::binary-size(@hash_len), signature::binary-size(@signature_len)>>
       ) do
    {:ok, :explicit, packet_hash, signature}
  end

  defp parse_proof_data(<<signature::binary-size(@signature_len)>>) do
    {:ok, :implicit, nil, signature}
  end

  defp parse_proof_data(_data), do: {:error, :invalid_proof_length}

  defp validate_destination_binding(:implicit, _destination_hash, _proved_packet_hash), do: :ok

  defp validate_destination_binding(:explicit, destination_hash, proved_packet_hash) do
    expected = binary_part(proved_packet_hash, 0, @truncated_hash_len)

    if expected == destination_hash do
      :ok
    else
      {:error, :proof_destination_hash_mismatch}
    end
  end

  defp validate_destination_binding(_mode, _destination_hash, _proved_packet_hash),
    do: {:error, :invalid_proof_mode}

  defp validate_mode(mode) when mode in [:explicit, :implicit], do: :ok
  defp validate_mode(_mode), do: {:error, :invalid_proof_mode}

  defp validate_explicit_binding(:explicit, proved_packet_hash, expected_packet_hash)
       when is_binary(proved_packet_hash) do
    if proved_packet_hash == expected_packet_hash do
      :ok
    else
      {:error, :proof_packet_hash_mismatch}
    end
  end

  defp validate_explicit_binding(:implicit, _proof_packet_hash, _expected_packet_hash), do: :ok

  defp validate_explicit_binding(_mode, _proof_packet_hash, _expected_packet_hash),
    do: {:error, :invalid_proof_mode}

  defp validate_signing_identity(%Identity{} = identity)
       when is_binary(identity.sig_sec) and is_binary(identity.sig_pub) and
              byte_size(identity.sig_pub) == 32,
       do: :ok

  defp validate_signing_identity(_identity), do: {:error, :invalid_signing_identity}

  defp validate_hash(value, _reason, expected_len)
       when is_binary(value) and byte_size(value) == expected_len,
       do: :ok

  defp validate_hash(_value, reason, _expected_len), do: {:error, reason}

  defp validate_context(context) when is_integer(context) and context in 0..255, do: :ok
  defp validate_context(_context), do: {:error, :invalid_context}

  defp validate_hops(hops) when is_integer(hops) and hops >= 0 and hops <= 255, do: :ok
  defp validate_hops(_hops), do: {:error, :invalid_hops}

  defp validate_implicit(value) when is_boolean(value), do: :ok
  defp validate_implicit(_value), do: {:error, :invalid_implicit_flag}
end
