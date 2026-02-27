defmodule Reticulum.Transport.Proofs do
  @moduledoc """
  Explicit proof packet creation and validation helpers.
  """

  alias Reticulum.Identity
  alias Reticulum.Packet
  alias Reticulum.Packet.Context

  @hash_len 32
  @truncated_hash_len 16
  @signature_len 64
  @public_key_len 64

  @type parsed_proof :: %{
          proved_packet_hash: binary(),
          proof_destination_hash: binary(),
          signature: binary(),
          packet: Packet.t()
        }

  def build_explicit_proof_packet(proved_packet_hash, %Identity{} = identity, opts \\ [])
      when is_binary(proved_packet_hash) and is_list(opts) do
    context = Keyword.get(opts, :context, Context.none())
    hops = Keyword.get(opts, :hops, 0)

    with :ok <- validate_hash(proved_packet_hash, :invalid_packet_hash, @hash_len),
         :ok <- validate_signing_identity(identity),
         :ok <- validate_context(context),
         :ok <- validate_hops(hops) do
      signature = Identity.sign(identity, proved_packet_hash)
      proof_destination_hash = binary_part(proved_packet_hash, 0, @truncated_hash_len)

      {:ok,
       %Packet{
         ifac: :open,
         propagation: :broadcast,
         destination: :single,
         type: :proof,
         hops: hops,
         addresses: [proof_destination_hash],
         context: context,
         data: proved_packet_hash <> signature
       }}
    end
  end

  def parse_explicit_proof_packet(
        %Packet{type: :proof, addresses: [destination_hash], data: data} = packet
      )
      when is_binary(destination_hash) and is_binary(data) do
    with :ok <-
           validate_hash(destination_hash, :invalid_proof_destination_hash, @truncated_hash_len),
         {:ok, proved_packet_hash, signature} <- parse_proof_data(data),
         :ok <- validate_destination_binding(destination_hash, proved_packet_hash) do
      {:ok,
       %{
         proved_packet_hash: proved_packet_hash,
         proof_destination_hash: destination_hash,
         signature: signature,
         packet: packet
       }}
    end
  end

  def parse_explicit_proof_packet(_packet), do: {:error, :not_proof_packet}

  def validate_explicit_proof(
        %{proved_packet_hash: packet_hash, signature: signature},
        public_key
      )
      when is_binary(public_key) do
    with :ok <- validate_hash(packet_hash, :invalid_packet_hash, @hash_len),
         :ok <- validate_hash(signature, :invalid_proof_signature, @signature_len),
         :ok <- validate_hash(public_key, :invalid_public_key, @public_key_len) do
      <<_enc_pub::binary-size(32), sig_pub::binary-size(32)>> = public_key
      identity = %Identity{sig_pub: sig_pub}

      if Identity.validate(identity, packet_hash, signature) do
        :ok
      else
        {:error, :invalid_proof_signature}
      end
    end
  end

  def validate_explicit_proof(_proof, _public_key), do: {:error, :invalid_proof}

  defp parse_proof_data(data) when byte_size(data) >= @hash_len + @signature_len do
    <<packet_hash::binary-size(@hash_len), signature::binary-size(@signature_len), _rest::binary>> =
      data

    {:ok, packet_hash, signature}
  end

  defp parse_proof_data(_data), do: {:error, :proof_payload_too_short}

  defp validate_destination_binding(destination_hash, proved_packet_hash) do
    expected = binary_part(proved_packet_hash, 0, @truncated_hash_len)

    if expected == destination_hash do
      :ok
    else
      {:error, :proof_destination_hash_mismatch}
    end
  end

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
end
