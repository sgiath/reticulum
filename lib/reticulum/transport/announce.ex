defmodule Reticulum.Transport.Announce do
  @moduledoc """
  Announce payload parser/validator and payload builder.
  """

  alias Reticulum.Crypto
  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Packet
  alias Reticulum.Packet.Context

  @destination_hash_len 16
  @public_key_len 64
  @name_hash_len 10
  @random_hash_len 10
  @ratchet_len 32
  @signature_len 64
  @type parsed :: %{
          destination_hash: binary(),
          public_key: binary(),
          name_hash: binary(),
          random_hash: binary(),
          ratchet: binary(),
          signature: binary(),
          app_data: binary() | nil,
          path_response: boolean()
        }

  @type built :: %{
          payload: binary(),
          context_flag: 0 | 1,
          app_data: binary() | nil
        }

  def parse(%Packet{type: :announce, addresses: [destination_hash], data: data} = packet)
      when is_binary(destination_hash) and is_binary(data) do
    with :ok <- validate_destination_hash(destination_hash),
         {:ok, fields} <- parse_fields(data, packet.context_flag),
         :ok <- validate_signature(destination_hash, fields),
         :ok <- validate_destination_hash_binding(destination_hash, fields) do
      {:ok,
       %{
         destination_hash: destination_hash,
         public_key: fields.public_key,
         name_hash: fields.name_hash,
         random_hash: fields.random_hash,
         ratchet: fields.ratchet,
         signature: fields.signature,
         app_data: fields.app_data,
         path_response: context_value(packet.context) == Context.path_response()
       }}
    end
  end

  def parse(_packet), do: {:error, :not_announce_packet}

  def build_payload(%Destination{} = destination, opts \\ []) when is_list(opts) do
    app_data = Keyword.get(opts, :app_data, nil)
    random_hash = Keyword.get(opts, :random_hash, :crypto.strong_rand_bytes(@random_hash_len))
    ratchet = Keyword.get(opts, :ratchet, <<>>)

    with :ok <- validate_destination_hash(destination.hash),
         :ok <- validate_name_hash(destination.name_hash),
         {:ok, identity} <- validate_signing_identity(destination.identity),
         :ok <- validate_random_hash(random_hash),
         :ok <- validate_ratchet(ratchet),
         {:ok, app_data_bin} <- normalize_app_data(app_data) do
      public_key = identity.enc_pub <> identity.sig_pub

      signed_data =
        destination.hash <>
          public_key <> destination.name_hash <> random_hash <> ratchet <> app_data_bin

      signature = Identity.sign(identity, signed_data)

      {:ok,
       %{
         payload:
           public_key <>
             destination.name_hash <> random_hash <> ratchet <> signature <> app_data_bin,
         context_flag: if(ratchet == <<>>, do: 0, else: 1),
         app_data: if(app_data_bin == <<>>, do: nil, else: app_data_bin)
       }}
    end
  end

  defp parse_fields(data, context_flag) do
    ratchet_size = if context_flag in [1, true, :set], do: @ratchet_len, else: 0
    min_size = @public_key_len + @name_hash_len + @random_hash_len + ratchet_size + @signature_len

    if byte_size(data) < min_size do
      {:error, :announce_payload_too_short}
    else
      <<public_key::binary-size(@public_key_len), name_hash::binary-size(@name_hash_len),
        random_hash::binary-size(@random_hash_len), rest::binary>> = data

      {ratchet, after_ratchet} =
        if ratchet_size > 0 do
          <<ratchet::binary-size(@ratchet_len), remain::binary>> = rest
          {ratchet, remain}
        else
          {<<>>, rest}
        end

      <<signature::binary-size(@signature_len), app_data::binary>> = after_ratchet

      {:ok,
       %{
         public_key: public_key,
         name_hash: name_hash,
         random_hash: random_hash,
         ratchet: ratchet,
         signature: signature,
         app_data: if(app_data == <<>>, do: nil, else: app_data)
       }}
    end
  end

  defp validate_signature(destination_hash, fields) do
    <<_enc_pub::binary-size(32), sig_pub::binary-size(32)>> = fields.public_key
    identity = %Identity{sig_pub: sig_pub}

    app_data = fields.app_data || <<>>

    signed_data =
      destination_hash <>
        fields.public_key <> fields.name_hash <> fields.random_hash <> fields.ratchet <> app_data

    if Identity.validate(identity, signed_data, fields.signature) do
      :ok
    else
      {:error, :invalid_announce_signature}
    end
  end

  defp validate_destination_hash_binding(destination_hash, fields) do
    <<identity_hash::binary-size(@destination_hash_len), _rest::binary>> =
      Crypto.sha256(fields.public_key)

    expected_material = fields.name_hash <> identity_hash

    <<expected_hash::binary-size(@destination_hash_len), _rest::binary>> =
      Crypto.sha256(expected_material)

    if expected_hash == destination_hash do
      :ok
    else
      {:error, :announce_destination_hash_mismatch}
    end
  end

  defp validate_signing_identity(%Identity{} = identity)
       when is_binary(identity.enc_pub) and is_binary(identity.sig_pub) and
              is_binary(identity.sig_sec) do
    if byte_size(identity.enc_pub) == 32 and byte_size(identity.sig_pub) == 32 do
      {:ok, identity}
    else
      {:error, :invalid_identity_public_keys}
    end
  end

  defp validate_signing_identity(_identity), do: {:error, :invalid_identity}

  defp normalize_app_data(nil), do: {:ok, <<>>}
  defp normalize_app_data(app_data) when is_binary(app_data), do: {:ok, app_data}
  defp normalize_app_data(_app_data), do: {:error, :invalid_app_data}

  defp validate_destination_hash(hash)
       when is_binary(hash) and byte_size(hash) == @destination_hash_len,
       do: :ok

  defp validate_destination_hash(_hash), do: {:error, :invalid_destination_hash}

  defp validate_name_hash(name_hash)
       when is_binary(name_hash) and byte_size(name_hash) == @name_hash_len,
       do: :ok

  defp validate_name_hash(_name_hash), do: {:error, :invalid_name_hash}

  defp validate_random_hash(hash)
       when is_binary(hash) and byte_size(hash) == @random_hash_len,
       do: :ok

  defp validate_random_hash(_hash), do: {:error, :invalid_random_hash}

  defp validate_ratchet(ratchet)
       when is_binary(ratchet) and byte_size(ratchet) in [0, @ratchet_len],
       do: :ok

  defp validate_ratchet(_ratchet), do: {:error, :invalid_ratchet}

  defp context_value(context) do
    case Context.normalize(context) do
      {:ok, value} -> value
      _ -> -1
    end
  end
end
