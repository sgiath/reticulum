defmodule Reticulum.Transport.PacketCrypto do
  @moduledoc false

  alias Reticulum.Destination
  alias Reticulum.Crypto.Fernet
  alias Reticulum.Identity
  alias Reticulum.Packet
  alias Reticulum.Packet.Context

  @public_key_len 64
  @group_key_lengths [32, 64]
  @ratchet_public_len 32

  def encrypt_outbound(%Packet{} = packet, destination_record) when is_map(destination_record) do
    with {:ok, _context} <- Context.normalize(packet.context),
         :ok <- validate_destination_type(packet.destination, packet.type) do
      if encryption_bypassed?(packet) do
        {:ok, packet}
      else
        encrypt_packet(packet, destination_record)
      end
    end
  end

  def encrypt_outbound(_packet, _destination_record), do: {:error, :invalid_packet}

  def decrypt_inbound(%Packet{} = packet, local_destination) when is_map(local_destination) do
    with {:ok, _context} <- Context.normalize(packet.context),
         :ok <- validate_destination_type(packet.destination, packet.type) do
      if encryption_bypassed?(packet) do
        {:ok, packet}
      else
        decrypt_packet(packet, local_destination)
      end
    end
  end

  def decrypt_inbound(_packet, _local_destination), do: {:error, :invalid_packet}

  defp encrypt_packet(%Packet{destination: :single, data: payload} = packet, destination_record)
       when is_binary(payload) do
    with {:ok, identity} <- destination_identity(destination_record),
         {:ok, ratchet} <- destination_ratchet(destination_record) do
      ciphertext =
        case ratchet do
          nil -> Identity.encrypt(identity, payload)
          ratchet_public -> Identity.encrypt(identity, payload, target_enc_pub: ratchet_public)
        end

      {:ok, %{packet | data: ciphertext}}
    end
  end

  defp encrypt_packet(%Packet{destination: :single}, _destination_record),
    do: {:error, :invalid_payload}

  defp encrypt_packet(%Packet{destination: :group, data: payload} = packet, destination_record)
       when is_binary(payload) do
    with {:ok, group_key} <- destination_group_key(destination_record) do
      ciphertext = destination_group_cipher(group_key, payload)
      {:ok, %{packet | data: ciphertext}}
    end
  end

  defp encrypt_packet(%Packet{destination: :group}, _destination_record),
    do: {:error, :invalid_payload}

  defp decrypt_packet(%Packet{destination: :single, data: ciphertext} = packet, local_destination)
       when is_binary(ciphertext) do
    with {:ok, identity, ratchets, enforce_ratchets} <- local_decrypt_identity(local_destination),
         {:ok, plaintext} <-
           Identity.decrypt(identity, ciphertext,
             ratchets: ratchets,
             enforce_ratchets: enforce_ratchets
           ) do
      {:ok, %{packet | data: plaintext}}
    end
  end

  defp decrypt_packet(%Packet{destination: :single}, _local_destination),
    do: {:error, :invalid_payload}

  defp decrypt_packet(%Packet{destination: :group, data: ciphertext} = packet, local_destination)
       when is_binary(ciphertext) do
    with {:ok, group_key} <- local_group_key(local_destination),
         {:ok, plaintext} <- destination_group_decipher(group_key, ciphertext) do
      {:ok, %{packet | data: plaintext}}
    end
  end

  defp decrypt_packet(%Packet{destination: :group}, _local_destination),
    do: {:error, :invalid_payload}

  defp validate_destination_type(:single, _type), do: :ok
  defp validate_destination_type(:group, _type), do: :ok
  defp validate_destination_type(:plain, _type), do: :ok
  defp validate_destination_type(:link, :proof), do: :ok
  defp validate_destination_type(:link, _type), do: {:error, :unsupported_destination_type}
  defp validate_destination_type(_destination, _type), do: {:error, :invalid_destination_type}

  defp encryption_bypassed?(%Packet{destination: :plain}), do: true
  defp encryption_bypassed?(%Packet{type: :announce}), do: true
  defp encryption_bypassed?(%Packet{type: :link_request}), do: true

  defp encryption_bypassed?(%Packet{type: :proof, destination: :link}),
    do: true

  defp encryption_bypassed?(%Packet{type: :proof, context: context}),
    do: context_value(context) == Context.resource_prf()

  defp encryption_bypassed?(%Packet{context: context}), do: Context.encryption_exempt?(context)

  defp destination_identity(%{public_key: <<enc_pub::binary-size(32), sig_pub::binary-size(32)>>}) do
    {:ok, Identity.update_hash(%Identity{enc_pub: enc_pub, sig_pub: sig_pub})}
  end

  defp destination_identity(%{public_key: public_key})
       when is_binary(public_key) and byte_size(public_key) != @public_key_len,
       do: {:error, :invalid_destination_public_key}

  defp destination_identity(_destination_record), do: {:error, :invalid_destination_public_key}

  defp destination_ratchet(%{ratchet: nil}), do: {:ok, nil}

  defp destination_ratchet(%{ratchet: ratchet})
       when is_binary(ratchet) and byte_size(ratchet) == @ratchet_public_len,
       do: {:ok, ratchet}

  defp destination_ratchet(%{ratchet: <<>>}), do: {:ok, nil}
  defp destination_ratchet(%{ratchet: _ratchet}), do: {:error, :invalid_destination_ratchet}
  defp destination_ratchet(_destination_record), do: {:ok, nil}

  defp destination_group_key(%{group_key: group_key})
       when is_binary(group_key) and byte_size(group_key) in @group_key_lengths,
       do: {:ok, group_key}

  defp destination_group_key(%{group_key: nil}), do: {:error, :missing_group_key}
  defp destination_group_key(%{group_key: _group_key}), do: {:error, :invalid_group_key}
  defp destination_group_key(_destination_record), do: {:error, :missing_group_key}

  defp local_decrypt_identity(%{
         destination: %Destination{identity: %Identity{} = identity} = destination
       }) do
    if is_binary(identity.enc_sec) do
      {:ok, Identity.update_hash(identity), normalize_local_ratchets(destination.ratchets),
       destination.ratchet_enforced == true}
    else
      {:error, :missing_private_key}
    end
  end

  defp local_decrypt_identity(%{destination: %Destination{}}),
    do: {:error, :missing_local_identity}

  defp local_decrypt_identity(_local_destination), do: {:error, :missing_local_identity}

  defp local_group_key(%{destination: %Destination{group_key: group_key}})
       when is_binary(group_key) and byte_size(group_key) in @group_key_lengths,
       do: {:ok, group_key}

  defp local_group_key(%{destination: %Destination{group_key: nil}}),
    do: {:error, :missing_group_key}

  defp local_group_key(%{destination: %Destination{group_key: _group_key}}),
    do: {:error, :invalid_group_key}

  defp local_group_key(_local_destination), do: {:error, :missing_group_key}

  defp destination_group_cipher(group_key, payload) do
    group_key
    |> Fernet.new()
    |> Fernet.encrypt(payload)
  end

  defp destination_group_decipher(group_key, ciphertext) do
    group_key
    |> Fernet.new()
    |> Fernet.decrypt(ciphertext)
    |> case do
      {:ok, plaintext} -> {:ok, plaintext}
      {:error, _reason} -> {:error, :invalid_ciphertext}
    end
  end

  defp normalize_local_ratchets(ratchets) when is_list(ratchets) do
    Enum.filter(ratchets, fn ratchet ->
      is_binary(ratchet) and byte_size(ratchet) == @ratchet_public_len
    end)
  end

  defp normalize_local_ratchets(_ratchets), do: []

  defp context_value(context) do
    case Context.normalize(context) do
      {:ok, value} -> value
      _ -> -1
    end
  end
end
