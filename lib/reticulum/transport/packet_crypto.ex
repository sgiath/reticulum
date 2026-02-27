defmodule Reticulum.Transport.PacketCrypto do
  @moduledoc false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Packet
  alias Reticulum.Packet.Context

  @public_key_len 64

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
    with {:ok, identity} <- destination_identity(destination_record) do
      {:ok, %{packet | data: Identity.encrypt(identity, payload)}}
    end
  end

  defp encrypt_packet(%Packet{destination: :single}, _destination_record),
    do: {:error, :invalid_payload}

  defp decrypt_packet(%Packet{destination: :single, data: ciphertext} = packet, local_destination)
       when is_binary(ciphertext) do
    with {:ok, identity} <- local_decrypt_identity(local_destination),
         {:ok, plaintext} <- Identity.decrypt(identity, ciphertext) do
      {:ok, %{packet | data: plaintext}}
    end
  end

  defp decrypt_packet(%Packet{destination: :single}, _local_destination),
    do: {:error, :invalid_payload}

  defp validate_destination_type(:single, _type), do: :ok
  defp validate_destination_type(:plain, _type), do: :ok
  defp validate_destination_type(:link, :proof), do: :ok
  defp validate_destination_type(:group, _type), do: {:error, :unsupported_destination_type}
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

  defp local_decrypt_identity(%{destination: %Destination{identity: %Identity{} = identity}}) do
    if is_binary(identity.enc_sec) do
      {:ok, Identity.update_hash(identity)}
    else
      {:error, :missing_private_key}
    end
  end

  defp local_decrypt_identity(%{destination: %Destination{}}),
    do: {:error, :missing_local_identity}

  defp local_decrypt_identity(_local_destination), do: {:error, :missing_local_identity}

  defp context_value(context) do
    case Context.normalize(context) do
      {:ok, value} -> value
      _ -> -1
    end
  end
end
