defmodule Reticulum.Transport.PacketCryptoTest do
  use ExUnit.Case, async: true

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Packet
  alias Reticulum.Packet.Context
  alias Reticulum.Transport.PacketCrypto

  test "encrypts single destination payload for active data context" do
    identity = Identity.new()

    packet = %Packet{
      ifac: :open,
      propagation: :broadcast,
      destination: :single,
      type: :data,
      hops: 0,
      addresses: [:crypto.strong_rand_bytes(16)],
      context: Context.none(),
      data: "phase4"
    }

    destination_record = %{public_key: identity.enc_pub <> identity.sig_pub}

    assert {:ok, encrypted_packet} = PacketCrypto.encrypt_outbound(packet, destination_record)
    refute encrypted_packet.data == packet.data
  end

  test "bypasses encryption for plain destination and exempt contexts" do
    identity = Identity.new()
    destination_record = %{public_key: identity.enc_pub <> identity.sig_pub}

    plain_packet = %Packet{
      destination: :plain,
      type: :data,
      context: Context.none(),
      data: "plain"
    }

    assert {:ok, ^plain_packet} = PacketCrypto.encrypt_outbound(plain_packet, destination_record)

    exempt_packet = %Packet{
      destination: :single,
      type: :data,
      context: Context.keepalive(),
      data: "keepalive"
    }

    assert {:ok, ^exempt_packet} =
             PacketCrypto.encrypt_outbound(exempt_packet, destination_record)
  end

  test "decrypts inbound single packet for local destination identity" do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase4", identity, ["decrypt"])

    destination_record = %{public_key: identity.enc_pub <> identity.sig_pub}

    packet = %Packet{destination: :single, type: :data, context: Context.none(), data: "secret"}

    assert {:ok, encrypted_packet} = PacketCrypto.encrypt_outbound(packet, destination_record)

    local_destination = %{destination: destination}

    assert {:ok, decrypted_packet} =
             PacketCrypto.decrypt_inbound(encrypted_packet, local_destination)

    assert decrypted_packet.data == "secret"
  end

  test "returns decrypt error when local destination has no private key" do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase4", identity, ["no-private"])

    destination_without_private = %{destination | identity: %{identity | enc_sec: nil}}
    local_destination = %{destination: destination_without_private}

    packet = %Packet{
      destination: :single,
      type: :data,
      context: Context.none(),
      data: "ciphertext"
    }

    assert {:error, :missing_private_key} =
             PacketCrypto.decrypt_inbound(packet, local_destination)
  end

  test "rejects unsupported destination type" do
    packet = %Packet{destination: :group, type: :data, context: Context.none(), data: "group"}

    assert {:error, :unsupported_destination_type} =
             PacketCrypto.encrypt_outbound(packet, %{public_key: :crypto.strong_rand_bytes(64)})
  end

  test "bypasses encryption for link proof packets" do
    packet = %Packet{
      destination: :link,
      type: :proof,
      context: Context.linkproof(),
      data: "proof"
    }

    assert {:ok, ^packet} = PacketCrypto.encrypt_outbound(packet, %{})
    assert {:ok, ^packet} = PacketCrypto.decrypt_inbound(packet, %{})
  end

  test "rejects link destination for non-proof packets" do
    packet = %Packet{destination: :link, type: :data, context: Context.none(), data: "data"}

    assert {:error, :unsupported_destination_type} = PacketCrypto.encrypt_outbound(packet, %{})
  end
end
