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

  test "encrypts and decrypts group destination payloads" do
    {:ok, destination} = Destination.new(:in, :group, "phase6", nil, ["group"])
    {:ok, destination} = Destination.create_group_key(destination)
    {:ok, group_key} = Destination.group_key(destination)

    packet = %Packet{destination: :group, type: :data, context: Context.none(), data: "group"}

    assert {:ok, encrypted_packet} =
             PacketCrypto.encrypt_outbound(packet, %{group_key: group_key})

    refute encrypted_packet.data == packet.data

    assert {:ok, decrypted_packet} =
             PacketCrypto.decrypt_inbound(encrypted_packet, %{destination: destination})

    assert decrypted_packet.data == "group"
  end

  test "returns group key errors for group destination packets" do
    packet = %Packet{destination: :group, type: :data, context: Context.none(), data: "group"}

    assert {:error, :missing_group_key} = PacketCrypto.encrypt_outbound(packet, %{})

    assert {:error, :invalid_group_key} =
             PacketCrypto.encrypt_outbound(packet, %{group_key: <<1>>})

    {:ok, destination} = Destination.new(:in, :group, "phase6", nil, ["group-missing"])

    assert {:error, :missing_group_key} =
             PacketCrypto.decrypt_inbound(packet, %{destination: destination})
  end

  test "enforces ratchet-only decryption when destination requires ratchets" do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase6", identity, ["ratchet-enforced"])
    ratchet_private = :crypto.strong_rand_bytes(32)
    {:ok, destination} = Destination.set_ratchets(destination, [ratchet_private])
    {:ok, destination} = Destination.enforce_ratchets(destination, true)

    {:ok, ratchet_public} = Destination.current_ratchet_public_key(destination)

    ratchet_record = %{
      public_key: identity.enc_pub <> identity.sig_pub,
      ratchet: ratchet_public
    }

    packet = %Packet{destination: :single, type: :data, context: Context.none(), data: "phase6"}

    assert {:ok, ratcheted_packet} = PacketCrypto.encrypt_outbound(packet, ratchet_record)

    assert {:ok, decrypted_packet} =
             PacketCrypto.decrypt_inbound(ratcheted_packet, %{destination: destination})

    assert decrypted_packet.data == "phase6"

    base_record = %{public_key: identity.enc_pub <> identity.sig_pub}
    assert {:ok, base_packet} = PacketCrypto.encrypt_outbound(packet, base_record)

    assert {:error, :ratchet_enforced} =
             PacketCrypto.decrypt_inbound(base_packet, %{destination: destination})
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
