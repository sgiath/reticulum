defmodule Reticulum.Transport.RuntimeTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Packet

  @loopback {127, 0, 0, 1}

  setup do
    node_name = Reticulum.Node.TransportRuntimeTest

    start_supervised!(
      {Node,
       name: node_name,
       storage_path: Path.join(System.tmp_dir!(), "reticulum-node-transport-runtime-test")}
    )

    :ok = Node.subscribe_packets(node_name, self())

    port_a = free_udp_port()
    port_b = free_udp_port()

    assert {:ok, _pid} =
             Node.start_udp_interface(node_name,
               name: :udp_a,
               listen_ip: @loopback,
               listen_port: port_a,
               default_peer_ip: @loopback,
               default_peer_port: port_b
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(node_name,
               name: :udp_b,
               listen_ip: @loopback,
               listen_port: port_b,
               default_peer_ip: @loopback,
               default_peer_port: port_a
             )

    {:ok, node_name: node_name}
  end

  test "sends destination payload as packet and decodes it on inbound", %{node_name: node_name} do
    destination_hash = :crypto.strong_rand_bytes(16)
    public_key = :crypto.strong_rand_bytes(64)
    payload = <<1, 2, 3, 4>>

    assert :ok = Node.put_destination(node_name, destination_hash, public_key, nil)
    assert :ok = Node.send_data(node_name, :udp_a, destination_hash, payload, destination: :plain)

    assert_receive {:reticulum, :packet,
                    %{direction: :outbound, packet: %Packet{data: ^payload}}},
                   1_000

    assert_receive {:reticulum, :packet,
                    %{
                      direction: :inbound,
                      interface: :udp_b,
                      duplicate: false,
                      known_destination: true,
                      packet_hash: packet_hash,
                      packet: %Packet{addresses: [^destination_hash], data: ^payload}
                    }},
                   1_000

    assert is_binary(packet_hash)
    assert byte_size(packet_hash) == 16
  end

  test "suppresses duplicate inbound dispatch and routes local destination", %{
    node_name: node_name
  } do
    destination_hash = :crypto.strong_rand_bytes(16)

    packet = %Packet{
      ifac: :open,
      propagation: :broadcast,
      destination: :plain,
      type: :data,
      hops: 0,
      addresses: [destination_hash],
      context: 0,
      data: <<11, 22, 33>>
    }

    assert :ok = Node.register_local_destination(node_name, destination_hash, self())

    assert :ok = Node.send_packet(node_name, :udp_a, packet)
    assert :ok = Node.send_packet(node_name, :udp_a, packet)

    assert_receive {:reticulum, :destination_packet,
                    %{destination_hash: ^destination_hash, packet: %Packet{data: <<11, 22, 33>>}}},
                   1_000

    refute_receive {:reticulum, :destination_packet, %{destination_hash: ^destination_hash}}, 250

    inbound_events = receive_inbound_events(2, [])
    assert Enum.count(inbound_events, &(!&1.duplicate)) == 1
    assert Enum.count(inbound_events, & &1.duplicate) == 1
  end

  test "publishes decode errors for malformed inbound payload", %{node_name: node_name} do
    malformed = <<1, 2, 3>>
    assert :ok = Node.send_frame(node_name, :udp_a, malformed)

    assert_receive {:reticulum, :packet,
                    %{
                      direction: :inbound,
                      interface: :udp_b,
                      packet: nil,
                      reason: reason
                    }},
                   1_000

    assert reason in [:invalid_packet, :raw_payload_too_short, :raw_header_too_short]
  end

  test "keeps transport alive for local plain announce destinations", %{node_name: node_name} do
    {:ok, destination} = Destination.new(:in, :plain, "runtime", nil, ["plain"])

    assert :ok = Node.register_local_announce_destination(node_name, destination, self())

    assert :ok =
             Node.put_destination(
               node_name,
               destination.hash,
               :crypto.strong_rand_bytes(64),
               nil
             )

    transport_pid_before = :global.whereis_name({Reticulum.Node, :transport, node_name})
    assert is_pid(transport_pid_before)

    payload = "plain-delivery"

    assert :ok = Node.send_data(node_name, :udp_a, destination.hash, payload, destination: :plain)

    assert_receive {:reticulum, :destination_packet,
                    %{destination_hash: destination_hash, packet: %Packet{data: ^payload}}},
                   1_000

    assert destination_hash == destination.hash

    Process.sleep(100)

    transport_pid_after = :global.whereis_name({Reticulum.Node, :transport, node_name})
    assert transport_pid_after == transport_pid_before
    assert Process.alive?(transport_pid_after)
  end

  test "encrypts outbound single payload and decrypts inbound local destination", %{
    node_name: node_name
  } do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "runtime", identity, ["secure"])
    payload = "runtime-encrypted"

    assert :ok = Node.register_local_announce_destination(node_name, destination, self())

    assert :ok =
             Node.put_destination(
               node_name,
               destination.hash,
               identity.enc_pub <> identity.sig_pub,
               nil,
               ratchet: nil,
               ratchet_received_at: nil
             )

    assert :ok = Node.send_data(node_name, :udp_a, destination.hash, payload)

    assert_receive {:reticulum, :packet,
                    %{direction: :outbound, packet: %Packet{data: outbound_payload}}},
                   1_000

    refute outbound_payload == payload

    assert_receive {:reticulum, :destination_packet,
                    %{destination_hash: destination_hash, packet: %Packet{data: ^payload}}},
                   1_000

    assert destination_hash == destination.hash
  end

  test "encrypts outbound group payload and decrypts inbound local destination", %{
    node_name: node_name
  } do
    {:ok, destination} = Destination.new(:in, :group, "runtime", nil, ["group"])
    {:ok, destination} = Destination.create_group_key(destination)
    {:ok, group_key} = Destination.group_key(destination)
    payload = "runtime-group-encrypted"

    assert :ok = Node.register_local_announce_destination(node_name, destination, self())
    assert :ok = Node.put_group_destination(node_name, destination.hash, group_key, nil)

    assert :ok =
             Node.send_data(node_name, :udp_a, destination.hash, payload, destination: :group)

    assert_receive {:reticulum, :packet,
                    %{direction: :outbound, packet: %Packet{data: outbound_payload}}},
                   1_000

    refute outbound_payload == payload

    assert_receive {:reticulum, :destination_packet,
                    %{destination_hash: destination_hash, packet: %Packet{data: ^payload}}},
                   1_000

    assert destination_hash == destination.hash
  end

  test "enforces ratchet-only inbound decryption for local single destination", %{
    node_name: node_name
  } do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "runtime", identity, ["ratchet-enforced"])
    ratchet_private = :crypto.strong_rand_bytes(32)
    {:ok, destination} = Destination.set_ratchets(destination, [ratchet_private])
    {:ok, destination} = Destination.enforce_ratchets(destination, true)
    {:ok, ratchet_public} = Destination.current_ratchet_public_key(destination)

    assert :ok = Node.register_local_announce_destination(node_name, destination, self())

    assert :ok =
             Node.put_destination(
               node_name,
               destination.hash,
               identity.enc_pub <> identity.sig_pub,
               nil,
               ratchet: ratchet_public
             )

    assert :ok = Node.send_data(node_name, :udp_a, destination.hash, "ratchet-pass")

    assert_receive {:reticulum, :destination_packet,
                    %{destination_hash: destination_hash, packet: %Packet{data: "ratchet-pass"}}},
                   1_000

    assert destination_hash == destination.hash

    assert :ok =
             Node.put_destination(
               node_name,
               destination.hash,
               identity.enc_pub <> identity.sig_pub,
               nil,
               ratchet: nil,
               ratchet_received_at: nil
             )

    assert {:ok, destination_record} = Node.destination(node_name, destination.hash)
    assert destination_record.ratchet == nil

    assert :ok = Node.send_data(node_name, :udp_a, destination.hash, "ratchet-fail")

    assert_receive {:reticulum, :packet,
                    %{direction: :inbound, reason: :ratchet_enforced, packet_hash: packet_hash}},
                   1_000

    assert is_binary(packet_hash)

    refute_receive {:reticulum, :destination_packet,
                    %{destination_hash: ^destination_hash, packet: %Packet{data: "ratchet-fail"}}},
                   250
  end

  test "publishes inbound packet event when local destination decryption fails", %{
    node_name: node_name
  } do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "runtime", identity, ["missing-private"])

    destination_without_private = %{
      destination
      | identity: %{destination.identity | enc_sec: nil}
    }

    assert :ok =
             Node.register_local_announce_destination(
               node_name,
               destination_without_private,
               self()
             )

    assert :ok =
             Node.put_destination(
               node_name,
               destination.hash,
               identity.enc_pub <> identity.sig_pub,
               nil
             )

    assert :ok = Node.send_data(node_name, :udp_a, destination.hash, "cannot-decrypt")

    destination_hash = destination.hash

    assert_receive {:reticulum, :packet,
                    %{direction: :inbound, reason: :missing_private_key, packet_hash: packet_hash}},
                   1_000

    assert is_binary(packet_hash)
    refute_receive {:reticulum, :destination_packet, %{destination_hash: ^destination_hash}}, 250
  end

  defp receive_inbound_events(target_count, acc) when length(acc) >= target_count,
    do: Enum.reverse(acc)

  defp receive_inbound_events(target_count, acc) do
    receive do
      {:reticulum, :packet, %{direction: :inbound} = event} ->
        receive_inbound_events(target_count, [event | acc])

      {:reticulum, :packet, _event} ->
        receive_inbound_events(target_count, acc)
    after
      1_000 ->
        Enum.reverse(acc)
    end
  end

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end
end
