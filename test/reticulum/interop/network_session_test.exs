defmodule Reticulum.Interop.NetworkSessionTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Packet
  alias Reticulum.ReferenceRunner

  @loopback {127, 0, 0, 1}

  setup do
    node_name = Reticulum.Node.InteropNetworkSession

    start_supervised!(
      {Node,
       name: node_name,
       storage_path: Path.join(System.tmp_dir!(), "reticulum-interop-network-session")}
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

  test "dispatches Python-packed inbound data packet to local destination", %{
    node_name: node_name
  } do
    destination_hash = :crypto.strong_rand_bytes(16)
    payload = "interop-session"

    assert :ok = Node.register_local_destination(node_name, destination_hash, self())

    raw =
      ReferenceRunner.run!("packet_pack", [
        "0",
        "0",
        "0",
        "2",
        "0",
        "0",
        hex(destination_hash),
        "0",
        hex(payload),
        "-"
      ])
      |> dehex()

    assert :ok = Node.send_frame(node_name, :udp_a, raw)

    assert_receive {:reticulum, :destination_packet,
                    %{destination_hash: ^destination_hash, packet: %Packet{data: ^payload}}},
                   1_000

    assert_receive {:reticulum, :packet, %{direction: :inbound, packet: %Packet{} = packet}},
                   1_000

    assert packet.type == :data
    assert packet.addresses == [destination_hash]
    assert packet.data == payload
  end

  test "decrypts Python-encrypted inbound single packet for local destination", %{
    node_name: node_name
  } do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "interop", identity, ["secure"])
    payload = "interop-encrypted"

    assert :ok = Node.register_local_announce_destination(node_name, destination, self())

    ciphertext =
      ReferenceRunner.run!("identity_encrypt", [
        hex(identity.enc_pub <> identity.sig_pub),
        hex(payload),
        "-"
      ])
      |> dehex()

    raw =
      ReferenceRunner.run!("packet_pack", [
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
        hex(destination.hash),
        "0",
        hex(ciphertext),
        "-"
      ])
      |> dehex()

    assert :ok = Node.send_frame(node_name, :udp_a, raw)

    assert_receive {:reticulum, :destination_packet,
                    %{destination_hash: destination_hash, packet: %Packet{data: ^payload}}},
                   1_000

    assert destination_hash == destination.hash
  end

  defp hex(data), do: Base.encode16(data, case: :lower)
  defp dehex(data), do: Base.decode16!(data, case: :mixed)

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end
end
