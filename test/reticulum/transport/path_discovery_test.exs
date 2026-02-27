defmodule Reticulum.Transport.PathDiscoveryTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Packet
  alias Reticulum.Transport.Pathfinder

  @loopback {127, 0, 0, 1}

  describe "announce ingestion and path requests" do
    setup do
      node_a = Reticulum.Node.TransportPhase4A
      node_b = Reticulum.Node.TransportPhase4B

      start_supervised!(
        Supervisor.child_spec(
          {Node, name: node_a, storage_path: Path.join(System.tmp_dir!(), "reticulum-phase4-a")},
          id: node_a
        )
      )

      start_supervised!(
        Supervisor.child_spec(
          {Node, name: node_b, storage_path: Path.join(System.tmp_dir!(), "reticulum-phase4-b")},
          id: node_b
        )
      )

      :ok = Node.subscribe_packets(node_a, self())

      port_a = free_udp_port()
      port_b = free_udp_port()

      assert {:ok, _pid} =
               Node.start_udp_interface(node_a,
                 name: :link,
                 listen_ip: @loopback,
                 listen_port: port_a,
                 default_peer_ip: @loopback,
                 default_peer_port: port_b
               )

      assert {:ok, _pid} =
               Node.start_udp_interface(node_b,
                 name: :link,
                 listen_ip: @loopback,
                 listen_port: port_b,
                 default_peer_ip: @loopback,
                 default_peer_port: port_a
               )

      {:ok, node_a: node_a, node_b: node_b}
    end

    test "path request receives signed announce path response", %{node_a: node_a, node_b: node_b} do
      identity = Identity.new()
      {:ok, destination} = Destination.new(:in, :single, "phase4", identity, ["chat"])

      assert :ok =
               Node.register_local_announce_destination(node_b, destination, self(),
                 app_data: "phase4-app"
               )

      assert {:ok, _request_tag} = Node.request_path(node_a, :link, destination.hash)

      assert_receive {:reticulum, :packet,
                      %{node: ^node_a, direction: :inbound, packet: %Packet{type: :announce}}},
                     1_000

      assert {:ok, record} = wait_for_destination(node_a, destination.hash)
      assert record.public_key == identity.enc_pub <> identity.sig_pub
      assert record.app_data == "phase4-app"

      assert {:ok, path} = wait_for_path(node_a, destination.hash)
      assert path.hops == 0
      assert is_binary(path.next_hop)
      assert byte_size(path.next_hop) == 16
    end

    test "ingests ratchet from announce payload", %{node_a: node_a, node_b: node_b} do
      identity = Identity.new()
      {:ok, destination} = Destination.new(:in, :single, "phase6", identity, ["ratchet"])
      {:ok, destination} = Destination.set_ratchets(destination, [:crypto.strong_rand_bytes(32)])

      assert :ok = Node.register_local_announce_destination(node_b, destination, self())
      assert {:ok, _request_tag} = Node.request_path(node_a, :link, destination.hash)

      assert_receive {:reticulum, :packet,
                      %{node: ^node_a, direction: :inbound, packet: %Packet{type: :announce}}},
                     1_000

      assert {:ok, record} = wait_for_destination(node_a, destination.hash)
      assert is_binary(record.ratchet)
      assert byte_size(record.ratchet) == 32
      assert is_integer(record.ratchet_received_at)
    end

    test "rejects invalid announce payloads", %{node_a: node_a, node_b: node_b} do
      destination_hash = :crypto.strong_rand_bytes(16)
      forged_public_key = :crypto.strong_rand_bytes(64)
      forged_name_hash = :crypto.strong_rand_bytes(10)
      forged_random_hash = :crypto.strong_rand_bytes(10)
      forged_signature = :crypto.strong_rand_bytes(64)

      packet = %Packet{
        ifac: :open,
        propagation: :broadcast,
        destination: :single,
        type: :announce,
        hops: 0,
        addresses: [destination_hash],
        context: 0,
        data: forged_public_key <> forged_name_hash <> forged_random_hash <> forged_signature
      }

      assert :ok = Node.send_packet(node_b, :link, packet)
      Process.sleep(200)

      assert :error == Node.destination(node_a, destination_hash)
      assert :error == Node.path(node_a, destination_hash)
    end
  end

  describe "path table maintenance" do
    test "expires paths older than configured TTL" do
      node_name = Reticulum.Node.TransportPhase4Maintenance

      start_supervised!(
        {Node,
         name: node_name,
         storage_path: Path.join(System.tmp_dir!(), "reticulum-phase4-maintenance"),
         path_ttl_seconds: 1,
         path_gc_interval_seconds: 1}
      )

      destination_hash = :crypto.strong_rand_bytes(16)
      next_hop = :crypto.strong_rand_bytes(16)

      assert :ok = Node.put_path(node_name, destination_hash, next_hop, 1)
      assert {:ok, path} = Node.path(node_name, destination_hash)
      state_server = Node.state_server(node_name)

      assert [] ==
               Pathfinder.expire_stale_paths(state_server, 1, path.updated_at + 1)

      assert [destination_hash] ==
               Pathfinder.expire_stale_paths(state_server, 1, path.updated_at + 2)

      assert :error == Node.path(node_name, destination_hash)
    end
  end

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end

  defp wait_for_destination(node_name, destination_hash, attempts \\ 20)

  defp wait_for_destination(node_name, destination_hash, attempts) when attempts > 0 do
    case Node.destination(node_name, destination_hash) do
      {:ok, _record} = result ->
        result

      :error ->
        Process.sleep(25)
        wait_for_destination(node_name, destination_hash, attempts - 1)
    end
  end

  defp wait_for_destination(_node_name, _destination_hash, 0), do: :error

  defp wait_for_path(node_name, destination_hash, attempts \\ 20)

  defp wait_for_path(node_name, destination_hash, attempts) when attempts > 0 do
    case Node.path(node_name, destination_hash) do
      {:ok, _path} = result ->
        result

      :error ->
        Process.sleep(25)
        wait_for_path(node_name, destination_hash, attempts - 1)
    end
  end

  defp wait_for_path(_node_name, _destination_hash, 0), do: :error
end
