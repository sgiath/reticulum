defmodule Reticulum.Node.StartupOwnershipTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Packet

  @loopback {127, 0, 0, 1}

  describe "shared_instance startup ownership" do
    test "rejects second shared instance for same storage path and releases on shutdown" do
      storage_path = unique_storage_path("shared-instance")
      node_a = Reticulum.Node.StartupSharedA
      node_b = Reticulum.Node.StartupSharedB

      assert {:ok, first_pid} =
               Node.start_link(name: node_a, storage_path: storage_path, shared_instance: true)

      assert Node.start_link(name: node_b, storage_path: storage_path, shared_instance: true) ==
               {:error, :shared_instance_already_running}

      assert :ok = Supervisor.stop(first_pid)

      assert {:ok, second_pid} =
               Node.start_link(name: node_b, storage_path: storage_path, shared_instance: true)

      assert :ok = Supervisor.stop(second_pid)
    end

    test "allows separate shared instances for different storage paths" do
      node_a = Reticulum.Node.StartupSharedPathA
      node_b = Reticulum.Node.StartupSharedPathB

      assert {:ok, first_pid} =
               Node.start_link(
                 name: node_a,
                 storage_path: unique_storage_path("shared-path-a"),
                 shared_instance: true
               )

      assert {:ok, second_pid} =
               Node.start_link(
                 name: node_b,
                 storage_path: unique_storage_path("shared-path-b"),
                 shared_instance: true
               )

      assert :ok = Supervisor.stop(first_pid)
      assert :ok = Supervisor.stop(second_pid)
    end
  end

  describe "transport_enabled startup behavior" do
    test "still ingests announces when transport is disabled" do
      node_a = Reticulum.Node.StartupTransportDisabledA
      node_b = Reticulum.Node.StartupTransportDisabledB

      start_supervised!(
        Supervisor.child_spec(
          {Node,
           name: node_a,
           storage_path: unique_storage_path("transport-disabled-a"),
           transport_enabled: false},
          id: {:startup_transport_disabled, node_a}
        )
      )

      start_supervised!(
        Supervisor.child_spec(
          {Node,
           name: node_b,
           storage_path: unique_storage_path("transport-disabled-b"),
           transport_enabled: true},
          id: {:startup_transport_disabled, node_b}
        )
      )

      assert :ok = Node.subscribe_packets(node_a, self())

      connect_pair(node_a, node_b)

      identity = Identity.new()
      {:ok, destination} = Destination.new(:in, :single, "phase1", identity, ["toggle"])

      assert :ok = Node.register_local_announce_destination(node_b, destination, self())
      assert :ok = Node.announce(node_b, :link, destination.hash)

      assert_receive {:reticulum, :packet,
                      %{node: ^node_a, direction: :inbound, packet: %Packet{type: :announce}}},
                     1_000

      assert {:ok, record} = wait_for_destination(node_a, destination.hash)
      assert record.public_key == identity.enc_pub <> identity.sig_pub

      assert {:ok, path} = wait_for_path(node_a, destination.hash)
      assert path.hops == 0
      assert is_binary(path.next_hop)
      assert byte_size(path.next_hop) == 16
    end

    test "ingests announces when transport is enabled" do
      node_a = Reticulum.Node.StartupTransportEnabledA
      node_b = Reticulum.Node.StartupTransportEnabledB

      start_supervised!(
        Supervisor.child_spec(
          {Node,
           name: node_a,
           storage_path: unique_storage_path("transport-enabled-a"),
           transport_enabled: true},
          id: {:startup_transport_enabled, node_a}
        )
      )

      start_supervised!(
        Supervisor.child_spec(
          {Node,
           name: node_b,
           storage_path: unique_storage_path("transport-enabled-b"),
           transport_enabled: true},
          id: {:startup_transport_enabled, node_b}
        )
      )

      assert :ok = Node.subscribe_packets(node_a, self())

      connect_pair(node_a, node_b)

      identity = Identity.new()
      {:ok, destination} = Destination.new(:in, :single, "phase1", identity, ["toggle"])

      assert :ok = Node.register_local_announce_destination(node_b, destination, self())
      assert :ok = Node.announce(node_b, :link, destination.hash)

      assert_receive {:reticulum, :packet,
                      %{node: ^node_a, direction: :inbound, packet: %Packet{type: :announce}}},
                     1_000

      assert {:ok, record} = wait_for_destination(node_a, destination.hash)
      assert record.public_key == identity.enc_pub <> identity.sig_pub

      assert {:ok, path} = wait_for_path(node_a, destination.hash)
      assert path.hops == 0
      assert is_binary(path.next_hop)
      assert byte_size(path.next_hop) == 16
    end

    test "responds to path requests when transport is disabled" do
      node_a = Reticulum.Node.StartupPathRequestEnabledA
      node_b = Reticulum.Node.StartupPathRequestDisabledB

      start_supervised!(
        Supervisor.child_spec(
          {Node,
           name: node_a,
           storage_path: unique_storage_path("path-request-enabled-a"),
           transport_enabled: true},
          id: {:startup_path_request_enabled, node_a}
        )
      )

      start_supervised!(
        Supervisor.child_spec(
          {Node,
           name: node_b,
           storage_path: unique_storage_path("path-request-disabled-b"),
           transport_enabled: false},
          id: {:startup_path_request_disabled, node_b}
        )
      )

      assert :ok = Node.subscribe_packets(node_a, self())

      connect_pair(node_a, node_b)

      identity = Identity.new()
      {:ok, destination} = Destination.new(:in, :single, "phase1", identity, ["path-request"])

      assert :ok = Node.register_local_announce_destination(node_b, destination, self())
      assert {:ok, _request_tag} = Node.request_path(node_a, :link, destination.hash)

      assert_receive {:reticulum, :packet,
                      %{node: ^node_a, direction: :inbound, packet: %Packet{type: :announce}}},
                     1_000

      assert {:ok, record} = wait_for_destination(node_a, destination.hash)
      assert record.public_key == identity.enc_pub <> identity.sig_pub

      assert {:ok, path} = wait_for_path(node_a, destination.hash)
      assert path.hops == 0
      assert is_binary(path.next_hop)
      assert byte_size(path.next_hop) == 16
    end
  end

  defp connect_pair(node_a, node_b) do
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

    :ok
  end

  defp unique_storage_path(prefix) do
    Path.join(System.tmp_dir!(), "reticulum-#{prefix}-#{System.unique_integer([:positive])}")
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

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end
end
