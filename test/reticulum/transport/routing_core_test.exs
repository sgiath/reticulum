defmodule Reticulum.Transport.RoutingCoreTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Packet
  alias Reticulum.Transport.Announce

  @loopback {127, 0, 0, 1}

  test "forwards path requests and announces across intermediary" do
    %{node_a: node_a, node_b: node_b, node_c: node_c} = start_chain!("routing-path")

    assert :ok = Node.subscribe_packets(node_a, self())

    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase8", identity, ["path"])

    assert :ok = Node.register_local_announce_destination(node_c, destination, self())
    assert {:ok, _request_tag} = Node.request_path(node_a, :ab, destination.hash)

    assert_receive {:reticulum, :packet,
                    %{
                      node: ^node_a,
                      direction: :inbound,
                      packet: %Packet{type: :announce, hops: 1}
                    }},
                   1_000

    assert {:ok, path_a} = wait_for_path(node_a, destination.hash)
    assert path_a.interface == :ab
    assert path_a.hops == 1

    assert {:ok, path_b} = wait_for_path(node_b, destination.hash)
    assert path_b.interface == :bc
    assert path_b.hops == 0
  end

  test "forwards transit data and proofs across intermediary" do
    %{node_a: node_a, node_c: node_c} = start_chain!("routing-proof")

    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase8", identity, ["proof"])
    {:ok, destination} = Destination.set_proof_strategy(destination, :all)

    assert :ok = Node.register_local_announce_destination(node_c, destination, self())
    assert :ok = Node.announce(node_c, :bc, destination.hash)
    assert {:ok, _path} = wait_for_path(node_a, destination.hash)

    assert {:ok, receipt_hash} =
             Node.send_data(node_a, :ab, destination.hash, "phase8-transit", track_receipt: true)

    assert_receive {:reticulum, :destination_packet,
                    %{destination_hash: destination_hash, packet: %Packet{data: "phase8-transit"}}},
                   1_000

    assert destination_hash == destination.hash

    assert {:ok, receipt} = wait_for_receipt(node_a, receipt_hash)
    assert receipt.status == :delivered
  end

  test "prefers lower-hop paths and falls back to healthy interfaces" do
    %{target: target, left: left, right: right} = start_dual_ingress!("routing-policy")

    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase8", identity, ["policy"])

    assert :ok = Node.send_packet(left, :left, announce_packet(destination, 2, <<1::80>>))
    assert {:ok, initial_path} = wait_for_path(target, destination.hash, &(&1.interface == :left))
    assert initial_path.interface == :left
    assert initial_path.hops == 2

    assert :ok = Node.send_packet(right, :right, announce_packet(destination, 0, <<2::80>>))

    assert {:ok, preferred_path} =
             wait_for_path(target, destination.hash, &(&1.interface == :right and &1.hops == 0))

    assert preferred_path.interface == :right
    assert preferred_path.hops == 0

    assert :ok = Node.stop_interface(target, :right)
    Process.sleep(100)

    assert :ok = Node.send_packet(left, :left, announce_packet(destination, 0, <<3::80>>))

    assert {:ok, recovered_path} =
             wait_for_path(target, destination.hash, &(&1.interface == :left and &1.hops == 0))

    assert recovered_path.interface == :left
    assert recovered_path.hops == 0
  end

  defp start_chain!(prefix) do
    {node_a, node_b, node_c} = chain_nodes(prefix)

    start_node!(node_a, prefix <> "-a")
    start_node!(node_b, prefix <> "-b")
    start_node!(node_c, prefix <> "-c")

    port_a = free_udp_port()
    port_ba = free_udp_port()
    port_bc = free_udp_port()
    port_c = free_udp_port()

    assert {:ok, _pid} =
             Node.start_udp_interface(node_a,
               name: :ab,
               listen_ip: @loopback,
               listen_port: port_a,
               default_peer_ip: @loopback,
               default_peer_port: port_ba
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(node_b,
               name: :ab,
               listen_ip: @loopback,
               listen_port: port_ba,
               default_peer_ip: @loopback,
               default_peer_port: port_a
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(node_b,
               name: :bc,
               listen_ip: @loopback,
               listen_port: port_bc,
               default_peer_ip: @loopback,
               default_peer_port: port_c
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(node_c,
               name: :bc,
               listen_ip: @loopback,
               listen_port: port_c,
               default_peer_ip: @loopback,
               default_peer_port: port_bc
             )

    %{node_a: node_a, node_b: node_b, node_c: node_c}
  end

  defp start_dual_ingress!(prefix) do
    {target, left, right} = dual_ingress_nodes(prefix)

    start_node!(target, prefix <> "-target")
    start_node!(left, prefix <> "-left")
    start_node!(right, prefix <> "-right")

    target_left_port = free_udp_port()
    left_port = free_udp_port()
    target_right_port = free_udp_port()
    right_port = free_udp_port()

    assert {:ok, _pid} =
             Node.start_udp_interface(target,
               name: :left,
               listen_ip: @loopback,
               listen_port: target_left_port,
               default_peer_ip: @loopback,
               default_peer_port: left_port
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(left,
               name: :left,
               listen_ip: @loopback,
               listen_port: left_port,
               default_peer_ip: @loopback,
               default_peer_port: target_left_port
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(target,
               name: :right,
               listen_ip: @loopback,
               listen_port: target_right_port,
               default_peer_ip: @loopback,
               default_peer_port: right_port
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(right,
               name: :right,
               listen_ip: @loopback,
               listen_port: right_port,
               default_peer_ip: @loopback,
               default_peer_port: target_right_port
             )

    %{target: target, left: left, right: right}
  end

  defp start_node!(node_name, storage_suffix) do
    start_supervised!(
      Supervisor.child_spec(
        {Node,
         name: node_name,
         storage_path: unique_storage_path(storage_suffix),
         transport_enabled: true,
         routing_max_hops: 8},
        id: node_name
      )
    )
  end

  defp chain_nodes("routing-path") do
    {
      Reticulum.Node.RoutingPathA,
      Reticulum.Node.RoutingPathB,
      Reticulum.Node.RoutingPathC
    }
  end

  defp chain_nodes("routing-proof") do
    {
      Reticulum.Node.RoutingProofA,
      Reticulum.Node.RoutingProofB,
      Reticulum.Node.RoutingProofC
    }
  end

  defp dual_ingress_nodes("routing-policy") do
    {
      Reticulum.Node.RoutingPolicyTarget,
      Reticulum.Node.RoutingPolicyLeft,
      Reticulum.Node.RoutingPolicyRight
    }
  end

  defp announce_packet(destination, hops, random_hash) do
    {:ok, announce} = Announce.build_payload(destination, random_hash: random_hash)

    %Packet{
      ifac: :open,
      propagation: :broadcast,
      destination: :single,
      type: :announce,
      hops: hops,
      addresses: [destination.hash],
      context_flag: announce.context_flag,
      context: 0,
      data: announce.payload
    }
  end

  defp wait_for_path(node_name, destination_hash, attempts \\ 40)

  defp wait_for_path(node_name, destination_hash, matcher)
       when is_function(matcher, 1),
       do: wait_for_path(node_name, destination_hash, matcher, 40)

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

  defp wait_for_path(node_name, destination_hash, matcher, attempts) when attempts > 0 do
    case Node.path(node_name, destination_hash) do
      {:ok, path} = result ->
        if matcher.(path) do
          result
        else
          Process.sleep(25)
          wait_for_path(node_name, destination_hash, matcher, attempts - 1)
        end

      _ ->
        Process.sleep(25)
        wait_for_path(node_name, destination_hash, matcher, attempts - 1)
    end
  end

  defp wait_for_path(_node_name, _destination_hash, _matcher, 0), do: :error

  defp wait_for_receipt(node_name, receipt_hash, attempts \\ 40)

  defp wait_for_receipt(node_name, receipt_hash, attempts) when attempts > 0 do
    case Node.receipt(node_name, receipt_hash) do
      {:ok, %{status: :delivered} = receipt} ->
        {:ok, receipt}

      {:ok, _receipt} ->
        Process.sleep(25)
        wait_for_receipt(node_name, receipt_hash, attempts - 1)

      :error ->
        Process.sleep(25)
        wait_for_receipt(node_name, receipt_hash, attempts - 1)
    end
  end

  defp wait_for_receipt(_node_name, _receipt_hash, 0), do: :error

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end

  defp unique_storage_path(prefix) do
    Path.join(System.tmp_dir!(), "reticulum-#{prefix}-#{System.unique_integer([:positive])}")
  end
end
