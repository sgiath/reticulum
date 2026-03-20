defmodule Reticulum.Transport.RoutingResilienceTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Packet
  alias Reticulum.TestSupport.RoutingTopology
  alias Reticulum.Transport.Pathfinder

  test "retries local path requests until a destination appears" do
    node_a = Reticulum.Node.RoutingRetryA
    node_b = Reticulum.Node.RoutingRetryB
    node_c = Reticulum.Node.RoutingRetryC

    start_supervised!(
      RoutingTopology.node_child_spec(node_a, "routing-retry-a",
        path_request_timeout_seconds: 6,
        path_request_retry_count: 2,
        path_request_retry_base_seconds: 1,
        path_request_retry_backoff_factor: 1,
        path_request_min_interval_seconds: 1,
        path_request_duplicate_ttl_seconds: 1
      )
    )

    start_supervised!(RoutingTopology.node_child_spec(node_b, "routing-retry-b"))
    start_supervised!(RoutingTopology.node_child_spec(node_c, "routing-retry-c"))

    :ok = RoutingTopology.connect_udp!(node_a, :ab, node_b, :ab)
    :ok = RoutingTopology.connect_udp!(node_b, :bc, node_c, :bc)
    assert :ok = Node.subscribe_packets(node_a, self())

    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase9", identity, ["retry"])

    assert {:ok, _request_tag} = Node.request_path(node_a, :ab, destination.hash)

    assert_receive {:reticulum, :packet,
                    %{node: ^node_a, direction: :outbound, packet: %Packet{} = initial_packet}},
                   1_000

    assert {:ok, initial_request} = Pathfinder.parse_path_request_packet(initial_packet)

    Process.sleep(150)
    assert :ok = Node.register_local_announce_destination(node_c, destination, self())

    assert_receive {:reticulum, :packet,
                    %{node: ^node_a, direction: :outbound, packet: %Packet{} = retry_packet}},
                   2_000

    assert {:ok, retry_request} = Pathfinder.parse_path_request_packet(retry_packet)
    refute retry_request.request_tag == initial_request.request_tag

    assert_receive {:reticulum, :packet,
                    %{node: ^node_a, direction: :inbound, packet: %Packet{type: :announce}}},
                   2_000

    assert {:ok, path} =
             RoutingTopology.wait_for_path(
               node_a,
               destination.hash,
               &(&1.interface == :ab and &1.hops == 1)
             )

    assert path.interface == :ab
    assert path.hops == 1
  end

  test "suppresses duplicate forwarded path requests with the same destination and tag" do
    left = Reticulum.Node.RoutingDuplicateLeft
    right = Reticulum.Node.RoutingDuplicateRight
    center = Reticulum.Node.RoutingDuplicateCenter
    down = Reticulum.Node.RoutingDuplicateDown

    start_supervised!(RoutingTopology.node_child_spec(left, "routing-duplicate-left"))
    start_supervised!(RoutingTopology.node_child_spec(right, "routing-duplicate-right"))

    start_supervised!(
      RoutingTopology.node_child_spec(center, "routing-duplicate-center",
        path_request_duplicate_ttl_seconds: 10,
        path_request_fanout: 3
      )
    )

    start_supervised!(RoutingTopology.node_child_spec(down, "routing-duplicate-down"))

    :ok = RoutingTopology.connect_udp!(left, :left, center, :left)
    :ok = RoutingTopology.connect_udp!(right, :right, center, :right)
    :ok = RoutingTopology.connect_udp!(center, :down, down, :down)

    assert :ok = Node.subscribe_packets(down, self())

    destination_hash = :crypto.strong_rand_bytes(16)
    request_tag = :crypto.strong_rand_bytes(16)
    initial_packet = RoutingTopology.request_path_packet(destination_hash, request_tag, 0)
    duplicate_packet = RoutingTopology.request_path_packet(destination_hash, request_tag, 1)

    assert :ok = Node.send_packet(left, :left, initial_packet)

    assert_receive {:reticulum, :packet,
                    %{node: ^down, direction: :inbound, packet: %Packet{} = forwarded_packet}},
                   1_000

    assert {:ok, forwarded_request} = Pathfinder.parse_path_request_packet(forwarded_packet)
    assert forwarded_request.destination_hash == destination_hash
    assert forwarded_request.request_tag == request_tag

    assert :ok = Node.send_packet(right, :right, duplicate_packet)

    refute_receive {:reticulum, :packet, %{node: ^down, direction: :inbound, packet: %Packet{}}},
                   400
  end

  test "honors forwarding fanout after skipping unhealthy interfaces" do
    ingress = Reticulum.Node.RoutingFanoutIngress
    center = Reticulum.Node.RoutingFanoutCenter
    alpha = Reticulum.Node.RoutingFanoutAlpha
    beta = Reticulum.Node.RoutingFanoutBeta
    gamma = Reticulum.Node.RoutingFanoutGamma

    start_supervised!(RoutingTopology.node_child_spec(ingress, "routing-fanout-ingress"))

    start_supervised!(
      RoutingTopology.node_child_spec(center, "routing-fanout-center",
        path_request_fanout: 1,
        path_request_duplicate_ttl_seconds: 10
      )
    )

    start_supervised!(RoutingTopology.node_child_spec(alpha, "routing-fanout-alpha"))
    start_supervised!(RoutingTopology.node_child_spec(beta, "routing-fanout-beta"))
    start_supervised!(RoutingTopology.node_child_spec(gamma, "routing-fanout-gamma"))

    :ok = RoutingTopology.connect_udp!(ingress, :ingress, center, :ingress)
    :ok = RoutingTopology.connect_udp!(center, :alpha, alpha, :alpha)
    :ok = RoutingTopology.connect_udp!(center, :beta, beta, :beta)
    :ok = RoutingTopology.connect_udp!(center, :gamma, gamma, :gamma)

    assert :ok = Node.subscribe_packets(alpha, self())
    assert :ok = Node.subscribe_packets(beta, self())
    assert :ok = Node.subscribe_packets(gamma, self())
    assert :ok = Node.stop_interface(center, :alpha)
    Process.sleep(100)

    destination_hash = :crypto.strong_rand_bytes(16)
    request_tag = :crypto.strong_rand_bytes(16)
    packet = RoutingTopology.request_path_packet(destination_hash, request_tag, 0)

    assert :ok = Node.send_packet(ingress, :ingress, packet)

    assert_receive {:reticulum, :packet,
                    %{node: ^beta, direction: :inbound, packet: %Packet{} = forwarded_packet}},
                   1_000

    assert {:ok, forwarded_request} = Pathfinder.parse_path_request_packet(forwarded_packet)
    assert forwarded_request.destination_hash == destination_hash

    refute_receive {:reticulum, :packet, %{node: ^alpha, direction: :inbound, packet: %Packet{}}},
                   400

    refute_receive {:reticulum, :packet, %{node: ^gamma, direction: :inbound, packet: %Packet{}}},
                   400
  end
end
