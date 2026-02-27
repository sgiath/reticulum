defmodule Reticulum.Messaging.ApiTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Messaging
  alias Reticulum.Node
  alias Reticulum.Node.State
  alias Reticulum.Packet

  @loopback {127, 0, 0, 1}

  setup do
    node_name = Reticulum.Node.TransportPhase5

    start_supervised!(
      {Node, name: node_name, storage_path: Path.join(System.tmp_dir!(), "reticulum-phase5")}
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

  test "local destination callbacks and request/response hooks", %{node_name: node_name} do
    destination_hash = :crypto.strong_rand_bytes(16)
    public_key = :crypto.strong_rand_bytes(64)

    caller = self()
    callback = fn event -> send(caller, {:callback_invoked, event.destination_hash}) end

    assert :ok = Node.put_destination(node_name, destination_hash, public_key, nil)

    assert :ok =
             Node.register_local_destination(node_name, destination_hash, self(),
               callback: callback
             )

    assert :ok = Messaging.register_request_handler(node_name, destination_hash, 7, self())
    assert :ok = Messaging.register_response_handler(node_name, destination_hash, 9, self())

    assert :ok = Messaging.send(node_name, destination_hash, "req", interface: :udp_a, context: 7)

    assert_receive {:callback_invoked, ^destination_hash}, 1_000
    assert_receive {:reticulum, :request, %{destination_hash: ^destination_hash}}, 1_000

    assert :ok = Messaging.send(node_name, destination_hash, "res", interface: :udp_a, context: 9)

    assert_receive {:reticulum, :response, %{destination_hash: ^destination_hash}}, 1_000
  end

  test "high-level send resolves interface from path table", %{node_name: node_name} do
    destination_hash = :crypto.strong_rand_bytes(16)
    public_key = :crypto.strong_rand_bytes(64)

    assert :ok = Node.put_destination(node_name, destination_hash, public_key, nil)

    assert :ok =
             Node.put_path(node_name, destination_hash, :crypto.strong_rand_bytes(16), 1,
               interface: :udp_a
             )

    assert {:ok, %{interface: :udp_a}} = Node.path(node_name, destination_hash)

    assert :ok = Messaging.send(node_name, destination_hash, <<5, 6, 7>>)

    assert_receive {:reticulum, :packet,
                    %{direction: :inbound, interface: :udp_b, packet: %Packet{data: <<5, 6, 7>>}}},
                   1_000
  end

  test "announce API emits announce packet for local destination", %{node_name: node_name} do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase5", identity, ["api"])

    assert :ok = Node.register_local_announce_destination(node_name, destination, self())
    assert :ok = Messaging.announce(node_name, destination.hash, interface: :udp_a)

    assert_receive {:reticulum, :packet,
                    %{direction: :outbound, packet: %Packet{type: :announce}}},
                   1_000

    assert_receive {:reticulum, :packet,
                    %{direction: :inbound, interface: :udp_b, packet: %Packet{type: :announce}}},
                   1_000
  end

  test "send rejects invalid interface option", %{node_name: node_name} do
    destination_hash = :crypto.strong_rand_bytes(16)

    assert :ok =
             Node.put_destination(node_name, destination_hash, :crypto.strong_rand_bytes(64), nil)

    assert {:error, :invalid_interface} =
             Messaging.send(node_name, destination_hash, "payload", interface: "udp_a")
  end

  test "send retries with first interface when path-selected interface is stale", %{
    node_name: node_name
  } do
    destination_hash = :crypto.strong_rand_bytes(16)
    payload = <<9, 8, 7>>

    assert :ok =
             Node.put_destination(node_name, destination_hash, :crypto.strong_rand_bytes(64), nil)

    assert :ok =
             Node.put_path(node_name, destination_hash, :crypto.strong_rand_bytes(16), 1,
               interface: :missing_interface
             )

    assert :ok = Messaging.send(node_name, destination_hash, payload)

    assert_receive {:reticulum, :packet,
                    %{direction: :inbound, interface: :udp_b, packet: %Packet{data: ^payload}}},
                   1_000
  end

  test "send does not retry unknown explicit interface", %{node_name: node_name} do
    destination_hash = :crypto.strong_rand_bytes(16)

    assert :ok =
             Node.put_destination(node_name, destination_hash, :crypto.strong_rand_bytes(64), nil)

    assert {:error, :unknown_interface} =
             Messaging.send(node_name, destination_hash, "payload", interface: :missing_interface)
  end

  test "send returns no_interfaces on a node with no interfaces" do
    node_name = Reticulum.Node.MessagingNoInterfaces

    start_supervised!(
      Supervisor.child_spec(
        {Node,
         name: node_name,
         storage_path: Path.join(System.tmp_dir!(), "reticulum-messaging-no-interfaces")},
        id: {:messaging_no_interfaces_node, node_name}
      )
    )

    destination_hash = :crypto.strong_rand_bytes(16)

    assert :ok =
             Node.put_destination(node_name, destination_hash, :crypto.strong_rand_bytes(64), nil)

    assert {:ok, []} = Node.interfaces(node_name)
    assert {:error, :no_interfaces} = Messaging.send(node_name, destination_hash, "payload")
  end

  test "default-node request and response handler wrappers register entries" do
    if is_nil(Process.whereis(Node)) do
      start_supervised!(
        Supervisor.child_spec(
          {Node,
           storage_path: Path.join(System.tmp_dir!(), "reticulum-messaging-default-wrappers")},
          id: :messaging_default_wrapper_node
        )
      )
    end

    destination_hash = :crypto.strong_rand_bytes(16)

    assert :ok = Messaging.register_request_handler(destination_hash, 12, self())
    assert :ok = Messaging.register_response_handler(destination_hash, 34, self())

    assert {:ok, %{pid: request_pid}} =
             State.request_handler(Node.state_server(), destination_hash, 12)

    assert {:ok, %{pid: response_pid}} =
             State.response_handler(Node.state_server(), destination_hash, 34)

    assert request_pid == self()
    assert response_pid == self()
  end

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end
end
