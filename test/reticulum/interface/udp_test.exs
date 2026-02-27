defmodule Reticulum.Interface.UDPTest do
  use ExUnit.Case, async: false

  alias Reticulum.Node

  @loopback {127, 0, 0, 1}

  setup do
    node_name = Reticulum.Node.InterfaceRuntimeTest

    start_supervised!(
      {Node,
       name: node_name,
       storage_path: Path.join(System.tmp_dir!(), "reticulum-node-interface-runtime-test")}
    )

    :ok = Node.subscribe_frames(node_name, self())

    {:ok, node_name: node_name}
  end

  test "starts and lists UDP interfaces", %{node_name: node_name} do
    listen_port = free_udp_port()

    assert {:ok, _pid} =
             Node.start_udp_interface(node_name,
               name: :udp_a,
               listen_ip: @loopback,
               listen_port: listen_port
             )

    assert {:ok, interfaces} = Node.interfaces(node_name)
    assert length(interfaces) == 1

    [interface] = interfaces
    assert interface.name == :udp_a
    assert interface.module == Reticulum.Interface.UDP
    assert interface.meta.listen_ip == @loopback
    assert interface.meta.listen_port == listen_port
  end

  test "sends raw frames between two local UDP interfaces", %{node_name: node_name} do
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

    payload = <<1, 2, 3, 4, 5>>
    assert :ok = Node.send_frame(node_name, :udp_a, payload)

    assert_receive {:reticulum, :frame,
                    %{
                      node: ^node_name,
                      direction: :outbound,
                      interface: :udp_a,
                      payload: ^payload,
                      endpoint: {@loopback, ^port_b}
                    }},
                   1_000

    assert_receive {:reticulum, :frame,
                    %{
                      node: ^node_name,
                      direction: :inbound,
                      interface: :udp_b,
                      payload: ^payload,
                      endpoint: {@loopback, ^port_a}
                    }},
                   1_000
  end

  test "returns unknown interface when stopped", %{node_name: node_name} do
    listen_port = free_udp_port()

    assert {:ok, _pid} =
             Node.start_udp_interface(node_name,
               name: :udp_a,
               listen_ip: @loopback,
               listen_port: listen_port
             )

    assert :ok = Node.stop_interface(node_name, :udp_a)
    assert {:error, :unknown_interface} = Node.send_frame(node_name, :udp_a, <<0>>)
  end

  test "supports per-send endpoint overrides", %{node_name: node_name} do
    port_a = free_udp_port()
    port_b = free_udp_port()

    assert {:ok, _pid} =
             Node.start_udp_interface(node_name,
               name: :udp_a,
               listen_ip: @loopback,
               listen_port: port_a
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(node_name,
               name: :udp_b,
               listen_ip: @loopback,
               listen_port: port_b
             )

    payload = <<77, 88, 99>>

    assert :ok =
             Node.send_frame(node_name, :udp_a, payload,
               ip: @loopback,
               port: port_b
             )

    assert_receive {:reticulum, :frame,
                    %{
                      direction: :inbound,
                      interface: :udp_b,
                      payload: ^payload,
                      endpoint: {@loopback, ^port_a}
                    }},
                   1_000
  end

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end
end
