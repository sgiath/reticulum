defmodule Reticulum.Interop.SendReceiveTest do
  use ExUnit.Case, async: false

  alias Reticulum.Node
  alias Reticulum.ReferenceRunner

  @loopback {127, 0, 0, 1}

  setup do
    node_name = Reticulum.Node.InteropSendReceive

    start_supervised!(
      {Node,
       name: node_name,
       storage_path: Path.join(System.tmp_dir!(), "reticulum-interop-send-receive")}
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

  test "Python reference parser can decode outbound Elixir data packets", %{node_name: node_name} do
    destination_hash = :crypto.strong_rand_bytes(16)
    payload = <<1, 2, 3, 4, 5, 200>>

    assert :ok =
             Node.put_destination(node_name, destination_hash, :crypto.strong_rand_bytes(64), nil)

    assert :ok = Node.send_data(node_name, :udp_a, destination_hash, payload)

    assert_receive {:reticulum, :packet, %{direction: :outbound, raw: raw}}, 1_000

    unpack_fields =
      raw
      |> hex()
      |> then(&ReferenceRunner.run!("packet_unpack", [&1]))
      |> ReferenceRunner.parse_kv_lines()

    assert unpack_fields["success"] == "true"
    assert unpack_fields["packet_type"] == "0"
    assert unpack_fields["destination_type"] == "0"
    assert unpack_fields["transport_type"] == "0"
    assert unpack_fields["destination_hash"] == hex(destination_hash)
    assert unpack_fields["data"] == hex(payload)
  end

  defp hex(data), do: Base.encode16(data, case: :lower)

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end
end
