defmodule Reticulum.Transport.RoutingHealthTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Packet
  alias Reticulum.TestSupport.TestInterface
  alias Reticulum.Transport.Announce

  @loopback {127, 0, 0, 1}

  test "prefers healthier interfaces over better hop count when updating paths" do
    node_name = Reticulum.Node.RoutingHealthTarget

    start_supervised!(
      {Node,
       name: node_name,
       storage_path: unique_storage_path("routing-health"),
       transport_enabled: true}
    )

    assert {:ok, _pid} =
             Node.start_interface(node_name, TestInterface,
               name: :left,
               test_pid: self()
             )

    assert {:ok, _pid} =
             Node.start_interface(node_name, TestInterface,
               name: :right,
               test_pid: self()
             )

    {:ok, left} = fetch_interface(node_name, :left)
    {:ok, right} = fetch_interface(node_name, :right)

    send(left.pid, {:adapter_status, :degraded})

    assert {:ok, _interface} =
             wait_for_interface(node_name, :left, &(&1.health.band == :degraded))

    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase10", identity, ["health"])

    send(
      left.pid,
      {:inject_inbound, encode_announce_packet(destination, 0, <<1::80>>), {@loopback, 41_001}}
    )

    assert {:ok, degraded_path} =
             wait_for_path(node_name, destination.hash, &(&1.interface == :left))

    assert degraded_path.hops == 0

    send(
      right.pid,
      {:inject_inbound, encode_announce_packet(destination, 2, <<2::80>>), {@loopback, 41_002}}
    )

    assert {:ok, healthy_path} =
             wait_for_path(
               node_name,
               destination.hash,
               &(&1.interface == :right and &1.hops == 2)
             )

    assert healthy_path.interface == :right
  end

  defp fetch_interface(node_name, interface_name) do
    case Node.interfaces(node_name) do
      {:ok, interfaces} ->
        case Enum.find(interfaces, &(&1.name == interface_name)) do
          nil -> :error
          interface -> {:ok, interface}
        end

      _other ->
        :error
    end
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

  defp encode_announce_packet(destination, hops, random_hash) do
    destination
    |> announce_packet(hops, random_hash)
    |> Packet.encode()
  end

  defp wait_for_interface(node_name, interface_name, matcher, attempts \\ 40)

  defp wait_for_interface(node_name, interface_name, matcher, attempts) when attempts > 0 do
    case fetch_interface(node_name, interface_name) do
      {:ok, interface} ->
        if matcher.(interface) do
          {:ok, interface}
        else
          Process.sleep(25)
          wait_for_interface(node_name, interface_name, matcher, attempts - 1)
        end

      :error ->
        Process.sleep(25)
        wait_for_interface(node_name, interface_name, matcher, attempts - 1)
    end
  end

  defp wait_for_interface(_node_name, _interface_name, _matcher, 0), do: :error

  defp wait_for_path(node_name, destination_hash, matcher, attempts \\ 40)

  defp wait_for_path(node_name, destination_hash, matcher, attempts) when attempts > 0 do
    case Node.path(node_name, destination_hash) do
      {:ok, path} = result ->
        if matcher.(path) do
          result
        else
          Process.sleep(25)
          wait_for_path(node_name, destination_hash, matcher, attempts - 1)
        end

      _other ->
        Process.sleep(25)
        wait_for_path(node_name, destination_hash, matcher, attempts - 1)
    end
  end

  defp wait_for_path(_node_name, _destination_hash, _matcher, 0), do: :error

  defp unique_storage_path(prefix) do
    Path.join(System.tmp_dir!(), "reticulum-#{prefix}-#{System.unique_integer([:positive])}")
  end
end
