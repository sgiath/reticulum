defmodule Reticulum.TestSupport.RoutingTopology do
  @moduledoc false

  import ExUnit.Assertions

  alias Reticulum.Node
  alias Reticulum.Packet
  alias Reticulum.Transport.Pathfinder

  @loopback {127, 0, 0, 1}

  def node_child_spec(node_name, storage_suffix, opts \\ []) do
    Supervisor.child_spec(
      {Node,
       Keyword.merge(
         [
           name: node_name,
           storage_path: unique_storage_path(storage_suffix),
           transport_enabled: true,
           routing_max_hops: 8
         ],
         opts
       )},
      id: node_name
    )
  end

  def connect_udp!(node_a, interface_a, node_b, interface_b \\ nil) do
    interface_b = interface_b || interface_a
    port_a = free_udp_port()
    port_b = free_udp_port()

    assert {:ok, _pid} =
             Node.start_udp_interface(node_a,
               name: interface_a,
               listen_ip: @loopback,
               listen_port: port_a,
               default_peer_ip: @loopback,
               default_peer_port: port_b
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(node_b,
               name: interface_b,
               listen_ip: @loopback,
               listen_port: port_b,
               default_peer_ip: @loopback,
               default_peer_port: port_a
             )

    :ok
  end

  def request_path_packet(destination_hash, request_tag, hops \\ 0, opts \\ []) do
    requester_hash = Keyword.get(opts, :requester_hash)

    {:ok, %Packet{} = packet} =
      Pathfinder.build_path_request_packet(
        destination_hash,
        requester_hash: requester_hash,
        request_tag: request_tag
      )

    %Packet{packet | hops: hops}
  end

  def wait_for_path(node_name, destination_hash, attempts \\ 40)

  def wait_for_path(node_name, destination_hash, matcher)
      when is_function(matcher, 1),
      do: wait_for_path(node_name, destination_hash, matcher, 40)

  def wait_for_path(node_name, destination_hash, attempts) when attempts > 0 do
    case Node.path(node_name, destination_hash) do
      {:ok, _path} = result ->
        result

      :error ->
        Process.sleep(25)
        wait_for_path(node_name, destination_hash, attempts - 1)
    end
  end

  def wait_for_path(_node_name, _destination_hash, 0), do: :error

  def wait_for_path(node_name, destination_hash, matcher, attempts) when attempts > 0 do
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

  def wait_for_path(_node_name, _destination_hash, _matcher, 0), do: :error

  def wait_for_receipt(node_name, receipt_hash, attempts \\ 40)

  def wait_for_receipt(node_name, receipt_hash, attempts) when attempts > 0 do
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

  def wait_for_receipt(_node_name, _receipt_hash, 0), do: :error

  def maybe_stop(pid) when is_pid(pid) do
    if Process.alive?(pid) do
      Process.unlink(pid)

      try do
        _ = Supervisor.stop(pid)
      catch
        :exit, _reason -> :ok
      end
    end

    :ok
  end

  def unique_storage_path(prefix) do
    Path.join(System.tmp_dir!(), "reticulum-#{prefix}-#{System.unique_integer([:positive])}")
  end

  def free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end
end
