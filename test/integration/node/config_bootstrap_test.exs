defmodule Reticulum.Node.ConfigBootstrapTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Packet

  @loopback {127, 0, 0, 1}

  test "starts node and UDP interface from TOML config" do
    node_name = Reticulum.Node.ConfigBootstrapRuntime
    storage_path = unique_storage_path("bootstrap-runtime")
    listen_port = free_udp_port()

    config_path =
      write_config!("""
      [node]
      storage_path = "#{storage_path}"
      transport_enabled = true
      shared_instance = false
      startup_mode = "cold"
      path_ttl_seconds = 120
      path_gc_interval_seconds = 2
      receipt_timeout_seconds = 8
      receipt_retention_seconds = 20

      [interfaces.link]
      type = "udp"
      listen_ip = "127.0.0.1"
      listen_port = #{listen_port}
      """)

    assert {:ok, pid} = Node.start_from_config(config_path, name: node_name)
    on_exit(fn -> maybe_stop(pid) end)

    assert {:ok, config} = Node.config(node_name)
    assert config.storage_path == Path.expand(storage_path)
    assert config.transport_enabled == true
    assert config.startup_mode == :cold
    assert config.path_ttl_seconds == 120
    assert config.path_gc_interval_seconds == 2
    assert config.receipt_timeout_seconds == 8
    assert config.receipt_retention_seconds == 20

    assert {:ok, [interface]} = Node.interfaces(node_name)
    assert interface.name == :link
    assert interface.module == Reticulum.Interface.UDP
    assert interface.meta.listen_ip == @loopback
    assert interface.meta.listen_port == listen_port
  end

  test "supports config-driven announce path between nodes" do
    node_a = Reticulum.Node.ConfigBootstrapA
    node_b = Reticulum.Node.ConfigBootstrapB
    port_a = free_udp_port()
    port_b = free_udp_port()

    config_a =
      write_config!("""
      [node]
      storage_path = "#{unique_storage_path("bootstrap-a")}"
      transport_enabled = true

      [interfaces.link]
      type = "udp"
      listen_ip = "127.0.0.1"
      listen_port = #{port_a}
      default_peer_ip = "127.0.0.1"
      default_peer_port = #{port_b}
      """)

    config_b =
      write_config!("""
      [node]
      storage_path = "#{unique_storage_path("bootstrap-b")}"
      transport_enabled = true

      [interfaces.link]
      type = "udp"
      listen_ip = "127.0.0.1"
      listen_port = #{port_b}
      default_peer_ip = "127.0.0.1"
      default_peer_port = #{port_a}
      """)

    assert {:ok, pid_a} = Node.start_from_config(config_a, name: node_a)
    assert {:ok, pid_b} = Node.start_from_config(config_b, name: node_b)

    on_exit(fn ->
      maybe_stop(pid_b)
      maybe_stop(pid_a)
    end)

    assert :ok = Node.subscribe_packets(node_a, self())

    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase2", identity, ["bootstrap"])

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

  test "rolls back node when interface bootstrap fails" do
    node_name = Reticulum.Node.ConfigBootstrapRollback
    listen_port = free_udp_port()
    storage_path = unique_storage_path("bootstrap-rollback")

    {:ok, socket} = :gen_udp.open(listen_port, [:binary, {:active, false}, {:ip, @loopback}])

    config_path =
      write_config!("""
      [node]
      storage_path = "#{storage_path}"
      transport_enabled = false

      [interfaces.link]
      type = "udp"
      listen_ip = "127.0.0.1"
      listen_port = #{listen_port}
      """)

    assert {:error, {:interface_start_failed, :link, {:udp_open_failed, :eaddrinuse}}} =
             Node.start_from_config(config_path, name: node_name)

    assert node_name
           |> Node.state_server()
           |> :global.whereis_name() == :undefined

    assert node_name
           |> Node.transport_server()
           |> :global.whereis_name() == :undefined

    assert node_name
           |> Node.interface_supervisor()
           |> :global.whereis_name() == :undefined

    :ok = :gen_udp.close(socket)
  end

  defp write_config!(contents) do
    path =
      Path.join(
        System.tmp_dir!(),
        "reticulum-bootstrap-#{System.unique_integer([:positive])}.toml"
      )

    :ok = File.write(path, contents)
    path
  end

  defp unique_storage_path(prefix) do
    Path.join(System.tmp_dir!(), "reticulum-#{prefix}-#{System.unique_integer([:positive])}")
  end

  defp maybe_stop(pid) when is_pid(pid) do
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
