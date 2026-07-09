defmodule Reticulum.Interface.RuntimeTest do
  use ExUnit.Case, async: false

  alias Reticulum.Node
  alias Reticulum.TestSupport.TestInterface

  test "starts a custom adapter under the managed interface runtime" do
    node_name = Reticulum.Node.CustomInterfaceRuntime

    start_supervised!(
      {Node, name: node_name, storage_path: unique_storage_path("custom-runtime")}
    )

    assert {:ok, _pid} =
             Node.start_interface(node_name, TestInterface,
               name: :custom,
               test_pid: self(),
               queue_limit: 3
             )

    assert {:ok, [interface]} = Node.interfaces(node_name)
    assert interface.name == :custom
    assert interface.module == TestInterface
    assert interface.meta.kind == :test
    assert interface.meta.queue_limit == 3
    assert interface.health.score == 100
    assert interface.health.band == :healthy
  end

  test "applies queue backpressure, rate limiting, and health updates" do
    node_name = Reticulum.Node.ManagedInterfaceBackpressure

    start_supervised!({Node, name: node_name, storage_path: unique_storage_path("backpressure")})

    assert {:ok, _pid} = start_throttled_interface(node_name, backpressure: :reject)

    assert :ok = Node.send_frame(node_name, :custom, "first")

    # send_frame replies on enqueue: a throttled interface must not block callers
    {elapsed_us, :ok} = :timer.tc(fn -> Node.send_frame(node_name, :custom, "second") end)
    assert elapsed_us < 500_000

    assert {:error, :interface_backpressure} = Node.send_frame(node_name, :custom, "third")

    assert_receive {:test_interface_sent, :custom, "first", _opts}, 200
    assert_receive {:test_interface_sent, :custom, "second", _opts}, 1_500

    assert {:ok, [interface]} = Node.interfaces(node_name)
    assert interface.stats.dropped_frames == 1
    assert interface.stats.throttled_count >= 1

    send(interface.pid, {:adapter_status, :degraded})

    assert {:ok, degraded} =
             wait_for_interface(node_name, :custom, fn interface ->
               interface.health.band == :degraded and interface.health.score < 100
             end)

    assert degraded.health.band == :degraded
  end

  test "drop_newest accepts and silently drops frames that overflow the queue" do
    node_name = Reticulum.Node.ManagedInterfaceDropNewest

    start_supervised!({Node, name: node_name, storage_path: unique_storage_path("drop-newest")})

    assert {:ok, _pid} = start_throttled_interface(node_name, backpressure: :drop_newest)

    assert :ok = Node.send_frame(node_name, :custom, "first")
    assert :ok = Node.send_frame(node_name, :custom, "second")
    assert :ok = Node.send_frame(node_name, :custom, "third")

    assert_receive {:test_interface_sent, :custom, "first", _opts}, 200
    assert_receive {:test_interface_sent, :custom, "second", _opts}, 1_500
    refute_receive {:test_interface_sent, :custom, "third", _opts}, 200

    assert {:ok, [interface]} = Node.interfaces(node_name)
    assert interface.stats.dropped_frames == 1
  end

  test "drop_oldest evicts the oldest queued frame in favor of new ones" do
    node_name = Reticulum.Node.ManagedInterfaceDropOldest

    start_supervised!({Node, name: node_name, storage_path: unique_storage_path("drop-oldest")})

    assert {:ok, _pid} = start_throttled_interface(node_name, backpressure: :drop_oldest)

    assert :ok = Node.send_frame(node_name, :custom, "first")
    assert :ok = Node.send_frame(node_name, :custom, "second")
    assert :ok = Node.send_frame(node_name, :custom, "third")

    assert_receive {:test_interface_sent, :custom, "first", _opts}, 200
    assert_receive {:test_interface_sent, :custom, "third", _opts}, 1_500
    refute_receive {:test_interface_sent, :custom, "second", _opts}, 200

    assert {:ok, [interface]} = Node.interfaces(node_name)
    assert interface.stats.dropped_frames == 1
  end

  defp start_throttled_interface(node_name, opts) do
    Node.start_interface(
      node_name,
      TestInterface,
      Keyword.merge(
        [
          name: :custom,
          test_pid: self(),
          queue_limit: 1,
          rate_limit_packets_per_second: 1,
          rate_limit_burst_packets: 1
        ],
        opts
      )
    )
  end

  defp wait_for_interface(node_name, interface_name, matcher, attempts \\ 40)

  defp wait_for_interface(node_name, interface_name, matcher, attempts) when attempts > 0 do
    case Node.interfaces(node_name) do
      {:ok, interfaces} ->
        interfaces
        |> Enum.find(&(&1.name == interface_name))
        |> match_interface(node_name, interface_name, matcher, attempts)

      _other ->
        Process.sleep(25)
        wait_for_interface(node_name, interface_name, matcher, attempts - 1)
    end
  end

  defp wait_for_interface(_node_name, _interface_name, _matcher, 0), do: :error

  defp match_interface(nil, node_name, interface_name, matcher, attempts) do
    Process.sleep(25)
    wait_for_interface(node_name, interface_name, matcher, attempts - 1)
  end

  defp match_interface(interface, node_name, interface_name, matcher, attempts) do
    if matcher.(interface) do
      {:ok, interface}
    else
      Process.sleep(25)
      wait_for_interface(node_name, interface_name, matcher, attempts - 1)
    end
  end

  defp unique_storage_path(prefix) do
    Path.join(System.tmp_dir!(), "reticulum-#{prefix}-#{System.unique_integer([:positive])}")
  end
end
