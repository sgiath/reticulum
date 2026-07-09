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

    assert {:ok, _pid} =
             Node.start_interface(node_name, TestInterface,
               name: :custom,
               test_pid: self(),
               queue_limit: 1,
               backpressure: :reject,
               rate_limit_packets_per_second: 1,
               rate_limit_burst_packets: 1
             )

    assert :ok = Node.send_frame(node_name, :custom, "first")

    task = Task.async(fn -> Node.send_frame(node_name, :custom, "second") end)
    Process.sleep(50)

    assert {:error, :interface_backpressure} = Node.send_frame(node_name, :custom, "third")
    assert :ok = Task.await(task, 2_000)

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
