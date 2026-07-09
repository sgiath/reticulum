defmodule Reticulum.Transport.ObservabilityTest do
  use ExUnit.Case, async: false

  alias Reticulum.Node
  alias Reticulum.Observability
  alias Reticulum.TestSupport.TestInterface

  @loopback {127, 0, 0, 1}

  test "emits telemetry events for receipt lifecycle when telemetry is available" do
    if function_exported?(:telemetry, :attach_many, 4) do
      handler_id = "reticulum-observability-#{System.unique_integer([:positive])}"

      events = [
        [:reticulum, :transport, :receipt, :tracked],
        [:reticulum, :transport, :receipt, :timed_out]
      ]

      :ok =
        apply(:telemetry, :attach_many, [
          handler_id,
          events,
          fn event, measurements, metadata, pid ->
            send(pid, {:telemetry_event, event, measurements, metadata})
          end,
          self()
        ])

      node_name = Reticulum.Node.TransportObservability

      start_supervised!(
        {Node,
         name: node_name,
         storage_path: Path.join(System.tmp_dir!(), "reticulum-transport-observability"),
         receipt_timeout_seconds: 1,
         path_gc_interval_seconds: 1}
      )

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

      destination_hash = :crypto.strong_rand_bytes(16)

      assert :ok =
               Node.put_destination(
                 node_name,
                 destination_hash,
                 :crypto.strong_rand_bytes(64),
                 nil
               )

      {:ok, receipt_hash} =
        Node.send_data(node_name, :udp_a, destination_hash, "obs-test",
          track_receipt: true,
          receipt_timeout_seconds: 1
        )

      assert_receive {:telemetry_event, [:reticulum, :transport, :receipt, :tracked], _,
                      %{node: ^node_name, receipt_hash: ^receipt_hash}},
                     1_000

      assert_receive {:telemetry_event, [:reticulum, :transport, :receipt, :timed_out], _,
                      %{node: ^node_name, receipt_hash: ^receipt_hash}},
                     3_000

      :ok = apply(:telemetry, :detach, [handler_id])
    else
      assert :ok = Observability.emit([:transport, :receipt, :tracked], %{count: 1}, %{})
    end
  end

  test "emits telemetry events for interface health and queue updates when telemetry is available" do
    if function_exported?(:telemetry, :attach_many, 4) do
      handler_id = "reticulum-interface-observability-#{System.unique_integer([:positive])}"

      events = [
        [:reticulum, :interface, :health, :updated],
        [:reticulum, :interface, :queue, :updated],
        [:reticulum, :interface, :send, :throttled]
      ]

      :ok =
        apply(:telemetry, :attach_many, [
          handler_id,
          events,
          fn event, measurements, metadata, pid ->
            send(pid, {:telemetry_event, event, measurements, metadata})
          end,
          self()
        ])

      node_name = Reticulum.Node.InterfaceObservability

      start_supervised!(
        {Node,
         name: node_name,
         storage_path: Path.join(System.tmp_dir!(), "reticulum-interface-observability")}
      )

      assert {:ok, _pid} =
               Node.start_interface(node_name, TestInterface,
                 name: :custom,
                 test_pid: self(),
                 queue_limit: 1,
                 rate_limit_packets_per_second: 1,
                 rate_limit_burst_packets: 1
               )

      assert_receive {:telemetry_event, [:reticulum, :interface, :health, :updated], _,
                      %{node: ^node_name, interface: :custom}},
                     1_000

      assert_receive {:telemetry_event, [:reticulum, :interface, :queue, :updated], _,
                      %{node: ^node_name, interface: :custom}},
                     1_000

      assert :ok = Node.send_frame(node_name, :custom, "first")
      task = Task.async(fn -> Node.send_frame(node_name, :custom, "second") end)

      assert_receive {:telemetry_event, [:reticulum, :interface, :send, :throttled], _,
                      %{node: ^node_name, interface: :custom}},
                     1_500

      assert :ok = Task.await(task, 2_000)
      :ok = apply(:telemetry, :detach, [handler_id])
    else
      assert :ok = Observability.emit([:interface, :health, :updated], %{score: 100}, %{})
    end
  end

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end
end
