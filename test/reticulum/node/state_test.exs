defmodule Reticulum.Node.StateTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Node.State

  setup do
    node_name = Reticulum.Node.StateTest

    start_supervised!(
      {Node,
       name: node_name, storage_path: Path.join(System.tmp_dir!(), "reticulum-node-state-test")}
    )

    {:ok, node_name: node_name, state_server: Node.state_server(node_name)}
  end

  test "returns config/tables and unknown table errors", %{state_server: state_server} do
    assert {:ok, _config} = State.config(state_server)
    assert {:ok, tables} = State.tables(state_server)

    assert Map.has_key?(tables, :destinations)
    assert Map.has_key?(tables, :paths)
    assert Map.has_key?(tables, :packet_hashes)

    assert {:error, :unknown_table} = State.table(state_server, :not_a_table)
  end

  test "validates destination/path inputs and path lifecycle", %{state_server: state_server} do
    destination_hash = :crypto.strong_rand_bytes(16)
    next_hop = :crypto.strong_rand_bytes(16)

    assert {:error, :invalid_destination_hash} =
             State.put_destination(state_server, :bad, <<1>>, nil)

    assert {:error, :invalid_public_key} =
             State.put_destination(state_server, destination_hash, :bad, nil)

    assert {:error, :invalid_app_data} =
             State.put_destination(
               state_server,
               destination_hash,
               :crypto.strong_rand_bytes(64),
               123
             )

    assert {:error, :invalid_destination_options} =
             State.put_destination(
               state_server,
               destination_hash,
               :crypto.strong_rand_bytes(64),
               nil,
               bad: true
             )

    assert {:error, :missing_destination_key} =
             State.put_destination(state_server, destination_hash, nil, nil)

    group_key = :crypto.strong_rand_bytes(64)

    assert :ok =
             State.put_destination(state_server, destination_hash, nil, nil,
               group_key: group_key,
               ratchet: :crypto.strong_rand_bytes(32)
             )

    assert {:ok, destination_record} = State.destination(state_server, destination_hash)
    assert destination_record.group_key == group_key
    assert is_binary(destination_record.ratchet)
    assert is_integer(destination_record.ratchet_received_at)

    assert :ok =
             State.put_destination(
               state_server,
               destination_hash,
               :crypto.strong_rand_bytes(64),
               nil,
               []
             )

    assert {:ok, destination_record_after_update} =
             State.destination(state_server, destination_hash)

    assert destination_record_after_update.group_key == group_key
    assert is_binary(destination_record_after_update.ratchet)
    assert is_integer(destination_record_after_update.ratchet_received_at)

    assert :ok =
             State.put_destination(
               state_server,
               destination_hash,
               :crypto.strong_rand_bytes(64),
               nil,
               ratchet: nil,
               ratchet_received_at: nil
             )

    assert {:ok, destination_record_after_ratchet_clear} =
             State.destination(state_server, destination_hash)

    assert destination_record_after_ratchet_clear.group_key == group_key
    assert destination_record_after_ratchet_clear.ratchet == nil
    assert destination_record_after_ratchet_clear.ratchet_received_at == nil

    assert {:error, :invalid_path_options} =
             State.put_path(state_server, destination_hash, next_hop, 1, :bad)

    assert {:error, :invalid_destination_hash} =
             State.put_path(state_server, :bad, next_hop, 1, [])

    assert {:error, :invalid_next_hop} =
             State.put_path(state_server, destination_hash, :bad, 1, [])

    assert {:error, :invalid_hops} =
             State.put_path(state_server, destination_hash, next_hop, -1, [])

    assert {:error, :invalid_interface} =
             State.put_path(state_server, destination_hash, next_hop, 1, interface: "udp")

    assert :ok = State.put_path(state_server, destination_hash, next_hop, 2, interface: :udp)
    assert {:ok, paths} = State.paths(state_server)
    assert Enum.any?(paths, &(&1.destination_hash == destination_hash and &1.interface == :udp))

    assert :ok = State.delete_path(state_server, destination_hash)
    assert {:error, :unknown_path} = State.delete_path(state_server, destination_hash)
  end

  test "expires remembered destination ratchets", %{state_server: state_server} do
    destination_hash = :crypto.strong_rand_bytes(16)

    assert :ok =
             State.put_destination(
               state_server,
               destination_hash,
               :crypto.strong_rand_bytes(64),
               nil,
               ratchet: :crypto.strong_rand_bytes(32),
               ratchet_received_at: 1
             )

    assert [^destination_hash] = State.expire_destination_ratchets(state_server, 1, 3)

    assert {:ok, destination_record} = State.destination(state_server, destination_hash)
    assert destination_record.ratchet == nil
    assert destination_record.ratchet_received_at == nil
  end

  test "validates duplicate cache and subscriber APIs", %{state_server: state_server} do
    packet_hash = :crypto.strong_rand_bytes(32)

    assert {:error, :invalid_packet_hash} = State.remember_packet_hash(state_server, :bad)
    assert :new = State.remember_packet_hash(state_server, packet_hash)
    assert :existing = State.remember_packet_hash(state_server, packet_hash)

    assert {:error, :invalid_subscriber} = State.subscribe_frames(state_server, :bad)
    assert {:error, :invalid_subscriber} = State.unsubscribe_frames(state_server, :bad)
    assert {:error, :invalid_subscriber} = State.subscribe_packets(state_server, :bad)
    assert {:error, :invalid_subscriber} = State.unsubscribe_packets(state_server, :bad)

    assert :ok = State.subscribe_frames(state_server, self())
    assert :ok = State.subscribe_packets(state_server, self())

    frame_event = %{direction: :outbound, payload: <<1>>, interface: :udp}
    packet_event = %{direction: :inbound, packet: nil, interface: :udp}

    State.publish_frame(state_server, frame_event)
    State.publish_packet(state_server, packet_event)

    assert_receive {:reticulum, :frame, ^frame_event}, 500
    assert_receive {:reticulum, :packet, ^packet_event}, 500

    assert :ok = State.unsubscribe_frames(state_server, self())
    assert :ok = State.unsubscribe_packets(state_server, self())
  end

  test "register_interface validates input and removes dead interfaces", %{
    state_server: state_server
  } do
    alive_interface = spawn(fn -> Process.sleep(:infinity) end)
    on_exit(fn -> Process.exit(alive_interface, :kill) end)

    {dead_interface, dead_ref} = spawn_monitor(fn -> :ok end)
    assert_receive {:DOWN, ^dead_ref, :process, ^dead_interface, :normal}

    assert {:error, :invalid_interface_name} =
             State.register_interface(
               state_server,
               "udp",
               alive_interface,
               Reticulum.Interface.UDP,
               %{}
             )

    assert {:error, :invalid_interface_pid} =
             State.register_interface(state_server, :udp, :bad, Reticulum.Interface.UDP, %{})

    assert {:error, :invalid_interface_module} =
             State.register_interface(state_server, :udp, alive_interface, "udp", %{})

    assert {:error, :invalid_interface_meta} =
             State.register_interface(
               state_server,
               :udp,
               alive_interface,
               Reticulum.Interface.UDP,
               []
             )

    assert {:error, :interface_not_alive} =
             State.register_interface(
               state_server,
               :dead,
               dead_interface,
               Reticulum.Interface.UDP,
               %{}
             )

    assert :ok =
             State.register_interface(
               state_server,
               :alive,
               alive_interface,
               Reticulum.Interface.UDP,
               %{
                 listen_port: 42_424
               }
             )

    assert {:error, :interface_already_registered} =
             State.register_interface(
               state_server,
               :alive,
               alive_interface,
               Reticulum.Interface.UDP,
               %{}
             )

    assert {:ok, registered} = State.interface(state_server, :alive)
    assert registered.name == :alive
    refute Map.has_key?(registered, :monitor_ref)
    assert {:ok, [%{name: :alive}]} = State.interfaces(state_server)

    assert {:error, :unknown_interface} = State.unregister_interface(state_server, :unknown)
    assert :ok = State.unregister_interface(state_server, :alive)

    monitored_interface = spawn(fn -> Process.sleep(:infinity) end)

    assert :ok =
             State.register_interface(
               state_server,
               :monitored,
               monitored_interface,
               Reticulum.Interface.UDP,
               %{}
             )

    Process.exit(monitored_interface, :kill)

    assert eventually(fn -> State.interface(state_server, :monitored) == :error end)
  end

  test "local destination and message handler APIs validate inputs", %{state_server: state_server} do
    destination_hash = :crypto.strong_rand_bytes(16)

    assert {:error, :invalid_local_destination_options} =
             State.register_local_destination(state_server, destination_hash, self(), :bad)

    assert {:error, :unknown_local_destination_option} =
             State.register_local_destination(state_server, destination_hash, self(),
               unknown: true
             )

    assert {:error, :invalid_destination} =
             State.register_local_destination(state_server, destination_hash, self(),
               destination: %{}
             )

    assert {:error, :invalid_destination_callback} =
             State.register_local_destination(state_server, destination_hash, self(),
               callback: :bad
             )

    assert {:error, :invalid_proof_requested_callback} =
             State.register_local_destination(state_server, destination_hash, self(),
               proof_requested_callback: :bad
             )

    assert {:error, :invalid_app_data} =
             State.register_local_destination(state_server, destination_hash, self(),
               app_data: 123
             )

    assert {:error, :invalid_destination_hash} =
             State.register_local_destination(state_server, <<1>>, self(), [])

    assert {:error, :invalid_destination_handler} =
             State.register_local_destination(state_server, destination_hash, :bad, [])

    {dead_handler, dead_ref} = spawn_monitor(fn -> :ok end)
    assert_receive {:DOWN, ^dead_ref, :process, ^dead_handler, :normal}

    assert {:error, :destination_handler_not_alive} =
             State.register_local_destination(state_server, destination_hash, dead_handler, [])

    {:ok, destination} = Destination.new(:in, :single, "state", Identity.new(), ["dest"])

    assert {:error, :destination_hash_mismatch} =
             State.register_local_destination(state_server, destination_hash, self(),
               destination: destination
             )

    assert :ok =
             State.register_local_destination(state_server, destination.hash, self(),
               destination: destination,
               callback: fn _event -> :ok end,
               app_data: "state-app"
             )

    {:ok, group_destination} = Destination.new(:in, :group, "state", nil, ["group"])

    assert {:error, :missing_group_key} =
             State.register_local_destination(state_server, group_destination.hash, self(),
               destination: group_destination
             )

    assert {:ok, local_destination} = State.local_destination(state_server, destination.hash)
    assert local_destination.pid == self()
    assert local_destination.destination.hash == destination.hash
    assert is_function(local_destination.callback, 1)
    assert local_destination.proof_requested_callback == nil

    assert :ok = State.unregister_local_destination(state_server, destination.hash)

    assert {:error, :unknown_local_destination} =
             State.unregister_local_destination(state_server, destination.hash)

    assert {:error, :invalid_handler_pid} =
             State.register_request_handler(state_server, destination_hash, 1, :bad)

    assert {:error, :invalid_destination_hash} =
             State.register_request_handler(state_server, <<1>>, 1, self())

    assert {:error, :invalid_message_context} =
             State.register_request_handler(state_server, destination_hash, 256, self())

    assert {:error, :destination_handler_not_alive} =
             State.register_request_handler(state_server, destination_hash, 7, dead_handler)

    assert :ok = State.register_request_handler(state_server, destination_hash, 7, self())
    assert {:ok, %{pid: pid}} = State.request_handler(state_server, destination_hash, 7)
    assert pid == self()
    assert :ok = State.unregister_request_handler(state_server, destination_hash, 7)

    assert {:error, :unknown_request_handler} =
             State.unregister_request_handler(state_server, destination_hash, 7)

    assert {:error, :invalid_handler_pid} =
             State.register_response_handler(state_server, destination_hash, 1, :bad)

    assert {:error, :invalid_message_context} =
             State.register_response_handler(state_server, destination_hash, -1, self())

    assert :ok = State.register_response_handler(state_server, destination_hash, 8, self())
    assert {:ok, %{pid: ^pid}} = State.response_handler(state_server, destination_hash, 8)
    assert :ok = State.unregister_response_handler(state_server, destination_hash, 8)

    assert {:error, :unknown_response_handler} =
             State.unregister_response_handler(state_server, destination_hash, 8)
  end

  defp eventually(fun, retries \\ 20)

  defp eventually(fun, retries) when retries > 0 do
    if fun.() do
      true
    else
      Process.sleep(10)
      eventually(fun, retries - 1)
    end
  end

  defp eventually(_fun, 0), do: false
end
