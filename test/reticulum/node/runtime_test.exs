defmodule Reticulum.Node.RuntimeTest do
  use ExUnit.Case, async: false

  alias Reticulum.Node
  alias Reticulum.Node.State

  describe "start_link/1" do
    test "starts with defaults and creates runtime tables" do
      pid = start_supervised!({Node, []})
      assert is_pid(pid)

      assert {:ok, config} = Node.config()
      assert config.name == Reticulum.Node
      assert is_binary(config.storage_path)
      assert config.transport_enabled == false
      assert config.use_implicit_proof == true
      assert config.shared_instance == false
      assert config.startup_mode == :cold
      assert config.startup_lifecycle == Reticulum.Node.StartupLifecycle.Default
      assert config.path_ttl_seconds == 300
      assert config.path_gc_interval_seconds == 5
      assert config.receipt_timeout_seconds == 10
      assert config.receipt_retention_seconds == 60

      assert {:ok, tables} = Node.tables()
      assert Map.has_key?(tables, :destinations)
      assert Map.has_key?(tables, :paths)
      assert Map.has_key?(tables, :packet_hashes)
      assert Map.has_key?(tables, :local_destinations)

      assert {:ok, destination_table} = Node.table(:destinations)
      assert :ets.info(destination_table, :protection) == :protected
    end

    test "accepts explicit runtime options" do
      node_name = Reticulum.Node.RuntimeTest
      storage_path = Path.join(System.tmp_dir!(), "reticulum-node-test")

      pid =
        start_supervised!(
          {Node,
           name: node_name,
           storage_path: storage_path,
           transport_enabled: true,
           use_implicit_proof: false,
           shared_instance: true,
           startup_mode: :warm_restore,
           startup_lifecycle: Reticulum.Node.StartupLifecycle.Default,
           path_ttl_seconds: 120,
           path_gc_interval_seconds: 2,
           receipt_timeout_seconds: 8,
           receipt_retention_seconds: 20}
        )

      assert is_pid(pid)

      assert {:ok, config} = Node.config(node_name)
      assert config.name == node_name
      assert config.storage_path == Path.expand(storage_path)
      assert config.transport_enabled == true
      assert config.use_implicit_proof == false
      assert config.shared_instance == true
      assert config.startup_mode == :warm_restore
      assert config.startup_lifecycle == Reticulum.Node.StartupLifecycle.Default
      assert config.path_ttl_seconds == 120
      assert config.path_gc_interval_seconds == 2
      assert config.receipt_timeout_seconds == 8
      assert config.receipt_retention_seconds == 20
    end

    test "returns errors on invalid options" do
      assert Node.start_link(storage_path: 1) == {:error, :invalid_storage_path}
      assert Node.start_link(name: "reticulum") == {:error, :invalid_node_name}
      assert Node.start_link(transport_enabled: :yes) == {:error, :invalid_transport_enabled}
      assert Node.start_link(use_implicit_proof: :yes) == {:error, :invalid_use_implicit_proof}
      assert Node.start_link(shared_instance: :yes) == {:error, :invalid_shared_instance}
      assert Node.start_link(startup_mode: :warm) == {:error, :invalid_startup_mode}

      assert Node.start_link(startup_lifecycle: Reticulum.Node) ==
               {:error, :invalid_startup_lifecycle}

      assert Node.start_link(path_ttl_seconds: 0) == {:error, :invalid_path_ttl_seconds}

      assert Node.start_link(path_gc_interval_seconds: 0) ==
               {:error, :invalid_path_gc_interval_seconds}

      assert Node.start_link(receipt_timeout_seconds: 0) ==
               {:error, :invalid_receipt_timeout_seconds}

      assert Node.start_link(receipt_retention_seconds: 0) ==
               {:error, :invalid_receipt_retention_seconds}

      assert Node.start_link(unknown: true) == {:error, :unknown_option}
    end
  end

  describe "state table helpers" do
    setup do
      start_supervised!({Node, []})
      :ok
    end

    test "stores and fetches destinations" do
      destination_hash = :crypto.strong_rand_bytes(16)
      public_key = :crypto.strong_rand_bytes(64)

      assert :ok == Node.put_destination(destination_hash, public_key, "chat")

      assert {:ok, record} = Node.destination(destination_hash)
      assert record.public_key == public_key
      assert record.app_data == "chat"
      assert is_integer(record.updated_at)

      unknown_destination = :crypto.strong_rand_bytes(16)
      assert :error == Node.destination(unknown_destination)
    end

    test "stores and fetches paths" do
      destination_hash = :crypto.strong_rand_bytes(16)
      next_hop = :crypto.strong_rand_bytes(16)

      assert :ok == Node.put_path(destination_hash, next_hop, 3)

      assert {:ok, record} = Node.path(destination_hash)
      assert record.next_hop == next_hop
      assert record.hops == 3
      assert is_integer(record.updated_at)
    end

    test "tracks seen packet hashes" do
      packet_hash = :crypto.strong_rand_bytes(32)

      refute Node.packet_seen?(packet_hash)
      assert :new == Node.remember_packet_hash(packet_hash)
      assert Node.packet_seen?(packet_hash)
      assert :existing == Node.remember_packet_hash(packet_hash)
    end

    test "restarts with empty ETS-backed runtime state" do
      node_name = Reticulum.Node.RuntimeRestartTest
      storage_path = Path.join(System.tmp_dir!(), "reticulum-node-restart-test")
      destination_hash = :crypto.strong_rand_bytes(16)
      public_key = :crypto.strong_rand_bytes(64)
      next_hop = :crypto.strong_rand_bytes(16)
      packet_hash = :crypto.strong_rand_bytes(32)

      {:ok, pid} = Node.start_link(name: node_name, storage_path: storage_path)

      assert :ok = Node.put_destination(node_name, destination_hash, public_key, nil)
      assert :ok = Node.put_path(node_name, destination_hash, next_hop, 1, interface: :udp)
      assert :new = Node.remember_packet_hash(node_name, packet_hash)
      assert :ok = Node.register_local_destination(node_name, destination_hash, self())
      assert :ok = Node.register_request_handler(node_name, destination_hash, 7, self())
      assert :ok = Node.register_response_handler(node_name, destination_hash, 8, self())

      state_server = Node.state_server(node_name)

      assert :ok =
               State.register_interface(
                 state_server,
                 :ephemeral,
                 self(),
                 Reticulum.Interface.UDP,
                 %{}
               )

      assert {:ok, _record} = Node.destination(node_name, destination_hash)
      assert {:ok, _record} = Node.path(node_name, destination_hash)
      assert Node.packet_seen?(node_name, packet_hash)
      assert {:ok, _interface} = State.interface(state_server, :ephemeral)
      assert {:ok, _local_destination} = State.local_destination(state_server, destination_hash)
      assert {:ok, _request_handler} = State.request_handler(state_server, destination_hash, 7)
      assert {:ok, _response_handler} = State.response_handler(state_server, destination_hash, 8)

      :ok = Supervisor.stop(pid)
      {:ok, _pid} = Node.start_link(name: node_name, storage_path: storage_path)

      state_server = Node.state_server(node_name)
      assert :error = Node.destination(node_name, destination_hash)
      assert :error = Node.path(node_name, destination_hash)
      refute Node.packet_seen?(node_name, packet_hash)
      assert :error = State.interface(state_server, :ephemeral)
      assert :error = State.local_destination(state_server, destination_hash)
      assert :error = State.request_handler(state_server, destination_hash, 7)
      assert :error = State.response_handler(state_server, destination_hash, 8)
    end
  end
end
