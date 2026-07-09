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
      assert config.routing_max_hops == 128
      assert config.announce_forwarding == true
      assert config.path_request_forwarding == true
      assert config.path_request_timeout_seconds == 15
      assert config.path_request_retry_count == 1
      assert config.path_request_retry_base_seconds == 5
      assert config.path_request_retry_backoff_factor == 2
      assert config.path_request_min_interval_seconds == 20
      assert config.path_request_duplicate_ttl_seconds == 15
      assert config.path_request_fanout == 2
      assert config.interface_queue_limit == 64
      assert config.interface_backpressure == :reject
      assert config.interface_rate_limit_bytes_per_second == nil
      assert config.interface_rate_limit_packets_per_second == nil
      assert config.interface_rate_limit_burst_bytes == nil
      assert config.interface_rate_limit_burst_packets == nil
      assert config.receipt_timeout_seconds == 10
      assert config.receipt_retention_seconds == 60
      assert config.ratchet_expiry_seconds == 2_592_000

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
           routing_max_hops: 8,
           announce_forwarding: false,
           path_request_forwarding: false,
           path_request_timeout_seconds: 12,
           path_request_retry_count: 2,
           path_request_retry_base_seconds: 3,
           path_request_retry_backoff_factor: 3,
           path_request_min_interval_seconds: 9,
           path_request_duplicate_ttl_seconds: 11,
           path_request_fanout: 4,
           interface_queue_limit: 8,
           interface_backpressure: :drop_oldest,
           interface_rate_limit_bytes_per_second: 2_048,
           interface_rate_limit_packets_per_second: 16,
           interface_rate_limit_burst_bytes: 4_096,
           interface_rate_limit_burst_packets: 32,
           receipt_timeout_seconds: 8,
           receipt_retention_seconds: 20,
           ratchet_expiry_seconds: 900}
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
      assert config.routing_max_hops == 8
      assert config.announce_forwarding == false
      assert config.path_request_forwarding == false
      assert config.path_request_timeout_seconds == 12
      assert config.path_request_retry_count == 2
      assert config.path_request_retry_base_seconds == 3
      assert config.path_request_retry_backoff_factor == 3
      assert config.path_request_min_interval_seconds == 9
      assert config.path_request_duplicate_ttl_seconds == 11
      assert config.path_request_fanout == 4
      assert config.interface_queue_limit == 8
      assert config.interface_backpressure == :drop_oldest
      assert config.interface_rate_limit_bytes_per_second == 2_048
      assert config.interface_rate_limit_packets_per_second == 16
      assert config.interface_rate_limit_burst_bytes == 4_096
      assert config.interface_rate_limit_burst_packets == 32
      assert config.receipt_timeout_seconds == 8
      assert config.receipt_retention_seconds == 20
      assert config.ratchet_expiry_seconds == 900
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

      assert Node.start_link(routing_max_hops: 0) == {:error, :invalid_routing_max_hops}

      assert Node.start_link(announce_forwarding: :yes) ==
               {:error, :invalid_announce_forwarding}

      assert Node.start_link(path_request_forwarding: :yes) ==
               {:error, :invalid_path_request_forwarding}

      assert Node.start_link(path_request_timeout_seconds: 0) ==
               {:error, :invalid_path_request_timeout_seconds}

      assert Node.start_link(path_request_retry_count: -1) ==
               {:error, :invalid_path_request_retry_count}

      assert Node.start_link(path_request_retry_base_seconds: 0) ==
               {:error, :invalid_path_request_retry_base_seconds}

      assert Node.start_link(path_request_retry_backoff_factor: 0) ==
               {:error, :invalid_path_request_retry_backoff_factor}

      assert Node.start_link(path_request_min_interval_seconds: 0) ==
               {:error, :invalid_path_request_min_interval_seconds}

      assert Node.start_link(path_request_duplicate_ttl_seconds: 0) ==
               {:error, :invalid_path_request_duplicate_ttl_seconds}

      assert Node.start_link(path_request_fanout: 0) ==
               {:error, :invalid_path_request_fanout}

      assert Node.start_link(interface_queue_limit: 0) ==
               {:error, :invalid_interface_queue_limit}

      assert Node.start_link(interface_backpressure: :block) ==
               {:error, :invalid_interface_backpressure}

      assert Node.start_link(interface_rate_limit_bytes_per_second: 0) ==
               {:error, :invalid_interface_rate_limit_bytes_per_second}

      assert Node.start_link(interface_rate_limit_packets_per_second: 0) ==
               {:error, :invalid_interface_rate_limit_packets_per_second}

      assert Node.start_link(interface_rate_limit_burst_bytes: 0) ==
               {:error, :invalid_interface_rate_limit_burst_bytes}

      assert Node.start_link(interface_rate_limit_burst_packets: 0) ==
               {:error, :invalid_interface_rate_limit_burst_packets}

      assert Node.start_link(receipt_timeout_seconds: 0) ==
               {:error, :invalid_receipt_timeout_seconds}

      assert Node.start_link(receipt_retention_seconds: 0) ==
               {:error, :invalid_receipt_retention_seconds}

      assert Node.start_link(ratchet_expiry_seconds: 0) ==
               {:error, :invalid_ratchet_expiry_seconds}

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

    test "stores and fetches group destinations" do
      destination_hash = :crypto.strong_rand_bytes(16)
      group_key = :crypto.strong_rand_bytes(64)

      assert :ok == Node.put_group_destination(destination_hash, group_key)

      assert {:ok, record} = Node.destination(destination_hash)
      assert record.group_key == group_key
      assert record.public_key == nil
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
