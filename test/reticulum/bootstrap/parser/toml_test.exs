defmodule Reticulum.Bootstrap.Parser.TOMLTest do
  use ExUnit.Case, async: true

  alias Reticulum.Bootstrap.Parser.TOML

  test "parses valid TOML bootstrap config" do
    config_path =
      write_config!("""
      [node]
      storage_path = "#{Path.join(System.tmp_dir!(), "reticulum-bootstrap-parser")}" 
      transport_enabled = true
      use_implicit_proof = false
      startup_mode = "warm_restore"
      routing_max_hops = 8
      announce_forwarding = false
      path_request_forwarding = false
      path_request_timeout_seconds = 12
      path_request_retry_count = 2
      path_request_retry_base_seconds = 3
      path_request_retry_backoff_factor = 3
      path_request_min_interval_seconds = 9
      path_request_duplicate_ttl_seconds = 11
      path_request_fanout = 4
      interface_queue_limit = 8
      interface_backpressure = "drop_oldest"
      interface_rate_limit_packets_per_second = 16
      ratchet_expiry_seconds = 900

      [interfaces.link]
      type = "udp"
      listen_ip = "127.0.0.1"
      listen_port = 43000
      ifac_netname = "mesh-alpha"
      ifac_netkey = "phase7-secret"
      ifac_size_bits = 128
      queue_limit = 2
      backpressure = "drop_newest"
      """)

    assert {:ok, bootstrap} = TOML.parse_file(config_path)
    assert bootstrap.node_opts[:transport_enabled] == true
    assert bootstrap.node_opts[:use_implicit_proof] == false
    assert bootstrap.node_opts[:startup_mode] == :warm_restore
    assert bootstrap.node_opts[:routing_max_hops] == 8
    assert bootstrap.node_opts[:announce_forwarding] == false
    assert bootstrap.node_opts[:path_request_forwarding] == false
    assert bootstrap.node_opts[:path_request_timeout_seconds] == 12
    assert bootstrap.node_opts[:path_request_retry_count] == 2
    assert bootstrap.node_opts[:path_request_retry_base_seconds] == 3
    assert bootstrap.node_opts[:path_request_retry_backoff_factor] == 3
    assert bootstrap.node_opts[:path_request_min_interval_seconds] == 9
    assert bootstrap.node_opts[:path_request_duplicate_ttl_seconds] == 11
    assert bootstrap.node_opts[:path_request_fanout] == 4
    assert bootstrap.node_opts[:interface_queue_limit] == 8
    assert bootstrap.node_opts[:interface_backpressure] == :drop_oldest
    assert bootstrap.node_opts[:interface_rate_limit_packets_per_second] == 16
    assert bootstrap.node_opts[:ratchet_expiry_seconds] == 900
    assert [%{name: :link, module: Reticulum.Interface.UDP, opts: opts}] = bootstrap.interfaces
    assert opts[:ifac_netname] == "mesh-alpha"
    assert opts[:ifac_netkey] == "phase7-secret"
    assert opts[:ifac_size] == 16
    assert opts[:queue_limit] == 2
    assert opts[:backpressure] == :drop_newest
  end

  test "returns not found error when config path does not exist" do
    missing_path =
      Path.join(System.tmp_dir!(), "reticulum-missing-#{System.unique_integer([:positive])}")

    assert TOML.parse_file(missing_path) == {:error, :config_file_not_found}
  end

  test "returns invalid_toml for malformed TOML" do
    config_path =
      write_config!("""
      [node
      transport_enabled = true
      """)

    assert TOML.parse_file(config_path) == {:error, :invalid_toml}
  end

  test "returns schema validation error for unknown section" do
    config_path =
      write_config!("""
      [node]
      transport_enabled = false

      [extra]
      value = 1
      """)

    assert TOML.parse_file(config_path) == {:error, {:unknown_config_section, "extra"}}
  end

  test "returns startup mode validation error for unsupported startup mode" do
    config_path =
      write_config!("""
      [node]
      startup_mode = "warm"
      """)

    assert TOML.parse_file(config_path) == {:error, :invalid_startup_mode}
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
end
