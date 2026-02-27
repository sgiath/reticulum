defmodule Reticulum.Bootstrap.ConfigTest do
  use ExUnit.Case, async: true

  alias Reticulum.Bootstrap.Config

  describe "new/1" do
    test "maps validated node and interface config into runtime options" do
      storage_path = Path.join(System.tmp_dir!(), "reticulum-bootstrap-config-test")

      config = %{
        "node" => %{
          "storage_path" => storage_path,
          "transport_enabled" => true,
          "use_implicit_proof" => false,
          "shared_instance" => false,
          "startup_mode" => "warm_restore",
          "path_ttl_seconds" => 120,
          "path_gc_interval_seconds" => 2,
          "receipt_timeout_seconds" => 8,
          "receipt_retention_seconds" => 20
        },
        "interfaces" => %{
          "link" => %{
            "type" => "udp",
            "listen_ip" => "127.0.0.1",
            "listen_port" => 42_424,
            "default_peer_ip" => [127, 0, 0, 1],
            "default_peer_port" => 42_425
          },
          "disabled" => %{
            "enabled" => false,
            "type" => "udp",
            "listen_port" => 42_426
          }
        }
      }

      assert {:ok, bootstrap} = Config.new(config)

      assert bootstrap.node_opts[:storage_path] == Path.expand(storage_path)
      assert bootstrap.node_opts[:transport_enabled] == true
      assert bootstrap.node_opts[:use_implicit_proof] == false
      assert bootstrap.node_opts[:startup_mode] == :warm_restore
      assert bootstrap.node_opts[:startup_lifecycle] == Reticulum.Node.StartupLifecycle.Default
      assert bootstrap.node_opts[:path_ttl_seconds] == 120
      assert bootstrap.node_opts[:path_gc_interval_seconds] == 2
      assert bootstrap.node_opts[:receipt_timeout_seconds] == 8
      assert bootstrap.node_opts[:receipt_retention_seconds] == 20

      assert [%{name: :link, type: :udp, opts: opts}] = bootstrap.interfaces
      assert opts[:listen_ip] == {127, 0, 0, 1}
      assert opts[:listen_port] == 42_424
      assert opts[:default_peer_ip] == {127, 0, 0, 1}
      assert opts[:default_peer_port] == 42_425
    end

    test "rejects unknown top-level section" do
      assert Config.new(%{"unknown" => %{}}) == {:error, {:unknown_config_section, "unknown"}}
    end

    test "rejects unknown node option" do
      assert Config.new(%{"node" => %{"unknown" => true}}) ==
               {:error, {:unknown_node_option, "unknown"}}
    end

    test "rejects invalid startup mode" do
      assert Config.new(%{"node" => %{"startup_mode" => "warm"}}) ==
               {:error, :invalid_startup_mode}
    end

    test "rejects invalid interface type" do
      assert Config.new(%{"interfaces" => %{"link" => %{"type" => "tcp"}}}) ==
               {:error, {:unsupported_interface_type, :link, "tcp"}}
    end

    test "rejects invalid interface name" do
      assert Config.new(%{"interfaces" => %{"bad name" => %{"type" => "udp"}}}) ==
               {:error, {:invalid_interface_name, "bad name"}}
    end

    test "rejects interface names that are not pre-existing atoms" do
      name = "bootstrap_non_existing_#{System.unique_integer([:positive, :monotonic])}"

      assert Config.new(%{"interfaces" => %{name => %{"type" => "udp"}}}) ==
               {:error, {:interface_name_requires_existing_atom, name}}
    end
  end
end
