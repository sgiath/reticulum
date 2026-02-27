defmodule Reticulum.Bootstrap.Parser.TOMLTest do
  use ExUnit.Case, async: true

  alias Reticulum.Bootstrap.Parser.TOML

  test "parses valid TOML bootstrap config" do
    config_path =
      write_config!("""
      [node]
      storage_path = "#{Path.join(System.tmp_dir!(), "reticulum-bootstrap-parser")}" 
      transport_enabled = true

      [interfaces.link]
      type = "udp"
      listen_ip = "127.0.0.1"
      listen_port = 43000
      """)

    assert {:ok, bootstrap} = TOML.parse_file(config_path)
    assert bootstrap.node_opts[:transport_enabled] == true
    assert [%{name: :link, type: :udp}] = bootstrap.interfaces
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
