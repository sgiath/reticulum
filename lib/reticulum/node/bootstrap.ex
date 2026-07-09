defmodule Reticulum.Node.Bootstrap do
  @moduledoc false

  alias Reticulum.Bootstrap.Config
  alias Reticulum.Bootstrap.Parser.TOML
  alias Reticulum.Node
  alias Reticulum.Node.Config, as: NodeConfig

  @node_runtime_keys [
    :name,
    :storage_path,
    :transport_enabled,
    :use_implicit_proof,
    :shared_instance,
    :startup_mode,
    :startup_lifecycle,
    :path_ttl_seconds,
    :path_gc_interval_seconds,
    :routing_max_hops,
    :announce_forwarding,
    :path_request_forwarding,
    :path_request_timeout_seconds,
    :path_request_retry_count,
    :path_request_retry_base_seconds,
    :path_request_retry_backoff_factor,
    :path_request_min_interval_seconds,
    :path_request_duplicate_ttl_seconds,
    :path_request_fanout,
    :interface_queue_limit,
    :interface_backpressure,
    :interface_rate_limit_bytes_per_second,
    :interface_rate_limit_packets_per_second,
    :interface_rate_limit_burst_bytes,
    :interface_rate_limit_burst_packets,
    :receipt_timeout_seconds,
    :receipt_retention_seconds,
    :ratchet_expiry_seconds
  ]

  @doc "Loads, validates, and maps TOML bootstrap config with node option overrides."
  def load(path, node_overrides \\ [])

  def load(path, node_overrides) when is_binary(path) and is_list(node_overrides) do
    with {:ok, %Config{} = config} <- TOML.parse_file(path),
         {:ok, node_opts} <- merge_node_overrides(config.node_opts, node_overrides) do
      {:ok, %Config{config | node_opts: node_opts}}
    end
  end

  def load(_path, _node_overrides), do: {:error, :invalid_options}

  @doc "Starts node and configured interfaces from TOML bootstrap config."
  def start(path, node_overrides \\ [])

  def start(path, node_overrides) when is_binary(path) and is_list(node_overrides) do
    with {:ok, %Config{} = config} <- load(path, node_overrides),
         {:ok, node_config} <- NodeConfig.new(config.node_opts),
         {:ok, pid} = started <- Node.start_link(config.node_opts) do
      case start_interfaces(node_config.name, config.interfaces) do
        :ok ->
          started

        {:error, _reason} = error ->
          _ = Supervisor.stop(pid)
          error
      end
    end
  end

  def start(_path, _node_overrides), do: {:error, :invalid_options}

  defp merge_node_overrides(node_opts, node_overrides) do
    node_opts
    |> Keyword.merge(node_overrides)
    |> NodeConfig.new()
    |> case do
      {:ok, %NodeConfig{} = config} -> {:ok, node_config_to_keyword(config)}
      {:error, _reason} = error -> error
    end
  end

  defp start_interfaces(node_name, interfaces) do
    Enum.reduce_while(interfaces, :ok, fn interface, :ok ->
      case start_interface(node_name, interface) do
        :ok -> {:cont, :ok}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  defp start_interface(node_name, %{name: name, module: module, opts: opts}) do
    case Node.start_interface(node_name, module, Keyword.put(opts, :name, name)) do
      {:ok, _pid} -> :ok
      {:error, reason} -> {:error, {:interface_start_failed, name, reason}}
    end
  end

  defp node_config_to_keyword(%NodeConfig{} = config) do
    Enum.map(@node_runtime_keys, fn key -> {key, Map.fetch!(config, key)} end)
  end
end
