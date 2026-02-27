defmodule Reticulum.Bootstrap.Config do
  @moduledoc """
  Schema-validated bootstrap config mapped to runtime startup options.
  """

  alias Reticulum.Node.Config, as: NodeConfig

  @node_option_keys [
    "storage_path",
    "transport_enabled",
    "shared_instance",
    "path_ttl_seconds",
    "path_gc_interval_seconds",
    "receipt_timeout_seconds",
    "receipt_retention_seconds"
  ]

  @node_option_key_map %{
    "storage_path" => :storage_path,
    "transport_enabled" => :transport_enabled,
    "shared_instance" => :shared_instance,
    "path_ttl_seconds" => :path_ttl_seconds,
    "path_gc_interval_seconds" => :path_gc_interval_seconds,
    "receipt_timeout_seconds" => :receipt_timeout_seconds,
    "receipt_retention_seconds" => :receipt_retention_seconds
  }

  @node_runtime_keys [
    :name,
    :storage_path,
    :transport_enabled,
    :shared_instance,
    :path_ttl_seconds,
    :path_gc_interval_seconds,
    :receipt_timeout_seconds,
    :receipt_retention_seconds
  ]

  @interface_option_keys [
    "enabled",
    "type",
    "listen_ip",
    "listen_port",
    "default_peer_ip",
    "default_peer_port"
  ]

  @max_interface_name_length 64

  @typedoc "Mapped bootstrap interface startup specification"
  @type interface_spec :: %{
          name: atom(),
          type: :udp,
          opts: keyword()
        }

  @typedoc "Schema-validated bootstrap config"
  @type t :: %__MODULE__{
          node_opts: keyword(),
          interfaces: [interface_spec()]
        }

  @enforce_keys [:node_opts, :interfaces]
  defstruct [:node_opts, :interfaces]

  @doc "Validates and maps decoded config map into runtime startup options."
  def new(config) when is_map(config) do
    with :ok <- validate_top_level_keys(config),
         {:ok, node_opts} <- map_node_opts(Map.get(config, "node", %{})),
         {:ok, interfaces} <- map_interfaces(Map.get(config, "interfaces", %{})) do
      {:ok, %__MODULE__{node_opts: node_opts, interfaces: interfaces}}
    end
  end

  def new(_config), do: {:error, :invalid_bootstrap_config}

  defp validate_top_level_keys(config) do
    config
    |> Map.keys()
    |> Enum.reject(&(&1 in ["node", "interfaces"]))
    |> case do
      [] -> :ok
      [unknown | _] -> {:error, {:unknown_config_section, unknown}}
    end
  end

  defp map_node_opts(node_config) when is_map(node_config) do
    with :ok <- validate_node_option_keys(node_config),
         {:ok, opts} <- keyword_from_map(node_config, @node_option_key_map),
         {:ok, node_config} <- NodeConfig.new(opts) do
      {:ok, node_config_to_keyword(node_config)}
    end
  end

  defp map_node_opts(_node_config), do: {:error, :invalid_node_config}

  defp validate_node_option_keys(node_config) do
    node_config
    |> Map.keys()
    |> Enum.reject(&(&1 in @node_option_keys))
    |> case do
      [] -> :ok
      [unknown | _] -> {:error, {:unknown_node_option, unknown}}
    end
  end

  defp map_interfaces(interfaces) when is_map(interfaces) do
    interfaces
    |> Enum.sort_by(fn {name, _config} -> name end)
    |> Enum.reduce_while({:ok, []}, fn {name, interface_config}, {:ok, acc} ->
      case map_interface(name, interface_config) do
        {:ok, :disabled} ->
          {:cont, {:ok, acc}}

        {:ok, interface} ->
          {:cont, {:ok, [interface | acc]}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, interfaces} -> {:ok, Enum.reverse(interfaces)}
      {:error, _reason} = error -> error
    end
  end

  defp map_interfaces(_interfaces), do: {:error, :invalid_interfaces_config}

  defp map_interface(name, interface_config) when is_map(interface_config) do
    with {:ok, interface_name} <- validate_interface_name(name),
         :ok <- validate_interface_option_keys(interface_config, interface_name),
         {:ok, enabled?} <- validate_enabled(Map.get(interface_config, "enabled", true)),
         {:ok, type} <- map_interface_type(Map.get(interface_config, "type"), interface_name),
         {:ok, opts} <- map_interface_opts(interface_config, interface_name) do
      if enabled? do
        {:ok, %{name: interface_name, type: type, opts: opts}}
      else
        {:ok, :disabled}
      end
    end
  end

  defp map_interface(name, _interface_config),
    do: {:error, {:invalid_interface_config, name, :invalid_interface_options}}

  defp validate_interface_name(name) when is_binary(name) and byte_size(name) > 0 do
    cond do
      byte_size(name) > @max_interface_name_length ->
        {:error, {:invalid_interface_name, name}}

      String.match?(name, ~r/^[A-Za-z0-9_-]+$/) ->
        case safe_to_existing_atom(name) do
          {:ok, atom_name} -> {:ok, atom_name}
          :error -> {:error, {:interface_name_requires_existing_atom, name}}
        end

      true ->
        {:error, {:invalid_interface_name, name}}
    end
  end

  defp validate_interface_name(name), do: {:error, {:invalid_interface_name, name}}

  defp safe_to_existing_atom(name) do
    try do
      {:ok, String.to_existing_atom(name)}
    rescue
      ArgumentError -> :error
    end
  end

  defp validate_interface_option_keys(interface_config, interface_name) do
    interface_config
    |> Map.keys()
    |> Enum.reject(&(&1 in @interface_option_keys))
    |> case do
      [] -> :ok
      [unknown | _] -> {:error, {:unknown_interface_option, interface_name, unknown}}
    end
  end

  defp validate_enabled(value) when is_boolean(value), do: {:ok, value}
  defp validate_enabled(_value), do: {:error, :invalid_interface_enabled}

  defp map_interface_type(type, interface_name) when is_binary(type) do
    case String.downcase(type) do
      "udp" -> {:ok, :udp}
      _ -> {:error, {:unsupported_interface_type, interface_name, type}}
    end
  end

  defp map_interface_type(_type, _interface_name), do: {:error, :invalid_interface_type}

  defp map_interface_opts(interface_config, interface_name) do
    with {:ok, listen_ip} <- maybe_parse_ip(interface_config, "listen_ip", :invalid_listen_ip),
         {:ok, listen_port} <-
           maybe_parse_port(interface_config, "listen_port", :invalid_listen_port, true),
         {:ok, peer_ip} <-
           maybe_parse_ip(interface_config, "default_peer_ip", :invalid_default_peer_ip),
         {:ok, peer_port} <-
           maybe_parse_port(
             interface_config,
             "default_peer_port",
             :invalid_default_peer_port,
             false
           ) do
      {:ok,
       []
       |> maybe_put(:listen_ip, listen_ip)
       |> maybe_put(:listen_port, listen_port)
       |> maybe_put(:default_peer_ip, peer_ip)
       |> maybe_put(:default_peer_port, peer_port)}
    else
      {:error, reason} ->
        {:error, {:invalid_interface_config, interface_name, reason}}
    end
  end

  defp maybe_parse_ip(interface_config, key, error) do
    case Map.fetch(interface_config, key) do
      :error ->
        {:ok, :not_set}

      {:ok, value} ->
        case parse_ip(value) do
          {:ok, ip} -> {:ok, ip}
          :error -> {:error, error}
        end
    end
  end

  defp parse_ip(value) when is_binary(value) do
    value
    |> String.to_charlist()
    |> :inet.parse_address()
    |> case do
      {:ok, ip} -> {:ok, ip}
      {:error, _reason} -> :error
    end
  end

  defp parse_ip(value) when is_list(value) do
    case Enum.all?(value, &is_integer/1) do
      true -> parse_ip(List.to_tuple(value))
      false -> :error
    end
  end

  defp parse_ip(value) when is_tuple(value) and tuple_size(value) in [4, 8], do: {:ok, value}
  defp parse_ip(_value), do: :error

  defp maybe_parse_port(interface_config, key, error, allow_zero?) do
    case Map.fetch(interface_config, key) do
      :error ->
        {:ok, :not_set}

      {:ok, value} ->
        case parse_port(value, allow_zero?) do
          :ok -> {:ok, value}
          :error -> {:error, error}
        end
    end
  end

  defp parse_port(value, allow_zero?)
       when is_integer(value) and value >= 0 and value <= 65_535 and
              (allow_zero? or value > 0),
       do: :ok

  defp parse_port(_value, _allow_zero?), do: :error

  defp maybe_put(keyword, _key, :not_set), do: keyword
  defp maybe_put(keyword, key, value), do: Keyword.put(keyword, key, value)

  defp keyword_from_map(config, key_map) do
    config
    |> Enum.reduce_while({:ok, []}, fn {key, value}, {:ok, acc} ->
      case Map.fetch(key_map, key) do
        {:ok, mapped_key} -> {:cont, {:ok, [{mapped_key, value} | acc]}}
        :error -> {:halt, {:error, :invalid_bootstrap_config}}
      end
    end)
    |> case do
      {:ok, opts} -> {:ok, Enum.reverse(opts)}
      {:error, _reason} = error -> error
    end
  end

  defp node_config_to_keyword(%NodeConfig{} = config) do
    Enum.map(@node_runtime_keys, fn key -> {key, Map.fetch!(config, key)} end)
  end
end
