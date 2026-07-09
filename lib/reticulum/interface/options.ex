defmodule Reticulum.Interface.Options do
  @moduledoc false

  @backpressure_modes [:reject, :drop_newest, :drop_oldest]

  @rate_limit_keys [
    rate_limit_bytes_per_second: :invalid_interface_rate_limit_bytes_per_second,
    rate_limit_packets_per_second: :invalid_interface_rate_limit_packets_per_second,
    rate_limit_burst_bytes: :invalid_interface_rate_limit_burst_bytes,
    rate_limit_burst_packets: :invalid_interface_rate_limit_burst_packets
  ]

  @type t :: %{
          adapter: module(),
          name: atom(),
          node_name: atom(),
          state_server: GenServer.server(),
          queue_limit: pos_integer(),
          backpressure: :reject | :drop_newest | :drop_oldest
        }

  @doc "Validates managed interface runtime options."
  @spec validate(keyword()) :: {:ok, t()} | {:error, term()}
  def validate(opts) when is_list(opts) do
    with {:ok, adapter} <- validate_adapter(Keyword.get(opts, :adapter)),
         {:ok, name} <- validate_name(Keyword.get(opts, :name)),
         {:ok, node_name} <- validate_node_name(Keyword.get(opts, :node_name)),
         {:ok, state_server} <- validate_state_server(Keyword.get(opts, :state_server)),
         {:ok, queue_limit} <- validate_queue_limit(Keyword.get(opts, :queue_limit, 64)),
         {:ok, backpressure} <- validate_backpressure(Keyword.get(opts, :backpressure, :reject)),
         :ok <- validate_rate_limits(opts) do
      {:ok,
       %{
         adapter: adapter,
         name: name,
         node_name: node_name,
         state_server: state_server,
         queue_limit: queue_limit,
         backpressure: backpressure
       }}
    end
  end

  defp validate_adapter(adapter) do
    if Reticulum.Interface.adapter?(adapter) do
      {:ok, adapter}
    else
      {:error, :invalid_interface_adapter}
    end
  end

  defp validate_name(name) when is_atom(name) and not is_nil(name), do: {:ok, name}
  defp validate_name(_name), do: {:error, :invalid_interface_name}

  defp validate_node_name(node_name) when is_atom(node_name) and not is_nil(node_name),
    do: {:ok, node_name}

  defp validate_node_name(_node_name), do: {:error, :invalid_node_name}

  defp validate_state_server(state_server) do
    if is_pid(state_server) or is_tuple(state_server) do
      {:ok, state_server}
    else
      {:error, :invalid_state_server}
    end
  end

  defp validate_queue_limit(limit) when is_integer(limit) and limit > 0, do: {:ok, limit}
  defp validate_queue_limit(_limit), do: {:error, :invalid_interface_queue_limit}

  defp validate_backpressure(mode) when mode in @backpressure_modes, do: {:ok, mode}
  defp validate_backpressure(_mode), do: {:error, :invalid_interface_backpressure}

  defp validate_rate_limits(opts) do
    Enum.reduce_while(@rate_limit_keys, :ok, fn {key, error}, :ok ->
      case Keyword.get(opts, key) do
        nil -> {:cont, :ok}
        value when is_integer(value) and value > 0 -> {:cont, :ok}
        _value -> {:halt, {:error, error}}
      end
    end)
  end
end
