defmodule Reticulum.Interface.Supervisor do
  @moduledoc """
  Helpers for managing runtime interfaces under `Reticulum.Node`.
  """

  alias Reticulum.Interface.Runtime
  alias Reticulum.Interface.UDP
  alias Reticulum.Node
  alias Reticulum.Node.State

  @doc "Starts interface `adapter` under `node_name`."
  def start_interface(node_name, adapter, opts) when is_atom(node_name) and is_list(opts) do
    with {:ok, config} <- Node.config(node_name) do
      child_opts =
        config
        |> interface_defaults()
        |> Keyword.merge(opts)
        |> Keyword.merge(
          adapter: adapter,
          node_name: node_name,
          state_server: Node.state_server(node_name)
        )

      node_name
      |> Node.interface_supervisor()
      |> DynamicSupervisor.start_child({Runtime, child_opts})
    end
  end

  @doc "Starts a UDP interface under `node_name`."
  def start_udp(node_name, opts) when is_atom(node_name) and is_list(opts) do
    start_interface(node_name, UDP, opts)
  end

  @doc "Stops interface `name` under `node_name`."
  def stop_interface(node_name, name) when is_atom(node_name) and is_atom(name) do
    interface =
      node_name
      |> Node.state_server()
      |> State.interface(name)

    case interface do
      {:ok, %{pid: pid}} ->
        node_name
        |> Node.interface_supervisor()
        |> DynamicSupervisor.terminate_child(pid)

      :error ->
        {:error, :unknown_interface}

      other ->
        other
    end
  end

  @doc "Lists registered interfaces for `node_name`."
  def interfaces(node_name) when is_atom(node_name) do
    node_name
    |> Node.state_server()
    |> State.interfaces()
  end

  @doc "Sends a raw frame on interface `name` for `node_name`."
  def send_frame(node_name, name, payload, opts \\ [])
      when is_atom(node_name) and is_atom(name) and is_list(opts) do
    interface =
      node_name
      |> Node.state_server()
      |> State.interface(name)

    case interface do
      {:ok, %{pid: pid}} ->
        Runtime.send_frame(pid, payload, opts)

      :error ->
        {:error, :unknown_interface}

      other ->
        other
    end
  end

  @doc "Prepares a transport payload for outbound transmission on `name`."
  def prepare_outbound(node_name, name, payload, opts \\ [])
      when is_atom(node_name) and is_atom(name) and is_binary(payload) and is_list(opts) do
    case fetch_interface(node_name, name) do
      {:ok, %{pid: pid}} -> Runtime.prepare_outbound(pid, payload, opts)
      :error -> {:error, :unknown_interface}
      other -> other
    end
  end

  @doc "Normalizes an inbound frame payload from interface `name`."
  def normalize_inbound(node_name, name, payload)
      when is_atom(node_name) and is_atom(name) and is_binary(payload) do
    case fetch_interface(node_name, name) do
      {:ok, %{pid: pid}} -> Runtime.normalize_inbound(pid, payload)
      :error -> {:error, :unknown_interface}
      other -> other
    end
  end

  defp interface_defaults(config) do
    [
      queue_limit: config.interface_queue_limit,
      backpressure: config.interface_backpressure,
      rate_limit_bytes_per_second: config.interface_rate_limit_bytes_per_second,
      rate_limit_packets_per_second: config.interface_rate_limit_packets_per_second,
      rate_limit_burst_bytes: config.interface_rate_limit_burst_bytes,
      rate_limit_burst_packets: config.interface_rate_limit_burst_packets
    ]
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
  end

  defp fetch_interface(node_name, name) do
    node_name
    |> Node.state_server()
    |> State.interface(name)
  end
end
