defmodule Reticulum.Interface.Supervisor do
  @moduledoc """
  Helpers for managing runtime interfaces under `Reticulum.Node`.
  """

  alias Reticulum.Interface.UDP
  alias Reticulum.Node
  alias Reticulum.Node.State

  @doc "Starts a UDP interface under `node_name`."
  def start_udp(node_name, opts) when is_atom(node_name) and is_list(opts) do
    child_opts =
      Keyword.merge(opts, node_name: node_name, state_server: Node.state_server(node_name))

    node_name
    |> Node.interface_supervisor()
    |> DynamicSupervisor.start_child({UDP, child_opts})
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
      {:ok, %{pid: pid, module: module}} ->
        module.send_frame(pid, payload, opts)

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
      {:ok, %{pid: pid, module: module}} -> module.prepare_outbound(pid, payload, opts)
      :error -> {:error, :unknown_interface}
      other -> other
    end
  end

  @doc "Normalizes an inbound frame payload from interface `name`."
  def normalize_inbound(node_name, name, payload)
      when is_atom(node_name) and is_atom(name) and is_binary(payload) do
    case fetch_interface(node_name, name) do
      {:ok, %{pid: pid, module: module}} -> module.normalize_inbound(pid, payload)
      :error -> {:error, :unknown_interface}
      other -> other
    end
  end

  defp fetch_interface(node_name, name) do
    node_name
    |> Node.state_server()
    |> State.interface(name)
  end
end
