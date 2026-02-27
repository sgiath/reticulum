defmodule Reticulum.Messaging do
  @moduledoc """
  High-level messaging helpers on top of `Reticulum.Node` transport APIs.
  """

  alias Reticulum.Node

  @default_node Reticulum.Node

  @doc "Sends payload to destination hash using resolved interface."
  def send(destination_hash, payload) when is_binary(payload) do
    send(@default_node, destination_hash, payload, [])
  end

  @doc "Sends payload to destination hash using resolved interface."
  def send(destination_hash, payload, opts) when is_binary(payload) and is_list(opts) do
    send(@default_node, destination_hash, payload, opts)
  end

  def send(node_name, destination_hash, payload)
      when is_atom(node_name) and is_binary(payload),
      do: send(node_name, destination_hash, payload, [])

  @doc "Sends payload to destination hash using resolved interface on `node_name`."
  def send(node_name, destination_hash, payload, opts)
      when is_atom(node_name) and is_binary(payload) and is_list(opts) do
    with {:ok, interface} <- resolve_interface(node_name, destination_hash, opts) do
      send_opts = Keyword.delete(opts, :interface)

      result =
        Node.send_data(
          node_name,
          interface,
          destination_hash,
          payload,
          send_opts
        )

      maybe_retry_without_explicit_interface(
        node_name,
        destination_hash,
        payload,
        opts,
        result,
        send_opts
      )
    end
  end

  @doc "Announces a registered local inbound destination on the default node."
  def announce(destination_hash, opts \\ []) when is_list(opts) do
    announce(@default_node, destination_hash, opts)
  end

  @doc "Announces a registered local inbound destination on `node_name`."
  def announce(node_name, destination_hash, opts)
      when is_atom(node_name) and is_list(opts) do
    with {:ok, interface} <- resolve_interface(node_name, destination_hash, opts) do
      Node.announce(node_name, interface, destination_hash, Keyword.delete(opts, :interface))
    end
  end

  @doc "Registers request handler hook for destination/context."
  def register_request_handler(destination_hash, context, pid \\ self()),
    do: Node.register_request_handler(destination_hash, context, pid)

  @doc "Registers request handler hook for destination/context on `node_name`."
  def register_request_handler(node_name, destination_hash, context, pid)
      when is_atom(node_name) and is_pid(pid),
      do: Node.register_request_handler(node_name, destination_hash, context, pid)

  @doc "Registers response handler hook for destination/context."
  def register_response_handler(destination_hash, context, pid \\ self()),
    do: Node.register_response_handler(destination_hash, context, pid)

  @doc "Registers response handler hook for destination/context on `node_name`."
  def register_response_handler(node_name, destination_hash, context, pid)
      when is_atom(node_name) and is_pid(pid),
      do: Node.register_response_handler(node_name, destination_hash, context, pid)

  defp resolve_interface(node_name, destination_hash, opts) do
    case Keyword.get(opts, :interface) do
      interface when is_atom(interface) ->
        {:ok, interface}

      nil ->
        resolve_path_or_single_interface(node_name, destination_hash)

      _other ->
        {:error, :invalid_interface}
    end
  end

  defp resolve_path_or_single_interface(node_name, destination_hash) do
    case Node.path(node_name, destination_hash) do
      {:ok, %{interface: interface}} when is_atom(interface) ->
        {:ok, interface}

      _ ->
        case Node.interfaces(node_name) do
          {:ok, [%{name: interface}]} -> {:ok, interface}
          {:ok, []} -> {:error, :no_interfaces}
          {:ok, _interfaces} -> {:error, :interface_required}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  defp maybe_retry_without_explicit_interface(
         node_name,
         destination_hash,
         payload,
         opts,
         {:error, :unknown_interface},
         send_opts
       ) do
    if Keyword.has_key?(opts, :interface) do
      {:error, :unknown_interface}
    else
      with {:ok, interface} <- first_interface(node_name) do
        Node.send_data(node_name, interface, destination_hash, payload, send_opts)
      end
    end
  end

  defp maybe_retry_without_explicit_interface(
         _node_name,
         _destination_hash,
         _payload,
         _opts,
         result,
         _send_opts
       ),
       do: result

  defp first_interface(node_name) do
    case Node.interfaces(node_name) do
      {:ok, [%{name: interface} | _]} -> {:ok, interface}
      {:ok, []} -> {:error, :no_interfaces}
      {:error, reason} -> {:error, reason}
    end
  end
end
