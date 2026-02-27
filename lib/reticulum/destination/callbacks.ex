defmodule Reticulum.Destination.Callbacks do
  @moduledoc """
  Local destination callback registration helpers.
  """

  alias Reticulum.Destination
  alias Reticulum.Node

  @default_node Reticulum.Node

  @doc "Registers callback for inbound packets on destination hash."
  def register(destination_hash, callback, opts \\ []) when is_binary(destination_hash) do
    register(@default_node, destination_hash, callback, opts)
  end

  @doc "Registers callback for inbound packets on destination hash and node."
  def register(node_name, destination_hash, callback, opts)
      when is_atom(node_name) and is_binary(destination_hash) and is_function(callback, 1) and
             is_list(opts) do
    pid = Keyword.get(opts, :pid, self())
    app_data = Keyword.get(opts, :app_data)

    Node.register_local_destination(node_name, destination_hash, pid,
      callback: callback,
      app_data: app_data
    )
  end

  def register(node_name, %Destination{} = destination, callback, opts)
      when is_atom(node_name) and is_function(callback, 1) and is_list(opts) do
    pid = Keyword.get(opts, :pid, self())
    app_data = Keyword.get(opts, :app_data)

    Node.register_local_announce_destination(node_name, destination, pid,
      callback: callback,
      app_data: app_data
    )
  end

  @doc "Unregisters local destination callback by destination hash."
  def unregister(destination_hash), do: Node.unregister_local_destination(destination_hash)

  @doc "Unregisters local destination callback by destination hash and node."
  def unregister(node_name, destination_hash)
      when is_atom(node_name) and is_binary(destination_hash),
      do: Node.unregister_local_destination(node_name, destination_hash)
end
