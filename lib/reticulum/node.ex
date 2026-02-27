defmodule Reticulum.Node do
  @moduledoc """
  Runtime shell for a Reticulum node process.

  This module introduces the first slice of node lifecycle support:

  - validated startup configuration
  - supervision tree for runtime services
  - in-memory ETS state for destinations, paths, packet hashes, and handlers

  Runtime state is intentionally ephemeral: every node start begins with empty
  ETS tables. No table-backed state is restored from disk yet.

  UDP interface wiring is available in this phase. Transport routing and
  link/session management are added in later phases.
  """
  use Supervisor

  alias Reticulum.Destination
  alias Reticulum.Interface.Supervisor, as: InterfaceSupervisor
  alias Reticulum.Node.Config
  alias Reticulum.Node.Ownership
  alias Reticulum.Node.State
  alias Reticulum.Transport

  @default_name __MODULE__

  @typedoc "Registered node name"
  @type name :: atom()

  @doc "Starts a node supervisor with validated options."
  def start_link(opts \\ []) when is_list(opts) do
    with {:ok, %Config{} = config} <- Config.new(opts),
         {:ok, pid} = started <- Supervisor.start_link(__MODULE__, config, name: config.name) do
      finalize_startup(config, started, pid)
    end
  end

  @doc "Returns runtime config for the default node."
  def config, do: config(@default_name)

  @doc "Returns runtime config for `node_name`."
  def config(node_name) when is_atom(node_name) do
    node_name
    |> state_server()
    |> State.config()
  end

  @doc "Returns all ETS table references for the default node."
  def tables, do: tables(@default_name)

  @doc "Returns all ETS table references for `node_name`."
  def tables(node_name) when is_atom(node_name) do
    node_name
    |> state_server()
    |> State.tables()
  end

  @doc "Returns table reference for the default node table key."
  def table(table_key), do: table(@default_name, table_key)

  @doc "Returns table reference for `table_key` on `node_name`."
  def table(node_name, table_key) when is_atom(node_name) do
    node_name
    |> state_server()
    |> State.table(table_key)
  end

  @doc "Stores/updates a known destination on the default node."
  def put_destination(destination_hash, public_key, app_data \\ nil),
    do: put_destination(@default_name, destination_hash, public_key, app_data)

  @doc "Stores/updates a known destination on `node_name`."
  def put_destination(node_name, destination_hash, public_key, app_data)
      when is_atom(node_name) do
    node_name
    |> state_server()
    |> State.put_destination(destination_hash, public_key, app_data)
  end

  @doc "Fetches known destination record from the default node."
  def destination(destination_hash), do: destination(@default_name, destination_hash)

  @doc "Fetches known destination record from `node_name`."
  def destination(node_name, destination_hash) when is_atom(node_name) do
    node_name
    |> state_server()
    |> State.destination(destination_hash)
  end

  @doc "Stores/updates a path record on the default node."
  def put_path(destination_hash, next_hop, hops),
    do: put_path(@default_name, destination_hash, next_hop, hops, [])

  @doc "Stores/updates a path record on the default node."
  def put_path(destination_hash, next_hop, hops, opts)
      when is_binary(destination_hash) and is_binary(next_hop) and is_list(opts),
      do: put_path(@default_name, destination_hash, next_hop, hops, opts)

  def put_path(node_name, destination_hash, next_hop, hops)
      when is_atom(node_name) and is_binary(destination_hash) and is_binary(next_hop),
      do: put_path(node_name, destination_hash, next_hop, hops, [])

  @doc "Stores/updates a path record on `node_name`."
  def put_path(node_name, destination_hash, next_hop, hops, opts)
      when is_atom(node_name) and is_binary(destination_hash) and is_binary(next_hop) and
             is_list(opts) do
    node_name
    |> state_server()
    |> State.put_path(destination_hash, next_hop, hops, opts)
  end

  @doc "Fetches path record from the default node."
  def path(destination_hash), do: path(@default_name, destination_hash)

  @doc "Fetches path record from `node_name`."
  def path(node_name, destination_hash) when is_atom(node_name) do
    node_name
    |> state_server()
    |> State.path(destination_hash)
  end

  @doc "Remembers packet hash in duplicate cache on the default node."
  def remember_packet_hash(packet_hash),
    do: remember_packet_hash(@default_name, packet_hash)

  @doc "Remembers packet hash in duplicate cache on `node_name`."
  def remember_packet_hash(node_name, packet_hash) when is_atom(node_name) do
    node_name
    |> state_server()
    |> State.remember_packet_hash(packet_hash)
  end

  @doc "Checks packet hash presence in duplicate cache on the default node."
  def packet_seen?(packet_hash), do: packet_seen?(@default_name, packet_hash)

  @doc "Checks packet hash presence in duplicate cache on `node_name`."
  def packet_seen?(node_name, packet_hash) when is_atom(node_name) do
    node_name
    |> state_server()
    |> State.packet_seen?(packet_hash)
  end

  @doc "Starts a UDP interface on the default node."
  def start_udp_interface(opts), do: start_udp_interface(@default_name, opts)

  @doc "Starts a UDP interface on `node_name`."
  def start_udp_interface(node_name, opts) when is_atom(node_name) and is_list(opts) do
    InterfaceSupervisor.start_udp(node_name, opts)
  end

  @doc "Stops interface `interface_name` on the default node."
  def stop_interface(interface_name), do: stop_interface(@default_name, interface_name)

  @doc "Stops interface `interface_name` on `node_name`."
  def stop_interface(node_name, interface_name)
      when is_atom(node_name) and is_atom(interface_name) do
    InterfaceSupervisor.stop_interface(node_name, interface_name)
  end

  @doc "Lists registered interfaces on the default node."
  def interfaces, do: interfaces(@default_name)

  @doc "Lists registered interfaces on `node_name`."
  def interfaces(node_name) when is_atom(node_name) do
    InterfaceSupervisor.interfaces(node_name)
  end

  @doc "Sends a raw frame on `interface_name` on the default node."
  def send_frame(interface_name, payload),
    do: send_frame(@default_name, interface_name, payload, [])

  @doc "Sends a raw frame on `interface_name` on the default node."
  def send_frame(interface_name, payload, opts)
      when is_atom(interface_name) and is_list(opts),
      do: send_frame(@default_name, interface_name, payload, opts)

  def send_frame(node_name, interface_name, payload)
      when is_atom(node_name) and is_atom(interface_name),
      do: send_frame(node_name, interface_name, payload, [])

  @doc "Sends a raw frame on `interface_name` on `node_name`."
  def send_frame(node_name, interface_name, payload, opts)
      when is_atom(node_name) and is_atom(interface_name) and is_list(opts) do
    InterfaceSupervisor.send_frame(node_name, interface_name, payload, opts)
  end

  @doc "Subscribes `pid` to raw frame events on the default node."
  def subscribe_frames(pid \\ self()), do: subscribe_frames(@default_name, pid)

  @doc "Subscribes `pid` to raw frame events on `node_name`."
  def subscribe_frames(node_name, pid) when is_atom(node_name) and is_pid(pid) do
    node_name
    |> state_server()
    |> State.subscribe_frames(pid)
  end

  @doc "Unsubscribes `pid` from raw frame events on the default node."
  def unsubscribe_frames(pid \\ self()), do: unsubscribe_frames(@default_name, pid)

  @doc "Unsubscribes `pid` from raw frame events on `node_name`."
  def unsubscribe_frames(node_name, pid) when is_atom(node_name) and is_pid(pid) do
    node_name
    |> state_server()
    |> State.unsubscribe_frames(pid)
  end

  @doc "Subscribes `pid` to decoded packet events on the default node."
  def subscribe_packets(pid \\ self()), do: subscribe_packets(@default_name, pid)

  @doc "Subscribes `pid` to decoded packet events on `node_name`."
  def subscribe_packets(node_name, pid) when is_atom(node_name) and is_pid(pid) do
    node_name
    |> state_server()
    |> State.subscribe_packets(pid)
  end

  @doc "Unsubscribes `pid` from decoded packet events on the default node."
  def unsubscribe_packets(pid \\ self()), do: unsubscribe_packets(@default_name, pid)

  @doc "Unsubscribes `pid` from decoded packet events on `node_name`."
  def unsubscribe_packets(node_name, pid) when is_atom(node_name) and is_pid(pid) do
    node_name
    |> state_server()
    |> State.unsubscribe_packets(pid)
  end

  @doc "Registers a local destination hash handler on the default node."
  def register_local_destination(destination_hash) when is_binary(destination_hash),
    do: register_local_destination(@default_name, destination_hash, self(), [])

  @doc "Registers a local destination hash handler on the default node."
  def register_local_destination(destination_hash, pid)
      when is_binary(destination_hash) and is_pid(pid),
      do: register_local_destination(@default_name, destination_hash, pid, [])

  @doc "Registers a local destination hash handler on the default node."
  def register_local_destination(destination_hash, pid, opts)
      when is_binary(destination_hash) and is_pid(pid) and is_list(opts),
      do: register_local_destination(@default_name, destination_hash, pid, opts)

  def register_local_destination(node_name, destination_hash, pid)
      when is_atom(node_name) and is_binary(destination_hash) and is_pid(pid),
      do: register_local_destination(node_name, destination_hash, pid, [])

  @doc "Registers a local destination hash handler on `node_name`."
  def register_local_destination(node_name, destination_hash, pid, opts)
      when is_atom(node_name) and is_binary(destination_hash) and is_pid(pid) and is_list(opts) do
    node_name
    |> state_server()
    |> State.register_local_destination(destination_hash, pid, opts)
  end

  @doc "Registers an announce-capable local destination on the default node."
  def register_local_announce_destination(%Destination{} = destination),
    do: register_local_announce_destination(@default_name, destination, self(), [])

  @doc "Registers an announce-capable local destination on the default node."
  def register_local_announce_destination(%Destination{} = destination, pid) when is_pid(pid),
    do: register_local_announce_destination(@default_name, destination, pid, [])

  @doc "Registers an announce-capable local destination on the default node."
  def register_local_announce_destination(%Destination{} = destination, pid, opts)
      when is_pid(pid) and is_list(opts),
      do: register_local_announce_destination(@default_name, destination, pid, opts)

  def register_local_announce_destination(node_name, %Destination{} = destination, pid)
      when is_atom(node_name) and is_pid(pid),
      do: register_local_announce_destination(node_name, destination, pid, [])

  @doc "Registers an announce-capable local destination on `node_name`."
  def register_local_announce_destination(node_name, %Destination{} = destination, pid, opts)
      when is_atom(node_name) and is_pid(pid) and is_list(opts) do
    node_name
    |> state_server()
    |> State.register_local_destination(
      destination.hash,
      pid,
      Keyword.put(opts, :destination, destination)
    )
  end

  @doc "Unregisters a local destination handler on the default node."
  def unregister_local_destination(destination_hash),
    do: unregister_local_destination(@default_name, destination_hash)

  @doc "Unregisters a local destination handler on `node_name`."
  def unregister_local_destination(node_name, destination_hash) when is_atom(node_name) do
    node_name
    |> state_server()
    |> State.unregister_local_destination(destination_hash)
  end

  @doc "Sends a packet struct or raw packet on the default node."
  def send_packet(interface_name, packet_or_raw),
    do: send_packet(@default_name, interface_name, packet_or_raw, [])

  @doc "Sends a packet struct or raw packet on the default node."
  def send_packet(interface_name, packet_or_raw, opts)
      when is_atom(interface_name) and is_list(opts),
      do: send_packet(@default_name, interface_name, packet_or_raw, opts)

  def send_packet(node_name, interface_name, packet_or_raw)
      when is_atom(node_name) and is_atom(interface_name),
      do: send_packet(node_name, interface_name, packet_or_raw, [])

  @doc "Sends a packet struct or raw packet on `node_name`."
  def send_packet(node_name, interface_name, packet_or_raw, opts)
      when is_atom(node_name) and is_atom(interface_name) and is_list(opts) do
    node_name
    |> transport_server()
    |> Transport.send_packet(interface_name, packet_or_raw, opts)
  end

  @doc "Sends packet data to `destination_hash` over `interface_name` on the default node."
  def send_data(interface_name, destination_hash, payload),
    do: send_data(@default_name, interface_name, destination_hash, payload, [])

  @doc "Sends packet data to `destination_hash` over `interface_name` on the default node."
  def send_data(interface_name, destination_hash, payload, opts)
      when is_atom(interface_name) and is_binary(payload) and is_list(opts),
      do: send_data(@default_name, interface_name, destination_hash, payload, opts)

  def send_data(node_name, interface_name, destination_hash, payload)
      when is_atom(node_name) and is_atom(interface_name) and is_binary(payload),
      do: send_data(node_name, interface_name, destination_hash, payload, [])

  @doc "Sends packet data to `destination_hash` over `interface_name` on `node_name`."
  def send_data(node_name, interface_name, destination_hash, payload, opts)
      when is_atom(node_name) and is_atom(interface_name) and is_binary(payload) and
             is_list(opts) do
    node_name
    |> transport_server()
    |> Transport.send_data(interface_name, destination_hash, payload, opts)
  end

  @doc "Sends a path request over `interface_name` on the default node."
  def request_path(interface_name, destination_hash),
    do: request_path(@default_name, interface_name, destination_hash, [])

  @doc "Sends a path request over `interface_name` on the default node."
  def request_path(interface_name, destination_hash, opts)
      when is_atom(interface_name) and is_list(opts),
      do: request_path(@default_name, interface_name, destination_hash, opts)

  def request_path(node_name, interface_name, destination_hash)
      when is_atom(node_name) and is_atom(interface_name),
      do: request_path(node_name, interface_name, destination_hash, [])

  @doc "Sends a path request over `interface_name` on `node_name`."
  def request_path(node_name, interface_name, destination_hash, opts)
      when is_atom(node_name) and is_atom(interface_name) and is_list(opts) do
    node_name
    |> transport_server()
    |> Transport.request_path(interface_name, destination_hash, opts)
  end

  @doc "Fetches tracked packet receipt on the default node."
  def receipt(receipt_hash), do: receipt(@default_name, receipt_hash)

  @doc "Fetches tracked packet receipt on `node_name`."
  def receipt(node_name, receipt_hash) when is_atom(node_name) and is_binary(receipt_hash) do
    node_name
    |> transport_server()
    |> Transport.receipt(receipt_hash)
  end

  @doc "Sends an announce packet for a local destination on the default node."
  def announce(interface_name, destination_hash),
    do: announce(@default_name, interface_name, destination_hash, [])

  @doc "Sends an announce packet for a local destination on the default node."
  def announce(interface_name, destination_hash, opts)
      when is_atom(interface_name) and is_binary(destination_hash) and is_list(opts),
      do: announce(@default_name, interface_name, destination_hash, opts)

  def announce(node_name, interface_name, destination_hash)
      when is_atom(node_name) and is_atom(interface_name) and is_binary(destination_hash),
      do: announce(node_name, interface_name, destination_hash, [])

  @doc "Sends an announce packet for a local destination on `node_name`."
  def announce(node_name, interface_name, destination_hash, opts)
      when is_atom(node_name) and is_atom(interface_name) and is_binary(destination_hash) and
             is_list(opts) do
    node_name
    |> transport_server()
    |> Transport.announce_destination(interface_name, destination_hash, opts)
  end

  @doc "Registers a request handler hook for destination/context on the default node."
  def register_request_handler(destination_hash, context, pid \\ self()),
    do: register_request_handler(@default_name, destination_hash, context, pid)

  @doc "Registers a request handler hook for destination/context on `node_name`."
  def register_request_handler(node_name, destination_hash, context, pid)
      when is_atom(node_name) and is_binary(destination_hash) and is_pid(pid) do
    node_name
    |> state_server()
    |> State.register_request_handler(destination_hash, context, pid)
  end

  @doc "Unregisters a request handler hook for destination/context on the default node."
  def unregister_request_handler(destination_hash, context),
    do: unregister_request_handler(@default_name, destination_hash, context)

  @doc "Unregisters a request handler hook for destination/context on `node_name`."
  def unregister_request_handler(node_name, destination_hash, context)
      when is_atom(node_name) and is_binary(destination_hash) do
    node_name
    |> state_server()
    |> State.unregister_request_handler(destination_hash, context)
  end

  @doc "Registers a response handler hook for destination/context on the default node."
  def register_response_handler(destination_hash, context, pid \\ self()),
    do: register_response_handler(@default_name, destination_hash, context, pid)

  @doc "Registers a response handler hook for destination/context on `node_name`."
  def register_response_handler(node_name, destination_hash, context, pid)
      when is_atom(node_name) and is_binary(destination_hash) and is_pid(pid) do
    node_name
    |> state_server()
    |> State.register_response_handler(destination_hash, context, pid)
  end

  @doc "Unregisters a response handler hook for destination/context on the default node."
  def unregister_response_handler(destination_hash, context),
    do: unregister_response_handler(@default_name, destination_hash, context)

  @doc "Unregisters a response handler hook for destination/context on `node_name`."
  def unregister_response_handler(node_name, destination_hash, context)
      when is_atom(node_name) and is_binary(destination_hash) do
    node_name
    |> state_server()
    |> State.unregister_response_handler(destination_hash, context)
  end

  @doc "Returns interface supervisor identity for `node_name`."
  def interface_supervisor(node_name \\ @default_name) when is_atom(node_name) do
    {:global, {__MODULE__, :interfaces, node_name}}
  end

  defp finalize_startup(config, started, pid) do
    case Ownership.claim_shared_instance(config, pid) do
      :ok ->
        started

      {:error, _reason} = error ->
        _ = Supervisor.stop(pid)
        error
    end
  end

  @doc "Returns state server identity for `node_name`."
  def state_server(node_name \\ @default_name) when is_atom(node_name) do
    {:global, {__MODULE__, :state, node_name}}
  end

  @doc "Returns transport server identity for `node_name`."
  def transport_server(node_name \\ @default_name) when is_atom(node_name) do
    {:global, {__MODULE__, :transport, node_name}}
  end

  @impl true
  def init(%Config{name: name, storage_path: storage_path} = config) do
    _ = File.mkdir_p(storage_path)

    children = [
      {State, name: state_server(name), config: config},
      {DynamicSupervisor, strategy: :one_for_one, name: interface_supervisor(name)},
      {Transport,
       name: transport_server(name),
       node_name: name,
       state_server: state_server(name),
       config: config}
    ]

    Supervisor.init(children, strategy: :one_for_all)
  end
end
