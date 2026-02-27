defmodule Reticulum.Node.State do
  @moduledoc false
  use GenServer

  alias Reticulum.Node.Config
  alias Reticulum.Destination

  @truncated_hash_len 16

  @typedoc "Known destination record"
  @type destination_record :: %{
          public_key: binary(),
          app_data: binary() | nil,
          updated_at: integer()
        }

  @typedoc "Known path record"
  @type path_record :: %{
          next_hop: binary(),
          hops: non_neg_integer(),
          interface: atom() | nil,
          updated_at: integer()
        }

  @typedoc "Runtime state tables"
  @type tables :: %{
          destinations: :ets.tid(),
          paths: :ets.tid(),
          packet_hashes: :ets.tid(),
          interfaces: :ets.tid(),
          local_destinations: :ets.tid(),
          request_handlers: :ets.tid(),
          response_handlers: :ets.tid()
        }

  @typedoc "Registered interface record"
  @type interface_record :: %{
          name: atom(),
          pid: pid(),
          module: module(),
          meta: map(),
          updated_at: integer()
        }

  @typedoc "Raw frame event"
  @type frame_event :: %{
          direction: :inbound | :outbound,
          interface: atom(),
          payload: binary(),
          endpoint: {tuple(), non_neg_integer()},
          at: integer(),
          node: atom()
        }

  @typedoc "Decoded packet event"
  @type packet_event :: %{
          interface: atom(),
          packet: Reticulum.Packet.t() | nil,
          packet_hash: binary() | nil,
          duplicate: boolean(),
          endpoint: {tuple(), non_neg_integer()} | nil,
          node: atom(),
          reason: atom() | nil,
          raw: binary() | nil,
          at: integer()
        }

  @typedoc "Local destination registration"
  @type local_destination_record :: %{
          pid: pid(),
          destination: Destination.t() | nil,
          callback: (map() -> term()) | nil,
          proof_requested_callback: (map() -> boolean()) | nil,
          app_data: binary() | nil,
          updated_at: integer()
        }

  @typedoc "Request/response handler registration"
  @type message_handler_record :: %{
          pid: pid(),
          updated_at: integer()
        }

  @type state :: %{
          config: Config.t(),
          tables: tables(),
          subscribers: MapSet.t(pid()),
          packet_subscribers: MapSet.t(pid()),
          monitor_refs: %{reference() => atom()}
        }

  def start_link(opts) do
    config = Keyword.fetch!(opts, :config)
    name = Keyword.fetch!(opts, :name)

    GenServer.start_link(__MODULE__, config, name: name)
  end

  def config(server), do: GenServer.call(server, :config)
  def tables(server), do: GenServer.call(server, :tables)
  def table(server, table_key), do: GenServer.call(server, {:table, table_key})

  def put_destination(server, destination_hash, public_key, app_data \\ nil) do
    GenServer.call(server, {:put_destination, destination_hash, public_key, app_data})
  end

  def destination(server, destination_hash),
    do: GenServer.call(server, {:destination, destination_hash})

  def put_path(server, destination_hash, next_hop, hops, opts \\ []) do
    GenServer.call(server, {:put_path, destination_hash, next_hop, hops, opts})
  end

  def path(server, destination_hash), do: GenServer.call(server, {:path, destination_hash})

  def paths(server), do: GenServer.call(server, :paths)

  def delete_path(server, destination_hash),
    do: GenServer.call(server, {:delete_path, destination_hash})

  def remember_packet_hash(server, packet_hash),
    do: GenServer.call(server, {:remember_packet_hash, packet_hash})

  def packet_seen?(server, packet_hash), do: GenServer.call(server, {:packet_seen?, packet_hash})

  def register_interface(server, name, pid, module, meta \\ %{}) do
    GenServer.call(server, {:register_interface, name, pid, module, meta})
  end

  def unregister_interface(server, name),
    do: GenServer.call(server, {:unregister_interface, name})

  def interface(server, name), do: GenServer.call(server, {:interface, name})

  def interfaces(server), do: GenServer.call(server, :interfaces)

  def subscribe_frames(server, pid \\ self()),
    do: GenServer.call(server, {:subscribe_frames, pid})

  def unsubscribe_frames(server, pid \\ self()),
    do: GenServer.call(server, {:unsubscribe_frames, pid})

  def publish_frame(server, event), do: GenServer.cast(server, {:publish_frame, event})

  def subscribe_packets(server, pid \\ self()),
    do: GenServer.call(server, {:subscribe_packets, pid})

  def unsubscribe_packets(server, pid \\ self()),
    do: GenServer.call(server, {:unsubscribe_packets, pid})

  def publish_packet(server, event), do: GenServer.cast(server, {:publish_packet, event})

  def register_local_destination(server, destination_hash, pid, opts \\ []) do
    GenServer.call(server, {:register_local_destination, destination_hash, pid, opts})
  end

  def unregister_local_destination(server, destination_hash) do
    GenServer.call(server, {:unregister_local_destination, destination_hash})
  end

  def local_destination(server, destination_hash) do
    GenServer.call(server, {:local_destination, destination_hash})
  end

  def register_request_handler(server, destination_hash, context, pid \\ self()) do
    GenServer.call(server, {:register_request_handler, destination_hash, context, pid})
  end

  def unregister_request_handler(server, destination_hash, context) do
    GenServer.call(server, {:unregister_request_handler, destination_hash, context})
  end

  def request_handler(server, destination_hash, context) do
    GenServer.call(server, {:request_handler, destination_hash, context})
  end

  def register_response_handler(server, destination_hash, context, pid \\ self()) do
    GenServer.call(server, {:register_response_handler, destination_hash, context, pid})
  end

  def unregister_response_handler(server, destination_hash, context) do
    GenServer.call(server, {:unregister_response_handler, destination_hash, context})
  end

  def response_handler(server, destination_hash, context) do
    GenServer.call(server, {:response_handler, destination_hash, context})
  end

  @impl true
  def init(%Config{} = config) do
    {:ok,
     %{
       config: config,
       tables: %{
         destinations:
           :ets.new(:reticulum_destinations, [:set, :protected, {:read_concurrency, true}]),
         paths: :ets.new(:reticulum_paths, [:set, :protected, {:read_concurrency, true}]),
         packet_hashes:
           :ets.new(:reticulum_packet_hashes, [
             :set,
             :protected,
             {:read_concurrency, true},
             {:write_concurrency, true}
           ]),
         interfaces:
           :ets.new(:reticulum_interfaces, [
             :set,
             :protected,
             {:read_concurrency, true},
             {:write_concurrency, true}
           ]),
         local_destinations:
           :ets.new(:reticulum_local_destinations, [
             :set,
             :protected,
             {:read_concurrency, true},
             {:write_concurrency, true}
           ]),
         request_handlers:
           :ets.new(:reticulum_request_handlers, [
             :set,
             :protected,
             {:read_concurrency, true},
             {:write_concurrency, true}
           ]),
         response_handlers:
           :ets.new(:reticulum_response_handlers, [
             :set,
             :protected,
             {:read_concurrency, true},
             {:write_concurrency, true}
           ])
       },
       subscribers: MapSet.new(),
       packet_subscribers: MapSet.new(),
       monitor_refs: %{}
     }}
  end

  @impl true
  def handle_call(:config, _from, %{config: config} = state), do: {:reply, {:ok, config}, state}

  def handle_call(:tables, _from, %{tables: tables} = state), do: {:reply, {:ok, tables}, state}

  def handle_call({:table, table_key}, _from, %{tables: tables} = state) do
    reply =
      case Map.fetch(tables, table_key) do
        {:ok, table} -> {:ok, table}
        :error -> {:error, :unknown_table}
      end

    {:reply, reply, state}
  end

  def handle_call({:put_destination, destination_hash, public_key, app_data}, _from, state) do
    reply =
      cond do
        not is_binary(destination_hash) ->
          {:error, :invalid_destination_hash}

        not is_binary(public_key) ->
          {:error, :invalid_public_key}

        not is_nil(app_data) and not is_binary(app_data) ->
          {:error, :invalid_app_data}

        true ->
          entry = %{
            public_key: public_key,
            app_data: app_data,
            updated_at: System.system_time(:second)
          }

          true = :ets.insert(state.tables.destinations, {destination_hash, entry})
          :ok
      end

    {:reply, reply, state}
  end

  def handle_call({:destination, destination_hash}, _from, state) do
    case :ets.lookup(state.tables.destinations, destination_hash) do
      [{^destination_hash, entry}] -> {:reply, {:ok, entry}, state}
      [] -> {:reply, :error, state}
    end
  end

  def handle_call({:put_path, destination_hash, next_hop, hops, opts}, _from, state) do
    reply =
      cond do
        not is_list(opts) ->
          {:error, :invalid_path_options}

        not is_binary(destination_hash) ->
          {:error, :invalid_destination_hash}

        not is_binary(next_hop) ->
          {:error, :invalid_next_hop}

        not (is_integer(hops) and hops >= 0) ->
          {:error, :invalid_hops}

        true ->
          interface = Keyword.get(opts, :interface, nil)

          if not is_nil(interface) and not is_atom(interface) do
            {:error, :invalid_interface}
          else
            entry = %{
              next_hop: next_hop,
              hops: hops,
              interface: interface,
              updated_at: System.system_time(:second)
            }

            true = :ets.insert(state.tables.paths, {destination_hash, entry})
            :ok
          end
      end

    {:reply, reply, state}
  end

  def handle_call({:path, destination_hash}, _from, state) do
    case :ets.lookup(state.tables.paths, destination_hash) do
      [{^destination_hash, entry}] -> {:reply, {:ok, entry}, state}
      [] -> {:reply, :error, state}
    end
  end

  def handle_call(:paths, _from, state) do
    paths =
      state.tables.paths
      |> :ets.tab2list()
      |> Enum.map(fn {destination_hash, entry} ->
        Map.put(entry, :destination_hash, destination_hash)
      end)
      |> Enum.sort_by(& &1.destination_hash)

    {:reply, {:ok, paths}, state}
  end

  def handle_call({:delete_path, destination_hash}, _from, state) do
    case :ets.lookup(state.tables.paths, destination_hash) do
      [{^destination_hash, _entry}] ->
        true = :ets.delete(state.tables.paths, destination_hash)
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :unknown_path}, state}
    end
  end

  def handle_call({:remember_packet_hash, packet_hash}, _from, state) do
    reply =
      cond do
        not is_binary(packet_hash) ->
          {:error, :invalid_packet_hash}

        :ets.insert_new(
          state.tables.packet_hashes,
          {packet_hash, System.system_time(:second)}
        ) ->
          :new

        true ->
          :existing
      end

    {:reply, reply, state}
  end

  def handle_call({:packet_seen?, packet_hash}, _from, state) do
    {:reply, :ets.member(state.tables.packet_hashes, packet_hash), state}
  end

  def handle_call({:register_interface, name, pid, module, meta}, _from, state) do
    reply_state =
      cond do
        not is_atom(name) ->
          {{:error, :invalid_interface_name}, state}

        not is_pid(pid) ->
          {{:error, :invalid_interface_pid}, state}

        not is_atom(module) ->
          {{:error, :invalid_interface_module}, state}

        not is_map(meta) ->
          {{:error, :invalid_interface_meta}, state}

        not Process.alive?(pid) ->
          {{:error, :interface_not_alive}, state}

        :ets.member(state.tables.interfaces, name) ->
          {{:error, :interface_already_registered}, state}

        true ->
          ref = Process.monitor(pid)

          entry = %{
            name: name,
            pid: pid,
            module: module,
            meta: meta,
            monitor_ref: ref,
            updated_at: System.system_time(:second)
          }

          true = :ets.insert(state.tables.interfaces, {name, entry})
          {:ok, %{state | monitor_refs: Map.put(state.monitor_refs, ref, name)}}
      end

    {reply, new_state} = reply_state
    {:reply, reply, new_state}
  end

  def handle_call({:unregister_interface, name}, _from, state) do
    case :ets.lookup(state.tables.interfaces, name) do
      [{^name, %{monitor_ref: ref}}] ->
        Process.demonitor(ref, [:flush])
        true = :ets.delete(state.tables.interfaces, name)

        {:reply, :ok, %{state | monitor_refs: Map.delete(state.monitor_refs, ref)}}

      [] ->
        {:reply, {:error, :unknown_interface}, state}
    end
  end

  def handle_call({:interface, name}, _from, state) do
    case :ets.lookup(state.tables.interfaces, name) do
      [{^name, entry}] ->
        {:reply, {:ok, Map.delete(entry, :monitor_ref)}, state}

      [] ->
        {:reply, :error, state}
    end
  end

  def handle_call(:interfaces, _from, state) do
    interfaces =
      state.tables.interfaces
      |> :ets.tab2list()
      |> Enum.map(fn {_name, entry} -> Map.delete(entry, :monitor_ref) end)
      |> Enum.sort_by(& &1.name)

    {:reply, {:ok, interfaces}, state}
  end

  def handle_call({:subscribe_frames, pid}, _from, state) do
    if is_pid(pid) do
      {:reply, :ok, %{state | subscribers: MapSet.put(state.subscribers, pid)}}
    else
      {:reply, {:error, :invalid_subscriber}, state}
    end
  end

  def handle_call({:unsubscribe_frames, pid}, _from, state) do
    if is_pid(pid) do
      {:reply, :ok, %{state | subscribers: MapSet.delete(state.subscribers, pid)}}
    else
      {:reply, {:error, :invalid_subscriber}, state}
    end
  end

  def handle_call({:subscribe_packets, pid}, _from, state) do
    if is_pid(pid) do
      {:reply, :ok, %{state | packet_subscribers: MapSet.put(state.packet_subscribers, pid)}}
    else
      {:reply, {:error, :invalid_subscriber}, state}
    end
  end

  def handle_call({:unsubscribe_packets, pid}, _from, state) do
    if is_pid(pid) do
      {:reply, :ok, %{state | packet_subscribers: MapSet.delete(state.packet_subscribers, pid)}}
    else
      {:reply, {:error, :invalid_subscriber}, state}
    end
  end

  def handle_call({:register_local_destination, destination_hash, pid, opts}, _from, state) do
    reply = register_local_destination_entry(state, destination_hash, pid, opts)

    {:reply, reply, state}
  end

  def handle_call({:unregister_local_destination, destination_hash}, _from, state) do
    case :ets.lookup(state.tables.local_destinations, destination_hash) do
      [{^destination_hash, _entry}] ->
        true = :ets.delete(state.tables.local_destinations, destination_hash)
        {:reply, :ok, state}

      [] ->
        {:reply, {:error, :unknown_local_destination}, state}
    end
  end

  def handle_call({:local_destination, destination_hash}, _from, state) do
    case :ets.lookup(state.tables.local_destinations, destination_hash) do
      [{^destination_hash, entry}] ->
        {:reply, {:ok, entry}, state}

      [] ->
        {:reply, :error, state}
    end
  end

  def handle_call({:register_request_handler, destination_hash, context, pid}, _from, state) do
    reply =
      register_message_handler_entry(
        state.tables.request_handlers,
        destination_hash,
        context,
        pid
      )

    {:reply, reply, state}
  end

  def handle_call({:unregister_request_handler, destination_hash, context}, _from, state) do
    reply =
      unregister_message_handler_entry(
        state.tables.request_handlers,
        destination_hash,
        context,
        :unknown_request_handler
      )

    {:reply, reply, state}
  end

  def handle_call({:request_handler, destination_hash, context}, _from, state) do
    reply = fetch_message_handler(state.tables.request_handlers, destination_hash, context)
    {:reply, reply, state}
  end

  def handle_call({:register_response_handler, destination_hash, context, pid}, _from, state) do
    reply =
      register_message_handler_entry(
        state.tables.response_handlers,
        destination_hash,
        context,
        pid
      )

    {:reply, reply, state}
  end

  def handle_call({:unregister_response_handler, destination_hash, context}, _from, state) do
    reply =
      unregister_message_handler_entry(
        state.tables.response_handlers,
        destination_hash,
        context,
        :unknown_response_handler
      )

    {:reply, reply, state}
  end

  def handle_call({:response_handler, destination_hash, context}, _from, state) do
    reply = fetch_message_handler(state.tables.response_handlers, destination_hash, context)
    {:reply, reply, state}
  end

  @impl true
  def handle_cast({:publish_frame, event}, state) when is_map(event) do
    Enum.each(state.subscribers, fn pid ->
      send(pid, {:reticulum, :frame, event})
    end)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:publish_packet, event}, state) when is_map(event) do
    Enum.each(state.packet_subscribers, fn pid ->
      send(pid, {:reticulum, :packet, event})
    end)

    {:noreply, state}
  end

  @impl true
  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.monitor_refs, ref) do
      {nil, _monitor_refs} ->
        {:noreply, state}

      {name, monitor_refs} ->
        true = :ets.delete(state.tables.interfaces, name)
        {:noreply, %{state | monitor_refs: monitor_refs}}
    end
  end

  defp register_local_destination_entry(_state, _destination_hash, _pid, opts)
       when not is_list(opts),
       do: {:error, :invalid_local_destination_options}

  defp register_local_destination_entry(state, destination_hash, pid, opts) do
    with {:ok, destination, callback, proof_requested_callback, app_data} <-
           parse_local_destination_opts(opts),
         :ok <- validate_registered_destination_hash(destination_hash),
         :ok <- validate_destination_handler(pid),
         :ok <- validate_destination_proof_strategy(destination),
         :ok <- validate_destination_binding(destination_hash, destination) do
      insert_local_destination_entry(
        state,
        destination_hash,
        pid,
        destination,
        callback,
        proof_requested_callback,
        app_data
      )
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_local_destination_opts(opts) do
    destination = Keyword.get(opts, :destination)
    callback = Keyword.get(opts, :callback)
    proof_requested_callback = Keyword.get(opts, :proof_requested_callback)
    app_data = Keyword.get(opts, :app_data)

    with :ok <- validate_local_destination_opt_keys(opts),
         :ok <- validate_local_destination_option(:destination, destination),
         :ok <- validate_local_destination_option(:callback, callback),
         :ok <-
           validate_local_destination_option(:proof_requested_callback, proof_requested_callback),
         :ok <- validate_local_destination_option(:app_data, app_data) do
      {:ok, destination, callback, proof_requested_callback, app_data}
    end
  end

  defp validate_local_destination_opt_keys(opts) do
    unknown_opts =
      opts
      |> Keyword.keys()
      |> Enum.reject(&(&1 in [:destination, :callback, :proof_requested_callback, :app_data]))

    case unknown_opts do
      [] -> :ok
      _ -> {:error, :unknown_local_destination_option}
    end
  end

  defp validate_local_destination_option(:destination, nil), do: :ok

  defp validate_local_destination_option(:destination, %Destination{}), do: :ok

  defp validate_local_destination_option(:destination, _destination),
    do: {:error, :invalid_destination}

  defp validate_local_destination_option(:callback, nil), do: :ok

  defp validate_local_destination_option(:callback, callback) when is_function(callback, 1),
    do: :ok

  defp validate_local_destination_option(:callback, _callback),
    do: {:error, :invalid_destination_callback}

  defp validate_local_destination_option(:proof_requested_callback, nil), do: :ok

  defp validate_local_destination_option(:proof_requested_callback, callback)
       when is_function(callback, 1),
       do: :ok

  defp validate_local_destination_option(:proof_requested_callback, _callback),
    do: {:error, :invalid_proof_requested_callback}

  defp validate_local_destination_option(:app_data, nil), do: :ok
  defp validate_local_destination_option(:app_data, app_data) when is_binary(app_data), do: :ok
  defp validate_local_destination_option(:app_data, _app_data), do: {:error, :invalid_app_data}

  defp validate_registered_destination_hash(destination_hash)
       when is_binary(destination_hash) and byte_size(destination_hash) == @truncated_hash_len,
       do: :ok

  defp validate_registered_destination_hash(_destination_hash),
    do: {:error, :invalid_destination_hash}

  defp validate_destination_handler(pid) when is_pid(pid) do
    if Process.alive?(pid) do
      :ok
    else
      {:error, :destination_handler_not_alive}
    end
  end

  defp validate_destination_handler(_pid), do: {:error, :invalid_destination_handler}

  defp validate_destination_binding(_destination_hash, nil), do: :ok

  defp validate_destination_binding(destination_hash, %Destination{} = destination) do
    if destination.hash == destination_hash do
      :ok
    else
      {:error, :destination_hash_mismatch}
    end
  end

  defp validate_destination_proof_strategy(nil), do: :ok

  defp validate_destination_proof_strategy(%Destination{proof_strategy: proof_strategy}) do
    if Destination.valid_proof_strategy?(proof_strategy) do
      :ok
    else
      {:error, :invalid_proof_strategy}
    end
  end

  defp insert_local_destination_entry(
         state,
         destination_hash,
         pid,
         destination,
         callback,
         proof_requested_callback,
         app_data
       ) do
    true =
      :ets.insert(
        state.tables.local_destinations,
        {
          destination_hash,
          %{
            pid: pid,
            destination: destination,
            callback: callback,
            proof_requested_callback: proof_requested_callback,
            app_data: app_data,
            updated_at: System.system_time(:second)
          }
        }
      )

    :ok
  end

  defp register_message_handler_entry(_table, _destination_hash, _context, pid)
       when not is_pid(pid),
       do: {:error, :invalid_handler_pid}

  defp register_message_handler_entry(table, destination_hash, context, pid) do
    with :ok <- validate_registered_destination_hash(destination_hash),
         :ok <- validate_message_context(context),
         :ok <- validate_destination_handler(pid) do
      true =
        :ets.insert(
          table,
          {{destination_hash, context}, %{pid: pid, updated_at: System.system_time(:second)}}
        )

      :ok
    end
  end

  defp unregister_message_handler_entry(table, destination_hash, context, missing_reason) do
    with :ok <- validate_registered_destination_hash(destination_hash),
         :ok <- validate_message_context(context) do
      key = {destination_hash, context}

      case :ets.lookup(table, key) do
        [{^key, _entry}] ->
          true = :ets.delete(table, key)
          :ok

        [] ->
          {:error, missing_reason}
      end
    end
  end

  defp fetch_message_handler(table, destination_hash, context) do
    with :ok <- validate_registered_destination_hash(destination_hash),
         :ok <- validate_message_context(context) do
      key = {destination_hash, context}

      case :ets.lookup(table, key) do
        [{^key, entry}] -> {:ok, entry}
        [] -> :error
      end
    end
  end

  defp validate_message_context(context) when is_integer(context) and context in 0..255, do: :ok
  defp validate_message_context(_context), do: {:error, :invalid_message_context}
end
