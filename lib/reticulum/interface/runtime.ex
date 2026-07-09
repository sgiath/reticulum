defmodule Reticulum.Interface.Runtime do
  @moduledoc false
  use GenServer

  alias Reticulum.Interface
  alias Reticulum.Interface.Health
  alias Reticulum.Interface.RateLimiter
  alias Reticulum.Node.State
  alias Reticulum.Observability

  @type stats :: %{
          tx_frames: non_neg_integer(),
          tx_bytes: non_neg_integer(),
          rx_frames: non_neg_integer(),
          rx_bytes: non_neg_integer(),
          dropped_frames: non_neg_integer(),
          dropped_bytes: non_neg_integer(),
          send_errors: non_neg_integer(),
          consecutive_send_errors: non_neg_integer(),
          throttled_count: non_neg_integer(),
          last_tx_at: integer() | nil,
          last_rx_at: integer() | nil,
          last_send_error_at: integer() | nil,
          last_throttle_at: integer() | nil
        }

  @type state :: %{
          adapter: module(),
          adapter_state: term(),
          backpressure: :reject | :drop_newest | :drop_oldest,
          drain_timer: reference() | nil,
          meta: map(),
          name: atom(),
          node_name: atom(),
          queue: :queue.queue({GenServer.from(), binary(), keyword()}),
          queue_depth: non_neg_integer(),
          queue_limit: pos_integer(),
          rate_limiter: RateLimiter.t(),
          state_server: GenServer.server(),
          stats: stats()
        }

  def child_spec(opts) do
    node_name = Keyword.fetch!(opts, :node_name)
    name = Keyword.fetch!(opts, :name)

    %{
      id: {__MODULE__, node_name, name},
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  def start_link(opts) when is_list(opts), do: GenServer.start_link(__MODULE__, opts)

  def send_frame(server, payload, opts \\ []) when is_list(opts) do
    GenServer.call(server, {:send_frame, IO.iodata_to_binary(payload), opts}, :infinity)
  end

  def prepare_outbound(server, payload, opts \\ []) when is_binary(payload) and is_list(opts) do
    GenServer.call(server, {:prepare_outbound, payload, opts})
  end

  def normalize_inbound(server, payload) when is_binary(payload) do
    GenServer.call(server, {:normalize_inbound, payload})
  end

  @impl true
  def init(opts) do
    with {:ok, adapter} <- validate_adapter(Keyword.get(opts, :adapter)),
         {:ok, name} <- validate_name(Keyword.get(opts, :name)),
         {:ok, node_name} <- validate_node_name(Keyword.get(opts, :node_name)),
         {:ok, state_server} <- validate_state_server(Keyword.get(opts, :state_server)),
         {:ok, queue_limit} <- validate_queue_limit(Keyword.get(opts, :queue_limit, 64)),
         {:ok, backpressure} <- validate_backpressure(Keyword.get(opts, :backpressure, :reject)),
         :ok <- validate_rate_limit_opts(opts),
         {:ok, adapter_state, adapter_meta} <- adapter.init(opts) do
      state = %{
        adapter: adapter,
        adapter_state: adapter_state,
        backpressure: backpressure,
        drain_timer: nil,
        meta: build_meta(adapter_meta, queue_limit, backpressure, opts),
        name: name,
        node_name: node_name,
        queue: :queue.new(),
        queue_depth: 0,
        queue_limit: queue_limit,
        rate_limiter: RateLimiter.new(opts),
        state_server: state_server,
        stats: initial_stats()
      }

      case State.register_interface(state_server, name, self(), adapter, state.meta) do
        :ok ->
          state = sync_interface_record(state, nil)
          {:ok, state}

        {:error, reason} ->
          terminate_adapter(adapter, reason, adapter_state)
          {:stop, reason}
      end
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:send_frame, payload, opts}, from, state) do
    case enqueue_frame(state, from, payload, opts) do
      {:reply, reply, state} -> {:reply, reply, state}
      {:drain, state} -> {:noreply, drain_queue(state)}
    end
  end

  def handle_call({:prepare_outbound, payload, opts}, _from, state) do
    case state.adapter.prepare_outbound(payload, opts, state.adapter_state) do
      {:ok, frame_payload, adapter_state} ->
        {:reply, {:ok, frame_payload}, %{state | adapter_state: adapter_state}}

      {:error, reason, adapter_state} ->
        {:reply, {:error, reason}, %{state | adapter_state: adapter_state}}
    end
  end

  def handle_call({:normalize_inbound, payload}, _from, state) do
    case state.adapter.normalize_inbound(payload, state.adapter_state) do
      {:ok, frame_payload, adapter_state} ->
        {:reply, {:ok, frame_payload}, %{state | adapter_state: adapter_state}}

      {:error, reason, adapter_state} ->
        {:reply, {:error, reason}, %{state | adapter_state: adapter_state}}
    end
  end

  @impl true
  def handle_info(:drain_queue, state) do
    {:noreply, drain_queue(%{state | drain_timer: nil})}
  end

  def handle_info(message, state) do
    if function_exported?(state.adapter, :handle_info, 2) do
      case state.adapter.handle_info(message, state.adapter_state) do
        {:noreply, adapter_state} ->
          {:noreply, sync_interface_record(%{state | adapter_state: adapter_state})}

        {:noreply, adapter_state, actions} ->
          state = %{state | adapter_state: adapter_state}

          state =
            state
            |> apply_actions(actions)
            |> sync_interface_record()

          {:noreply, state}

        {:stop, reason, adapter_state} ->
          {:stop, reason, %{state | adapter_state: adapter_state}}
      end
    else
      {:noreply, state}
    end
  end

  @impl true
  def terminate(reason, state) do
    _ = State.unregister_interface(state.state_server, state.name)
    terminate_adapter(state.adapter, reason, state.adapter_state)
    :ok
  end

  defp enqueue_frame(state, from, payload, opts) when state.queue_depth < state.queue_limit do
    previous_health = interface_health(state)

    state = %{
      state
      | queue: :queue.in({from, payload, opts}, state.queue),
        queue_depth: state.queue_depth + 1
    }

    state =
      state
      |> emit_queue_event()
      |> sync_interface_record(previous_health)

    {:drain, state}
  end

  defp enqueue_frame(%{backpressure: :reject} = state, _from, payload, _opts) do
    state = record_drop(state, payload, :reject)
    {:reply, {:error, :interface_backpressure}, state}
  end

  defp enqueue_frame(%{backpressure: :drop_newest} = state, _from, payload, _opts) do
    state = record_drop(state, payload, :drop_newest)
    {:reply, {:error, :interface_backpressure}, state}
  end

  defp enqueue_frame(%{backpressure: :drop_oldest} = state, from, payload, opts) do
    {{:value, {dropped_from, dropped_payload, _dropped_opts}}, queue} = :queue.out(state.queue)
    GenServer.reply(dropped_from, {:error, :interface_backpressure})

    state =
      %{state | queue: queue, queue_depth: max(state.queue_depth - 1, 0)}
      |> record_drop(dropped_payload, :drop_oldest)

    enqueue_frame(state, from, payload, opts)
  end

  defp drain_queue(state) do
    case :queue.out(state.queue) do
      {:empty, _queue} ->
        sync_interface_record(state)

      {{:value, {from, payload, opts}}, queue} ->
        packet_size = byte_size(payload)

        case RateLimiter.allow?(state.rate_limiter, packet_size) do
          {:allow, rate_limiter} ->
            send_queued_frame(state, from, payload, opts, queue, rate_limiter)

          {:delay, wait_ms, rate_limiter} ->
            state
            |> Map.put(:rate_limiter, rate_limiter)
            |> record_throttle(wait_ms)
            |> maybe_schedule_drain(wait_ms)
            |> emit_queue_event()
            |> sync_interface_record()
        end
    end
  end

  defp send_queued_frame(state, from, payload, opts, queue, rate_limiter) do
    previous_health = interface_health(state)

    state = %{
      state
      | queue: queue,
        queue_depth: max(state.queue_depth - 1, 0),
        rate_limiter: rate_limiter
    }

    case state.adapter.send_frame(payload, opts, state.adapter_state) do
      {:ok, adapter_state, endpoint} ->
        GenServer.reply(from, :ok)

        state
        |> Map.put(:adapter_state, adapter_state)
        |> publish_outbound(payload, endpoint)
        |> record_send_success(byte_size(payload))
        |> emit_queue_event()
        |> sync_interface_record(previous_health)
        |> drain_queue()

      {:error, reason, adapter_state} ->
        GenServer.reply(from, {:error, reason})

        state
        |> Map.put(:adapter_state, adapter_state)
        |> record_send_error(reason)
        |> emit_queue_event()
        |> sync_interface_record(previous_health)
        |> drain_queue()
    end
  end

  defp maybe_schedule_drain(%{drain_timer: nil} = state, wait_ms) do
    %{state | drain_timer: Process.send_after(self(), :drain_queue, wait_ms)}
  end

  defp maybe_schedule_drain(state, _wait_ms), do: state

  defp apply_actions(state, actions) do
    Enum.reduce(actions, state, fn
      {:inbound_frame, payload, endpoint}, acc ->
        State.publish_frame(acc.state_server, %{
          direction: :inbound,
          interface: acc.name,
          payload: payload,
          endpoint: endpoint,
          at: System.system_time(:millisecond),
          node: acc.node_name
        })

        record_receive(acc, byte_size(payload))

      _action, acc ->
        acc
    end)
  end

  defp publish_outbound(state, payload, endpoint) do
    State.publish_frame(state.state_server, %{
      direction: :outbound,
      interface: state.name,
      payload: payload,
      endpoint: endpoint,
      at: System.system_time(:millisecond),
      node: state.node_name
    })

    state
  end

  defp record_receive(state, payload_size) do
    now = System.system_time(:millisecond)

    %{
      state
      | stats: %{
          state.stats
          | rx_frames: state.stats.rx_frames + 1,
            rx_bytes: state.stats.rx_bytes + payload_size,
            last_rx_at: now
        }
    }
  end

  defp record_send_success(state, payload_size) do
    now = System.system_time(:millisecond)

    %{
      state
      | stats: %{
          state.stats
          | tx_frames: state.stats.tx_frames + 1,
            tx_bytes: state.stats.tx_bytes + payload_size,
            last_tx_at: now,
            consecutive_send_errors: 0
        }
    }
  end

  defp record_send_error(state, reason) do
    Observability.emit(
      [:interface, :send, :error],
      %{count: 1},
      %{node: state.node_name, interface: state.name, module: state.adapter, reason: reason},
      log_level: :debug
    )

    %{
      state
      | stats: %{
          state.stats
          | send_errors: state.stats.send_errors + 1,
            consecutive_send_errors: state.stats.consecutive_send_errors + 1,
            last_send_error_at: System.system_time(:millisecond)
        }
    }
  end

  defp record_throttle(state, wait_ms) do
    Observability.emit(
      [:interface, :send, :throttled],
      %{count: 1, wait_ms: wait_ms, queue_depth: state.queue_depth},
      %{node: state.node_name, interface: state.name, module: state.adapter},
      log_level: :debug
    )

    %{
      state
      | stats: %{
          state.stats
          | throttled_count: state.stats.throttled_count + 1,
            last_throttle_at: System.monotonic_time(:millisecond)
        }
    }
  end

  defp record_drop(state, payload, strategy) do
    payload_size = byte_size(payload)

    Observability.emit(
      [:interface, :queue, :dropped],
      %{count: 1, bytes: payload_size, queue_depth: state.queue_depth},
      %{node: state.node_name, interface: state.name, module: state.adapter, strategy: strategy},
      log_level: :debug
    )

    state = %{
      state
      | stats: %{
          state.stats
          | dropped_frames: state.stats.dropped_frames + 1,
            dropped_bytes: state.stats.dropped_bytes + payload_size
        }
    }

    sync_interface_record(state)
  end

  defp emit_queue_event(state) do
    Observability.emit(
      [:interface, :queue, :updated],
      %{queue_depth: state.queue_depth, queue_limit: state.queue_limit},
      %{node: state.node_name, interface: state.name, module: state.adapter},
      log_level: :debug
    )

    state
  end

  defp sync_interface_record(state, previous_health \\ nil) do
    health = interface_health(state)

    _ =
      State.update_interface(state.state_server, state.name, %{
        meta: state.meta,
        stats: Map.put(state.stats, :queue_depth, state.queue_depth),
        health: health
      })

    emit_health_event(previous_health, health, state)
    state
  end

  defp interface_health(state) do
    adapter_health = state.adapter.health(state.adapter_state)

    Health.score(%{
      available: Process.alive?(self()),
      adapter_status: Map.get(adapter_health, :adapter_status, :up),
      queue_depth: state.queue_depth,
      queue_limit: state.queue_limit,
      backpressure: state.backpressure,
      consecutive_send_errors: state.stats.consecutive_send_errors,
      last_throttle_at: state.stats.last_throttle_at
    })
  end

  defp emit_health_event(previous_health, next_health, state) do
    if previous_health != next_health do
      Observability.emit(
        [:interface, :health, :updated],
        %{score: next_health.score, queue_depth: next_health.queue_depth},
        %{
          node: state.node_name,
          interface: state.name,
          module: state.adapter,
          band: next_health.band,
          adapter_status: next_health.adapter_status
        },
        log_level: :debug
      )
    end

    state
  end

  defp build_meta(adapter_meta, queue_limit, backpressure, opts) when is_map(adapter_meta) do
    rate_limit_meta =
      opts
      |> RateLimiter.new()
      |> RateLimiter.summary()

    Map.merge(adapter_meta, %{
      queue_limit: queue_limit,
      backpressure: backpressure
    })
    |> Map.merge(rate_limit_meta)
  end

  defp build_meta(_adapter_meta, queue_limit, backpressure, opts) do
    build_meta(%{}, queue_limit, backpressure, opts)
  end

  defp initial_stats do
    %{
      tx_frames: 0,
      tx_bytes: 0,
      rx_frames: 0,
      rx_bytes: 0,
      dropped_frames: 0,
      dropped_bytes: 0,
      send_errors: 0,
      consecutive_send_errors: 0,
      throttled_count: 0,
      last_tx_at: nil,
      last_rx_at: nil,
      last_send_error_at: nil,
      last_throttle_at: nil
    }
  end

  defp terminate_adapter(adapter, reason, adapter_state) do
    if function_exported?(adapter, :terminate, 2) do
      _ = adapter.terminate(reason, adapter_state)
    end

    :ok
  end

  defp validate_adapter(adapter) do
    if Interface.adapter?(adapter), do: {:ok, adapter}, else: {:error, :invalid_interface_adapter}
  end

  defp validate_name(name) when is_atom(name), do: {:ok, name}
  defp validate_name(_name), do: {:error, :invalid_interface_name}

  defp validate_node_name(node_name) when is_atom(node_name), do: {:ok, node_name}
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

  defp validate_backpressure(mode) when mode in [:reject, :drop_newest, :drop_oldest],
    do: {:ok, mode}

  defp validate_backpressure(_mode), do: {:error, :invalid_interface_backpressure}

  defp validate_rate_limit_opts(opts) do
    with :ok <-
           validate_optional_positive_integer(
             Keyword.get(opts, :rate_limit_bytes_per_second),
             :invalid_interface_rate_limit_bytes_per_second
           ),
         :ok <-
           validate_optional_positive_integer(
             Keyword.get(opts, :rate_limit_packets_per_second),
             :invalid_interface_rate_limit_packets_per_second
           ),
         :ok <-
           validate_optional_positive_integer(
             Keyword.get(opts, :rate_limit_burst_bytes),
             :invalid_interface_rate_limit_burst_bytes
           ) do
      validate_optional_positive_integer(
        Keyword.get(opts, :rate_limit_burst_packets),
        :invalid_interface_rate_limit_burst_packets
      )
    end
  end

  defp validate_optional_positive_integer(nil, _error), do: :ok

  defp validate_optional_positive_integer(value, _error) when is_integer(value) and value > 0,
    do: :ok

  defp validate_optional_positive_integer(_value, error), do: {:error, error}
end
