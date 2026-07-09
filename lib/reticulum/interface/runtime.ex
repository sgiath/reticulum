defmodule Reticulum.Interface.Runtime do
  @moduledoc false
  use GenServer

  alias Reticulum.Interface.Health
  alias Reticulum.Interface.Options
  alias Reticulum.Interface.RateLimiter
  alias Reticulum.Interface.Stats
  alias Reticulum.Node.State
  alias Reticulum.Observability

  @type state :: %{
          adapter: module(),
          adapter_state: term(),
          backpressure: :reject | :drop_newest | :drop_oldest,
          drain_timer: reference() | nil,
          meta: map(),
          name: atom(),
          node_name: atom(),
          queue: :queue.queue({binary(), keyword()}),
          queue_depth: non_neg_integer(),
          queue_limit: pos_integer(),
          rate_limiter: RateLimiter.t(),
          state_server: GenServer.server(),
          stats: Stats.t()
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

  @doc """
  Enqueues `payload` for transmission on the managed interface.

  Replies as soon as the frame is accepted into the outbound queue (or dropped
  by the configured backpressure strategy) so callers are never blocked on the
  rate limiter or the adapter. Returns `{:error, :interface_backpressure}` only
  for the `:reject` strategy on a full queue; delivery failures after
  acceptance surface through telemetry, stats, and health scoring.
  """
  def send_frame(server, payload, opts \\ []) when is_list(opts) do
    GenServer.call(server, {:send_frame, IO.iodata_to_binary(payload), opts})
  end

  def prepare_outbound(server, payload, opts \\ []) when is_binary(payload) and is_list(opts) do
    GenServer.call(server, {:prepare_outbound, payload, opts})
  end

  def normalize_inbound(server, payload) when is_binary(payload) do
    GenServer.call(server, {:normalize_inbound, payload})
  end

  @impl true
  def init(opts) do
    with {:ok, validated} <- Options.validate(opts),
         {:ok, adapter_state, adapter_meta} <- validated.adapter.init(opts) do
      state = %{
        adapter: validated.adapter,
        adapter_state: adapter_state,
        backpressure: validated.backpressure,
        drain_timer: nil,
        meta: build_meta(adapter_meta, validated.queue_limit, validated.backpressure, opts),
        name: validated.name,
        node_name: validated.node_name,
        queue: :queue.new(),
        queue_depth: 0,
        queue_limit: validated.queue_limit,
        rate_limiter: RateLimiter.new(opts),
        state_server: validated.state_server,
        stats: Stats.new()
      }

      case State.register_interface(
             state.state_server,
             state.name,
             self(),
             state.adapter,
             state.meta
           ) do
        :ok ->
          {:ok, sync_interface_record(state, nil)}

        {:error, reason} ->
          terminate_adapter(state.adapter, reason, adapter_state)
          {:stop, reason}
      end
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:send_frame, payload, opts}, _from, state) do
    case enqueue_frame(state, payload, opts) do
      {:enqueued, state} -> {:reply, :ok, state, {:continue, :drain_queue}}
      {:rejected, state} -> {:reply, {:error, :interface_backpressure}, state}
      {:dropped, state} -> {:reply, :ok, state}
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
  def handle_continue(:drain_queue, state) do
    {:noreply, drain_queue(state)}
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

  defp enqueue_frame(state, payload, opts) when state.queue_depth < state.queue_limit do
    previous_health = interface_health(state)

    state = %{
      state
      | queue: :queue.in({payload, opts}, state.queue),
        queue_depth: state.queue_depth + 1
    }

    state =
      state
      |> emit_queue_event()
      |> sync_interface_record(previous_health)

    {:enqueued, state}
  end

  defp enqueue_frame(%{backpressure: :reject} = state, payload, _opts) do
    {:rejected, record_drop(state, payload, :reject)}
  end

  defp enqueue_frame(%{backpressure: :drop_newest} = state, payload, _opts) do
    {:dropped, record_drop(state, payload, :drop_newest)}
  end

  defp enqueue_frame(%{backpressure: :drop_oldest} = state, payload, opts) do
    {{:value, {dropped_payload, _dropped_opts}}, queue} = :queue.out(state.queue)

    state =
      %{state | queue: queue, queue_depth: max(state.queue_depth - 1, 0)}
      |> record_drop(dropped_payload, :drop_oldest)

    enqueue_frame(state, payload, opts)
  end

  defp drain_queue(state) do
    case :queue.out(state.queue) do
      {:empty, _queue} ->
        sync_interface_record(state)

      {{:value, {payload, opts}}, queue} ->
        packet_size = byte_size(payload)

        case RateLimiter.allow?(state.rate_limiter, packet_size) do
          {:allow, rate_limiter} ->
            send_queued_frame(state, payload, opts, queue, rate_limiter)

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

  defp send_queued_frame(state, payload, opts, queue, rate_limiter) do
    previous_health = interface_health(state)

    state = %{
      state
      | queue: queue,
        queue_depth: max(state.queue_depth - 1, 0),
        rate_limiter: rate_limiter
    }

    case state.adapter.send_frame(payload, opts, state.adapter_state) do
      {:ok, adapter_state, endpoint} ->
        state
        |> Map.put(:adapter_state, adapter_state)
        |> publish_outbound(payload, endpoint)
        |> record_send_success(byte_size(payload))
        |> emit_queue_event()
        |> sync_interface_record(previous_health)
        |> drain_queue()

      {:error, reason, adapter_state} ->
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

      action, acc ->
        Observability.emit(
          [:interface, :adapter, :unknown_action],
          %{count: 1},
          %{node: acc.node_name, interface: acc.name, module: acc.adapter, action: action},
          log_level: :warning
        )

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
    %{state | stats: Stats.record_receive(state.stats, payload_size)}
  end

  defp record_send_success(state, payload_size) do
    %{state | stats: Stats.record_send_success(state.stats, payload_size)}
  end

  defp record_send_error(state, reason) do
    Observability.emit(
      [:interface, :send, :error],
      %{count: 1},
      %{node: state.node_name, interface: state.name, module: state.adapter, reason: reason},
      log_level: :debug
    )

    %{state | stats: Stats.record_send_error(state.stats)}
  end

  defp record_throttle(state, wait_ms) do
    Observability.emit(
      [:interface, :send, :throttled],
      %{count: 1, wait_ms: wait_ms, queue_depth: state.queue_depth},
      %{node: state.node_name, interface: state.name, module: state.adapter},
      log_level: :debug
    )

    %{state | stats: Stats.record_throttle(state.stats)}
  end

  defp record_drop(state, payload, strategy) do
    payload_size = byte_size(payload)

    Observability.emit(
      [:interface, :queue, :dropped],
      %{count: 1, bytes: payload_size, queue_depth: state.queue_depth},
      %{node: state.node_name, interface: state.name, module: state.adapter, strategy: strategy},
      log_level: :debug
    )

    sync_interface_record(%{state | stats: Stats.record_drop(state.stats, payload_size)})
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

  defp terminate_adapter(adapter, reason, adapter_state) do
    if function_exported?(adapter, :terminate, 2) do
      _ = adapter.terminate(reason, adapter_state)
    end

    :ok
  end
end
