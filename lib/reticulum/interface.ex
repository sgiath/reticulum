defmodule Reticulum.Interface do
  @moduledoc """
  Stable adapter contract for Reticulum runtime interfaces.

  Adapters plug into the managed interface worker
  (`Reticulum.Interface.Runtime`), which provides OTP supervision, queueing,
  backpressure, rate limiting, telemetry, and health reporting. An adapter only
  implements the transport-specific pieces: opening the medium, writing frames,
  wrapping/unwrapping frames (for example IFAC), and reporting its own status.

  ## Writing a custom adapter

      defmodule MyApp.SerialInterface do
        @behaviour Reticulum.Interface

        @impl true
        def init(opts), do: {:ok, open_port(opts), %{kind: :serial}}

        @impl true
        def send_frame(payload, _opts, state), do: {:ok, write(state, payload), nil}

        @impl true
        def prepare_outbound(payload, _opts, state),
          do: {:ok, %{payload: payload, ifac: :open}, state}

        @impl true
        def normalize_inbound(payload, state),
          do: {:ok, %{payload: payload, ifac: :open}, state}

        @impl true
        def handle_info({:data, payload}, state),
          do: {:noreply, state, [{:inbound_frame, payload, nil}]}

        @impl true
        def health(state), do: %{adapter_status: if(port_open?(state), do: :up, else: :down)}
      end

  Start it with `Reticulum.Node.start_interface(node_name, MyApp.SerialInterface, opts)`
  or from config with `module = "MyApp.SerialInterface"`.
  """

  @typedoc "Managed interface worker reference"
  @type server :: GenServer.server()

  @typedoc "Adapter start options"
  @type start_opts :: keyword()

  @typedoc "Send options"
  @type send_opts :: keyword()

  @typedoc "Normalized frame payload"
  @type frame_payload :: %{payload: binary(), ifac: :open | :auth}

  @typedoc "Adapter endpoint metadata"
  @type endpoint :: {tuple(), non_neg_integer()} | nil

  @typedoc "Adapter action emitted back to the managed runtime"
  @type action :: {:inbound_frame, binary(), endpoint()}

  @typedoc "Adapter-private state"
  @type adapter_state :: term()

  @typedoc """
  Adapter transport status, reported through `c:health/1`.

  - `:up` - fully operational
  - `:degraded` - usable but impaired; caps the interface health score
  - `:down` - unusable; marks the interface unavailable for route selection
  """
  @type adapter_status :: :up | :degraded | :down

  @doc """
  Opens the transport medium.

  Receives the full runtime option list. Returns the adapter state plus a
  metadata map that is published on the interface record (for example the bound
  address); the runtime merges in queue/backpressure/rate-limit metadata.
  """
  @callback init(start_opts()) :: {:ok, adapter_state(), map()} | {:error, term()}

  @doc """
  Writes one frame to the medium.

  Called by the runtime after queueing and rate limiting. Returns the endpoint
  the frame was sent to (or `nil` for point-to-point media). Errors are counted
  against the interface health score.
  """
  @callback send_frame(iodata(), send_opts(), adapter_state()) ::
              {:ok, adapter_state(), endpoint()} | {:error, term(), adapter_state()}

  @doc """
  Wraps a raw transport payload into the on-wire frame (for example IFAC
  masking) before transmission.
  """
  @callback prepare_outbound(binary(), send_opts(), adapter_state()) ::
              {:ok, frame_payload(), adapter_state()} | {:error, term(), adapter_state()}

  @doc """
  Unwraps an on-wire frame into a transport payload, reporting whether it was
  IFAC-authenticated.
  """
  @callback normalize_inbound(binary(), adapter_state()) ::
              {:ok, frame_payload(), adapter_state()} | {:error, term(), adapter_state()}

  @doc """
  Handles messages sent to the managed interface worker (socket data, port
  messages, timers). Emit `{:inbound_frame, payload, endpoint}` actions to
  publish received frames into the node.
  """
  @callback handle_info(term(), adapter_state()) ::
              {:noreply, adapter_state()}
              | {:noreply, adapter_state(), [action()]}
              | {:stop, term(), adapter_state()}

  @doc """
  Reports adapter transport status as `%{adapter_status: adapter_status()}`.

  The runtime combines this with queue pressure, throttling, and send failures
  into the interface health score used by route selection.
  """
  @callback health(adapter_state()) :: %{adapter_status: adapter_status()}

  @doc "Closes the transport medium on worker shutdown."
  @callback terminate(term(), adapter_state()) :: :ok

  @optional_callbacks handle_info: 2, terminate: 2

  @required_callbacks [
    init: 1,
    send_frame: 3,
    prepare_outbound: 3,
    normalize_inbound: 2,
    health: 1
  ]

  @doc "Returns true when `module` implements the stable interface adapter contract."
  def adapter?(module) when is_atom(module) do
    Code.ensure_loaded?(module) and
      Enum.all?(@required_callbacks, fn {name, arity} ->
        function_exported?(module, name, arity)
      end)
  end

  def adapter?(_module), do: false
end
