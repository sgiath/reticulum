defmodule Reticulum.Interface do
  @moduledoc """
  Stable adapter contract for Reticulum runtime interfaces.

  Adapters plug into the managed interface worker, which
  provides OTP supervision, queueing, backpressure, rate limiting, telemetry,
  and health reporting.
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

  @callback init(start_opts()) :: {:ok, adapter_state(), map()} | {:error, term()}

  @callback send_frame(iodata(), send_opts(), adapter_state()) ::
              {:ok, adapter_state(), endpoint()} | {:error, term(), adapter_state()}

  @callback prepare_outbound(binary(), send_opts(), adapter_state()) ::
              {:ok, frame_payload(), adapter_state()} | {:error, term(), adapter_state()}

  @callback normalize_inbound(binary(), adapter_state()) ::
              {:ok, frame_payload(), adapter_state()} | {:error, term(), adapter_state()}

  @callback handle_info(term(), adapter_state()) ::
              {:noreply, adapter_state()}
              | {:noreply, adapter_state(), [action()]}
              | {:stop, term(), adapter_state()}

  @callback health(adapter_state()) :: map()

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
