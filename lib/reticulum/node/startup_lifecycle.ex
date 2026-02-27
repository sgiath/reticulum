defmodule Reticulum.Node.StartupLifecycle do
  @moduledoc """
  Startup lifecycle callback contract for `Reticulum.Node`.

  Startup callbacks run after node runtime services are started and ownership
  semantics are applied.

  - `cold_start/2` runs when `startup_mode: :cold`
  - `warm_restore/2` runs when `startup_mode: :warm_restore`

  Both callbacks receive the validated node config and node supervisor PID.
  """

  alias Reticulum.Node.Config

  @typedoc "Supported startup mode"
  @type mode :: :cold | :warm_restore

  @typedoc "Startup lifecycle callback return"
  @type callback_result :: :ok | {:error, term()}

  @callback cold_start(Config.t(), pid()) :: callback_result()
  @callback warm_restore(Config.t(), pid()) :: callback_result()

  @doc "Runs startup lifecycle callback for selected mode."
  @spec run(module(), mode(), Config.t(), pid()) :: callback_result()
  def run(module, mode, %Config{} = config, node_pid)
      when is_atom(module) and mode in [:cold, :warm_restore] and is_pid(node_pid) do
    callback = callback_for_mode(mode)

    try do
      case apply(module, callback, [config, node_pid]) do
        :ok -> :ok
        {:error, _reason} = error -> error
        other -> {:error, {:invalid_startup_lifecycle_result, other}}
      end
    rescue
      error -> {:error, {:startup_lifecycle_crashed, error}}
    catch
      kind, reason -> {:error, {:startup_lifecycle_crashed, {kind, reason}}}
    end
  end

  defp callback_for_mode(:cold), do: :cold_start
  defp callback_for_mode(:warm_restore), do: :warm_restore
end

defmodule Reticulum.Node.StartupLifecycle.Default do
  @moduledoc """
  Default startup lifecycle implementation.

  This implementation is intentionally a no-op for both startup modes.
  """

  @behaviour Reticulum.Node.StartupLifecycle

  @impl true
  def cold_start(_config, _node_pid), do: :ok

  @impl true
  def warm_restore(_config, _node_pid), do: :ok
end
