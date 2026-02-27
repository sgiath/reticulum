defmodule Reticulum.Observability do
  @moduledoc """
  Runtime observability hooks for Reticulum events.

  - Emits telemetry events when `:telemetry` is available.
  - Optionally logs structured event data via `Logger`.
  """

  require Logger

  @doc "Emits an observability event."
  def emit(event, measurements \\ %{}, metadata \\ %{}, opts \\ [])

  def emit(event, measurements, metadata, opts)
      when is_list(event) and is_map(measurements) and is_map(metadata) and is_list(opts) do
    event_name = [:reticulum | event]

    emit_telemetry(event_name, measurements, metadata)
    maybe_log(event_name, measurements, metadata, opts)
    :ok
  end

  defp emit_telemetry(event_name, measurements, metadata) do
    if function_exported?(:telemetry, :execute, 3) do
      apply(:telemetry, :execute, [event_name, measurements, metadata])
    end

    :ok
  rescue
    _ -> :ok
  end

  defp maybe_log(event_name, measurements, metadata, opts) do
    case Keyword.get(opts, :log_level, nil) do
      nil ->
        :ok

      level ->
        Logger.log(level, fn ->
          "reticulum_event=#{Enum.map_join(event_name, ".", &to_string/1)} " <>
            "measurements=#{inspect(measurements)} metadata=#{inspect(metadata)}"
        end)
    end
  end
end
