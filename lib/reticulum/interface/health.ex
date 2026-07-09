defmodule Reticulum.Interface.Health do
  @moduledoc false

  @recent_throttle_window_ms 5_000

  def score(snapshot) when is_map(snapshot) do
    available = Map.get(snapshot, :available, true)
    adapter_status = Map.get(snapshot, :adapter_status, :up)

    if not available or adapter_status == :down do
      %{
        score: 0,
        band: :unavailable,
        available: false,
        adapter_status: adapter_status,
        queue_depth: Map.get(snapshot, :queue_depth, 0),
        queue_limit: Map.get(snapshot, :queue_limit, 1),
        backpressure: Map.get(snapshot, :backpressure, :reject),
        rate_limited: recent?(Map.get(snapshot, :last_throttle_at))
      }
    else
      queue_depth = max(Map.get(snapshot, :queue_depth, 0), 0)
      queue_limit = max(Map.get(snapshot, :queue_limit, 1), 1)
      queue_ratio = min(queue_depth / queue_limit, 1.0)
      queue_penalty = round(queue_ratio * 45)
      throttle_penalty = if recent?(Map.get(snapshot, :last_throttle_at)), do: 15, else: 0

      error_penalty =
        snapshot
        |> Map.get(:consecutive_send_errors, 0)
        |> max(0)
        |> Kernel.*(12)
        |> min(36)

      status_penalty = if adapter_status == :degraded, do: 20, else: 0

      score =
        max(0, 100 - queue_penalty - throttle_penalty - error_penalty - status_penalty)
        |> maybe_cap_degraded_score(adapter_status)

      %{
        score: score,
        band: band(score),
        available: true,
        adapter_status: adapter_status,
        queue_depth: queue_depth,
        queue_limit: queue_limit,
        backpressure: Map.get(snapshot, :backpressure, :reject),
        rate_limited: recent?(Map.get(snapshot, :last_throttle_at))
      }
    end
  end

  defp band(0), do: :unavailable
  defp band(score) when score < 60, do: :degraded
  defp band(_score), do: :healthy

  defp maybe_cap_degraded_score(score, :degraded), do: min(score, 55)
  defp maybe_cap_degraded_score(score, _adapter_status), do: score

  defp recent?(nil), do: false

  defp recent?(timestamp_ms) when is_integer(timestamp_ms) do
    System.monotonic_time(:millisecond) - timestamp_ms <= @recent_throttle_window_ms
  end

  defp recent?(_timestamp_ms), do: false
end
