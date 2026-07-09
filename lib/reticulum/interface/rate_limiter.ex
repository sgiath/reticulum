defmodule Reticulum.Interface.RateLimiter do
  @moduledoc false

  @type t :: %{
          bytes_per_second: pos_integer() | nil,
          packets_per_second: pos_integer() | nil,
          burst_bytes: pos_integer() | nil,
          burst_packets: pos_integer() | nil,
          available_bytes: float() | nil,
          available_packets: float() | nil,
          last_refill_at: integer()
        }

  def new(opts) when is_list(opts) do
    now = System.monotonic_time(:millisecond)
    bytes_per_second = Keyword.get(opts, :rate_limit_bytes_per_second)
    packets_per_second = Keyword.get(opts, :rate_limit_packets_per_second)
    burst_bytes = Keyword.get(opts, :rate_limit_burst_bytes, bytes_per_second)
    burst_packets = Keyword.get(opts, :rate_limit_burst_packets, packets_per_second)

    %{
      bytes_per_second: bytes_per_second,
      packets_per_second: packets_per_second,
      burst_bytes: burst_bytes,
      burst_packets: burst_packets,
      available_bytes: initial_tokens(bytes_per_second, burst_bytes),
      available_packets: initial_tokens(packets_per_second, burst_packets),
      last_refill_at: now
    }
  end

  def summary(%{} = limiter) do
    %{
      rate_limit_bytes_per_second: limiter.bytes_per_second,
      rate_limit_packets_per_second: limiter.packets_per_second,
      rate_limit_burst_bytes: limiter.burst_bytes,
      rate_limit_burst_packets: limiter.burst_packets
    }
  end

  def allow?(%{} = limiter, packet_size) when is_integer(packet_size) and packet_size >= 0 do
    now = System.monotonic_time(:millisecond)
    limiter = refill(limiter, now)

    case wait_time_ms(limiter, packet_size) do
      0 -> {:allow, consume(limiter, packet_size)}
      wait_ms -> {:delay, wait_ms, limiter}
    end
  end

  defp initial_tokens(nil, _burst), do: nil
  defp initial_tokens(_rate, nil), do: nil
  defp initial_tokens(_rate, burst), do: burst * 1.0

  defp refill(limiter, now) do
    elapsed_seconds = max(now - limiter.last_refill_at, 0) / 1_000

    %{
      limiter
      | available_bytes:
          refill_dimension(
            limiter.available_bytes,
            limiter.bytes_per_second,
            limiter.burst_bytes,
            elapsed_seconds
          ),
        available_packets:
          refill_dimension(
            limiter.available_packets,
            limiter.packets_per_second,
            limiter.burst_packets,
            elapsed_seconds
          ),
        last_refill_at: now
    }
  end

  defp refill_dimension(nil, _rate, _burst, _elapsed), do: nil
  defp refill_dimension(tokens, _rate, nil, _elapsed), do: tokens
  defp refill_dimension(tokens, nil, _burst, _elapsed), do: tokens

  defp refill_dimension(tokens, rate, burst, elapsed_seconds) do
    min(tokens + rate * elapsed_seconds, burst * 1.0)
  end

  defp wait_time_ms(limiter, packet_size) do
    [
      dimension_wait_ms(limiter.available_packets, limiter.packets_per_second, 1),
      dimension_wait_ms(limiter.available_bytes, limiter.bytes_per_second, packet_size)
    ]
    |> Enum.max()
  end

  defp dimension_wait_ms(nil, _rate, _required), do: 0
  defp dimension_wait_ms(_tokens, nil, _required), do: 0

  defp dimension_wait_ms(tokens, rate, required) do
    deficit = required - tokens

    if deficit <= 0 do
      0
    else
      deficit
      |> Kernel./(rate)
      |> Kernel.*(1_000)
      |> Float.ceil()
      |> trunc()
      |> max(1)
    end
  end

  defp consume(limiter, packet_size) do
    %{
      limiter
      | available_packets: consume_dimension(limiter.available_packets, 1),
        available_bytes: consume_dimension(limiter.available_bytes, packet_size)
    }
  end

  defp consume_dimension(nil, _required), do: nil
  defp consume_dimension(tokens, required), do: max(tokens - required, 0.0)
end
