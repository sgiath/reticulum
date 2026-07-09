defmodule Reticulum.Interface.Stats do
  @moduledoc false

  @type t :: %{
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

  @spec new() :: t()
  def new do
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

  @spec record_receive(t(), non_neg_integer()) :: t()
  def record_receive(stats, payload_size) do
    %{
      stats
      | rx_frames: stats.rx_frames + 1,
        rx_bytes: stats.rx_bytes + payload_size,
        last_rx_at: System.system_time(:millisecond)
    }
  end

  @spec record_send_success(t(), non_neg_integer()) :: t()
  def record_send_success(stats, payload_size) do
    %{
      stats
      | tx_frames: stats.tx_frames + 1,
        tx_bytes: stats.tx_bytes + payload_size,
        last_tx_at: System.system_time(:millisecond),
        consecutive_send_errors: 0
    }
  end

  @spec record_send_error(t()) :: t()
  def record_send_error(stats) do
    %{
      stats
      | send_errors: stats.send_errors + 1,
        consecutive_send_errors: stats.consecutive_send_errors + 1,
        last_send_error_at: System.system_time(:millisecond)
    }
  end

  @spec record_throttle(t()) :: t()
  def record_throttle(stats) do
    %{
      stats
      | throttled_count: stats.throttled_count + 1,
        last_throttle_at: System.monotonic_time(:millisecond)
    }
  end

  @spec record_drop(t(), non_neg_integer()) :: t()
  def record_drop(stats, payload_size) do
    %{
      stats
      | dropped_frames: stats.dropped_frames + 1,
        dropped_bytes: stats.dropped_bytes + payload_size
    }
  end
end
