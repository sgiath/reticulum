defmodule Reticulum.PacketReceipt do
  @moduledoc """
  Outbound packet delivery receipt tracking.

  A receipt starts in `:sent` and transitions to either:

  - `:delivered` when a valid proof arrives
  - `:failed` when timeout is reached before proof validation
  """

  @enforce_keys [:packet_hash, :destination_hash, :sent_at, :status, :timeout_seconds]
  defstruct [
    :packet_hash,
    :destination_hash,
    :sent_at,
    :status,
    :timeout_seconds,
    :concluded_at,
    :proof_packet_hash
  ]

  @type status :: :sent | :delivered | :failed

  @type t :: %__MODULE__{
          packet_hash: binary(),
          destination_hash: binary(),
          sent_at: integer(),
          status: status(),
          timeout_seconds: pos_integer(),
          concluded_at: integer() | nil,
          proof_packet_hash: binary() | nil
        }

  def new(
        packet_hash,
        destination_hash,
        timeout_seconds,
        now_seconds \\ System.system_time(:second)
      )
      when is_binary(packet_hash) and is_binary(destination_hash) and is_integer(timeout_seconds) and
             timeout_seconds > 0 and is_integer(now_seconds) do
    %__MODULE__{
      packet_hash: packet_hash,
      destination_hash: destination_hash,
      sent_at: now_seconds,
      status: :sent,
      timeout_seconds: timeout_seconds,
      concluded_at: nil,
      proof_packet_hash: nil
    }
  end

  def delivered(%__MODULE__{} = receipt, proof_packet_hash \\ nil) do
    %{
      receipt
      | status: :delivered,
        concluded_at: System.system_time(:second),
        proof_packet_hash: proof_packet_hash
    }
  end

  def failed(%__MODULE__{} = receipt) do
    %{receipt | status: :failed, concluded_at: System.system_time(:second)}
  end

  def timed_out?(receipt, now_seconds \\ System.system_time(:second))

  def timed_out?(%__MODULE__{status: :sent} = receipt, now_seconds)
      when is_integer(now_seconds) do
    now_seconds - receipt.sent_at >= receipt.timeout_seconds
  end

  def timed_out?(%__MODULE__{}, _now_seconds), do: false

  def concluded?(%__MODULE__{status: status}) when status in [:delivered, :failed], do: true
  def concluded?(%__MODULE__{}), do: false
end
