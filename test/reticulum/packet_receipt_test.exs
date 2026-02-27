defmodule Reticulum.PacketReceiptTest do
  use ExUnit.Case, async: true

  alias Reticulum.PacketReceipt

  test "new/4 initializes sent receipt" do
    packet_hash = :crypto.strong_rand_bytes(32)
    destination_hash = :crypto.strong_rand_bytes(16)

    receipt = PacketReceipt.new(packet_hash, destination_hash, 7, 1_000)

    assert receipt.packet_hash == packet_hash
    assert receipt.destination_hash == destination_hash
    assert receipt.timeout_seconds == 7
    assert receipt.sent_at == 1_000
    assert receipt.status == :sent
    assert receipt.concluded_at == nil
    assert receipt.proof_packet_hash == nil
    refute PacketReceipt.concluded?(receipt)
  end

  test "timed_out?/2 only returns true when pending receipt exceeded timeout" do
    packet_hash = :crypto.strong_rand_bytes(32)
    destination_hash = :crypto.strong_rand_bytes(16)
    receipt = PacketReceipt.new(packet_hash, destination_hash, 5, 100)

    refute PacketReceipt.timed_out?(receipt, 104)
    assert PacketReceipt.timed_out?(receipt, 105)
    assert PacketReceipt.timed_out?(receipt, 120)
  end

  test "delivered/2 concludes receipt and preserves proof packet hash" do
    packet_hash = :crypto.strong_rand_bytes(32)
    destination_hash = :crypto.strong_rand_bytes(16)
    receipt = PacketReceipt.new(packet_hash, destination_hash, 5, 100)

    proof_packet_hash = :crypto.strong_rand_bytes(16)

    delivered = PacketReceipt.delivered(receipt, proof_packet_hash)

    assert delivered.status == :delivered
    assert delivered.proof_packet_hash == proof_packet_hash
    assert is_integer(delivered.concluded_at)
    assert PacketReceipt.concluded?(delivered)
    refute PacketReceipt.timed_out?(delivered, 1_000)
  end

  test "failed/1 concludes receipt without proof hash" do
    packet_hash = :crypto.strong_rand_bytes(32)
    destination_hash = :crypto.strong_rand_bytes(16)
    receipt = PacketReceipt.new(packet_hash, destination_hash, 5, 100)

    failed = PacketReceipt.failed(receipt)

    assert failed.status == :failed
    assert failed.proof_packet_hash == nil
    assert is_integer(failed.concluded_at)
    assert PacketReceipt.concluded?(failed)
    refute PacketReceipt.timed_out?(failed, 1_000)
  end
end
