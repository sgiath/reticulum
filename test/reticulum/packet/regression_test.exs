defmodule Reticulum.PacketRegressionTest do
  use ExUnit.Case, async: true

  describe "Reticulum.Packet" do
    test "accepts integer context when encoding" do
      address = <<0::128>>

      packet = %Reticulum.Packet{
        ifac: :open,
        propagation: :broadcast,
        destination: :single,
        type: :data,
        hops: 1,
        addresses: [address],
        context: 1,
        data: <<2, 3>>
      }

      encoded = Reticulum.Packet.encode(packet)
      decoded = Reticulum.Packet.decode(encoded)

      assert decoded.context == <<1>>
      assert decoded.addresses == [address]
      assert decoded.data == <<2, 3>>
    end

    test "rejects address lists outside wire format" do
      base_packet = %Reticulum.Packet{
        ifac: :open,
        propagation: :broadcast,
        destination: :single,
        type: :data,
        hops: 1,
        context: <<0>>,
        data: <<>>
      }

      assert_raise FunctionClauseError, fn ->
        Reticulum.Packet.encode(%{base_packet | addresses: []})
      end

      address = <<0::128>>

      assert_raise FunctionClauseError, fn ->
        Reticulum.Packet.encode(%{base_packet | addresses: [address, address, address]})
      end
    end
  end
end
