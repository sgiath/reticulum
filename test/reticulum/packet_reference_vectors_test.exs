defmodule Reticulum.PacketReferenceVectorsTest do
  use ExUnit.Case, async: true

  alias Reticulum.ReferenceRunner

  describe "packet wire-format vectors" do
    test "header_1 announce packet bytes match Python reference" do
      destination_hash = bin_range(1..16)
      data = <<0, 1, 2, 3, 255>>
      context = 58

      expected =
        ReferenceRunner.run!("packet_pack", [
          "0",
          "0",
          "0",
          "0",
          "1",
          "5",
          hex(destination_hash),
          Integer.to_string(context),
          hex(data),
          "-"
        ])
        |> dehex()

      packet = %Reticulum.Packet{
        ifac: :open,
        propagation: :broadcast,
        destination: :single,
        type: :announce,
        hops: 5,
        addresses: [destination_hash],
        context: context,
        data: data
      }

      assert Reticulum.Packet.encode(packet) == expected

      decoded = Reticulum.Packet.decode(expected)
      assert decoded.ifac == :open
      assert decoded.propagation == :broadcast
      assert decoded.destination == :single
      assert decoded.type == :announce
      assert decoded.hops == 5
      assert decoded.addresses == [destination_hash]
      assert decoded.context == <<context>>
      assert decoded.data == data

      assert_packet_hash_parity(expected)
    end

    test "header_2 announce packet bytes match Python reference" do
      transport_id = bin_range(33..48)
      destination_hash = bin_range(65..80)
      data = <<10, 20, 30, 40, 50, 60>>
      context = 17

      expected =
        ReferenceRunner.run!("packet_pack", [
          "1",
          "0",
          "1",
          "1",
          "1",
          "2",
          hex(destination_hash),
          Integer.to_string(context),
          hex(data),
          hex(transport_id)
        ])
        |> dehex()

      packet = %Reticulum.Packet{
        ifac: :open,
        propagation: :transport,
        destination: :group,
        type: :announce,
        hops: 2,
        addresses: [transport_id, destination_hash],
        context: context,
        data: data
      }

      assert Reticulum.Packet.encode(packet) == expected

      decoded = Reticulum.Packet.decode(expected)
      assert decoded.ifac == :open
      assert decoded.propagation == :transport
      assert decoded.destination == :group
      assert decoded.type == :announce
      assert decoded.hops == 2
      assert decoded.addresses == [transport_id, destination_hash]
      assert decoded.context == <<context>>
      assert decoded.data == data

      assert_packet_hash_parity(expected)
    end

    test "reference unpack output agrees with generated packet vectors" do
      destination_hash = bin_range(101..116)
      data = <<1, 3, 5, 7, 9>>

      raw_hex =
        ReferenceRunner.run!("packet_pack", [
          "0",
          "0",
          "0",
          "2",
          "1",
          "3",
          hex(destination_hash),
          "44",
          hex(data),
          "-"
        ])

      fields =
        raw_hex
        |> then(&ReferenceRunner.run!("packet_unpack", [&1]))
        |> ReferenceRunner.parse_kv_lines()

      assert fields["success"] == "true"
      assert fields["header_type"] == "0"
      assert fields["context_flag"] == "0"
      assert fields["transport_type"] == "0"
      assert fields["destination_type"] == "2"
      assert fields["packet_type"] == "1"
      assert fields["hops"] == "3"
      assert fields["destination_hash"] == hex(destination_hash)
      assert fields["transport_id"] == "-"
      assert fields["context"] == "44"
      assert fields["data"] == hex(data)

      assert_packet_hash_parity(dehex(raw_hex))
    end

    test "context_flag vectors decode and re-encode correctly" do
      destination_hash = bin_range(1..16)
      data = <<90, 91, 92>>

      raw =
        ReferenceRunner.run!("packet_pack", [
          "0",
          "1",
          "0",
          "0",
          "1",
          "0",
          hex(destination_hash),
          "33",
          hex(data),
          "-"
        ])
        |> dehex()

      decoded = Reticulum.Packet.decode(raw)
      assert decoded.ifac == :open
      assert decoded.propagation == :broadcast
      assert decoded.context_flag == 1
      assert decoded.destination == :single
      assert decoded.type == :announce
      assert decoded.hops == 0
      assert decoded.addresses == [destination_hash]
      assert decoded.context == <<33>>
      assert decoded.data == data

      reencoded =
        %Reticulum.Packet{
          ifac: decoded.ifac,
          propagation: decoded.propagation,
          destination: decoded.destination,
          type: decoded.type,
          hops: decoded.hops,
          addresses: decoded.addresses,
          context_flag: decoded.context_flag,
          context: decoded.context,
          data: decoded.data
        }
        |> Reticulum.Packet.encode()

      assert reencoded == raw

      assert_packet_hash_parity(raw)
    end

    test "malformed short raw packet is dropped like reference" do
      raw = <<0>>

      assert_reference_drop(raw)

      assert_raise FunctionClauseError, fn ->
        Reticulum.Packet.decode(raw)
      end

      assert Reticulum.Packet.hashable_part(raw) == {:error, :raw_header_too_short}
      assert Reticulum.Packet.hash(raw) == {:error, :raw_header_too_short}
      assert Reticulum.Packet.truncated_hash(raw) == {:error, :raw_header_too_short}
    end

    test "malformed header_2 raw packet is dropped like reference" do
      raw = <<0b01000001, 0, 0::size(16 * 8), 0>>

      assert_reference_drop(raw)

      assert_raise FunctionClauseError, fn ->
        Reticulum.Packet.decode(raw)
      end

      assert Reticulum.Packet.hashable_part(raw) == {:error, :raw_payload_too_short}
      assert Reticulum.Packet.hash(raw) == {:error, :raw_payload_too_short}
      assert Reticulum.Packet.truncated_hash(raw) == {:error, :raw_payload_too_short}
    end
  end

  defp assert_packet_hash_parity(raw) do
    fields =
      raw
      |> hex()
      |> then(&ReferenceRunner.run!("packet_hash", [&1]))
      |> ReferenceRunner.parse_kv_lines()

    assert fields["success"] == "true"

    assert Reticulum.Packet.hashable_part(raw) == {:ok, dehex(fields["hashable_part"])}
    assert Reticulum.Packet.hash(raw) == {:ok, dehex(fields["hash"])}
    assert Reticulum.Packet.truncated_hash(raw) == {:ok, dehex(fields["truncated_hash"])}
  end

  defp assert_reference_drop(raw) do
    unpack_fields =
      raw
      |> hex()
      |> then(&ReferenceRunner.run!("packet_unpack", [&1]))
      |> ReferenceRunner.parse_kv_lines()

    hash_fields =
      raw
      |> hex()
      |> then(&ReferenceRunner.run!("packet_hash", [&1]))
      |> ReferenceRunner.parse_kv_lines()

    assert unpack_fields["success"] == "false"
    assert hash_fields["success"] == "false"
  end

  defp hex(data), do: Base.encode16(data, case: :lower)
  defp dehex(data), do: Base.decode16!(data, case: :mixed)

  defp bin_range(range) do
    range
    |> Enum.to_list()
    |> :binary.list_to_bin()
  end
end
