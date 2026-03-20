defmodule Reticulum.Reference.IFACVectorsTest do
  use ExUnit.Case, async: true

  alias Reticulum.Interface.IFAC
  alias Reticulum.Packet
  alias Reticulum.ReferenceRunner

  test "IFAC wrap and unwrap match Python reference" do
    raw =
      %Packet{
        ifac: :open,
        propagation: :broadcast,
        destination: :plain,
        type: :data,
        hops: 0,
        addresses: [bin_range(1..16)],
        context: 0,
        data: <<5, 6, 7, 8, 9>>
      }
      |> Packet.encode()

    netname = "mesh-alpha"
    netkey = "phase7-secret"
    size_bits = 128

    wrapped =
      ReferenceRunner.run!("ifac_wrap", [hex(raw), netname, netkey, Integer.to_string(size_bits)])
      |> dehex()

    assert {:ok, config} =
             IFAC.new(ifac_netname: netname, ifac_netkey: netkey, ifac_size: div(size_bits, 8))

    assert {:ok, %{payload: ^wrapped, ifac: :auth}} = IFAC.prepare_outbound(raw, config, [])
    assert {:ok, %{payload: ^raw, ifac: :auth}} = IFAC.normalize_inbound(wrapped, config)

    assert ReferenceRunner.run!("ifac_unwrap", [
             hex(wrapped),
             netname,
             netkey,
             Integer.to_string(size_bits)
           ]) ==
             hex(raw)
  end

  defp bin_range(range) do
    range
    |> Enum.to_list()
    |> :binary.list_to_bin()
  end

  defp hex(data), do: Base.encode16(data, case: :lower)
  defp dehex(data), do: Base.decode16!(data, case: :mixed)
end
