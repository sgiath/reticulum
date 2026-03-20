defmodule Reticulum.Interface.IFACTest do
  use ExUnit.Case, async: true

  alias Reticulum.Interface.IFAC
  alias Reticulum.Packet

  test "returns open summary when no IFAC config is present" do
    assert {:ok, nil} = IFAC.new([])
    assert IFAC.summary(nil) == %{ifac: :open}
  end

  test "derives auth config and redacts secret fields from summary" do
    assert {:ok, config} =
             IFAC.new(ifac_netname: "mesh", ifac_netkey: "phase7-secret", ifac_size: 16)

    summary = IFAC.summary(config)

    assert IFAC.enabled?(config)
    assert %{ifac: :auth, ifac_size: 16, ifac_netname: "mesh"} = summary
    refute Map.has_key?(summary, :ifac_netkey)
    refute Map.has_key?(summary, :key)
  end

  test "rejects auth outbound frames when interface has no IFAC config" do
    packet = sample_raw_packet()

    assert {:error, :ifac_not_configured} = IFAC.prepare_outbound(packet, nil, ifac: :auth)
  end

  test "rejects missing or invalid IFAC auth on configured interfaces" do
    packet = sample_raw_packet()
    assert {:ok, config} = IFAC.new(ifac_netname: "mesh", ifac_netkey: "phase7-secret")
    assert {:ok, other_config} = IFAC.new(ifac_netname: "mesh", ifac_netkey: "wrong-secret")

    assert {:error, :missing_ifac_auth} = IFAC.normalize_inbound(packet, config)

    assert {:ok, %{payload: wrapped, ifac: :auth}} = IFAC.prepare_outbound(packet, config, [])
    assert {:error, :invalid_ifac_auth} = IFAC.normalize_inbound(wrapped, other_config)
  end

  defp sample_raw_packet do
    %Packet{
      ifac: :open,
      propagation: :broadcast,
      destination: :plain,
      type: :data,
      hops: 0,
      addresses: [:crypto.strong_rand_bytes(16)],
      context: 0,
      data: "ifac"
    }
    |> Packet.encode()
  end
end
