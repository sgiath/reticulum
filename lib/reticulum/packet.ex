defmodule Reticulum.Packet do
  @moduledoc """
  Reticulum packet wire format helpers.

  Encodes and decodes the compact packet header used in the Reticulum wire
  format, and provides packet hash helpers compatible with the reference
  implementation.

  References:

  - Manual wire format section:
    https://reticulum.network/manual/understanding.html#wire-format
  - Python reference implementation: `Reticulum/RNS/Packet.py`
  """
  import Bitwise

  alias Reticulum.Crypto

  @address_len 16
  @truncated_hash_len 16

  @typedoc "Reticulum packet representation used by encode/decode helpers"
  @type t :: %__MODULE__{
          ifac: :open | :auth | nil,
          propagation: :broadcast | :transport | nil,
          destination: :single | :group | :plain | :link | nil,
          type: :data | :announce | :link_request | :proof | nil,
          hops: non_neg_integer(),
          addresses: [binary()],
          context_flag: 0 | 1 | true | false | :set | :unset | nil,
          context: binary() | integer() | nil,
          data: binary() | nil
        }

  defstruct ifac: nil,
            propagation: nil,
            destination: nil,
            type: nil,
            hops: 0,
            addresses: [],
            context_flag: 0,
            context: nil,
            data: nil

  @doc "Encodes a packet struct into wire-format binary."
  def encode(%__MODULE__{} = packet) do
    addresses = encode_addresses(packet.addresses)
    propagation = encode_propagation(packet.propagation, packet.context_flag)

    <<
      ifac(packet.ifac)::integer-size(1),
      length(addresses) - 1::integer-size(1),
      propagation::integer-size(2),
      destination(packet.destination)::integer-size(2),
      packet_type(packet.type)::integer-size(2),
      packet.hops::integer-size(8),
      Enum.join(addresses, "")::binary,
      encode_context(packet.context)::bytes-size(1),
      packet.data::binary
    >>
  end

  @doc "Decodes wire-format packet binary into `%Reticulum.Packet{}`."
  def decode(
        <<ifac::integer-size(1), header::integer-size(1), prop::integer-size(2),
          dest::integer-size(2), type::integer-size(2), hops::integer-size(8),
          addresses::bytes-size(@address_len * (header + 1)), context::bytes-size(1),
          data::binary>>
      ) do
    %__MODULE__{
      ifac: ifac(ifac),
      propagation: propagation(propagation_transport(prop)),
      destination: destination(dest),
      type: packet_type(type),
      hops: hops,
      addresses: addresses(addresses),
      context_flag: propagation_context_flag(prop),
      context: context,
      data: data
    }
  end

  @doc "Returns packet hashable bytes (`{:ok, bytes}`) from packet struct or raw binary."
  def hashable_part(packet_or_raw)

  def hashable_part(%__MODULE__{} = packet) do
    packet
    |> encode()
    |> hashable_part()
  end

  def hashable_part(raw) when is_binary(raw) do
    with :ok <- validate_hashable_raw(raw) do
      <<flags::integer-size(8), _hops::integer-size(8), rest::binary>> = raw
      masked_flags = <<band(flags, 0b00001111)>>
      header_type = bsr(band(flags, 0b01000000), 6)

      payload =
        case header_type do
          0 ->
            rest

          1 ->
            <<_transport_id::binary-size(@address_len), retained::binary>> = rest
            retained
        end

      {:ok, masked_flags <> payload}
    end
  end

  @doc "Returns `{:ok, sha256_hash}` for packet struct/raw binary."
  def hash(data) do
    with {:ok, hashable_part} <- hashable_part(data) do
      {:ok, Crypto.sha256(hashable_part)}
    end
  end

  @doc "Returns `{:ok, truncated_hash}` (16-byte hash prefix)."
  def truncated_hash(data) do
    with {:ok, hash} <- hash(data) do
      {:ok, binary_part(hash, 0, @truncated_hash_len)}
    end
  end

  defp validate_hashable_raw(
         <<_ifac::integer-size(1), header::integer-size(1), _prop::integer-size(2),
           _dest::integer-size(2), _type::integer-size(2), _hops::integer-size(8), rest::binary>>
       ) do
    min_payload_size = @address_len * (header + 1) + 1

    if byte_size(rest) < min_payload_size do
      {:error, :raw_payload_too_short}
    else
      :ok
    end
  end

  defp validate_hashable_raw(_raw), do: {:error, :raw_header_too_short}

  defp ifac(0), do: :open
  defp ifac(1), do: :auth
  defp ifac(:open), do: 0
  defp ifac(:auth), do: 1

  defp propagation(0b00), do: :broadcast
  defp propagation(0b01), do: :transport
  defp propagation(:broadcast), do: 0b00
  defp propagation(:transport), do: 0b01

  defp propagation_transport(propagation), do: band(propagation, 0b01)
  defp propagation_context_flag(propagation), do: bsr(propagation, 1)

  defp encode_propagation(propagation, context_flag) do
    transport_type = propagation(propagation)
    context_flag = encode_context_flag(context_flag)

    bor(bsl(context_flag, 1), transport_type)
  end

  defp encode_context_flag(nil), do: 0
  defp encode_context_flag(false), do: 0
  defp encode_context_flag(true), do: 1
  defp encode_context_flag(:unset), do: 0
  defp encode_context_flag(:set), do: 1
  defp encode_context_flag(context_flag) when context_flag in [0, 1], do: context_flag

  defp destination(0b00), do: :single
  defp destination(0b01), do: :group
  defp destination(0b10), do: :plain
  defp destination(0b11), do: :link
  defp destination(:single), do: 0b00
  defp destination(:group), do: 0b01
  defp destination(:plain), do: 0b10
  defp destination(:link), do: 0b11

  defp packet_type(0b00), do: :data
  defp packet_type(0b01), do: :announce
  defp packet_type(0b10), do: :link_request
  defp packet_type(0b11), do: :proof
  defp packet_type(:data), do: 0b00
  defp packet_type(:announce), do: 0b01
  defp packet_type(:link_request), do: 0b10
  defp packet_type(:proof), do: 0b11

  defp addresses(address) when byte_size(address) == @address_len, do: [address]

  defp addresses(<<address1::binary-size(@address_len), address2::binary-size(@address_len)>>),
    do: [address1, address2]

  defp encode_addresses([address]) when is_binary(address) and byte_size(address) == @address_len,
    do: [address]

  defp encode_addresses([address1, address2])
       when is_binary(address1) and byte_size(address1) == @address_len and is_binary(address2) and
              byte_size(address2) == @address_len,
       do: [address1, address2]

  defp encode_context(context) when is_integer(context) and context in 0..255,
    do: <<context>>

  defp encode_context(<<context::binary-size(1)>>), do: <<context::binary>>
end
