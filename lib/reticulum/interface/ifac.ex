defmodule Reticulum.Interface.IFAC do
  @moduledoc false

  import Bitwise

  alias Reticulum.Crypto
  alias Reticulum.Identity

  @default_ifac_size 16
  @max_ifac_size 64
  @ifac_salt Base.decode16!("ADF54D882C9A9B80771EB4995D702D4A3E733391B2A0F53F416D9F907E55CFF8",
               case: :mixed
             )

  @type t :: %{
          key: binary(),
          identity: Identity.t(),
          netname: String.t() | nil,
          size: pos_integer()
        }

  def new(opts \\ []) when is_list(opts) do
    netname = Keyword.get(opts, :ifac_netname)
    netkey = Keyword.get(opts, :ifac_netkey)
    size = Keyword.get(opts, :ifac_size, @default_ifac_size)

    with :ok <- validate_string(netname, :invalid_ifac_netname),
         :ok <- validate_string(netkey, :invalid_ifac_netkey),
         :ok <- validate_size(size) do
      build_config(netname, netkey, size)
    end
  end

  def enabled?(config) when is_map(config), do: true
  def enabled?(_config), do: false

  def summary(config)

  def summary(nil), do: %{ifac: :open}

  def summary(%{size: size, netname: netname}) do
    %{
      ifac: :auth,
      ifac_size: size,
      ifac_netname: netname
    }
  end

  def prepare_outbound(raw, config, opts \\ [])

  def prepare_outbound(raw, nil, opts) when is_binary(raw) and is_list(opts) do
    case Keyword.get(opts, :ifac) do
      :auth -> {:error, :ifac_not_configured}
      _ -> {:ok, %{payload: raw, ifac: :open}}
    end
  end

  def prepare_outbound(raw, %{identity: _identity} = config, opts)
      when is_binary(raw) and is_list(opts) do
    case Keyword.get(opts, :ifac) do
      :open -> {:error, :ifac_required}
      _ -> wrap_outbound(raw, config)
    end
  end

  def prepare_outbound(_raw, _config, _opts), do: {:error, :invalid_ifac_frame}

  def normalize_inbound(raw, config)

  def normalize_inbound(raw, nil) when is_binary(raw) do
    case auth_flag_set?(raw) do
      true -> {:error, :unexpected_ifac_auth}
      false -> {:ok, %{payload: raw, ifac: :open}}
    end
  end

  def normalize_inbound(raw, %{identity: _identity} = config) when is_binary(raw) do
    unwrap_inbound(raw, config)
  end

  def normalize_inbound(_raw, _config), do: {:error, :invalid_ifac_frame}

  defp build_config(nil, nil, _size), do: {:ok, nil}

  defp build_config(netname, netkey, size) do
    origin =
      []
      |> maybe_append_hash(netname)
      |> maybe_append_hash(netkey)
      |> IO.iodata_to_binary()

    derived_private_key =
      origin
      |> Crypto.sha256()
      |> Crypto.hkdf(@ifac_salt, <<>>, 64)

    with {:ok, identity} <- Identity.from_private_key(derived_private_key) do
      {:ok,
       %{
         key: derived_private_key,
         identity: identity,
         netname: netname,
         size: size
       }}
    end
  end

  defp wrap_outbound(<<header::8, hops::8, rest::binary>> = raw, %{
         identity: identity,
         key: key,
         size: size
       }) do
    signature = Identity.sign(identity, raw)
    ifac = binary_part(signature, byte_size(signature) - size, size)
    mask = Crypto.hkdf(ifac, key, <<>>, byte_size(raw) + size)
    payload = <<bor(header, 0x80), hops, ifac::binary, rest::binary>>

    {:ok,
     %{
       payload: apply_mask(payload, mask, size, :outbound),
       ifac: :auth
     }}
  end

  defp wrap_outbound(_raw, _config), do: {:error, :invalid_ifac_frame}

  defp unwrap_inbound(raw, %{identity: identity, key: key, size: size}) do
    with true <- auth_flag_set?(raw) or {:error, :missing_ifac_auth},
         true <- byte_size(raw) > 2 + size or {:error, :ifac_frame_too_short},
         <<_header::8, _hops::8, ifac::binary-size(^size), _rest::binary>> <- raw do
      mask = Crypto.hkdf(ifac, key, <<>>, byte_size(raw))
      unmasked = apply_mask(raw, mask, size, :inbound)

      <<header::8, hops::8, _ifac::binary-size(^size), rest::binary>> = unmasked
      payload = <<band(header, 0x7F), hops, rest::binary>>
      signature = Identity.sign(identity, payload)
      expected_ifac = binary_part(signature, byte_size(signature) - size, size)

      if expected_ifac == ifac do
        {:ok, %{payload: payload, ifac: :auth}}
      else
        {:error, :invalid_ifac_auth}
      end
    else
      {:error, _reason} = error -> error
      _ -> {:error, :invalid_ifac_frame}
    end
  end

  defp apply_mask(payload, mask, size, direction) do
    payload
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {byte, index} -> mask_byte(byte, index, size, mask, direction) end)
    |> :binary.list_to_bin()
  end

  defp mask_byte(byte, 0, _size, mask, :outbound), do: bor(bxor(byte, :binary.at(mask, 0)), 0x80)

  defp mask_byte(byte, index, size, _mask, _direction) when index > 1 and index <= size + 1,
    do: byte

  defp mask_byte(byte, index, _size, mask, _direction), do: bxor(byte, :binary.at(mask, index))

  defp auth_flag_set?(<<header::8, _rest::binary>>), do: band(header, 0x80) == 0x80
  defp auth_flag_set?(_raw), do: false

  defp maybe_append_hash(acc, nil), do: acc
  defp maybe_append_hash(acc, value), do: [acc, Crypto.sha256(value)]

  defp validate_string(nil, _error), do: :ok
  defp validate_string(value, _error) when is_binary(value) and value != "", do: :ok
  defp validate_string(_value, error), do: {:error, error}

  defp validate_size(size) when is_integer(size) and size >= 1 and size <= @max_ifac_size, do: :ok
  defp validate_size(_size), do: {:error, :invalid_ifac_size}
end
