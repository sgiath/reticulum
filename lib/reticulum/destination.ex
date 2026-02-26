defmodule Reticulum.Destination do
  @moduledoc """
  Reticulum destination naming and hash derivation.

  A destination combines:

  - direction (`:in` or `:out`)
  - type (`:single`, `:group`, `:plain`, `:link`)
  - app name and aspects
  - optional identity hash material

  Naming and hashing behavior follows the Python reference implementation in
  `Reticulum/RNS/Destination.py`.

  The destination hash is derived as:

  1. `name_hash = sha256(app_name <> "." <> aspects) |> first(10)`
  2. `material = name_hash` or `name_hash <> identity_hash`
  3. `destination_hash = sha256(material) |> first(16)`
  """

  alias Reticulum.Crypto
  alias Reticulum.Identity

  @name_hash_len 10
  @destination_hash_len 16
  @types [:single, :group, :plain, :link]
  @directions [:in, :out]

  @typedoc "Reticulum destination"
  @type t :: %__MODULE__{
          type: :single | :group | :plain | :link | nil,
          direction: :in | :out | nil,
          proof_strategy: atom(),
          mtu: non_neg_integer(),
          links: list(),
          identity: Identity.t() | nil,
          name: String.t() | nil,
          hash: binary() | nil
        }

  defstruct type: nil,
            direction: nil,
            proof_strategy: :none,
            mtu: 0,
            links: [],
            identity: nil,
            name: nil,
            hash: nil

  @doc """
  Builds a destination struct.

  Returns `{:ok, destination}` or an error tuple:

  - `{:error, :unknown_destination_direction}`
  - `{:error, :unknown_destination_type}`
  - `{:error, :dots_in_app_name}`
  - `{:error, :invalid_aspects}`
  - `{:error, :dots_in_aspects}`
  - `{:error, :plain_destination_with_identity}`
  - `{:error, :missing_identity}`
  - `{:error, :invalid_hash_material}`
  """
  def new(direction, type, app_name, identity \\ nil, aspects \\ [])

  def new(direction, type, app_name, identity, aspects)
      when is_binary(app_name) and is_list(aspects) do
    with :ok <- validate_direction(direction),
         :ok <- validate_type(type),
         :ok <- validate_name(app_name, aspects),
         {:ok, destination} <-
           add_identity(%__MODULE__{direction: direction, type: type, identity: identity}),
         {:ok, destination_hash} <- hash(identity_hash(destination), app_name, aspects) do
      destination =
        destination
        |> add_name(app_name, aspects)
        |> Map.put(:hash, destination_hash)

      {:ok, destination}
    end
  end

  @doc """
  Calculates destination hash from optional identity hash material and name.

  Returns `{:ok, hash}` or an error tuple.
  """
  def hash(identity_hash_or_identity, app_name, aspects \\ [])

  def hash(identity_hash_or_identity, app_name, aspects)
      when is_binary(app_name) and is_list(aspects) do
    with :ok <- validate_name(app_name, aspects),
         {:ok, material} <- hash_material(identity_hash_or_identity, app_name, aspects) do
      {:ok,
       material
       |> Crypto.sha256()
       |> binary_part(0, @destination_hash_len)}
    end
  end

  defp add_identity(%__MODULE__{type: :plain, identity: nil} = dest), do: {:ok, dest}

  defp add_identity(%__MODULE__{type: :plain}), do: {:error, :plain_destination_with_identity}

  defp add_identity(%__MODULE__{direction: :in, identity: nil} = dest) do
    {:ok, %__MODULE__{dest | identity: Identity.new()}}
  end

  defp add_identity(%__MODULE__{direction: :out, type: type, identity: nil})
       when type != :plain do
    {:error, :missing_identity}
  end

  defp add_identity(%__MODULE__{} = dest), do: {:ok, dest}

  defp add_name(%__MODULE__{identity: nil} = dest, app_name, aspects) do
    %__MODULE__{dest | name: Enum.join([app_name | aspects], ".")}
  end

  defp add_name(%__MODULE__{identity: %Identity{hash: hash}} = dest, app_name, aspects) do
    name =
      [Base.encode16(hash, case: :lower) | Enum.reverse([app_name | aspects])]
      |> Enum.reverse()
      |> Enum.join(".")

    %__MODULE__{dest | name: name}
  end

  defp identity_hash(%__MODULE__{identity: nil}), do: nil

  defp identity_hash(%__MODULE__{identity: %Identity{hash: identity_hash}}), do: identity_hash

  defp hash_material(identity_hash_or_identity, app_name, aspects) do
    name_hash =
      [app_name | aspects]
      |> Enum.join(".")
      |> Crypto.sha256()
      |> binary_part(0, @name_hash_len)

    case identity_hash_or_identity do
      nil ->
        {:ok, name_hash}

      %Identity{hash: hash} when is_binary(hash) and byte_size(hash) == @destination_hash_len ->
        {:ok, name_hash <> hash}

      hash when is_binary(hash) and byte_size(hash) == @destination_hash_len ->
        {:ok, name_hash <> hash}

      _ ->
        {:error, :invalid_hash_material}
    end
  end

  defp validate_direction(direction) when direction in @directions, do: :ok
  defp validate_direction(_direction), do: {:error, :unknown_destination_direction}

  defp validate_type(type) when type in @types, do: :ok
  defp validate_type(_type), do: {:error, :unknown_destination_type}

  defp validate_name(app_name, aspects) when is_binary(app_name) and is_list(aspects) do
    cond do
      String.contains?(app_name, ".") ->
        {:error, :dots_in_app_name}

      not Enum.all?(aspects, &is_binary/1) ->
        {:error, :invalid_aspects}

      Enum.any?(aspects, &String.contains?(&1, ".")) ->
        {:error, :dots_in_aspects}

      true ->
        :ok
    end
  end
end
