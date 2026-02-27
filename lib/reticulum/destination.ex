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
  @group_key_lengths [32, 64]
  @default_group_key_len 64
  @ratchet_private_len 32
  @types [:single, :group, :plain, :link]
  @directions [:in, :out]
  @proof_strategies [:none, :app, :all]

  @type proof_strategy :: :none | :app | :all

  @typedoc "Reticulum destination"
  @type t :: %__MODULE__{
          type: :single | :group | :plain | :link | nil,
          direction: :in | :out | nil,
          proof_strategy: proof_strategy(),
          group_key: binary() | nil,
          ratchets: [binary()],
          ratchet_enforced: boolean(),
          mtu: non_neg_integer(),
          links: list(),
          identity: Identity.t() | nil,
          name: String.t() | nil,
          name_hash: binary() | nil,
          hash: binary() | nil
        }

  defstruct type: nil,
            direction: nil,
            proof_strategy: :none,
            group_key: nil,
            ratchets: [],
            ratchet_enforced: false,
            mtu: 0,
            links: [],
            identity: nil,
            name: nil,
            name_hash: nil,
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
         {:ok, name_hash} <- name_hash(app_name, aspects),
         {:ok, destination} <-
           add_identity(%__MODULE__{direction: direction, type: type, identity: identity}),
         {:ok, destination_hash} <- hash(identity_hash(destination), app_name, aspects) do
      destination =
        destination
        |> add_name(app_name, aspects)
        |> Map.put(:name_hash, name_hash)
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

  @doc "Returns `{:ok, name_hash}` for app name and aspects."
  def name_hash(app_name, aspects \\ [])

  def name_hash(app_name, aspects) when is_binary(app_name) and is_list(aspects) do
    with :ok <- validate_name(app_name, aspects) do
      {:ok,
       [app_name | aspects]
       |> Enum.join(".")
       |> Crypto.sha256()
       |> binary_part(0, @name_hash_len)}
    end
  end

  @doc "Returns supported destination proof strategies."
  def proof_strategies, do: @proof_strategies

  @doc "Returns true when `proof_strategy` is valid."
  def valid_proof_strategy?(proof_strategy), do: proof_strategy in @proof_strategies

  @doc "Sets destination proof strategy."
  def set_proof_strategy(%__MODULE__{} = destination, proof_strategy) do
    if valid_proof_strategy?(proof_strategy) do
      {:ok, %{destination | proof_strategy: proof_strategy}}
    else
      {:error, :invalid_proof_strategy}
    end
  end

  @doc "Generates and stores a group key on a `:group` destination."
  def create_group_key(%__MODULE__{type: :group} = destination) do
    {:ok, %{destination | group_key: :crypto.strong_rand_bytes(@default_group_key_len)}}
  end

  def create_group_key(%__MODULE__{}), do: {:error, :not_group_destination}

  @doc "Loads a group key on a `:group` destination."
  def load_group_key(%__MODULE__{type: :group} = destination, key)
      when is_binary(key) and byte_size(key) in @group_key_lengths do
    {:ok, %{destination | group_key: key}}
  end

  def load_group_key(%__MODULE__{type: :group}, _key), do: {:error, :invalid_group_key}
  def load_group_key(%__MODULE__{}, _key), do: {:error, :not_group_destination}

  @doc "Fetches group key from a `:group` destination."
  def group_key(%__MODULE__{type: :group, group_key: key}) when is_binary(key), do: {:ok, key}
  def group_key(%__MODULE__{type: :group}), do: {:error, :missing_group_key}
  def group_key(%__MODULE__{}), do: {:error, :not_group_destination}

  @doc "Replaces ratchet private keys for a `:single` destination."
  def set_ratchets(%__MODULE__{type: :single} = destination, ratchets) when is_list(ratchets) do
    if Enum.all?(ratchets, &valid_ratchet_private?/1) do
      {:ok, %{destination | ratchets: ratchets}}
    else
      {:error, :invalid_ratchet}
    end
  end

  def set_ratchets(%__MODULE__{type: :single}, _ratchets), do: {:error, :invalid_ratchets}
  def set_ratchets(%__MODULE__{}, _ratchets), do: {:error, :ratchets_only_supported_for_single}

  @doc "Prepends one ratchet private key for a `:single` destination."
  def add_ratchet(%__MODULE__{type: :single} = destination, ratchet)
      when is_binary(ratchet) and byte_size(ratchet) == @ratchet_private_len do
    ratchets = [ratchet | Enum.reject(destination.ratchets, &(&1 == ratchet))]
    {:ok, %{destination | ratchets: ratchets}}
  end

  def add_ratchet(%__MODULE__{type: :single}, _ratchet), do: {:error, :invalid_ratchet}
  def add_ratchet(%__MODULE__{}, _ratchet), do: {:error, :ratchets_only_supported_for_single}

  @doc "Enables/disables ratchet-only decryption enforcement for `:single` destinations."
  def enforce_ratchets(%__MODULE__{type: :single} = destination, enabled)
      when is_boolean(enabled) do
    {:ok, %{destination | ratchet_enforced: enabled}}
  end

  def enforce_ratchets(%__MODULE__{type: :single}, _enabled), do: {:error, :invalid_enforcement}
  def enforce_ratchets(%__MODULE__{}, _enabled), do: {:error, :ratchets_only_supported_for_single}

  @doc "Returns ratchet enforcement status."
  def ratchet_enforced?(%__MODULE__{} = destination), do: destination.ratchet_enforced == true

  @doc "Returns current ratchet public key for `:single` destination, if available."
  def current_ratchet_public_key(%__MODULE__{type: :single, ratchets: [ratchet | _]}) do
    ratchet_public_key(ratchet)
  end

  def current_ratchet_public_key(%__MODULE__{type: :single}), do: :error
  def current_ratchet_public_key(%__MODULE__{}), do: {:error, :ratchets_only_supported_for_single}

  @doc "Derives ratchet public key from a ratchet private key."
  def ratchet_public_key(ratchet)
      when is_binary(ratchet) and byte_size(ratchet) == @ratchet_private_len do
    try do
      {public_key, _private_key} = :crypto.generate_key(:eddh, :x25519, ratchet)
      {:ok, public_key}
    rescue
      _ -> {:error, :invalid_ratchet}
    end
  end

  def ratchet_public_key(_ratchet), do: {:error, :invalid_ratchet}

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
    {:ok, name_hash} = name_hash(app_name, aspects)

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

  defp valid_ratchet_private?(ratchet),
    do: is_binary(ratchet) and byte_size(ratchet) == @ratchet_private_len
end
