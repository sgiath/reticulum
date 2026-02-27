defmodule Reticulum.Transport.Pathfinder do
  @moduledoc """
  Path request/response helpers and path expiration utilities.
  """

  alias Reticulum.Destination
  alias Reticulum.Node.State
  alias Reticulum.Packet
  alias Reticulum.Packet.Context
  alias Reticulum.Transport.Announce

  @truncated_hash_len 16
  @path_request_app "rnstransport"
  @path_request_aspects ["path", "request"]

  @path_request_hash (case Destination.hash(nil, @path_request_app, @path_request_aspects) do
                        {:ok, hash} -> hash
                      end)

  @type parsed_request :: %{
          destination_hash: binary(),
          requester_hash: binary() | nil,
          request_tag: binary(),
          path_request_hash: binary()
        }

  def path_request_destination_hash, do: @path_request_hash

  def build_path_request_packet(destination_hash, opts \\ []) when is_list(opts) do
    requester_hash = Keyword.get(opts, :requester_hash, nil)
    request_tag = Keyword.get(opts, :request_tag, :crypto.strong_rand_bytes(@truncated_hash_len))

    with :ok <- validate_hash(destination_hash, :invalid_destination_hash),
         :ok <- validate_optional_hash(requester_hash, :invalid_requester_hash),
         :ok <- validate_hash(request_tag, :invalid_request_tag) do
      data =
        if requester_hash do
          destination_hash <> requester_hash <> request_tag
        else
          destination_hash <> request_tag
        end

      {:ok,
       %Packet{
         ifac: :open,
         propagation: :broadcast,
         destination: :plain,
         type: :data,
         hops: 0,
         addresses: [@path_request_hash],
         context: Context.none(),
         data: data
       }}
    end
  end

  def parse_path_request_packet(%Packet{} = packet) do
    with :ok <- validate_request_packet(packet),
         {:ok, parsed} <- parse_path_request_data(packet.data) do
      {:ok, Map.put(parsed, :path_request_hash, @path_request_hash)}
    end
  end

  def parse_path_request_packet(_packet), do: {:error, :not_path_request}

  def build_path_response_packet(local_entry, opts \\ [])

  def build_path_response_packet(%{destination: %Destination{} = destination} = local_entry, opts)
      when is_list(opts) do
    app_data = Map.get(local_entry, :app_data)
    random_hash = Keyword.get(opts, :random_hash, :crypto.strong_rand_bytes(10))

    with {:ok, announce} <-
           Announce.build_payload(destination, app_data: app_data, random_hash: random_hash) do
      {:ok,
       %Packet{
         ifac: :open,
         propagation: :broadcast,
         destination: :single,
         type: :announce,
         hops: 0,
         addresses: [destination.hash],
         context_flag: announce.context_flag,
         context: Context.path_response(),
         data: announce.payload
       }}
    end
  end

  def build_path_response_packet(_entry, _opts), do: {:error, :invalid_local_destination}

  def expire_stale_paths(state_server, ttl_seconds, now_seconds \\ System.system_time(:second))
      when is_integer(ttl_seconds) and ttl_seconds > 0 and is_integer(now_seconds) do
    {:ok, paths} = State.paths(state_server)

    paths
    |> Enum.filter(fn %{destination_hash: destination_hash, updated_at: updated_at} ->
      if now_seconds - updated_at > ttl_seconds do
        :ok = State.delete_path(state_server, destination_hash)
        true
      else
        false
      end
    end)
    |> Enum.map(& &1.destination_hash)
  end

  defp validate_request_packet(%Packet{
         type: :data,
         destination: :plain,
         addresses: [address],
         context: context
       }) do
    with :ok <- validate_hash(address, :invalid_path_request_address),
         :ok <- validate_context_none(context) do
      validate_path_request_address(address)
    end
  end

  defp validate_request_packet(_packet), do: {:error, :not_path_request}

  defp validate_context_none(context) do
    case Context.normalize(context) do
      {:ok, value} when value == 0 -> :ok
      _ -> {:error, :invalid_path_request_context}
    end
  end

  defp validate_path_request_address(@path_request_hash), do: :ok
  defp validate_path_request_address(_address), do: {:error, :invalid_path_request_destination}

  defp parse_path_request_data(data) when is_binary(data) and byte_size(data) >= 48 do
    <<destination_hash::binary-size(@truncated_hash_len),
      requester_hash::binary-size(@truncated_hash_len),
      request_tag::binary-size(@truncated_hash_len), _rest::binary>> = data

    {:ok,
     %{
       destination_hash: destination_hash,
       requester_hash: requester_hash,
       request_tag: request_tag
     }}
  end

  defp parse_path_request_data(data) when is_binary(data) and byte_size(data) >= 32 do
    <<destination_hash::binary-size(@truncated_hash_len),
      request_tag::binary-size(@truncated_hash_len), _rest::binary>> = data

    {:ok,
     %{
       destination_hash: destination_hash,
       requester_hash: nil,
       request_tag: request_tag
     }}
  end

  defp parse_path_request_data(_data), do: {:error, :path_request_payload_too_short}

  defp validate_hash(hash, _reason)
       when is_binary(hash) and byte_size(hash) == @truncated_hash_len,
       do: :ok

  defp validate_hash(_hash, reason), do: {:error, reason}

  defp validate_optional_hash(nil, _reason), do: :ok
  defp validate_optional_hash(hash, reason), do: validate_hash(hash, reason)
end
