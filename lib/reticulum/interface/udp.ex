defmodule Reticulum.Interface.UDP do
  @moduledoc """
  UDP interface implementation for raw Reticulum frame exchange.
  """

  @behaviour Reticulum.Interface

  alias Reticulum.Interface.IFAC

  @type ip_address :: :inet.ip_address()

  @type state :: %{
          ifac: map() | nil,
          socket: port(),
          listen_ip: ip_address(),
          listen_port: non_neg_integer(),
          default_peer_ip: ip_address() | nil,
          default_peer_port: non_neg_integer() | nil
        }

  @impl true
  def init(opts) when is_list(opts), do: init_adapter(opts)

  @impl true
  def send_frame(payload, opts, state) when is_list(opts) do
    payload = IO.iodata_to_binary(payload)

    with {:ok, ip, port} <- resolve_endpoint(opts, state),
         :ok <- :gen_udp.send(state.socket, ip, port, payload) do
      {:ok, state, {ip, port}}
    else
      {:error, reason} -> {:error, reason, state}
      {:error, reason, _rest} -> {:error, reason, state}
    end
  end

  @impl true
  def prepare_outbound(payload, opts, state) when is_binary(payload) and is_list(opts) do
    case IFAC.prepare_outbound(payload, state.ifac, opts) do
      {:ok, frame_payload} -> {:ok, frame_payload, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  @impl true
  def normalize_inbound(payload, state) when is_binary(payload) do
    case IFAC.normalize_inbound(payload, state.ifac) do
      {:ok, frame_payload} -> {:ok, frame_payload, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  @impl true
  def handle_info({:udp, socket, ip, port, payload}, %{socket: socket} = state) do
    {:noreply, state, [{:inbound_frame, payload, {ip, port}}]}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def health(_state), do: %{adapter_status: :up}

  @impl true
  def terminate(_reason, %{socket: socket}) do
    :ok = :gen_udp.close(socket)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp init_adapter(opts) do
    with {:ok, base_state} <- parse_opts(opts),
         {:ok, socket, listen_port} <- open_socket(base_state, opts) do
      state = %{base_state | socket: socket, listen_port: listen_port}
      {:ok, state, interface_meta(state)}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp parse_opts(opts) do
    with {:ok, listen_ip} <-
           validate_ip(Keyword.get(opts, :listen_ip, {127, 0, 0, 1}), :listen_ip),
         {:ok, listen_port} <-
           validate_port(Keyword.get(opts, :listen_port, 0), :listen_port, allow_zero: true),
         {:ok, default_peer_ip} <-
           validate_optional_ip(Keyword.get(opts, :default_peer_ip, nil), :default_peer_ip),
         {:ok, default_peer_port} <-
           validate_optional_port(Keyword.get(opts, :default_peer_port, nil), :default_peer_port),
         {:ok, ifac} <- IFAC.new(opts) do
      {:ok,
       %{
         ifac: ifac,
         socket: nil,
         listen_ip: listen_ip,
         listen_port: listen_port,
         default_peer_ip: default_peer_ip,
         default_peer_port: default_peer_port
       }}
    end
  end

  defp open_socket(base_state, opts) do
    socket_opts =
      Keyword.get(opts, :socket_opts, [])
      |> List.wrap()

    udp_opts =
      [
        :binary,
        {:active, true},
        {:reuseaddr, true},
        {:ip, base_state.listen_ip}
      ] ++ socket_opts

    case :gen_udp.open(base_state.listen_port, udp_opts) do
      {:ok, socket} ->
        case :inet.sockname(socket) do
          {:ok, {_ip, port}} ->
            {:ok, socket, port}

          {:error, reason} ->
            :ok = :gen_udp.close(socket)
            {:error, {:socket_name_lookup_failed, reason}}
        end

      {:error, reason} ->
        {:error, {:udp_open_failed, reason}}
    end
  end

  defp resolve_endpoint(opts, state) do
    with {:ok, ip} <-
           validate_optional_ip(Keyword.get(opts, :ip, state.default_peer_ip), :ip),
         {:ok, port} <-
           validate_optional_port(Keyword.get(opts, :port, state.default_peer_port), :port),
         {:ok, ip} <- ensure_present(ip, :missing_peer_ip),
         {:ok, port} <- ensure_present(port, :missing_peer_port) do
      {:ok, ip, port}
    end
  end

  defp interface_meta(state) do
    %{
      listen_ip: state.listen_ip,
      listen_port: state.listen_port,
      default_peer_ip: state.default_peer_ip,
      default_peer_port: state.default_peer_port
    }
    |> Map.merge(IFAC.summary(state.ifac))
  end

  defp validate_ip(ip, _field) when is_tuple(ip) and tuple_size(ip) in [4, 8], do: {:ok, ip}
  defp validate_ip(_ip, :listen_ip), do: {:error, :invalid_listen_ip}
  defp validate_ip(_ip, :default_peer_ip), do: {:error, :invalid_default_peer_ip}
  defp validate_ip(_ip, :ip), do: {:error, :invalid_peer_ip}

  defp validate_optional_ip(nil, _field), do: {:ok, nil}
  defp validate_optional_ip(ip, field), do: validate_ip(ip, field)

  defp validate_port(port, field, allow_zero: allow_zero)
       when is_integer(port) and port >= 0 and port <= 65_535 do
    if port > 0 or allow_zero do
      {:ok, port}
    else
      {:error, field_error(:port, field)}
    end
  end

  defp validate_port(_port, :listen_port, _opts), do: {:error, :invalid_listen_port}
  defp validate_port(_port, :default_peer_port, _opts), do: {:error, :invalid_default_peer_port}
  defp validate_port(_port, :port, _opts), do: {:error, :invalid_peer_port}

  defp validate_optional_port(nil, _field), do: {:ok, nil}
  defp validate_optional_port(port, field), do: validate_port(port, field, allow_zero: false)

  defp field_error(:port, :listen_port), do: :invalid_listen_port
  defp field_error(:port, :default_peer_port), do: :invalid_default_peer_port
  defp field_error(:port, :port), do: :invalid_peer_port

  defp ensure_present(value, _error) when not is_nil(value), do: {:ok, value}
  defp ensure_present(nil, error), do: {:error, error}
end
