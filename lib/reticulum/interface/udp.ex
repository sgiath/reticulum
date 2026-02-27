defmodule Reticulum.Interface.UDP do
  @moduledoc """
  UDP interface implementation for raw Reticulum frame exchange.
  """
  use GenServer

  @behaviour Reticulum.Interface

  alias Reticulum.Node.State

  @type ip_address :: :inet.ip_address()

  @type state :: %{
          socket: port(),
          name: atom(),
          node_name: atom(),
          state_server: GenServer.server(),
          listen_ip: ip_address(),
          listen_port: non_neg_integer(),
          default_peer_ip: ip_address() | nil,
          default_peer_port: non_neg_integer() | nil
        }

  def child_spec(opts) do
    node_name = Keyword.fetch!(opts, :node_name)
    name = Keyword.fetch!(opts, :name)

    %{
      id: {__MODULE__, node_name, name},
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  @impl true
  def start_link(opts) when is_list(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @impl true
  def send_frame(server, payload, opts \\ []) when is_list(opts) do
    payload = IO.iodata_to_binary(payload)
    GenServer.call(server, {:send_frame, payload, opts})
  end

  @impl true
  def init(opts) do
    with {:ok, base_state} <- parse_opts(opts),
         {:ok, socket, listen_port} <- open_socket(base_state, opts),
         :ok <- register_interface(base_state, listen_port) do
      {:ok, %{base_state | socket: socket, listen_port: listen_port}}
    else
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call({:send_frame, payload, opts}, _from, state) do
    with {:ok, ip, port} <- resolve_endpoint(opts, state),
         :ok <- :gen_udp.send(state.socket, ip, port, payload) do
      publish_frame(state, :outbound, payload, ip, port)
      {:reply, :ok, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
      {:error, reason, _rest} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info({:udp, socket, ip, port, payload}, %{socket: socket} = state) do
    publish_frame(state, :inbound, payload, ip, port)
    {:noreply, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{socket: socket, state_server: state_server, name: name}) do
    _ = State.unregister_interface(state_server, name)
    :ok = :gen_udp.close(socket)
    :ok
  end

  def terminate(_reason, _state), do: :ok

  defp parse_opts(opts) do
    with {:ok, name} <- validate_name(Keyword.get(opts, :name)),
         {:ok, node_name} <- validate_node_name(Keyword.get(opts, :node_name)),
         {:ok, state_server} <- validate_state_server(Keyword.get(opts, :state_server)),
         {:ok, listen_ip} <-
           validate_ip(Keyword.get(opts, :listen_ip, {127, 0, 0, 1}), :listen_ip),
         {:ok, listen_port} <-
           validate_port(Keyword.get(opts, :listen_port, 0), :listen_port, allow_zero: true),
         {:ok, default_peer_ip} <-
           validate_optional_ip(Keyword.get(opts, :default_peer_ip, nil), :default_peer_ip),
         {:ok, default_peer_port} <-
           validate_optional_port(Keyword.get(opts, :default_peer_port, nil), :default_peer_port) do
      {:ok,
       %{
         socket: nil,
         name: name,
         node_name: node_name,
         state_server: state_server,
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

  defp register_interface(base_state, listen_port) do
    meta = %{
      listen_ip: base_state.listen_ip,
      listen_port: listen_port,
      default_peer_ip: base_state.default_peer_ip,
      default_peer_port: base_state.default_peer_port
    }

    State.register_interface(
      base_state.state_server,
      base_state.name,
      self(),
      __MODULE__,
      meta
    )
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

  defp publish_frame(state, direction, payload, ip, port) do
    State.publish_frame(state.state_server, %{
      direction: direction,
      interface: state.name,
      payload: payload,
      endpoint: {ip, port},
      at: System.system_time(:millisecond),
      node: state.node_name
    })
  end

  defp validate_name(name) when is_atom(name), do: {:ok, name}
  defp validate_name(_name), do: {:error, :invalid_interface_name}

  defp validate_node_name(node_name) when is_atom(node_name), do: {:ok, node_name}
  defp validate_node_name(_node_name), do: {:error, :invalid_node_name}

  defp validate_state_server(state_server) do
    if is_pid(state_server) or is_tuple(state_server) do
      {:ok, state_server}
    else
      {:error, :invalid_state_server}
    end
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
