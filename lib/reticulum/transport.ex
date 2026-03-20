defmodule Reticulum.Transport do
  @moduledoc """
  Transport runtime for packet ingress/egress and path discovery.

  Responsibilities in this phase:

  - outbound packet pipeline (`Reticulum.Packet` -> interface frame)
  - inbound frame parsing to decoded packets
  - packet duplicate suppression via packet hash cache
  - local destination dispatch for inbound data packets
  - announce validation/ingestion and known destination memory updates
  - path request emission, response, and path table maintenance
  """
  use GenServer

  alias Reticulum.Crypto
  alias Reticulum.Destination
  alias Reticulum.Interface.Supervisor, as: InterfaceSupervisor
  alias Reticulum.Node.State
  alias Reticulum.Observability
  alias Reticulum.Packet
  alias Reticulum.Packet.Context
  alias Reticulum.PacketReceipt
  alias Reticulum.Transport.Announce
  alias Reticulum.Transport.PacketCrypto
  alias Reticulum.Transport.Pathfinder
  alias Reticulum.Transport.Proofs
  alias Reticulum.Transport.Routing

  @truncated_hash_len 16
  @default_path_ttl_seconds 300
  @default_path_gc_interval_seconds 5
  @default_receipt_timeout_seconds 10
  @default_receipt_retention_seconds 60
  @default_ratchet_expiry_seconds 2_592_000
  @default_routing_max_hops 128
  @default_path_request_timeout_seconds 15
  @default_path_request_retry_count 1
  @default_path_request_retry_base_seconds 5
  @default_path_request_retry_backoff_factor 2
  @default_path_request_min_interval_seconds 20
  @default_path_request_duplicate_ttl_seconds 15
  @default_path_request_fanout 2
  @default_reverse_route_ttl_seconds 60
  @local_control_packet_ttl_seconds 60
  @path_request_retry_check_interval_ms 250

  @type pending_path_request :: %{
          destination_hash: binary(),
          requester_hash: binary() | nil,
          interface: atom(),
          request_tag: binary(),
          first_sent_at_ms: integer(),
          last_sent_at_ms: integer(),
          next_retry_at_ms: integer() | nil,
          retries_sent: non_neg_integer(),
          expires_at_ms: integer()
        }

  @type seen_path_request :: %{
          interface: atom() | nil,
          updated_at_ms: integer()
        }

  @type state :: %{
          node_name: atom(),
          state_server: GenServer.server(),
          transport_enabled: boolean(),
          use_implicit_proof: boolean(),
          pending_path_requests: %{binary() => pending_path_request()},
          seen_path_requests: %{binary() => seen_path_request()},
          path_ttl_seconds: pos_integer(),
          path_gc_interval_seconds: pos_integer(),
          receipt_timeout_seconds: pos_integer(),
          receipt_retention_seconds: pos_integer(),
          ratchet_expiry_seconds: pos_integer(),
          routing_max_hops: pos_integer(),
          announce_forwarding: boolean(),
          path_request_forwarding: boolean(),
          path_request_timeout_seconds: pos_integer(),
          path_request_retry_count: non_neg_integer(),
          path_request_retry_base_seconds: pos_integer(),
          path_request_retry_backoff_factor: pos_integer(),
          path_request_min_interval_seconds: pos_integer(),
          path_request_duplicate_ttl_seconds: pos_integer(),
          path_request_fanout: pos_integer(),
          reverse_routes: %{binary() => %{interface: atom(), updated_at: integer()}},
          local_control_packets: %{binary() => integer()},
          packet_receipts: %{
            binary() => %{
              receipt: PacketReceipt.t(),
              on_delivery: function() | nil,
              on_timeout: function() | nil
            }
          }
        }

  def child_spec(opts) do
    node_name = Keyword.fetch!(opts, :node_name)

    %{
      id: {__MODULE__, node_name},
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  def start_link(opts) when is_list(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.fetch!(opts, :name))
  end

  def send_packet(server, interface_name, packet_or_raw, opts \\ [])
      when is_atom(interface_name) and is_list(opts) do
    GenServer.call(server, {:send_packet, interface_name, packet_or_raw, opts})
  end

  def send_data(server, interface_name, destination_hash, payload, opts \\ [])
      when is_atom(interface_name) and is_binary(payload) and is_list(opts) do
    GenServer.call(server, {:send_data, interface_name, destination_hash, payload, opts})
  end

  def request_path(server, interface_name, destination_hash, opts \\ [])
      when is_atom(interface_name) and is_list(opts) do
    GenServer.call(server, {:request_path, interface_name, destination_hash, opts})
  end

  def announce_destination(server, interface_name, destination_hash, opts \\ [])
      when is_atom(interface_name) and is_binary(destination_hash) and is_list(opts) do
    GenServer.call(server, {:announce_destination, interface_name, destination_hash, opts})
  end

  def receipt(server, receipt_hash) when is_binary(receipt_hash) do
    GenServer.call(server, {:receipt, receipt_hash})
  end

  @impl true
  def init(opts) do
    node_name = Keyword.fetch!(opts, :node_name)
    state_server = Keyword.fetch!(opts, :state_server)
    config = Keyword.get(opts, :config, %{})
    transport_enabled = Map.get(config, :transport_enabled, false) == true
    use_implicit_proof = Map.get(config, :use_implicit_proof, true) == true

    path_ttl_seconds =
      normalize_positive_integer(
        Map.get(config, :path_ttl_seconds),
        @default_path_ttl_seconds
      )

    path_gc_interval_seconds =
      normalize_positive_integer(
        Map.get(config, :path_gc_interval_seconds),
        @default_path_gc_interval_seconds
      )

    receipt_timeout_seconds =
      normalize_positive_integer(
        Map.get(config, :receipt_timeout_seconds),
        @default_receipt_timeout_seconds
      )

    receipt_retention_seconds =
      normalize_positive_integer(
        Map.get(config, :receipt_retention_seconds),
        @default_receipt_retention_seconds
      )

    ratchet_expiry_seconds =
      normalize_positive_integer(
        Map.get(config, :ratchet_expiry_seconds),
        @default_ratchet_expiry_seconds
      )

    routing_max_hops =
      normalize_positive_integer(
        Map.get(config, :routing_max_hops),
        @default_routing_max_hops
      )

    announce_forwarding = Map.get(config, :announce_forwarding, true) == true
    path_request_forwarding = Map.get(config, :path_request_forwarding, true) == true

    path_request_timeout_seconds =
      normalize_positive_integer(
        Map.get(config, :path_request_timeout_seconds),
        @default_path_request_timeout_seconds
      )

    path_request_retry_count =
      normalize_non_negative_integer(
        Map.get(config, :path_request_retry_count),
        @default_path_request_retry_count
      )

    path_request_retry_base_seconds =
      normalize_positive_integer(
        Map.get(config, :path_request_retry_base_seconds),
        @default_path_request_retry_base_seconds
      )

    path_request_retry_backoff_factor =
      normalize_positive_integer(
        Map.get(config, :path_request_retry_backoff_factor),
        @default_path_request_retry_backoff_factor
      )

    path_request_min_interval_seconds =
      normalize_positive_integer(
        Map.get(config, :path_request_min_interval_seconds),
        @default_path_request_min_interval_seconds
      )

    path_request_duplicate_ttl_seconds =
      normalize_positive_integer(
        Map.get(config, :path_request_duplicate_ttl_seconds),
        @default_path_request_duplicate_ttl_seconds
      )

    path_request_fanout =
      normalize_positive_integer(
        Map.get(config, :path_request_fanout),
        @default_path_request_fanout
      )

    :ok = State.subscribe_frames(state_server, self())
    schedule_path_maintenance(path_gc_interval_seconds)
    schedule_path_request_retry_check()

    {:ok,
     %{
       node_name: node_name,
       state_server: state_server,
       transport_enabled: transport_enabled,
       use_implicit_proof: use_implicit_proof,
       pending_path_requests: %{},
       seen_path_requests: %{},
       path_ttl_seconds: path_ttl_seconds,
       path_gc_interval_seconds: path_gc_interval_seconds,
       receipt_timeout_seconds: receipt_timeout_seconds,
       receipt_retention_seconds: receipt_retention_seconds,
       ratchet_expiry_seconds: ratchet_expiry_seconds,
       routing_max_hops: routing_max_hops,
       announce_forwarding: announce_forwarding,
       path_request_forwarding: path_request_forwarding,
       path_request_timeout_seconds: path_request_timeout_seconds,
       path_request_retry_count: path_request_retry_count,
       path_request_retry_base_seconds: path_request_retry_base_seconds,
       path_request_retry_backoff_factor: path_request_retry_backoff_factor,
       path_request_min_interval_seconds: path_request_min_interval_seconds,
       path_request_duplicate_ttl_seconds: path_request_duplicate_ttl_seconds,
       path_request_fanout: path_request_fanout,
       reverse_routes: %{},
       local_control_packets: %{},
       packet_receipts: %{}
     }}
  end

  @impl true
  def handle_call({:send_packet, interface_name, packet_or_raw, opts}, _from, state) do
    case transmit_outbound(state, interface_name, packet_or_raw, opts) do
      {:ok, canonical_raw, transmitted_raw, ifac} ->
        publish_outbound_packet(state, interface_name, canonical_raw, transmitted_raw, ifac)
        {:reply, :ok, state}

      {:error, reason} ->
        {:reply, {:error, reason}, state}

      other ->
        {:reply, other, state}
    end
  end

  def handle_call(
        {:send_data, interface_name, destination_hash, payload, opts},
        _from,
        %{state_server: state_server} = state
      ) do
    with :ok <- validate_destination_hash(destination_hash),
         {:ok, destination_record} <- fetch_destination(state_server, destination_hash),
         {:ok, packet} <- build_data_packet(destination_hash, payload, opts),
         {:ok, encrypted_packet} <- PacketCrypto.encrypt_outbound(packet, destination_record),
         {:ok, canonical_raw, transmitted_raw, ifac} <-
           transmit_outbound(state, interface_name, encrypted_packet, opts) do
      publish_outbound_packet(state, interface_name, canonical_raw, transmitted_raw, ifac)

      {reply, updated_state} = maybe_track_receipt(state, destination_hash, canonical_raw, opts)
      {:reply, reply, updated_state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, other, state}
    end
  end

  def handle_call({:request_path, interface_name, destination_hash, opts}, _from, state) do
    now_ms = now_ms()

    if reuse_pending_path_request?(state, destination_hash, interface_name, now_ms) do
      {:reply, {:ok, state.pending_path_requests[destination_hash].request_tag}, state}
    else
      requester_hash = Keyword.get(opts, :requester_hash, nil)

      request_tag =
        Keyword.get(opts, :request_tag, :crypto.strong_rand_bytes(@truncated_hash_len))

      case emit_path_request(
             state,
             interface_name,
             destination_hash,
             requester_hash,
             request_tag,
             opts
           ) do
        {:ok, updated_state} ->
          pending =
            Map.put(
              updated_state.pending_path_requests,
              destination_hash,
              new_pending_path_request(
                state,
                destination_hash,
                interface_name,
                requester_hash,
                request_tag,
                now_ms
              )
            )

          {:reply, {:ok, request_tag}, %{updated_state | pending_path_requests: pending}}

        {:error, reason} ->
          {:reply, {:error, reason}, state}

        other ->
          {:reply, other, state}
      end
    end
  end

  def handle_call(
        {:announce_destination, interface_name, destination_hash, opts},
        _from,
        %{state_server: state_server} = state
      ) do
    with {:ok, local_destination} <- State.local_destination(state_server, destination_hash),
         {:ok, response_packet} <- Pathfinder.build_path_response_packet(local_destination, opts),
         {:ok, canonical_raw, transmitted_raw, ifac} <-
           transmit_outbound(state, interface_name, response_packet, opts) do
      updated_state = maybe_track_local_control_packet(state, canonical_raw)
      publish_outbound_packet(state, interface_name, canonical_raw, transmitted_raw, ifac)
      {:reply, :ok, updated_state}
    else
      :error -> {:reply, {:error, :unknown_local_destination}, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, other, state}
    end
  end

  def handle_call({:receipt, receipt_hash}, _from, state) do
    case Map.get(state.packet_receipts, receipt_hash) do
      %{receipt: receipt} -> {:reply, {:ok, receipt}, state}
      nil -> {:reply, :error, state}
    end
  end

  @impl true
  def handle_info({:reticulum, :frame, %{direction: :inbound} = frame}, state) do
    {:noreply, process_inbound_frame(frame, state)}
  end

  def handle_info(:path_maintenance, state) do
    _expired = Pathfinder.expire_stale_paths(state.state_server, state.path_ttl_seconds)

    _expired_ratchets =
      State.expire_destination_ratchets(
        state.state_server,
        state.ratchet_expiry_seconds
      )

    now = System.system_time(:second)
    pending_path_requests = expire_pending_path_requests(state.pending_path_requests, now_ms())

    seen_path_requests =
      expire_seen_path_requests(
        state.seen_path_requests,
        now_ms(),
        state.path_request_duplicate_ttl_seconds
      )

    packet_receipts =
      expire_packet_receipts(
        state.packet_receipts,
        now,
        state.receipt_retention_seconds,
        state.node_name
      )

    reverse_routes =
      expire_timestamp_map(state.reverse_routes, now, @default_reverse_route_ttl_seconds)

    local_control_packets =
      expire_timestamp_map(state.local_control_packets, now, @local_control_packet_ttl_seconds)

    schedule_path_maintenance(state.path_gc_interval_seconds)

    {:noreply,
     %{
       state
       | pending_path_requests: pending_path_requests,
         seen_path_requests: seen_path_requests,
         packet_receipts: packet_receipts,
         reverse_routes: reverse_routes,
         local_control_packets: local_control_packets
     }}
  end

  def handle_info(:path_request_retry_check, state) do
    schedule_path_request_retry_check()
    {:noreply, retry_pending_path_requests(state)}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp process_inbound_frame(%{payload: raw} = frame, %{state_server: state_server} = state)
       when is_binary(raw) do
    with {:ok, %{payload: canonical_raw, ifac: ifac}} <-
           InterfaceSupervisor.normalize_inbound(state.node_name, frame.interface, raw),
         {:ok, packet_hash_full} <- Packet.hash(canonical_raw),
         {:ok, packet_hash} <- Packet.truncated_hash(canonical_raw),
         {:ok, packet} <- decode_packet(canonical_raw) do
      packet = %{packet | ifac: ifac}

      duplicate =
        State.remember_packet_hash(state_server, packet_hash) == :existing or
          Map.has_key?(state.local_control_packets, packet_hash)

      publish_inbound_packet(state, frame, raw, packet, packet_hash, duplicate)

      if duplicate do
        state
      else
        state
        |> route_control_packets(frame, canonical_raw, packet, packet_hash, packet_hash_full)
        |> dispatch_to_local_destination(
          frame,
          canonical_raw,
          packet,
          packet_hash,
          packet_hash_full
        )
        |> forward_transit_packet(frame, packet, packet_hash_full)
      end
    else
      {:error, reason} ->
        publish_decode_error(state, frame, raw, reason)
        state
    end
  end

  defp process_inbound_frame(_frame, state), do: state

  defp route_control_packets(
         state,
         frame,
         _raw,
         %Packet{type: :announce} = packet,
         _packet_hash,
         _packet_hash_full
       ) do
    with {:ok, announce} <- Announce.parse(packet),
         :ok <-
           State.put_destination(
             state.state_server,
             announce.destination_hash,
             announce.public_key,
             announce.app_data,
             announce_destination_opts(announce)
           ),
         :ok <-
           maybe_store_path(
             state,
             announce.destination_hash,
             endpoint_hash(frame.endpoint),
             packet.hops,
             frame.interface
           ) do
      state
      |> clear_pending_path_request(announce.destination_hash)
      |> maybe_forward_announce(frame, packet, announce)
    else
      _ ->
        state
    end
  end

  defp route_control_packets(
         state,
         frame,
         _raw,
         %Packet{type: :data} = packet,
         _packet_hash,
         _packet_hash_full
       ) do
    case Pathfinder.parse_path_request_packet(packet) do
      {:ok, path_request} ->
        handle_path_request_packet(state, frame, packet, path_request)

      _ ->
        state
    end
  end

  defp route_control_packets(
         %{state_server: state_server} = state,
         frame,
         _raw,
         %Packet{type: :proof} = packet,
         proof_packet_hash,
         _packet_hash_full
       ) do
    case resolve_receipt_proof(state.packet_receipts, packet, state_server) do
      {:ok, receipt_hash, %{receipt: receipt} = entry} ->
        delivered_receipt = PacketReceipt.delivered(receipt, proof_packet_hash)
        emit_receipt_delivery(state.node_name, delivered_receipt)
        invoke_delivery_callback(entry.on_delivery, delivered_receipt)

        packet_receipts =
          Map.put(state.packet_receipts, receipt_hash, %{
            entry
            | receipt: delivered_receipt
          })

        %{state | packet_receipts: packet_receipts}

      :no_match ->
        maybe_forward_proof(state, frame, packet)

      {:error, reason} ->
        Observability.emit(
          [:transport, :proof, :invalid],
          %{count: 1},
          %{node: state.node_name, reason: reason},
          log_level: :debug
        )

        state
    end
  end

  defp route_control_packets(state, _frame, _raw, _packet, _packet_hash, _packet_hash_full),
    do: state

  defp clear_pending_path_request(state, destination_hash) when is_binary(destination_hash) do
    %{state | pending_path_requests: Map.delete(state.pending_path_requests, destination_hash)}
  end

  defp clear_pending_path_request(state, _destination_hash), do: state

  defp maybe_forward_announce(
         %{transport_enabled: true, announce_forwarding: true} = state,
         frame,
         %Packet{} = packet,
         announce
       ) do
    cond do
      packet.hops >= state.routing_max_hops ->
        state

      local_destination?(state.state_server, announce.destination_hash) ->
        state

      true ->
        state
        |> forward_packet_to_interfaces(
          next_hop_packet(packet),
          eligible_broadcast_interfaces(state, frame.interface)
        )
    end
  end

  defp maybe_forward_announce(state, _frame, _packet, _announce), do: state

  defp maybe_forward_path_request(
         %{transport_enabled: true, path_request_forwarding: true} = state,
         frame,
         %Packet{} = packet
       ) do
    if packet.hops >= state.routing_max_hops do
      state
    else
      forward_packet_to_interfaces(
        state,
        next_hop_packet(packet),
        eligible_path_request_interfaces(state, frame.interface)
      )
    end
  end

  defp maybe_forward_path_request(state, _frame, _packet), do: state

  defp maybe_forward_proof(
         %{transport_enabled: true, reverse_routes: reverse_routes} = state,
         frame,
         %Packet{addresses: [proof_destination_hash]} = packet
       )
       when is_binary(proof_destination_hash) do
    case Map.get(reverse_routes, proof_destination_hash) do
      %{interface: interface} when interface != frame.interface ->
        forward_packet_to_interfaces(state, next_hop_packet(packet), [interface])

      _ ->
        state
    end
  end

  defp maybe_forward_proof(state, _frame, _packet), do: state

  defp handle_path_request_packet(state, frame, packet, path_request) do
    case remember_inbound_path_request(state, frame.interface, path_request) do
      {:duplicate, updated_state} ->
        updated_state

      {:new, updated_state} ->
        answer_or_forward_path_request(updated_state, frame, packet, path_request)
    end
  end

  defp answer_or_forward_path_request(state, frame, packet, path_request) do
    case State.local_destination(state.state_server, path_request.destination_hash) do
      {:ok, local_destination} ->
        answer_path_request(state, frame, local_destination)

      :error ->
        maybe_forward_path_request(state, frame, packet)
    end
  end

  defp answer_path_request(state, frame, local_destination) do
    case Pathfinder.build_path_response_packet(local_destination) do
      {:ok, response_packet} ->
        case send_path_response(state, frame, response_packet) do
          {:ok, canonical_raw, transmitted_raw, ifac} ->
            publish_outbound_packet(state, frame.interface, canonical_raw, transmitted_raw, ifac)
            state

          _ ->
            state
        end

      _ ->
        state
    end
  end

  defp send_path_response(state, %{interface: interface, endpoint: {ip, port}}, packet_or_raw) do
    transmit_outbound(state, interface, packet_or_raw, ip: ip, port: port)
  end

  defp send_path_response(state, %{interface: interface}, packet_or_raw) do
    transmit_outbound(state, interface, packet_or_raw, [])
  end

  defp dispatch_to_local_destination(
         %{state_server: state_server, node_name: node_name} = state,
         frame,
         raw,
         %Packet{type: :data, addresses: [destination_hash | _]} = packet,
         packet_hash,
         packet_hash_full
       )
       when is_binary(destination_hash) do
    case State.local_destination(state_server, destination_hash) do
      {:ok, %{pid: pid} = local_destination} ->
        case PacketCrypto.decrypt_inbound(packet, local_destination) do
          {:ok, decrypted_packet} ->
            event = %{
              node: node_name,
              destination_hash: destination_hash,
              packet: decrypted_packet,
              packet_hash: packet_hash,
              raw: raw,
              interface: frame.interface,
              endpoint: frame.endpoint,
              at: frame.at
            }

            send(pid, {:reticulum, :destination_packet, event})
            maybe_invoke_destination_callback(local_destination, event)
            dispatch_message_hooks(state_server, destination_hash, decrypted_packet, event)
            maybe_send_proof(state, frame, local_destination, event, packet_hash_full)

          {:error, reason} ->
            publish_processing_error(state, frame, raw, packet, packet_hash, reason)
            state
        end

      :error ->
        state
    end
  end

  defp dispatch_to_local_destination(
         state,
         _frame,
         _raw,
         _packet,
         _packet_hash,
         _packet_hash_full
       ),
       do: state

  defp forward_transit_packet(
         %{transport_enabled: true} = state,
         frame,
         %Packet{type: type, addresses: [destination_hash | _]} = packet,
         packet_hash_full
       )
       when type in [:data, :link_request] and is_binary(destination_hash) do
    cond do
      local_destination?(state.state_server, destination_hash) ->
        state

      match?({:ok, _}, Pathfinder.parse_path_request_packet(packet)) ->
        state

      packet.hops >= state.routing_max_hops ->
        state

      true ->
        case select_transit_interface(state, destination_hash, frame.interface) do
          {:ok, interface} ->
            state
            |> remember_reverse_route(packet_hash_full, frame.interface)
            |> forward_packet_to_interfaces(next_hop_packet(packet), [interface])

          :error ->
            state
        end
    end
  end

  defp forward_transit_packet(state, _frame, _packet, _packet_hash_full), do: state

  defp select_transit_interface(state, destination_hash, ingress_interface) do
    case State.path(state.state_server, destination_hash) do
      {:ok, %{interface: interface}} when is_atom(interface) and interface != ingress_interface ->
        if interface_healthy?(state.state_server, interface) do
          {:ok, interface}
        else
          :error
        end

      _ ->
        :error
    end
  end

  defp maybe_store_path(state, destination_hash, next_hop, hops, interface)
       when is_binary(destination_hash) and is_binary(next_hop) and is_integer(hops) do
    candidate = %{hops: hops, interface: interface, updated_at: System.system_time(:second)}
    candidate_healthy = interface_healthy?(state.state_server, interface)

    current_path =
      case State.path(state.state_server, destination_hash) do
        {:ok, path} -> path
        _ -> nil
      end

    current_healthy =
      case current_path do
        %{interface: current_interface} ->
          interface_healthy?(state.state_server, current_interface)

        _ ->
          false
      end

    if Routing.prefer_candidate?(candidate, current_path,
         candidate_healthy: candidate_healthy,
         current_healthy: current_healthy
       ) do
      State.put_path(state.state_server, destination_hash, next_hop, hops, interface: interface)
    else
      :ok
    end
  end

  defp maybe_store_path(_state, _destination_hash, _next_hop, _hops, _interface),
    do: {:error, :invalid_path}

  defp eligible_broadcast_interfaces(state, ingress_interface) do
    case State.interfaces(state.state_server) do
      {:ok, interfaces} ->
        interfaces
        |> Enum.map(& &1.name)
        |> Enum.filter(&(&1 != ingress_interface and interface_healthy?(state.state_server, &1)))

      _ ->
        []
    end
  end

  defp eligible_path_request_interfaces(state, ingress_interface) do
    state
    |> eligible_broadcast_interfaces(ingress_interface)
    |> Enum.take(state.path_request_fanout)
  end

  defp interface_healthy?(state_server, interface) when is_atom(interface) do
    case State.interface(state_server, interface) do
      {:ok, %{pid: pid}} when is_pid(pid) -> Process.alive?(pid)
      _ -> false
    end
  end

  defp interface_healthy?(_state_server, _interface), do: false

  defp local_destination?(state_server, destination_hash) when is_binary(destination_hash) do
    match?({:ok, _}, State.local_destination(state_server, destination_hash))
  end

  defp local_destination?(_state_server, _destination_hash), do: false

  defp remember_reverse_route(state, packet_hash_full, ingress_interface)
       when is_binary(packet_hash_full) and is_atom(ingress_interface) do
    reverse_key = binary_part(packet_hash_full, 0, @truncated_hash_len)

    reverse_routes =
      Map.put(state.reverse_routes, reverse_key, %{
        interface: ingress_interface,
        updated_at: System.system_time(:second)
      })

    %{state | reverse_routes: reverse_routes}
  end

  defp remember_reverse_route(state, _packet_hash_full, _ingress_interface), do: state

  defp forward_packet_to_interfaces(state, _packet, []), do: state

  defp forward_packet_to_interfaces(state, %Packet{} = packet, interfaces) do
    Enum.reduce(interfaces, state, fn interface, acc ->
      case transmit_outbound(acc, interface, packet, []) do
        {:ok, canonical_raw, transmitted_raw, ifac} ->
          publish_outbound_packet(acc, interface, canonical_raw, transmitted_raw, ifac)
          acc

        _ ->
          acc
      end
    end)
  end

  defp next_hop_packet(%Packet{} = packet) do
    %{packet | hops: min(packet.hops + 1, 255)}
  end

  defp maybe_track_local_control_packet(state, canonical_raw) when is_binary(canonical_raw) do
    with {:ok, packet_hash} <- Packet.truncated_hash(canonical_raw),
         {:ok, packet} <- decode_packet(canonical_raw),
         true <- local_control_packet?(packet) do
      local_control_packets =
        Map.put(state.local_control_packets, packet_hash, System.system_time(:second))

      %{state | local_control_packets: local_control_packets}
    else
      _ -> state
    end
  end

  defp maybe_track_local_control_packet(state, _canonical_raw), do: state

  defp local_control_packet?(%Packet{type: :announce}), do: true

  defp local_control_packet?(%Packet{} = packet) do
    match?({:ok, _}, Pathfinder.parse_path_request_packet(packet))
  end

  defp local_control_packet?(_packet), do: false

  defp expire_timestamp_map(entries, now, ttl_seconds)
       when is_map(entries) and is_integer(now) and is_integer(ttl_seconds) and ttl_seconds > 0 do
    entries
    |> Enum.reject(fn {_key, value} -> timestamp_expired?(value, now, ttl_seconds) end)
    |> Map.new()
  end

  defp timestamp_expired?(%{updated_at: updated_at}, now, ttl_seconds)
       when is_integer(updated_at),
       do: now - updated_at > ttl_seconds

  defp timestamp_expired?(updated_at, now, ttl_seconds) when is_integer(updated_at),
    do: now - updated_at > ttl_seconds

  defp timestamp_expired?(_value, _now, _ttl_seconds), do: false

  defp dispatch_message_hooks(state_server, destination_hash, packet, event) do
    with {:ok, context} <- Context.normalize(packet.context) do
      case State.request_handler(state_server, destination_hash, context) do
        {:ok, %{pid: pid}} -> send(pid, {:reticulum, :request, event})
        _ -> :ok
      end

      case State.response_handler(state_server, destination_hash, context) do
        {:ok, %{pid: pid}} -> send(pid, {:reticulum, :response, event})
        _ -> :ok
      end
    end
  end

  defp maybe_invoke_destination_callback(%{callback: callback}, event)
       when is_function(callback, 1) do
    _ = callback.(event)
    :ok
  rescue
    _ -> :ok
  end

  defp maybe_invoke_destination_callback(_local_destination, _event), do: :ok

  defp maybe_send_proof(state, frame, local_destination, event, packet_hash_full) do
    with true <- proof_requested?(local_destination, event),
         {:ok, identity} <- proving_identity(local_destination),
         {:ok, proof_packet} <-
           Proofs.build_proof_packet(packet_hash_full, identity,
             implicit: state.use_implicit_proof
           ),
         {:ok, canonical_raw, transmitted_raw, ifac} <-
           send_path_response(state, frame, proof_packet) do
      publish_outbound_packet(state, frame.interface, canonical_raw, transmitted_raw, ifac)

      Observability.emit(
        [:transport, :proof, :sent],
        %{count: 1},
        %{node: state.node_name, interface: frame.interface},
        log_level: :debug
      )

      state
    else
      _reason -> state
    end
  end

  defp resolve_receipt_proof(packet_receipts, packet, state_server) do
    with {:ok, proof} <- Proofs.parse_proof_packet(packet) do
      packet_receipts
      |> receipt_candidate_hashes(proof)
      |> match_receipt_candidate(packet_receipts, proof, state_server)
    end
  end

  defp receipt_candidate_hashes(packet_receipts, %{
         mode: :explicit,
         proved_packet_hash: packet_hash
       })
       when is_binary(packet_hash) do
    case Map.has_key?(packet_receipts, packet_hash) do
      true -> [packet_hash]
      false -> []
    end
  end

  defp receipt_candidate_hashes(packet_receipts, %{mode: :implicit, proof_destination_hash: hash})
       when is_binary(hash) and byte_size(hash) == @truncated_hash_len do
    packet_receipts
    |> Enum.reduce([], fn {packet_hash, _entry}, acc ->
      if is_binary(packet_hash) and byte_size(packet_hash) >= @truncated_hash_len and
           binary_part(packet_hash, 0, @truncated_hash_len) == hash do
        [packet_hash | acc]
      else
        acc
      end
    end)
    |> Enum.reverse()
  end

  defp receipt_candidate_hashes(_packet_receipts, _proof), do: []

  defp match_receipt_candidate([], _packet_receipts, _proof, _state_server), do: :no_match

  defp match_receipt_candidate(candidate_hashes, packet_receipts, proof, state_server) do
    candidate_hashes
    |> Enum.reduce_while(%{attempted?: false, last_error: nil}, fn candidate_hash, acc ->
      reduce_receipt_candidate(candidate_hash, packet_receipts, proof, state_server, acc)
    end)
    |> case do
      {:ok, _candidate_hash, _entry} = success ->
        success

      %{attempted?: true, last_error: reason} when not is_nil(reason) ->
        {:error, reason}

      _ ->
        :no_match
    end
  end

  defp reduce_receipt_candidate(candidate_hash, packet_receipts, proof, state_server, acc) do
    with %{receipt: receipt} = entry <- Map.get(packet_receipts, candidate_hash),
         validation <- validate_receipt_candidate(proof, receipt, state_server) do
      receipt_candidate_result(validation, candidate_hash, entry, acc)
    else
      _ -> {:cont, acc}
    end
  end

  defp receipt_candidate_result(:ok, candidate_hash, entry, _acc),
    do: {:halt, {:ok, candidate_hash, entry}}

  defp receipt_candidate_result(:skip, _candidate_hash, _entry, acc), do: {:cont, acc}

  defp receipt_candidate_result({:error, reason}, _candidate_hash, _entry, _acc),
    do: {:cont, %{attempted?: true, last_error: reason}}

  defp validate_receipt_candidate(_proof, %PacketReceipt{status: status}, _state_server)
       when status != :sent,
       do: :skip

  defp validate_receipt_candidate(
         proof,
         %PacketReceipt{packet_hash: packet_hash, destination_hash: destination_hash},
         state_server
       ) do
    with {:ok, destination} <- State.destination(state_server, destination_hash),
         :ok <- Proofs.validate_proof(proof, destination.public_key, packet_hash) do
      :ok
    else
      :error -> {:error, :unknown_destination_for_receipt}
      {:error, reason} -> {:error, reason}
    end
  end

  defp proof_requested?(%{destination: %Destination{proof_strategy: :all}}, _event), do: true
  defp proof_requested?(%{destination: %Destination{proof_strategy: :none}}, _event), do: false

  defp proof_requested?(
         %{destination: %Destination{proof_strategy: :app}, proof_requested_callback: callback},
         event
       )
       when is_function(callback, 1) do
    callback.(event) == true
  rescue
    _ -> false
  end

  defp proof_requested?(%{destination: %Destination{}}, _event), do: false
  defp proof_requested?(_local_destination, _event), do: false

  defp proving_identity(%{destination: %Destination{identity: %Reticulum.Identity{} = identity}}) do
    if is_binary(identity.sig_sec) do
      {:ok, identity}
    else
      {:error, :missing_proof_signing_identity}
    end
  end

  defp proving_identity(_local_destination), do: {:error, :missing_proof_signing_identity}

  defp maybe_track_receipt(
         %{receipt_timeout_seconds: default_timeout, packet_receipts: packet_receipts} = state,
         destination_hash,
         raw,
         opts
       ) do
    track_receipt =
      Keyword.get(opts, :track_receipt, false) or
        is_function(Keyword.get(opts, :on_delivery), 1) or
        is_function(Keyword.get(opts, :on_timeout), 1)

    if track_receipt do
      timeout_seconds =
        normalize_positive_integer(Keyword.get(opts, :receipt_timeout_seconds), default_timeout)

      {:ok, packet_hash} = Packet.hash(raw)

      receipt = PacketReceipt.new(packet_hash, destination_hash, timeout_seconds)

      Observability.emit(
        [:transport, :receipt, :tracked],
        %{count: 1, timeout_seconds: timeout_seconds},
        %{node: state.node_name, destination_hash: destination_hash, receipt_hash: packet_hash},
        log_level: :debug
      )

      entry = %{
        receipt: receipt,
        on_delivery: normalize_callback(Keyword.get(opts, :on_delivery)),
        on_timeout: normalize_callback(Keyword.get(opts, :on_timeout))
      }

      {{:ok, packet_hash},
       %{state | packet_receipts: Map.put(packet_receipts, packet_hash, entry)}}
    else
      {:ok, state}
    end
  end

  defp normalize_callback(callback) when is_function(callback, 1), do: callback
  defp normalize_callback(_callback), do: nil

  defp expire_packet_receipts(packet_receipts, now_seconds, retention_seconds, node_name)
       when is_integer(now_seconds) and is_integer(retention_seconds) and retention_seconds > 0 and
              is_atom(node_name) do
    packet_receipts
    |> Enum.reduce(%{}, fn {packet_hash, %{receipt: receipt} = entry}, acc ->
      cond do
        PacketReceipt.timed_out?(receipt, now_seconds) ->
          failed_receipt = PacketReceipt.failed(receipt)
          emit_receipt_timeout(node_name, failed_receipt)
          invoke_timeout_callback(entry.on_timeout, failed_receipt)
          Map.put(acc, packet_hash, %{entry | receipt: failed_receipt})

        PacketReceipt.concluded?(receipt) and
          is_integer(receipt.concluded_at) and
            now_seconds - receipt.concluded_at > retention_seconds ->
          acc

        true ->
          Map.put(acc, packet_hash, entry)
      end
    end)
  end

  defp invoke_delivery_callback(callback, receipt) when is_function(callback, 1) do
    _ = callback.(receipt)
    :ok
  rescue
    _ -> :ok
  end

  defp invoke_delivery_callback(_callback, _receipt), do: :ok

  defp invoke_timeout_callback(callback, receipt) when is_function(callback, 1) do
    _ = callback.(receipt)
    :ok
  rescue
    _ -> :ok
  end

  defp invoke_timeout_callback(_callback, _receipt), do: :ok

  defp emit_receipt_delivery(node_name, %PacketReceipt{} = receipt) do
    Observability.emit(
      [:transport, :receipt, :delivered],
      %{count: 1},
      %{
        node: node_name,
        destination_hash: receipt.destination_hash,
        receipt_hash: receipt.packet_hash,
        proof_packet_hash: receipt.proof_packet_hash
      },
      log_level: :debug
    )
  end

  defp emit_receipt_timeout(node_name, %PacketReceipt{} = receipt) do
    Observability.emit(
      [:transport, :receipt, :timed_out],
      %{count: 1},
      %{
        node: node_name,
        destination_hash: receipt.destination_hash,
        receipt_hash: receipt.packet_hash
      },
      log_level: :debug
    )
  end

  defp send_on_interface(node_name, interface_name, raw, opts) do
    send_opts =
      Keyword.drop(opts, [
        :requester_hash,
        :request_tag,
        :ifac,
        :track_receipt,
        :on_delivery,
        :on_timeout,
        :receipt_timeout_seconds
      ])

    with {:ok, %{payload: payload, ifac: ifac}} <-
           InterfaceSupervisor.prepare_outbound(node_name, interface_name, raw, opts),
         :ok <- InterfaceSupervisor.send_frame(node_name, interface_name, payload, send_opts) do
      {:ok, %{payload: payload, ifac: ifac}}
    end
  end

  defp transmit_outbound(state, interface_name, packet_or_raw, opts) do
    with {:ok, canonical_raw} <- canonical_outbound_raw(packet_or_raw),
         {:ok, %{payload: transmitted_raw, ifac: ifac}} <-
           send_on_interface(
             state.node_name,
             interface_name,
             canonical_raw,
             outbound_ifac_opts(packet_or_raw, opts)
           ) do
      {:ok, canonical_raw, transmitted_raw, ifac}
    end
  end

  defp canonical_outbound_raw(%Packet{} = packet) do
    encode_packet(%{packet | ifac: :open})
  end

  defp canonical_outbound_raw(raw) when is_binary(raw), do: {:ok, raw}
  defp canonical_outbound_raw(_packet_or_raw), do: {:error, :invalid_packet}

  defp outbound_ifac_opts(%Packet{ifac: :auth}, opts), do: Keyword.put_new(opts, :ifac, :auth)
  defp outbound_ifac_opts(_packet_or_raw, opts), do: opts

  defp encode_packet(%Packet{} = packet), do: {:ok, Packet.encode(packet)}
  defp encode_packet(raw) when is_binary(raw), do: {:ok, raw}
  defp encode_packet(_packet_or_raw), do: {:error, :invalid_packet}

  defp decode_packet(raw) when is_binary(raw) do
    try do
      {:ok, Packet.decode(raw)}
    rescue
      _ -> {:error, :invalid_packet}
    end
  end

  defp build_data_packet(destination_hash, payload, opts) do
    ifac = Keyword.get(opts, :ifac, :open)
    propagation = Keyword.get(opts, :propagation, :broadcast)
    destination = Keyword.get(opts, :destination, :single)
    type = Keyword.get(opts, :type, :data)
    hops = Keyword.get(opts, :hops, 0)
    context = Keyword.get(opts, :context, Context.none())

    with :ok <- validate_ifac(ifac),
         :ok <- validate_propagation(propagation),
         :ok <- validate_packet_destination(destination),
         :ok <- validate_packet_type(type),
         :ok <- validate_hops(hops),
         {:ok, context} <- Context.normalize(context) do
      {:ok,
       %Packet{
         ifac: ifac,
         propagation: propagation,
         destination: destination,
         type: type,
         hops: hops,
         addresses: [destination_hash],
         context: context,
         data: payload
       }}
    end
  end

  defp fetch_destination(state_server, destination_hash) do
    case State.destination(state_server, destination_hash) do
      {:ok, destination_record} -> {:ok, destination_record}
      :error -> {:error, :unknown_destination}
    end
  end

  defp validate_destination_hash(hash)
       when is_binary(hash) and byte_size(hash) == @truncated_hash_len,
       do: :ok

  defp validate_destination_hash(_hash), do: {:error, :invalid_destination_hash}

  defp publish_outbound_packet(
         %{state_server: state_server, node_name: node_name},
         interface,
         canonical_raw,
         transmitted_raw,
         ifac
       ) do
    case decode_packet(canonical_raw) do
      {:ok, packet} ->
        {:ok, packet_hash} = Packet.truncated_hash(canonical_raw)

        State.publish_packet(state_server, %{
          interface: interface,
          packet: %{packet | ifac: ifac},
          packet_hash: packet_hash,
          duplicate: false,
          endpoint: nil,
          node: node_name,
          reason: nil,
          raw: transmitted_raw,
          direction: :outbound,
          at: System.system_time(:millisecond)
        })

      {:error, _reason} ->
        :ok
    end
  end

  defp publish_inbound_packet(
         %{state_server: state_server, node_name: node_name},
         frame,
         raw,
         packet,
         packet_hash,
         duplicate
       ) do
    known_destination = known_destination?(state_server, packet)

    State.publish_packet(state_server, %{
      interface: frame.interface,
      packet: packet,
      packet_hash: packet_hash,
      duplicate: duplicate,
      endpoint: frame.endpoint,
      node: node_name,
      reason: nil,
      raw: raw,
      direction: :inbound,
      known_destination: known_destination,
      at: frame.at
    })
  end

  defp publish_decode_error(
         %{state_server: state_server, node_name: node_name},
         frame,
         raw,
         reason
       ) do
    State.publish_packet(state_server, %{
      interface: frame.interface,
      packet: nil,
      packet_hash: nil,
      duplicate: false,
      endpoint: frame.endpoint,
      node: node_name,
      reason: reason,
      raw: raw,
      direction: :inbound,
      known_destination: false,
      at: frame.at
    })
  end

  defp publish_processing_error(
         %{state_server: state_server, node_name: node_name},
         frame,
         raw,
         packet,
         packet_hash,
         reason
       ) do
    State.publish_packet(state_server, %{
      interface: frame.interface,
      packet: packet,
      packet_hash: packet_hash,
      duplicate: false,
      endpoint: frame.endpoint,
      node: node_name,
      reason: reason,
      raw: raw,
      direction: :inbound,
      known_destination: true,
      at: frame.at
    })
  end

  defp known_destination?(
         state_server,
         %Packet{addresses: [destination_hash | _]}
       )
       when is_binary(destination_hash) do
    match?({:ok, _}, State.destination(state_server, destination_hash))
  end

  defp known_destination?(_state_server, _packet), do: false

  defp endpoint_hash({ip, port}) do
    <<hash::binary-size(@truncated_hash_len), _rest::binary>> =
      {ip, port}
      |> :erlang.term_to_binary()
      |> Crypto.sha256()

    hash
  end

  defp endpoint_hash(_endpoint), do: <<0::128>>

  defp announce_destination_opts(%{ratchet: ratchet})
       when is_binary(ratchet) and byte_size(ratchet) == 32 do
    [ratchet: ratchet, ratchet_received_at: System.system_time(:second)]
  end

  defp announce_destination_opts(_announce), do: [ratchet: nil, ratchet_received_at: nil]

  defp now_ms, do: System.monotonic_time(:millisecond)

  defp reuse_pending_path_request?(state, destination_hash, interface_name, now_ms)
       when is_binary(destination_hash) and is_atom(interface_name) and is_integer(now_ms) do
    min_interval_ms = state.path_request_min_interval_seconds * 1_000

    case Map.get(state.pending_path_requests, destination_hash) do
      %{interface: ^interface_name, last_sent_at_ms: last_sent_at_ms} = entry ->
        not pending_path_request_expired?(entry, now_ms) and
          now_ms - last_sent_at_ms < min_interval_ms

      _ ->
        false
    end
  end

  defp reuse_pending_path_request?(_state, _destination_hash, _interface_name, _now_ms), do: false

  defp new_pending_path_request(
         state,
         destination_hash,
         interface_name,
         requester_hash,
         request_tag,
         now_ms
       ) do
    %{
      destination_hash: destination_hash,
      requester_hash: requester_hash,
      interface: interface_name,
      request_tag: request_tag,
      first_sent_at_ms: now_ms,
      last_sent_at_ms: now_ms,
      next_retry_at_ms: next_retry_at_ms(state, now_ms, 0),
      retries_sent: 0,
      expires_at_ms: now_ms + state.path_request_timeout_seconds * 1_000
    }
  end

  defp emit_path_request(
         state,
         interface_name,
         destination_hash,
         requester_hash,
         request_tag,
         opts
       ) do
    with {:ok, packet} <-
           Pathfinder.build_path_request_packet(
             destination_hash,
             requester_hash: requester_hash,
             request_tag: request_tag
           ),
         {:ok, canonical_raw, transmitted_raw, ifac} <-
           transmit_outbound(state, interface_name, packet, opts) do
      updated_state =
        state
        |> maybe_track_local_control_packet(canonical_raw)
        |> remember_path_request_key(destination_hash, request_tag, interface_name)

      publish_outbound_packet(updated_state, interface_name, canonical_raw, transmitted_raw, ifac)
      {:ok, updated_state}
    end
  end

  defp retry_pending_path_requests(state) do
    now_ms = now_ms()

    {pending_path_requests, updated_state} =
      Enum.reduce(state.pending_path_requests, {%{}, state}, fn {destination_hash, entry},
                                                                {pending_acc, acc_state} ->
        case maybe_retry_pending_path_request(acc_state, destination_hash, entry, now_ms) do
          {:drop, next_state} ->
            {pending_acc, next_state}

          {:keep, next_entry, next_state} ->
            {Map.put(pending_acc, destination_hash, next_entry), next_state}
        end
      end)

    %{updated_state | pending_path_requests: pending_path_requests}
  end

  defp maybe_retry_pending_path_request(state, _destination_hash, entry, now_ms)
       when is_integer(now_ms) do
    cond do
      pending_path_request_expired?(entry, now_ms) ->
        {:drop, state}

      is_nil(entry.next_retry_at_ms) or now_ms < entry.next_retry_at_ms ->
        {:keep, entry, state}

      entry.retries_sent >= state.path_request_retry_count ->
        {:keep, %{entry | next_retry_at_ms: nil}, state}

      true ->
        retry_pending_path_request(state, entry, now_ms)
    end
  end

  defp retry_pending_path_request(state, entry, now_ms) do
    request_tag = :crypto.strong_rand_bytes(@truncated_hash_len)

    case emit_path_request(
           state,
           entry.interface,
           entry.destination_hash,
           entry.requester_hash,
           request_tag,
           []
         ) do
      {:ok, updated_state} ->
        retries_sent = entry.retries_sent + 1

        updated_entry = %{
          entry
          | request_tag: request_tag,
            last_sent_at_ms: now_ms,
            next_retry_at_ms: next_retry_at_ms(state, now_ms, retries_sent),
            retries_sent: retries_sent
        }

        {:keep, updated_entry, updated_state}

      {:error, _reason} ->
        deferred_entry = %{entry | next_retry_at_ms: now_ms + 1_000}
        {:keep, deferred_entry, state}
    end
  end

  defp next_retry_at_ms(state, now_ms, retries_sent)
       when is_integer(now_ms) and is_integer(retries_sent) do
    if retries_sent < state.path_request_retry_count do
      retry_delay_ms =
        state.path_request_retry_base_seconds *
          Integer.pow(state.path_request_retry_backoff_factor, retries_sent) * 1_000

      now_ms + retry_delay_ms
    else
      nil
    end
  end

  defp expire_pending_path_requests(pending_path_requests, now_ms)
       when is_map(pending_path_requests) and is_integer(now_ms) do
    pending_path_requests
    |> Enum.reject(fn {_destination_hash, entry} ->
      pending_path_request_expired?(entry, now_ms)
    end)
    |> Map.new()
  end

  defp pending_path_request_expired?(%{expires_at_ms: expires_at_ms}, now_ms)
       when is_integer(expires_at_ms) and is_integer(now_ms),
       do: now_ms >= expires_at_ms

  defp pending_path_request_expired?(_entry, _now_ms), do: false

  defp remember_inbound_path_request(state, ingress_interface, path_request) do
    request_key = Pathfinder.request_key(path_request.destination_hash, path_request.request_tag)
    now_ms = now_ms()
    ttl_ms = state.path_request_duplicate_ttl_seconds * 1_000

    case Map.get(state.seen_path_requests, request_key) do
      %{updated_at_ms: updated_at_ms} ->
        if now_ms - updated_at_ms < ttl_ms do
          {:duplicate, state}
        else
          {:new,
           put_in(state.seen_path_requests[request_key], %{
             interface: ingress_interface,
             updated_at_ms: now_ms
           })}
        end

      _ ->
        {:new,
         put_in(state.seen_path_requests[request_key], %{
           interface: ingress_interface,
           updated_at_ms: now_ms
         })}
    end
  end

  defp remember_path_request_key(state, destination_hash, request_tag, interface)
       when is_binary(destination_hash) and is_binary(request_tag) do
    request_key = Pathfinder.request_key(destination_hash, request_tag)

    put_in(state.seen_path_requests[request_key], %{
      interface: interface,
      updated_at_ms: now_ms()
    })
  end

  defp remember_path_request_key(state, _destination_hash, _request_tag, _interface), do: state

  defp expire_seen_path_requests(seen_path_requests, now_ms, ttl_seconds)
       when is_map(seen_path_requests) and is_integer(now_ms) and is_integer(ttl_seconds) and
              ttl_seconds > 0 do
    ttl_ms = ttl_seconds * 1_000

    seen_path_requests
    |> Enum.reject(fn {_request_key, %{updated_at_ms: updated_at_ms}} ->
      now_ms - updated_at_ms >= ttl_ms
    end)
    |> Map.new()
  end

  defp expire_seen_path_requests(seen_path_requests, _now_ms, _ttl_seconds),
    do: seen_path_requests

  defp normalize_positive_integer(value, _default) when is_integer(value) and value > 0, do: value
  defp normalize_positive_integer(_value, default), do: default

  defp normalize_non_negative_integer(value, _default) when is_integer(value) and value >= 0,
    do: value

  defp normalize_non_negative_integer(_value, default), do: default

  defp validate_ifac(ifac) when ifac in [:open, :auth], do: :ok
  defp validate_ifac(_ifac), do: {:error, :invalid_ifac}

  defp validate_propagation(propagation) when propagation in [:broadcast, :transport], do: :ok
  defp validate_propagation(_propagation), do: {:error, :invalid_propagation}

  defp validate_packet_destination(destination)
       when destination in [:single, :group, :plain, :link],
       do: :ok

  defp validate_packet_destination(_destination), do: {:error, :invalid_destination_type}

  defp validate_packet_type(type) when type in [:data, :announce, :link_request, :proof], do: :ok
  defp validate_packet_type(_type), do: {:error, :invalid_packet_type}

  defp validate_hops(hops) when is_integer(hops) and hops >= 0 and hops <= 255, do: :ok
  defp validate_hops(_hops), do: {:error, :invalid_hops}

  defp schedule_path_maintenance(interval_seconds) do
    Process.send_after(self(), :path_maintenance, interval_seconds * 1_000)
  end

  defp schedule_path_request_retry_check do
    Process.send_after(self(), :path_request_retry_check, @path_request_retry_check_interval_ms)
  end
end
