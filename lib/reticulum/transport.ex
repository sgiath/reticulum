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

  @truncated_hash_len 16
  @default_path_ttl_seconds 300
  @default_path_gc_interval_seconds 5
  @default_receipt_timeout_seconds 10
  @default_receipt_retention_seconds 60
  @default_ratchet_expiry_seconds 2_592_000
  @pending_path_request_ttl_seconds 30

  @type state :: %{
          node_name: atom(),
          state_server: GenServer.server(),
          transport_enabled: boolean(),
          use_implicit_proof: boolean(),
          pending_path_requests: %{binary() => integer()},
          path_ttl_seconds: pos_integer(),
          path_gc_interval_seconds: pos_integer(),
          receipt_timeout_seconds: pos_integer(),
          receipt_retention_seconds: pos_integer(),
          ratchet_expiry_seconds: pos_integer(),
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

    :ok = State.subscribe_frames(state_server, self())
    schedule_path_maintenance(path_gc_interval_seconds)

    {:ok,
     %{
       node_name: node_name,
       state_server: state_server,
       transport_enabled: transport_enabled,
       use_implicit_proof: use_implicit_proof,
       pending_path_requests: %{},
       path_ttl_seconds: path_ttl_seconds,
       path_gc_interval_seconds: path_gc_interval_seconds,
       receipt_timeout_seconds: receipt_timeout_seconds,
       receipt_retention_seconds: receipt_retention_seconds,
       ratchet_expiry_seconds: ratchet_expiry_seconds,
       packet_receipts: %{}
     }}
  end

  @impl true
  def handle_call({:send_packet, interface_name, packet_or_raw, opts}, _from, state) do
    with {:ok, raw} <- encode_packet(packet_or_raw),
         :ok <- send_on_interface(state.node_name, interface_name, raw, opts) do
      publish_outbound_packet(state, interface_name, raw)
      {:reply, :ok, state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, other, state}
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
         {:ok, raw} <- encode_packet(encrypted_packet),
         :ok <- send_on_interface(state.node_name, interface_name, raw, opts) do
      publish_outbound_packet(state, interface_name, raw)

      {reply, updated_state} = maybe_track_receipt(state, destination_hash, raw, opts)
      {:reply, reply, updated_state}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, other, state}
    end
  end

  def handle_call({:request_path, interface_name, destination_hash, opts}, _from, state) do
    requester_hash = Keyword.get(opts, :requester_hash, nil)
    request_tag = Keyword.get(opts, :request_tag, :crypto.strong_rand_bytes(@truncated_hash_len))

    with {:ok, packet} <-
           Pathfinder.build_path_request_packet(
             destination_hash,
             requester_hash: requester_hash,
             request_tag: request_tag
           ),
         {:ok, raw} <- encode_packet(packet),
         :ok <- send_on_interface(state.node_name, interface_name, raw, opts) do
      publish_outbound_packet(state, interface_name, raw)

      pending =
        Map.put(state.pending_path_requests, destination_hash, System.system_time(:second))

      {:reply, {:ok, request_tag}, %{state | pending_path_requests: pending}}
    else
      {:error, reason} -> {:reply, {:error, reason}, state}
      other -> {:reply, other, state}
    end
  end

  def handle_call(
        {:announce_destination, interface_name, destination_hash, opts},
        _from,
        %{state_server: state_server} = state
      ) do
    with {:ok, local_destination} <- State.local_destination(state_server, destination_hash),
         {:ok, response_packet} <- Pathfinder.build_path_response_packet(local_destination, opts),
         {:ok, response_raw} <- encode_packet(response_packet),
         :ok <- send_on_interface(state.node_name, interface_name, response_raw, opts) do
      publish_outbound_packet(state, interface_name, response_raw)
      {:reply, :ok, state}
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

    pending_path_requests =
      state.pending_path_requests
      |> Enum.reject(fn {_destination_hash, requested_at} ->
        now - requested_at > @pending_path_request_ttl_seconds
      end)
      |> Map.new()

    packet_receipts =
      expire_packet_receipts(
        state.packet_receipts,
        now,
        state.receipt_retention_seconds,
        state.node_name
      )

    schedule_path_maintenance(state.path_gc_interval_seconds)

    {:noreply,
     %{state | pending_path_requests: pending_path_requests, packet_receipts: packet_receipts}}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp process_inbound_frame(%{payload: raw} = frame, %{state_server: state_server} = state)
       when is_binary(raw) do
    with {:ok, packet_hash_full} <- Packet.hash(raw),
         {:ok, packet_hash} <- Packet.truncated_hash(raw),
         {:ok, packet} <- decode_packet(raw) do
      duplicate = State.remember_packet_hash(state_server, packet_hash) == :existing

      publish_inbound_packet(state, frame, raw, packet, packet_hash, duplicate)

      if duplicate do
        state
      else
        state
        |> route_control_packets(frame, raw, packet, packet_hash, packet_hash_full)
        |> dispatch_to_local_destination(frame, raw, packet, packet_hash, packet_hash_full)
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
           State.put_path(
             state.state_server,
             announce.destination_hash,
             endpoint_hash(frame.endpoint),
             packet.hops,
             interface: frame.interface
           ) do
      %{
        state
        | pending_path_requests:
            Map.delete(state.pending_path_requests, announce.destination_hash)
      }
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
    with {:ok, path_request} <- Pathfinder.parse_path_request_packet(packet),
         {:ok, local_destination} <-
           State.local_destination(state.state_server, path_request.destination_hash),
         {:ok, response_packet} <- Pathfinder.build_path_response_packet(local_destination),
         {:ok, response_raw} <- encode_packet(response_packet),
         :ok <- send_path_response(state, frame, response_raw) do
      publish_outbound_packet(state, frame.interface, response_raw)
      state
    else
      _ ->
        state
    end
  end

  defp route_control_packets(
         %{state_server: state_server} = state,
         _frame,
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
        state

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

  defp send_path_response(state, %{interface: interface, endpoint: {ip, port}}, raw) do
    InterfaceSupervisor.send_frame(state.node_name, interface, raw, ip: ip, port: port)
  end

  defp send_path_response(state, %{interface: interface}, raw) do
    InterfaceSupervisor.send_frame(state.node_name, interface, raw, [])
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
         {:ok, raw} <- encode_packet(proof_packet),
         :ok <- send_path_response(state, frame, raw) do
      publish_outbound_packet(state, frame.interface, raw)

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
        :track_receipt,
        :on_delivery,
        :on_timeout,
        :receipt_timeout_seconds
      ])

    InterfaceSupervisor.send_frame(node_name, interface_name, raw, send_opts)
  end

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
         raw
       ) do
    case decode_packet(raw) do
      {:ok, packet} ->
        {:ok, packet_hash} = Packet.truncated_hash(raw)

        State.publish_packet(state_server, %{
          interface: interface,
          packet: packet,
          packet_hash: packet_hash,
          duplicate: false,
          endpoint: nil,
          node: node_name,
          reason: nil,
          raw: raw,
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

  defp normalize_positive_integer(value, _default) when is_integer(value) and value > 0, do: value
  defp normalize_positive_integer(_value, default), do: default

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
end
