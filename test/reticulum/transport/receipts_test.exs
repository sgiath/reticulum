defmodule Reticulum.Transport.ReceiptsTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.PacketReceipt

  @loopback {127, 0, 0, 1}

  setup context do
    node_a = Reticulum.Node.TransportPhase6A
    node_b = Reticulum.Node.TransportPhase6B
    use_implicit_proof = Map.get(context, :use_implicit_proof, true)

    start_supervised!(
      Supervisor.child_spec(
        {Node,
         name: node_a,
         storage_path: Path.join(System.tmp_dir!(), "reticulum-phase6-a"),
         use_implicit_proof: use_implicit_proof,
         path_gc_interval_seconds: 1,
         receipt_timeout_seconds: 1,
         receipt_retention_seconds: 30},
        id: node_a
      )
    )

    start_supervised!(
      Supervisor.child_spec(
        {Node,
         name: node_b,
         storage_path: Path.join(System.tmp_dir!(), "reticulum-phase6-b"),
         use_implicit_proof: use_implicit_proof,
         path_gc_interval_seconds: 1,
         receipt_timeout_seconds: 1,
         receipt_retention_seconds: 30},
        id: node_b
      )
    )

    port_a = free_udp_port()
    port_b = free_udp_port()

    assert {:ok, _pid} =
             Node.start_udp_interface(node_a,
               name: :link,
               listen_ip: @loopback,
               listen_port: port_a,
               default_peer_ip: @loopback,
               default_peer_port: port_b
             )

    assert {:ok, _pid} =
             Node.start_udp_interface(node_b,
               name: :link,
               listen_ip: @loopback,
               listen_port: port_b,
               default_peer_ip: @loopback,
               default_peer_port: port_a
             )

    {:ok, node_a: node_a, node_b: node_b}
  end

  test "tracks receipt and marks delivered when implicit proof is validated", %{
    node_a: node_a,
    node_b: node_b
  } do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase6", identity, ["proof-implicit"])
    {:ok, destination} = Destination.set_proof_strategy(destination, :all)

    assert :ok = Node.register_local_announce_destination(node_b, destination, self())

    assert :ok =
             Node.put_destination(
               node_a,
               destination.hash,
               identity.enc_pub <> identity.sig_pub,
               nil
             )

    caller = self()

    assert {:ok, receipt_hash} =
             Node.send_data(node_a, :link, destination.hash, "phase6-delivery-implicit",
               track_receipt: true,
               receipt_timeout_seconds: 2,
               on_delivery: fn receipt ->
                 send(caller, {:delivery, receipt.packet_hash, receipt.status})
               end
             )

    assert_receive {:delivery, ^receipt_hash, :delivered}, 2_000

    assert {:ok, %PacketReceipt{} = receipt} = Node.receipt(node_a, receipt_hash)
    assert receipt.status == :delivered
    assert receipt.proof_packet_hash != nil
  end

  @tag use_implicit_proof: false
  test "tracks receipt and marks delivered when explicit proof is validated", %{
    node_a: node_a,
    node_b: node_b
  } do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase6", identity, ["proof-explicit"])
    {:ok, destination} = Destination.set_proof_strategy(destination, :all)

    assert :ok = Node.register_local_announce_destination(node_b, destination, self())

    assert :ok =
             Node.put_destination(
               node_a,
               destination.hash,
               identity.enc_pub <> identity.sig_pub,
               nil
             )

    caller = self()

    assert {:ok, receipt_hash} =
             Node.send_data(node_a, :link, destination.hash, "phase6-delivery-explicit",
               track_receipt: true,
               receipt_timeout_seconds: 2,
               on_delivery: fn receipt ->
                 send(caller, {:delivery, receipt.packet_hash, receipt.status})
               end
             )

    assert_receive {:delivery, ^receipt_hash, :delivered}, 2_000

    assert {:ok, %PacketReceipt{} = receipt} = Node.receipt(node_a, receipt_hash)
    assert receipt.status == :delivered
    assert receipt.proof_packet_hash != nil
  end

  test "proof strategy app sends proof when callback returns true", %{
    node_a: node_a,
    node_b: node_b
  } do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase6", identity, ["proof-app-true"])
    {:ok, destination} = Destination.set_proof_strategy(destination, :app)

    caller = self()

    assert :ok =
             Node.register_local_announce_destination(node_b, destination, self(),
               proof_requested_callback: fn event ->
                 send(caller, {:proof_requested, event.destination_hash, event.packet.data})
                 true
               end
             )

    assert :ok =
             Node.put_destination(
               node_a,
               destination.hash,
               identity.enc_pub <> identity.sig_pub,
               nil
             )

    assert {:ok, receipt_hash} =
             Node.send_data(node_a, :link, destination.hash, "phase6-proof-app-true",
               track_receipt: true,
               receipt_timeout_seconds: 2
             )

    assert_receive {:proof_requested, destination_hash, "phase6-proof-app-true"}, 1_000
    assert destination_hash == destination.hash

    assert_receive {:reticulum, :destination_packet, %{destination_hash: ^destination_hash}},
                   1_000

    assert_eventually(fn ->
      match?({:ok, %PacketReceipt{status: :delivered}}, Node.receipt(node_a, receipt_hash))
    end)
  end

  test "proof strategy app does not send proof when callback returns false", %{
    node_a: node_a,
    node_b: node_b
  } do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "phase6", identity, ["proof-app-false"])
    {:ok, destination} = Destination.set_proof_strategy(destination, :app)

    caller = self()

    assert :ok =
             Node.register_local_announce_destination(node_b, destination, self(),
               proof_requested_callback: fn event ->
                 send(caller, {:proof_requested, event.destination_hash, event.packet.data})
                 false
               end
             )

    assert :ok =
             Node.put_destination(
               node_a,
               destination.hash,
               identity.enc_pub <> identity.sig_pub,
               nil
             )

    caller = self()

    assert {:ok, receipt_hash} =
             Node.send_data(node_a, :link, destination.hash, "phase6-proof-app-false",
               track_receipt: true,
               receipt_timeout_seconds: 1,
               on_timeout: fn receipt ->
                 send(caller, {:timeout, receipt.packet_hash, receipt.status})
               end
             )

    assert_receive {:proof_requested, destination_hash, "phase6-proof-app-false"}, 1_000
    assert destination_hash == destination.hash

    force_receipt_timeout(node_a, receipt_hash)
    assert_receive {:timeout, ^receipt_hash, :failed}, 1_000

    assert {:ok, %PacketReceipt{} = receipt} = Node.receipt(node_a, receipt_hash)
    assert receipt.status == :failed
  end

  test "marks receipt failed on timeout and invokes timeout callback", %{
    node_a: node_a,
    node_b: _node_b
  } do
    destination_hash = :crypto.strong_rand_bytes(16)
    public_key = :crypto.strong_rand_bytes(64)

    assert :ok = Node.put_destination(node_a, destination_hash, public_key, nil)

    caller = self()

    assert {:ok, receipt_hash} =
             Node.send_data(node_a, :link, destination_hash, "phase6-timeout",
               track_receipt: true,
               receipt_timeout_seconds: 1,
               on_timeout: fn receipt ->
                 send(caller, {:timeout, receipt.packet_hash, receipt.status})
               end
             )

    force_receipt_timeout(node_a, receipt_hash)

    assert_receive {:timeout, ^receipt_hash, :failed}, 1_000

    assert {:ok, %PacketReceipt{} = receipt} = Node.receipt(node_a, receipt_hash)
    assert receipt.status == :failed
  end

  defp force_receipt_timeout(node_name, receipt_hash) do
    transport_server = Node.transport_server(node_name)

    :sys.replace_state(transport_server, fn state ->
      case Map.fetch(state.packet_receipts, receipt_hash) do
        {:ok, %{receipt: receipt} = entry} ->
          backdated_entry = %{entry | receipt: %{receipt | sent_at: receipt.sent_at - 5}}

          %{
            state
            | packet_receipts: Map.put(state.packet_receipts, receipt_hash, backdated_entry)
          }

        :error ->
          state
      end
    end)

    transport_pid = :global.whereis_name({Reticulum.Node, :transport, node_name})
    assert is_pid(transport_pid)

    send(transport_pid, :path_maintenance)
  end

  defp assert_eventually(fun, retries \\ 40)

  defp assert_eventually(fun, retries) when retries > 0 do
    if fun.() do
      :ok
    else
      Process.sleep(25)
      assert_eventually(fun, retries - 1)
    end
  end

  defp assert_eventually(_fun, 0), do: flunk("condition was not met")

  defp free_udp_port do
    {:ok, socket} = :gen_udp.open(0, [:binary, {:active, false}, {:ip, @loopback}])
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_udp.close(socket)
    port
  end
end
