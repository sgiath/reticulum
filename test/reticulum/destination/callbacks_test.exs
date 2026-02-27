defmodule Reticulum.Destination.CallbacksTest do
  use ExUnit.Case, async: false

  alias Reticulum.Destination
  alias Reticulum.Destination.Callbacks
  alias Reticulum.Identity
  alias Reticulum.Node
  alias Reticulum.Node.State

  setup do
    node_name = Reticulum.Node.DestinationCallbacks

    start_supervised!(
      {Node,
       name: node_name,
       storage_path: Path.join(System.tmp_dir!(), "reticulum-destination-callbacks")}
    )

    {:ok, node_name: node_name}
  end

  test "registers callback for destination hash", %{node_name: node_name} do
    destination_hash = :crypto.strong_rand_bytes(16)
    parent = self()

    callback = fn event -> send(parent, {:callback_invoked, event.destination_hash}) end

    assert :ok =
             Callbacks.register(node_name, destination_hash, callback,
               pid: self(),
               app_data: "callback-data"
             )

    state_server = Node.state_server(node_name)

    assert {:ok, registration} =
             State.local_destination(state_server, destination_hash)

    assert registration.pid == self()
    assert registration.destination == nil
    assert registration.app_data == "callback-data"

    registration.callback.(%{destination_hash: destination_hash})
    assert_receive {:callback_invoked, ^destination_hash}, 1_000

    assert :ok = Callbacks.unregister(node_name, destination_hash)
    assert :error = State.local_destination(state_server, destination_hash)
  end

  test "registers announce destination callback", %{node_name: node_name} do
    identity = Identity.new()
    {:ok, destination} = Destination.new(:in, :single, "callbacks", identity, ["announce"])
    {:ok, destination} = Destination.set_proof_strategy(destination, :app)

    parent = self()
    callback = fn event -> send(parent, {:announce_callback, event.destination_hash}) end

    proof_requested_callback = fn event ->
      send(parent, {:proof_requested, event.destination_hash})
    end

    assert :ok =
             Callbacks.register(node_name, destination, callback,
               pid: self(),
               proof_requested_callback: proof_requested_callback,
               app_data: "announce-app-data"
             )

    state_server = Node.state_server(node_name)

    assert {:ok, registration} =
             State.local_destination(state_server, destination.hash)

    destination_hash = destination.hash

    assert registration.pid == self()
    assert registration.destination.hash == destination.hash
    assert registration.app_data == "announce-app-data"
    assert registration.proof_requested_callback == proof_requested_callback

    registration.callback.(%{destination_hash: destination_hash})
    assert_receive {:announce_callback, ^destination_hash}, 1_000

    registration.proof_requested_callback.(%{destination_hash: destination_hash})
    assert_receive {:proof_requested, ^destination_hash}, 1_000
  end

  test "default node register and unregister wrappers work" do
    if is_nil(Process.whereis(Node)) do
      start_supervised!(
        Supervisor.child_spec(
          {Node,
           storage_path: Path.join(System.tmp_dir!(), "reticulum-destination-callbacks-default")},
          id: :destination_callbacks_default_node
        )
      )
    end

    destination_hash = :crypto.strong_rand_bytes(16)
    callback = fn _event -> :ok end

    assert :ok = Callbacks.register(destination_hash, callback, pid: self())

    assert {:ok, _registration} =
             Node.state_server()
             |> State.local_destination(destination_hash)

    assert :ok = Callbacks.unregister(destination_hash)

    assert :error =
             Node.state_server()
             |> State.local_destination(destination_hash)
  end
end
