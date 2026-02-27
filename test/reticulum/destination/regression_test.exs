defmodule Reticulum.DestinationRegressionTest do
  use ExUnit.Case, async: true

  describe "Reticulum.Destination" do
    test "outbound non-plain destination requires identity" do
      assert Reticulum.Destination.new(:out, :single, "app") == {:error, :missing_identity}
    end

    test "group key lifecycle APIs" do
      {:ok, destination} = Reticulum.Destination.new(:in, :group, "app", nil, ["group"])

      assert {:error, :missing_group_key} = Reticulum.Destination.group_key(destination)

      assert {:ok, destination} = Reticulum.Destination.create_group_key(destination)
      assert {:ok, key} = Reticulum.Destination.group_key(destination)
      assert byte_size(key) == 64

      loaded_key = :crypto.strong_rand_bytes(32)
      assert {:ok, destination} = Reticulum.Destination.load_group_key(destination, loaded_key)
      assert {:ok, ^loaded_key} = Reticulum.Destination.group_key(destination)

      assert {:error, :invalid_group_key} =
               Reticulum.Destination.load_group_key(destination, <<1, 2, 3>>)
    end

    test "ratchet lifecycle APIs" do
      identity = Reticulum.Identity.new()
      {:ok, destination} = Reticulum.Destination.new(:in, :single, "app", identity, ["single"])

      ratchet_a = :crypto.strong_rand_bytes(32)
      ratchet_b = :crypto.strong_rand_bytes(32)

      assert {:ok, destination} = Reticulum.Destination.set_ratchets(destination, [ratchet_a])
      assert {:ok, destination} = Reticulum.Destination.add_ratchet(destination, ratchet_b)
      assert destination.ratchets == [ratchet_b, ratchet_a]

      assert {:ok, destination} = Reticulum.Destination.enforce_ratchets(destination, true)
      assert Reticulum.Destination.ratchet_enforced?(destination)

      assert {:ok, public_key} = Reticulum.Destination.current_ratchet_public_key(destination)
      assert is_binary(public_key)
      assert byte_size(public_key) == 32
    end
  end
end
